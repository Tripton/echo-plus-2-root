// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Intentionally fixed. This program does not provide a command interface. */
#define PACKAGE "me.jxl.kiosk_satellite"
#define PERMISSION "android.permission.RECORD_AUDIO"
#define PM "/system/bin/pm"
#define AM "/system/bin/am"
#define DUMPSYS "/system/bin/dumpsys"
#define MAX_OUTPUT (256U * 1024U)
#define STEADY_POLL_SECONDS 60U

static volatile sig_atomic_t stop_requested;

static void on_signal(int signum) { (void)signum; stop_requested=1; }

static long long monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC,&ts)!=0) return -1;
    return (long long)ts.tv_sec*1000+ts.tv_nsec/1000000;
}

static void status_log(const char *event, const char *fmt, ...) {
    fprintf(stderr,"KIOSK_MIC_KEEPER time=%lld event=%s",(long long)time(NULL),event);
    if (fmt) {
        va_list ap;
        va_start(ap,fmt);
        fputc(' ',stderr);
        vfprintf(stderr,fmt,ap);
        va_end(ap);
    }
    fputc('\n',stderr);
    fflush(stderr);
}

/* Run only an absolute, compiled-in executable with compiled-in arguments.
 * Neither package-manager output nor environment variables reach a shell. */
static int run_capture(const char *program, char *const argv[],
                       char *output, size_t capacity, int timeout_ms) {
    int pipefd[2];
    if (pipe2(pipefd,O_CLOEXEC)!=0) return -errno;
    int flags=fcntl(pipefd[0],F_GETFL,0);
    if (flags<0 || fcntl(pipefd[0],F_SETFL,flags|O_NONBLOCK)<0) {
        int saved=errno;
        close(pipefd[0]); close(pipefd[1]);
        return -saved;
    }
    pid_t child=fork();
    if (child<0) {
        int saved=errno;
        close(pipefd[0]); close(pipefd[1]);
        return -saved;
    }
    if (child==0) {
        close(pipefd[0]);
        int nullfd=open("/dev/null",O_RDONLY|O_CLOEXEC);
        if (nullfd>=0) { dup2(nullfd,STDIN_FILENO); if (nullfd>2) close(nullfd); }
        dup2(pipefd[1],STDOUT_FILENO);
        dup2(pipefd[1],STDERR_FILENO);
        if (pipefd[1]>2) close(pipefd[1]);
        /* Android's app_process needs these even when the parent was started
         * by the minimal root broker rather than adbd's normal shell. */
        char *const environment[]={
            "PATH=/system/bin", "LANG=C", "ANDROID_DATA=/data",
            "ANDROID_ROOT=/system", NULL
        };
#ifdef MIC_KEEPER_RUNCON_CHILD
        /* The core-pattern root process is in kernel:s0. Enter shell:s0
         * through the trusted /system/bin/runcon before each fixed Android
         * tool, without changing the parent's security context. */
        char *wrapped[12]={"runcon","u:r:shell:s0",(char *)program,NULL};
        size_t index=1;
        while (argv[index] && index<9) {
            wrapped[index+2]=argv[index];
            ++index;
        }
        if (argv[index]) _exit(126);
        wrapped[index+2]=NULL;
        execve("/system/bin/runcon",wrapped,environment);
#else
        execve(program,argv,environment);
#endif
        _exit(127);
    }
    close(pipefd[1]);
    size_t used=0;
    int status=0, child_done=0, eof=0, result=0;
    long long start=monotonic_ms();
    long long deadline=start+timeout_ms;
    if (start<0) result=-EIO;
    while (!result && (!child_done || !eof)) {
        if (!child_done) {
            pid_t got=waitpid(child,&status,WNOHANG);
            if (got==child) child_done=1;
            else if (got<0) { result=-errno; break; }
        }
        char chunk[4096];
        ssize_t count=read(pipefd[0],chunk,sizeof(chunk));
        if (count>0) {
            if ((size_t)count>capacity-1-used) { result=-EOVERFLOW; break; }
            memcpy(output+used,chunk,(size_t)count); used+=(size_t)count;
            output[used]=0;
        } else if (count==0) {
            eof=1;
        } else if (errno!=EAGAIN && errno!=EINTR) {
            result=-errno;
            break;
        }
        if (child_done && eof) break;
        long long now=monotonic_ms();
        if (now<0) { result=-EIO; break; }
        if (now>=deadline || stop_requested) { result=-ETIMEDOUT; break; }
        if (eof) {
            struct timespec delay={0,100000000};
            nanosleep(&delay,NULL);
        } else {
            struct timeval delay={0,100000};
            fd_set readfds;
            FD_ZERO(&readfds); FD_SET(pipefd[0],&readfds);
            (void)select(pipefd[0]+1,&readfds,NULL,NULL,&delay);
        }
    }
    close(pipefd[0]);
    if (!child_done) {
        kill(child,SIGKILL);
        while (waitpid(child,&status,0)<0 && errno==EINTR) {}
    }
    if (capacity) output[used]=0;
    if (result) return result;
    return WIFEXITED(status) && WEXITSTATUS(status)==0 ? 0 : -ECHILD;
}

static int is_safe_base_apk_path(const char *path) {
    const char *prefix="/data/app/";
    size_t length=strlen(path);
    if (strncmp(path,prefix,strlen(prefix))!=0 ||
        length<=strlen(prefix)+strlen("/base.apk") ||
        strcmp(path+length-strlen("/base.apk"),"/base.apk")!=0 ||
        strstr(path,"..")!=NULL) return 0;
    for (const unsigned char *p=(const unsigned char *)path;*p;++p)
        if (!((*p>='a'&&*p<='z') || (*p>='A'&&*p<='Z') ||
              (*p>='0'&&*p<='9') || *p=='/' || *p=='_' || *p=='-' || *p=='.'))
            return 0;
    return 1;
}

static int parse_pm_path(const char *output, char path[512]) {
    const char *cursor=output;
    int matches=0;
    while (*cursor) {
        const char *end=strchr(cursor,'\n');
        if (!end) end=cursor+strlen(cursor);
        if ((size_t)(end-cursor)>8 && strncmp(cursor,"package:",8)==0) {
            size_t length=(size_t)(end-cursor-8);
            if (length>=512) return -1;
            char candidate[512];
            memcpy(candidate,cursor+8,length); candidate[length]=0;
            if (is_safe_base_apk_path(candidate)) {
                memcpy(path,candidate,length+1);
                ++matches;
            }
        }
        cursor=*end ? end+1 : end;
    }
    return matches==1 ? 0 : -1;
}

typedef struct {
    int package_found;
    int requested;
    int runtime_seen;
    int granted; /* -1 unknown; 0 denied; 1 granted */
} permission_state;

static permission_state parse_package_dump(char *dump) {
    permission_state state={0,0,0,-1};
    int inside=0, requested_section=0, user0=0, runtime_section=0;
    for (char *line=dump; line && *line;) {
        char *next=strchr(line,'\n');
        if (next) { *next=0; ++next; }
        while (*line==' ' || *line=='\t') ++line;
        size_t size=strlen(line);
        while (size && (line[size-1]=='\r' || line[size-1]==' ')) line[--size]=0;
        if (strncmp(line,"Package [",9)==0) {
            inside=strncmp(line,"Package [" PACKAGE "]",10+strlen(PACKAGE))==0;
            if (inside) state.package_found=1;
            requested_section=user0=runtime_section=0;
        }
        if (inside) {
            if (strcmp(line,"requested permissions:")==0) {
                requested_section=1;
            } else if (requested_section) {
                if (strcmp(line,PERMISSION)==0) state.requested=1;
                else if (strchr(line,':')!=NULL) requested_section=0;
            }
            if (strncmp(line,"User ",5)==0) {
                user0=strncmp(line,"User 0:",7)==0;
                runtime_section=0;
            } else if (user0 && strcmp(line,"runtime permissions:")==0) {
                runtime_section=1;
                state.runtime_seen=1;
            } else if (runtime_section &&
                       strncmp(line,PERMISSION ":",sizeof(PERMISSION))==0) {
                if (strstr(line,"granted=true")) state.granted=1;
                else if (strstr(line,"granted=false")) state.granted=0;
            }
        }
        line=next;
    }
    if (state.runtime_seen && state.granted<0) state.granted=0;
    return state;
}

#ifndef MIC_KEEPER_TEST
static int sleep_to_next(unsigned seconds) {
    long long end=monotonic_ms()+(long long)seconds*1000;
    while (!stop_requested && monotonic_ms()<end) {
        struct timespec delay={1,0};
        nanosleep(&delay,NULL);
    }
    return stop_requested;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc!=1 || getuid()!=0 || geteuid()!=0) return 64;
    signal(SIGTERM,on_signal); signal(SIGINT,on_signal);
    char output[MAX_OUTPUT];
    char path[512]={0}, previous_path[512]={0};
    struct stat observed={0};
    int path_observed=0, last_granted=-1, error_logged=0;
    status_log("START","lifetime=until_signal_or_reboot package=%s",PACKAGE);
    for (unsigned iteration=0; !stop_requested; ++iteration) {
        /* Android 7's pm file has no shebang. Invoke it through the fixed
         * system shell; execve(PM, ...) alone fails with ENOEXEC. */
        char *const path_args[]={"sh",PM,"path",PACKAGE,NULL};
        int rc=run_capture("/system/bin/sh",path_args,output,sizeof(output),8000);
        if (rc==0) rc=parse_pm_path(output,path);
        if (rc!=0) {
            if (!error_logged) status_log("PACKAGE_UNAVAILABLE","rc=%d",rc);
            error_logged=1;
            goto next;
        }
        struct stat current;
        if (lstat(path,&current)!=0 || !S_ISREG(current.st_mode) ||
            current.st_size<1 || current.st_size>512000000) {
            if (!error_logged) status_log("APK_UNAVAILABLE",NULL);
            error_logged=1;
            goto next;
        }
        if (!path_observed || strcmp(path,previous_path)!=0 ||
            current.st_dev!=observed.st_dev || current.st_ino!=observed.st_ino ||
            current.st_size!=observed.st_size || current.st_mtime!=observed.st_mtime) {
            observed=current;
            memcpy(previous_path,path,strlen(path)+1);
            path_observed=1;
            status_log("PACKAGE_PATH_READY",NULL);
        }
        char *const dump_args[]={"dumpsys","package",PACKAGE,NULL};
        rc=run_capture(DUMPSYS,dump_args,output,sizeof(output),8000);
        if (rc!=0) {
            if (!error_logged) status_log("PACKAGE_DUMP_FAILED","rc=%d",rc);
            error_logged=1;
            goto next;
        }
        permission_state permission=parse_package_dump(output);
        if (!permission.package_found || !permission.requested ||
            !permission.runtime_seen || permission.granted<0) {
            if (!error_logged) status_log("PERMISSION_STATE_UNKNOWN",NULL);
            error_logged=1;
            goto next;
        }
        error_logged=0;
        if (permission.granted) {
            if (last_granted!=1) status_log("GRANTED_ALREADY",NULL);
            last_granted=1;
            goto next;
        }
        if (last_granted!=0) status_log("REVOKED_DETECTED",NULL);
        last_granted=0;
        /* Resolve the installed package again immediately before the grant. */
        char confirmed_path[512];
        struct stat confirmed;
        rc=run_capture("/system/bin/sh",path_args,output,sizeof(output),8000);
        if (rc!=0 || parse_pm_path(output,confirmed_path)!=0 ||
            strcmp(path,confirmed_path)!=0 ||
            lstat(path,&confirmed)!=0 ||
            confirmed.st_dev!=observed.st_dev || confirmed.st_ino!=observed.st_ino ||
            confirmed.st_size!=observed.st_size || confirmed.st_mtime!=observed.st_mtime) {
            status_log("IDENTITY_CHANGED_BEFORE_GRANT",NULL);
            goto next;
        }
        /* The fixed command is the only permission mutation in this binary. */
        char *const grant_args[]={"sh",PM,"grant",PACKAGE,PERMISSION,NULL};
        rc=run_capture("/system/bin/sh",grant_args,output,sizeof(output),8000);
        if (rc!=0) {
            status_log("GRANT_FAILED","rc=%d",rc);
            goto next;
        }
        rc=run_capture(DUMPSYS,dump_args,output,sizeof(output),8000);
        if (rc!=0) {
            status_log("VERIFY_FAILED","rc=%d",rc);
            goto next;
        }
        permission=parse_package_dump(output);
        if (permission.package_found && permission.requested && permission.granted==1) {
            status_log("GRANT_VERIFIED",NULL);
            last_granted=1;
            /* Permission revocation kills Kiosk. The guard can relaunch it
             * before the grant, leaving the voice engine idle. Restart only
             * after verifying the grant, using fixed package/component. */
            char *const stop_args[]={"sh",AM,"force-stop",PACKAGE,NULL};
            rc=run_capture("/system/bin/sh",stop_args,output,sizeof(output),8000);
            if (rc!=0) {
                status_log("RESTART_STOP_FAILED","rc=%d",rc);
                goto next;
            }
            char *const start_args[]={"sh",AM,"start","-n",PACKAGE "/.MainActivity",NULL};
            rc=run_capture("/system/bin/sh",start_args,output,sizeof(output),8000);
            if (rc==0) status_log("APP_RESTARTED_AFTER_GRANT",NULL);
            else status_log("RESTART_START_FAILED","rc=%d",rc);
        } else status_log("VERIFY_DENIED",NULL);
next:
        ;
        /* Fast boot window, then low-rate observation for Arcus re-sync.
         * A later permission revocation can occur long after boot. */
        unsigned pause=iteration<10 ? 3U : STEADY_POLL_SECONDS;
        if (sleep_to_next(pause)) break;
    }
    status_log("STOP","reason=signal");
    return 0;
}
#endif
