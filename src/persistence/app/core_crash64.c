#include <signal.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

/* Run only after the app has read back the checked core_pattern change.
 * This disposable child enables its own core dump and crashes itself; it is
 * not a crash of Android init or the long-running voice application. The
 * kernel's pipe helper then starts /data/x, whose UID must be checked
 * independently by the caller. */
int main(void) {
    struct rlimit limit = {0, 0};
    int got_limit = getrlimit(RLIMIT_CORE, &limit);
    int dumpable = prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    printf("CORE_CHILD uid=%ld dumpable_rc=%d limit_rc=%d soft=%llu hard=%llu\n",
           (long)getuid(), dumpable, got_limit,
           (unsigned long long)limit.rlim_cur,
           (unsigned long long)limit.rlim_max);
    fflush(stdout);
    raise(SIGSEGV);
    return 3;
}
