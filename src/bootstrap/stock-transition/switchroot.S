.section .text
.global _start
.balign 4
_start:
    // Preserve the existing environment for stock init (or selftest).
    ldr x24, [sp]
    add x22, sp, #8
    add x22, x22, x24, lsl #3
    add x22, x22, #8

    // Isolate mount moves from the recovery adbd and the host's USB shell.
    mov x0, #0x20000
    mov x8, #97
    svc #0
    cmp x0, #0
    b.lt failure
    adr x1, unshare_ok
    mov x2, #unshare_ok_end - unshare_ok
    bl emit

    mov x0, #0
    adr x1, root_path
    mov x2, #0
    movz x3, #4, lsl #16
    movk x3, #0x4000
    mov x4, #0
    mov x8, #40
    svc #0
    cmp x0, #0
    b.lt failure

    // These are the three top-level mounts in the checked recovery layout.
    adr x0, dev_path
    adr x1, new_dev_path
    mov x2, #0
    mov x3, #0x2000
    mov x4, #0
    mov x8, #40
    svc #0
    cmp x0, #0
    b.lt failure

    adr x0, proc_path
    adr x1, new_proc_path
    mov x2, #0
    mov x3, #0x2000
    mov x4, #0
    mov x8, #40
    svc #0
    cmp x0, #0
    b.lt failure

    adr x0, sys_path
    adr x1, new_sys_path
    mov x2, #0
    mov x3, #0x2000
    mov x4, #0
    mov x8, #40
    svc #0
    cmp x0, #0
    b.lt failure
    adr x1, mounts_ok
    mov x2, #mounts_ok_end - mounts_ok
    bl emit

    adr x0, new_root_path
    mov x8, #49
    svc #0
    cmp x0, #0
    b.lt failure
    adr x0, new_root_path
    adr x1, root_path
    mov x2, #0
    mov x3, #0x2000
    mov x4, #0
    mov x8, #40
    svc #0
    cmp x0, #0
    b.lt failure
    adr x0, dot_path
    mov x8, #51
    svc #0
    cmp x0, #0
    b.lt failure
    adr x0, root_path
    mov x8, #49
    svc #0
    cmp x0, #0
    b.lt failure
    adr x1, root_ok
    mov x2, #root_ok_end - root_ok
    bl emit

    // The recovery PID 1 owns /dev/ttyGS0 on fds 0,1,2,3,10. Zygote
    // refuses every non-whitelisted fd inherited from init.
    mov x0, #-100
    adr x1, null_path
    mov x2, #2
    mov x3, #0
    mov x8, #56
    svc #0
    cmp x0, #3
    b.lt failure
    mov x19, x0
    mov x21, #0
dup_standard_fd:
    mov x0, x19
    mov x1, x21
    mov x2, #0
    mov x8, #24
    svc #0
    cmp x0, #0
    b.lt failure
    add x21, x21, #1
    cmp x21, #3
    b.lt dup_standard_fd

    mov x21, #3
    mov x23, #1024
close_extra_fd:
    mov x0, x21
    mov x8, #57
    svc #0
    add x21, x21, #1
    cmp x21, x23
    b.lt close_extra_fd

    // argc=2 is a child-process selftest. PID 1 passes argc=1.
    cmp x24, #2
    b.eq selftest
    adr x0, init_path
    adr x1, init_argv
    mov x2, x22
    mov x8, #221
    svc #0
    b failure

selftest:
    adr x0, true_path
    adr x1, true_argv
    mov x2, x22
    mov x8, #221
    svc #0

failure:
    adr x1, failed
    mov x2, #failed_end - failed
    bl emit
    mov x0, #127
    mov x8, #93
    svc #0

emit:
    mov x0, #1
    mov x8, #64
    svc #0
    ret

.balign 8
init_argv:
    .xword init_path
    .xword stage_arg
    .xword 0
true_argv:
    .xword true_path
    .xword 0
root_path: .asciz "/"
new_root_path: .asciz "/system_root"
dot_path: .asciz "."
dev_path: .asciz "/dev"
proc_path: .asciz "/proc"
sys_path: .asciz "/sys"
new_dev_path: .asciz "/system_root/dev"
new_proc_path: .asciz "/system_root/proc"
new_sys_path: .asciz "/system_root/sys"
null_path: .asciz "/dev/null"
init_path: .asciz "/init"
stage_arg: .asciz "--second-stage"
true_path: .asciz "/system/bin/true"
unshare_ok: .ascii "LIDAR_SWITCHROOT_UNSHARE_OK\n"
unshare_ok_end:
mounts_ok: .ascii "LIDAR_SWITCHROOT_MOUNTS_OK\n"
mounts_ok_end:
root_ok: .ascii "LIDAR_SWITCHROOT_ROOT_OK\n"
root_ok_end:
failed: .ascii "LIDAR_SWITCHROOT_INIT_FAIL\n"
failed_end:
