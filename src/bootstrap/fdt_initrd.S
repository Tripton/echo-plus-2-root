.text
.balign 4
.global fdt_initrd_entry
/* AArch64 kernel-entry shim. x0 is the FDT pointer passed by LK.
 * The original image entry is 0x40080000. Invalid, unexpected or duplicate
 * data always forwards there without modifying the FDT or ramdisk. */
fdt_initrd_entry:
    /* 1. Bound the FDT header, structure block and strings block. */
    cbz x0, forward
    lsr x16, x0, #30
    cmp x16, #1
    b.ne forward
    ldr w16, [x0]
    movz w17, #0x0dd0
    movk w17, #0xedfe, lsl #16
    cmp w16, w17
    b.ne forward
    ldr w16, [x0, #4]
    rev w16, w16
    cmp w16, #40
    b.lo forward
    cmp w16, #0x20000
    b.hi forward
    add x26, x0, x16
    movz x17, #0x8000, lsl #16
    cmp x26, x17
    b.hi forward
    ldr w16, [x0, #8]
    rev w16, w16
    add x5, x0, x16
    ldr w16, [x0, #36]
    rev w16, w16
    add x6, x5, x16
    cmp x6, x26
    b.hi forward
    ldr w16, [x0, #12]
    rev w16, w16
    add x7, x0, x16
    ldr w16, [x0, #32]
    rev w16, w16
    add x8, x7, x16
    cmp x8, x26
    b.hi forward
    mov w9, #0
    mov w10, #0
    mov x24, xzr
    mov x25, xzr
    /* 2. Walk FDT tokens and locate the one /chosen/bootargs property. */
next_token:
    add x11, x5, #4
    cmp x11, x6
    b.hi forward
    ldr w11, [x5], #4
    rev w11, w11
    cmp w11, #1
    b.eq begin_node
    cmp w11, #2
    b.eq end_node
    cmp w11, #3
    b.eq property
    cmp w11, #4
    b.eq next_token
    cmp w11, #9
    b.eq scan_args
    b forward
begin_node:
    mov x12, x5
    mov x13, x5
node_name_end:
    cmp x13, x6
    b.hs forward
    ldrb w16, [x13], #1
    cbnz w16, node_name_end
    sub x14, x13, x12
    sub x14, x14, #1
    cmp w9, #1
    b.ne node_advance
    cmp x14, #6
    b.ne node_advance
    adr x15, chosen_name
    mov x14, x12
    mov w17, #6
compare_chosen:
    ldrb w16, [x14], #1
    ldrb w11, [x15], #1
    cmp w16, w11
    b.ne node_advance
    subs w17, w17, #1
    b.ne compare_chosen
    mov w10, #1
node_advance:
    add x5, x13, #3
    bic x5, x5, #3
    cmp x5, x6
    b.hi forward
    add w9, w9, #1
    b next_token
end_node:
    cbz w9, forward
    cmp w9, #2
    b.ne end_advance
    mov w10, #0
end_advance:
    sub w9, w9, #1
    b next_token
property:
    add x11, x5, #8
    cmp x11, x6
    b.hi forward
    ldr w11, [x5], #4
    rev w11, w11
    ldr w12, [x5], #4
    rev w12, w12
    mov x18, x5
    add x13, x5, x11
    mov x19, x13
    cmp x13, x6
    b.hi forward
    add x14, x13, #3
    bic x14, x14, #3
    cmp x14, x6
    b.hi forward
    mov x5, x14
    cbz w10, next_token
    cmp w9, #2
    b.ne next_token
    add x15, x7, x12
    add x14, x15, #9
    cmp x14, x8
    b.hi forward
    adr x14, bootargs_name
    mov w17, #9
compare_bootargs:
    ldrb w16, [x15], #1
    ldrb w11, [x14], #1
    cmp w16, w11
    b.ne next_token
    subs w17, w17, #1
    b.ne compare_bootargs
    cbnz x24, forward
    mov x24, x18
    mov x25, x19
    b next_token
/* Historical 4-byte diagnostic loop is retained for binary identity. It is
 * unreachable in this selected release path. */
halt:
    b halt
scan_args:
    /* 3. Require one exact earlycon token and one skip_initramfs token. */
    cbz x24, forward
    sub x16, x25, x24
    cmp x16, #2048
    b.hi forward
    mov x18, x24
check_string:
    cmp x18, x25
    b.hs forward
    ldrb w16, [x18], #1
    cbnz w16, check_string
    cmp x18, x25
    b.ne forward
    adr x20, early_token
    mov w23, #35
    bl find_unique
    cbz x9, forward
    mov x27, x9
    adr x20, skip_token
    mov w23, #14
    bl find_unique
    cbz x9, forward
    mov x28, x9
    /* 4. Check both source gzip headers and append the 2,038-byte overlay. */
    movz x21, #0x4400, lsl #16
    ldr w16, [x21]
    movz w17, #0x8b1f
    movk w17, #0x0008, lsl #16
    cmp w16, w17
    b.ne forward
    movz x20, #0x41e3, lsl #16
    movk x20, #0x2400
    ldr w16, [x20]
    movz w17, #0x8b1f
    movk w17, #0x0008, lsl #16
    cmp w16, w17
    b.ne forward
    movz x21, #0x443e, lsl #16
    movk x21, #0xd7eb
    mov w23, #2038
copy_marker:
    ldrb w16, [x20], #1
    strb w16, [x21], #1
    subs w23, w23, #1
    b.ne copy_marker
    movz x21, #0x443e, lsl #16
    movk x21, #0xd7eb
    add x22, x21, #2038
    bl clean_range
    dsb sy
    /* 5. Reuse the 35-byte earlycon span for initrd= and clear skip_initramfs. */
    adr x20, replacement
    mov x21, x27
    mov w23, #35
copy_argument:
    ldrb w16, [x20], #1
    strb w16, [x21], #1
    subs w23, w23, #1
    b.ne copy_argument
    mov x21, x28
    mov w23, #14
    mov w16, #32
clear_skip:
    strb w16, [x21], #1
    subs w23, w23, #1
    b.ne clear_skip
    mov x21, x27
    add x22, x27, #35
    bl clean_range
    mov x21, x28
    add x22, x28, #14
    bl clean_range
    dsb sy
    b forward
/* Search within the bounded property and fail if a token occurs twice. */
find_unique:
    mov x9, xzr
    mov x18, x24
    sub x19, x25, x23
token_scan:
    cmp x18, x19
    b.hi token_done
    mov x21, x18
    mov x22, x20
    mov w17, w23
token_compare:
    ldrb w16, [x21], #1
    ldrb w11, [x22], #1
    cmp w16, w11
    b.ne token_next
    subs w17, w17, #1
    b.ne token_compare
    cbnz x9, token_duplicate
    mov x9, x18
token_next:
    add x18, x18, #1
    b token_scan
token_duplicate:
    mov x9, xzr
token_done:
    ret
clean_range:
    /* LK's cache state requires explicit clean before the kernel reads data. */
    bic x21, x21, #31
clean_line:
    dc cvac, x21
    add x21, x21, #32
    cmp x21, x22
    b.lo clean_line
    ret
forward:
    /* Resume the signed stock kernel even if any guard failed. */
    movz x16, #0x4008, lsl #16
    br x16
chosen_name:
    .ascii "chosen"
bootargs_name:
    .asciz "bootargs"
early_token:
    .ascii "earlycon=uart8250,mmio32,0x11005000"
skip_token:
    .ascii "skip_initramfs"
replacement:
    .ascii "initrd=0x44000000,0x3edfe1 panic=1 "
    .balign 4
marker_data:
    .org 1024
    .incbin "initramfs_overlay.cpio.gz"
    .balign 4
