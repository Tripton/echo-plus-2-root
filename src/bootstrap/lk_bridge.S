.syntax unified
.cpu cortex-a7
.thumb
.global lk_bridge_entry
.thumb_func
/* Called from the checked preloader hook after LK is loaded in DRAM.
 * Every mismatch returns to the original preloader call. The only live LK
 * instruction patched is its checked four-byte handoff into the kernel. */
lk_bridge_entry:
    stmdb sp!, {r0-r12, lr}

    /* 1. Check LK entry and the final handoff instruction. */
    ldr r4, =0x41e00080
    ldr r5, [r4]
    ldr r6, =0xe10f0000
    cmp r5, r6
    bne stock_handoff
    ldr r4, =0x41e1be56
    ldrh r5, [r4]
    ldr r6, =0xf8da
    cmp r5, r6
    bne stock_handoff
    ldrh r5, [r4, #2]
    cmp r5, #0
    bne stock_handoff

    /* 2. Confirm both destination caves still contain their stock fill. */
    ldr r4, =0x41e24500
    movs r5, #32
    mvn r6, #0
check_thumb_cave:
    ldr r7, [r4], #4
    cmp r7, r6
    bne stock_handoff
    subs r5, #1
    bne check_thumb_cave
    ldr r4, =0x41e32000
    movw r5, #768
check_a64_buffer:
    ldr r7, [r4], #4
    cmp r7, #0
    bne stock_handoff
    subs r5, #1
    bne check_a64_buffer

    /* 3. Copy the bounded AArch64 payload and Thumb handoff cave from SRAM. */
    ldr r4, =0x00228000
    ldr r5, =0x41e32000
    movw r6, #768
copy_a64:
    ldr r7, [r4], #4
    str r7, [r5], #4
    subs r6, #1
    bne copy_a64
    ldr r4, =0x00229000
    ldr r5, =0x41e24500
    movs r6, #32
copy_thumb_cave:
    ldr r7, [r4], #4
    str r7, [r5], #4
    subs r6, #1
    bne copy_thumb_cave

    /* 4. Flush both caves, then change the checked handoff instruction. */
    ldr r4, =0x41e32000
    movs r5, #96
clean_a64_buffer:
    mcr p15, 0, r4, c7, c14, 1
    adds r4, #32
    subs r5, #1
    bne clean_a64_buffer
    ldr r4, =0x41e24500
    movs r5, #4
clean_thumb_cave:
    mcr p15, 0, r4, c7, c14, 1
    adds r4, #32
    subs r5, #1
    bne clean_thumb_cave
    dsb sy
    ldr r4, =0x41e1be56
    ldr r5, =0xf008
    strh r5, [r4]
    ldr r5, =0xbb53
    strh r5, [r4, #2]
    mcr p15, 0, r4, c7, c14, 1
    dsb sy
    movs r5, #0
    mcr p15, 0, r5, c7, c5, 0
    mcr p15, 0, r5, c7, c5, 6
    mcr p15, 0, r5, c7, c1, 0
    dsb sy
    isb sy
stock_handoff:
    /* 5. Resume the preloader's original LK handoff. */
    ldmia sp!, {r0-r12, lr}
    ldr lr, =0x20e5b9
    ldr pc, =0x20e199
.align 2
.ltorg
