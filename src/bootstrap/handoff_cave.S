.syntax unified
.cpu cortex-a7
.thumb
.global handoff_cave_entry
.thumb_func

/* At 0x41e1be56 the original instruction is ldr.w r0, [sl]. The AArch64
 * path later takes the Image entry from [sp,#0x18] and passes it to SMC
 * 0x82000200. Redirect only a checked 0x40080000 to our DRAM shim, then
 * resume the original LK instruction stream at 0x41e1be5b. */
handoff_cave_entry:
    push.w {r1, r2, lr}
    ldr.w r0, [sl]
    cbz r0, resume
    ldr r1, [sp, #0x24]
    ldr r2, =0x40080000
    cmp r1, r2
    bne resume
    ldr r2, =0x41e32000
    str r2, [sp, #0x24]
resume:
    pop.w {r1, r2, lr}
    ldr pc, =0x41e1be5b

.align 2
.ltorg
.org 128, 0xff
