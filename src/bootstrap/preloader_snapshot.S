.syntax unified
.cpu cortex-a7
.thumb
.global snapshot_and_jump

/* Stage 1 calls this at 0x227001 after all checked SRAM images are uploaded.
 * Preserve live registers and the BootROM SRAM range before the staged
 * preloader executes. Then write back the uploaded preloader from D-cache and
 * branch to its SRAM entry with physical addressing. */
.thumb_func
snapshot_and_jump:
    ldr r0, =0x237fc0
    add r1, r0, #32
    stmia r1, {r4-r11}
    str lr, [r0, #28]
    ldr r4, =0x237fc0
    mov r0, sp
    str r0, [r4, #0]
    mrs r0, cpsr
    str r0, [r4, #4]
    mrc p15, 0, r0, c1, c0, 0
    str r0, [r4, #8]
    mrc p15, 0, r0, c2, c0, 0
    str r0, [r4, #12]
    mrc p15, 0, r0, c3, c0, 0
    str r0, [r4, #16]
    ldr r0, =0x53534e50
    str r0, [r4, #20]

    ldr r0, =0x102180
    ldr r1, =0x230000
    ldr r2, =0x109dac
    movs r5, #0
1:
    ldr r3, [r0], #4
    str r3, [r1], #4
    eors r5, r3
    cmp r0, r2
    blo 1b
    str r5, [r4, #24]
    dsb sy

    /* The preloader disables D-cache; force the backup into SRAM first. */
    ldr r0, =0x230000
    ldr r1, =0x237c40
2:
    mcr p15, 0, r0, c7, c14, 1
    adds r0, #32
    cmp r0, r1
    blo 2b
    ldr r0, =0x237fc0
    mcr p15, 0, r0, c7, c14, 1
    adds r0, #32
    mcr p15, 0, r0, c7, c14, 1
    dsb sy
    /* Stage 1 may have left the newly uploaded preloader only in D-cache. */
    ldr r0, =0x201000
    ldr r1, =0x226200
3:
    mcr p15, 0, r0, c7, c14, 1
    adds r0, #32
    cmp r0, r1
    blo 3b
    dsb sy
    /* Enter the preloader with physical SRAM addressing. */
    mrc p15, 0, r0, c1, c0, 0
    bic r0, r0, #5          /* MMU and D-cache off. */
    mcr p15, 0, r0, c1, c0, 0
    dsb sy
    isb sy
    ldr r0, =0x201000
    movs r4, #0
    bx r0

.ltorg
