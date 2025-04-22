/* This file exemplifies how to use multiple sources. It needs to be linked with 'sampleLib' and the '-lc' flag. */
.data

/* Defines a printf template to show the subroutine return value. */
retMsg:    .asciz   "Return value from last call: %d\n"

.text

/* Lets us call routines from other source files. */
.extern _exampleRoutine, printf

/* Our application's entry point. */
.global _start
_start:
    /* Call subroutine with (1,2,3,4) should receive 10. */
    stp     x29, x30, [sp, #-16]!
    mov     x0, #1
    mov     x1, #2
    mov     x2, #3
    mov     x3, #4
    bl      _exampleRoutine
    ldp     x29, x30, [sp]
    /* Output return value. */
    stp     x29, x30, [sp, #-16]!
    mov     x1, x0
    adr     x0, retMsg
    bl      printf
    ldp     x29, x30, [sp]
    /* Call subroutine with (9,18,29,36) should receive 92. */
    stp     x29, x30, [sp, #-16]!
    mov     x0, #9
    mov     x1, #18
    mov     x2, #29
    mov     x3, #36
    bl      _exampleRoutine
    ldp     x29, x30, [sp]
    /* Output return value. */
    stp     x29, x30, [sp, #-16]!
    mov     x1, x0
    adr     x0, retMsg
    bl      printf
    ldp     x29, x30, [sp]
    /* syscall exit(int status) */
    mov     x0, #0      /* status := 0 */
    mov     w8, #93     /* exit is syscall #93 */
    svc     #0          /* invoke syscall */
