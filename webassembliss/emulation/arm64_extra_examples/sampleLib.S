/* This file exemplifies how to use multiple sources. It needs to be linked with 'multipleTwo'. */
.data

/* Defines a printf template to show the subroutine return value. */
argMsg:    .asciz   "Received these four arguments: %d, %d, %d, %d\n"

.text

/* Lets us call routines from other source files. */
.extern printf
.global _exampleRoutine

/* Defines entrypoint for our subroutine. */
_exampleRoutine:
    /* Adds values together and stores result in x19. */
    add     x19, x0, x1
    add     x20, x2, x3
    add     x19, x19, x20
    /* Displays arguments received. For simplicity, if received (1,2,3,4) will show (2,3,4,1). */
    stp     x29, x30, [sp, #-16]!
    mov     x4, x0
    adr     x0, argMsg
    bl      printf
    ldp     x29, x30, [sp]
    /* Adds values together and stores result in x0. */
    add     x1, x1, x2
    add     x3, x3, x4
    add     x0, x1, x3
    /* Set return value and return to caller. */
    mov     x0, x19
    ret
