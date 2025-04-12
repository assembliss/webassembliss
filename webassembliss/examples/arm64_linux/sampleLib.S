/* This file defines a subroutine that can be accessed from external files. */

.text

.global _exampleRoutine

/* Defines entrypoint for our subroutine. */
_exampleRoutine:
    /* Adds values together and stores result in x0. */
    add     x1, x1, x2
    add     x3, x3, x4
    add     x0, x1, x3
    /* Return to caller. */
    ret
