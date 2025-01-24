.data

.text

/* Our application's entry point. */
.globl _start
_start:
    mov     x0, #1      /* move 1 into x0 */
    b       _start      /* jump back to the line above */

    /* syscall exit(int status) -- never reached */
    mov     x0, #0      /* status := 0 */
    mov     w8, #93     /* exit is syscall #93 */
    svc     #0          /* invoke syscall */
