.text

/* Our application's entry point. */
.global _start
_start:
    mov     x0, #1
    adds    x1, x0, #2
    subs    x2, x0, x1

    /* syscall exit(int status) */
    mov     x0, #0      /* status := 0 */
    mov     w8, #93     /* exit is syscall #93 */
    svc     #0          /* invoke syscall */
