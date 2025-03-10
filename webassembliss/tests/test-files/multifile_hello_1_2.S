.text

/* Lets us call routines from other source files. */
.extern subHelloWorld

/* Our application's entry point. */
.global _start

_start:
    /* calls the subHelloWorld subroutine defined in multifile_hello_2_2.S */
    bl      subHelloWorld
    /* syscall exit(int status) */
    mov     x0, #0      /* status := 0 */
    mov     w8, #93     /* exit is syscall #93 */
    svc     #0          /* invoke syscall */
