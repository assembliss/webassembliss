.data

msg: .asciz "Arg #%d: '%s'\n"

.text

/* Our application's entry point. */
.global _start
.extern printf

_start:
    mov     x19, #1         /* store our count into x19 */
    add     x20, sp, #8     /* skips argc and store &argv in x20 */

print_loop:  /* print current arg */
    ldr     x0, =msg        /* store our format string into printf's 1st param */
    mov     x1, x19         /* move our current count into printf's 2nd param */
    ldr     x2, [x20]       /* load argv[i] into printf's 3rd param */
    cmp     x2, #0          /* check if arg exists */
    beq     exit            /* if arg is null, exit the program */
    bl      printf          /* print the formatted messages with the appropriate values */

step:   /* advance to next argument and loop */
    add     x19, x19, #1    /* increase our count */
    add     x20, x20, #8    /* move from argv[i] to argv[i+1] */
    b       print_loop

exit:   /* syscall exit(int status) */
    mov     x0, #0          /* status := 0 */
    mov     w8, #93         /* exit is syscall #93 */
    svc     #0              /* invoke syscall */
