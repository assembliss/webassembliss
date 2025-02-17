/* Shows how many cl-arguments it received and outputs each one. */

.data

msg:        .ascii      "Received " 
val:        .ascii      "0"
            .asciz      " argument(s):"
newLine:    .asciz      "\n"

.text

/* Our application's entry point. */
.global _start

_start:
    /* initialize control registers to loop over arguments */
    /* using x19-21 because they *should* be preserved after our syscalls */
    ldr     x19, [sp]       /* read argc */
    mov     x20, #1         /* store our count into x20 */
    add     x21, sp, #8     /* skips argc and store &argv in x21 */

firstPrint: /* print the formatted message saying how many arguments were received */
    add     x0, x19, '0'    /* convert argc into a char */
    ldr     x1, =val        /* get val's memory address */
    strb    w0, [x1]        /* store char_argc into appropriate mem location */
    ldr     x1, =msg        /* x1 points to message to output */
    bl      printX1         /* call our print subroutine */

print_loop:  /* print current arg */
    bl      printLinebreak  /* print a new line so args are separated */
    ldr     x1, [x21]       /* load argv[i] into x1 */
    bl      printX1         /* print the formatted messages with the appropriate values */

step:       /* advance to next argument and loop */
    add     x20, x20, #1    /* increase our count */
    add     x21, x21, #8    /* move from argv[i] to argv[i+1] */
    cmp     x19, x20        /* compare arg_num with argc */
    bpl     print_loop      /* if not printed all args, loop */

exit:       /* exit program */
    /* syscall exit(int status) */
    mov     x0, #0          /* status := 0 */
    mov     w8, #93         /* exit is syscall #93 */
    svc     #0              /* invoke syscall */

printX1:    /* print the buffer that x1 holds */
    /* first, find the length of x1 and store it into x2 */
    mov     x2, #0          /* init len as 0 */
_lenLoop:
    ldrb    w3, [x1, x2]    /* load the x2'th char of the buffer*/
    cmp     w3, #0          /* check for null terminator */
    cinc    x2, x2, ne      /* increase x2 count if it was not the null-terminator */
    bne     _lenLoop        /* if not null-terminator, loop to check next char */

    /* then, call the syscall; buff and count are already in place */
    /* syscall write(int fd, const void *buf, size_t count) */
    mov     x0, #1          /* fd := STDOUT_FILENO */
    mov     w8, #64         /* write is syscall #64 */
    svc     #0              /* invoke syscall */
    ret                     /* return to caller */

printLinebreak:
    /* syscall write(int fd, const void *buf, size_t count) */
    mov     x0, #1          /* fd := STDOUT_FILENO */
    ldr     x1, =newLine    /* buf := msg */
    mov     x2, #1          /* one byte */
    mov     w8, #64         /* write is syscall #64 */
    svc     #0              /* invoke syscall */
    ret                     /* return to caller */
