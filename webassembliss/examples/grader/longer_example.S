.data

    char: .byte 0

.text

/* Our application's entry point. */
.global _start
_start:
    /* load char's address into x19 */
    ldr     x19, =char

echoBlock:
    /* syscall read(int fd, const void *buf, size_t count) */
    mov     x0, #0      /* fd := STDIN_FILENO */
    mov     x1, x19     /* buf := char */
    mov     x2, #1      /* count := 1 */
    mov     w8, #63     /* read is syscall #63 */
    svc     #0          /* invoke syscall */

    /* check for repeat character */
    ldrb    w20, [x19]
    cmp     w20, w21
    b.eq    end         /* if repeat character, exit */
    mov     w21, w20    /* otherwise, echo it and loop again */

    /* syscall write(int fd, const void *buf, size_t count) */
    mov     x0, #1      /* fd := STDOUT_FILENO */
    mov     x1, x19     /* buf := char */
    mov     x2, #1      /* count := 1 */
    mov     w8, #64     /* write is syscall #64 */
    svc     #0          /* invoke syscall */

    /* process next character */
    b echoBlock

exit:
    /* syscall exit(int status) */
    mov     x0, #0      /* status code is 0 */
    mov     w8, #93     /* exit is syscall #93 */
    svc     #0          /* invoke syscall */
