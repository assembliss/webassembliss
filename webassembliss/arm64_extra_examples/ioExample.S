/* This file receives input from stdin and stores into msg. Then it outputs the received data back to stdout. */
.data

/* Data segment: define a 41-byte buffer to receive input and calculate its length. */
msg:    .ascii  "1234567890123456789012345678901234567890\n"
len = . - msg

.text

/* Our application's entry point. */
.global _start
_start:
    /* syscall read(int fd, const void *buf, size_t count) */
    mov     x0, #0      /* fd := STDIN_FILENO */
    ldr     x1, =msg    /* buf := msg */
    ldr     x2, =len    /* count := len */
    mov     w8, #63     /* read is syscall #63 */
    svc     #0          /* invoke syscall */
    
    /* syscall write(int fd, const void *buf, size_t count) */
    mov     x0, #1      /* fd := STDOUT_FILENO */
    ldr     x1, =msg    /* buf := msg */
    ldr     x2, =len    /* count := len */
    mov     w8, #64     /* write is syscall #64 */
    svc     #0          /* invoke syscall */

    /* syscall exit(int status) */
    mov     x0, #0      /* status := 0 */
    mov     w8, #93     /* exit is syscall #93 */
    svc     #0          /* invoke syscall */
