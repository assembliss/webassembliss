from emulation.arm64_linux import emulate
from io import BytesIO

# Example code the user might provide.
hello_world = """
.data

/* Data segment: define our message string and calculate its length. */
msg:
    .ascii        "Hello folks!\n"
len = . - msg

.text

/* Our application's entry point. */
.globl _start
_start:
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
"""

# Call the arm64 main function that will emulate the provided code.
# ok_results1 = emulate(code=hello_world)
# print(f"{ok_results1=}")
# print("\n")

# Example code with errors the user might provide.
infinite_loop = """
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
"""

# bad_results1 = emulate(code=infinite_loop, timeout=1_000_000)
# print(f"{bad_results1=}")
# print("\n")

# Example code the user might provide that asks for input.
io_example = """
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
"""

# We have input for the read instruction!
ok_results2 = emulate(
    code=io_example, timeout=1_000_000, stdin=BytesIO("hello-hello!".encode())
)
print(f"{ok_results2=}")
print("\n")

# We do NOT have input for the read instruction!
bad_results2 = emulate(code=io_example, timeout=1_000_000)
print(f"{bad_results2=}")
print("\n")
