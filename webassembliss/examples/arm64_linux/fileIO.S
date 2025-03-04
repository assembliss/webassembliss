/* This file copies the contents of rootfs/arm64_linux/testfile.txt into a new file in that same directory. */
.data

inerrormsg: .ascii "Could not open file to read: "
infilename: .asciz "/userprograms/testfile.txt"     // using absolute path because we only have access to the roofts/arm64_linux directory
inerrormsgLen = . - inerrormsg - 1                  // -1 because of the null-terminator

outerrormsg: .ascii "Could not open file to write: "
outfilename: .asciz "/userprograms/testfile-copy.txt"
outerrormsgLen = . - outerrormsg - 1

buffer: .space 512
bufLen = . - buffer

.text

/* Our application's entry point. */
.global _start
_start:

openIn: /* Open file to read */
    /* syscall openat(int dirfd, const char *pathname, int flags) */
    /* dirfd should be AT_FDCWD (-100 on linux) if you have a relative pathname from the current working directory */
    /* if you're using an absolute path like in this example, dirfd is ignored */
    mov     x0, #-100       /* AT_FDCWD -> use current working directory for relative path */
    ldr     x1, =infilename /* filename to be open */
    /* flags can be O_RDONLY (0), O_WRONLY(1), or O_RDWR (2) */
    /* if you want to create the file, add O_CREAT (100) to it */
    mov     x2, #0          /* O_RDONLY -> will only read the file */
    mov     w8, #56         /* openat is syscall #56 */
    svc     #0

checkIn: /* Make sure input file was open correctly */
    cmp     x0, #-1         /* if the file handle is -1, then coud not open the file. */
    beq     errorIn         /* print message saying input file could not be open */
    mov     x19, x0         /* save the filehandle if we need it later */

read: /* Read input file contents into buffer. */
    /* syscall read(int fd, const void *buf, size_t count) */
    /* fd is already in x0 */
    ldr     x1, =buffer     /* buf := buffer */
    ldr     x2, =bufLen     /* count := len */
    mov     w8, #63         /* read is syscall #63 */
    svc     #0              /* invoke syscall */
    mov     x20, x0         /* store the actual buffer size in x20 */

closeIn: /* Close input file */
    /* syscall close(int fd) */
    mov     x0, x19         /* load filehandle to be closed */
    mov     w8, #57         /* close is syscall #57 */
    svc     #0

openOut: /* Open file to write */
    /* syscall openat(int dirfd, const char *pathname, int flags) */
    mov     x0, #-100           /* AT_FDCWD -> use current working directory for relative path */
    ldr     x1, =outfilename    /* filename to be open */
    mov     x2, #101            /* O_WRONLY (1) + O_CREAT (100) -> will only write to file + create it if doesn't exist */
    mov     w8, #56             /* openat is syscall #56 */
    svc     #0

checkOut: /* Make sure output file was open correctly */
    cmp     x0, #-1         /* if the file handle is -1, then coud not open the file. */
    beq     errorOut        /* print message saying output file could not be open */
    mov     x21, x0         /* save the filehandle if we need it later */

write: /* Write buffer contents into output file. */
    /* syscall write(int fd, const void *buf, size_t count) */
    /* fd is already in x0 */
    ldr     x1, =buffer     /* buf := buffer */
    mov     x2, x20         /* count := actual buffer size */
    mov     w8, #64         /* write is syscall #64 */
    svc     #0              /* invoke syscall */

closeOut: /* Close output file */
    /* syscall close(int fd) */
    mov     x0, x21         /* load filehandle to be closed */
    mov     w8, #57         /* close is syscall #57 */
    svc     #0

exit: /* finish the program execution */
    /* syscall exit(int status) */
    mov     x0, #0      /* exit code */
    mov     w8, #93     /* exit is syscall #93 */
    svc     #0

errorIn: /* prepare error message for input file error to be shown */
    ldr     x1, =inerrormsg     /* buf := msg */
    ldr     x2, =inerrormsgLen  /* count := len */
    b       printAndExit

errorOut: /* prepare error message for output file error to be shown */
    ldr     x1, =outerrormsg    /* buf := msg */
    ldr     x2, =outerrormsgLen /* count := len */

printAndExit: /* print x2 bytes of message in x1 and branch to exit */
    /* syscall write(int fd, const void *buf, size_t count) */
    mov     x0, #1      /* fd := STDOUT_FILENO */
    mov     w8, #64     /* write is syscall #64 */
    svc     #0          /* invoke syscall */
    b       exit        /* jump to exit */
