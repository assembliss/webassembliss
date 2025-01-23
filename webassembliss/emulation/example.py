from qiling import Qiling
import subprocess

# Assemble the code:
subprocess.run(
    [
        "aarch64-linux-gnu-as",
        "hello.S",
        "-o",
        "hello.obj",
    ],
    check=True,
    text=True,
)

# Link the code:
subprocess.run(
    [
        "aarch64-linux-gnu-ld",
        "hello.obj",
        "-o",
        "rootfs/arm64_linux/userprograms/hello",
    ],
    check=True,
    text=True,
)

# Emulate the binary:
ql = Qiling(
    [r"rootfs/arm64_linux/userprograms/hello"],
    r"rootfs/arm64_linux",
)
ql.run()
