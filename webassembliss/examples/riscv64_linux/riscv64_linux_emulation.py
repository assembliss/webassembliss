from qiling import Qiling

rootfs = "../../rootfs/riscv64_linux"
profile = "linux.ql"
argv = ["hello.out"]

ql = Qiling(argv, rootfs, profile=profile)

ql.run()
