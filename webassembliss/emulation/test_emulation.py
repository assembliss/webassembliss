from qiling import Qiling

rootfs = "/webassembliss/rootfs/riscv64_linux"
profile = "linux.ql"
argv = ["HelloWorld"]

ql = Qiling(argv, rootfs, profile=profile)

ql.run()