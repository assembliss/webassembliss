from qiling import Qiling

rootfs = "../../rootfs/x8664_linux"
profile = "linux.ql"
argv = ["hello.out"]

ql = Qiling(argv, rootfs, profile=profile)

ql.run()
