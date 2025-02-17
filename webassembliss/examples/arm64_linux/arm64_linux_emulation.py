from qiling import Qiling  # type: ignore[import-untyped]
from qiling.const import QL_VERBOSE  # type: ignore[import-untyped]

if __name__ == "__main__":
    # Emulates one program at a time.
    for program in [
        "hello.out",
        "infiniteLoop.out",
        "ioExample.out",
        "multiExample.out",
        "cExample.out",
        "clArgs.out",
    ]:
        print("\n\n---- ---- ---- ---- ----\n---- ---- ---- ---- ----\n")
        print(f"Emulating {program}:\n\n")

        # Set up command line argv, emulated os root path, os default profile, and verboseness level.
        argv = [program, "test1", "two", "3"]
        rootfs = "../../rootfs/arm64_linux"
        profile = "linux.ql"
        # QL_VERBOSE.DISABLED   logging is disabled entirely
        # QL_VERBOSE.OFF    logging is restricted to warnings, errors and critical entries
        # QL_VERBOSE.DEFAULT    info verbosity
        # QL_VERBOSE.DEBUG  debug verbosity; increased verbosity
        # QL_VERBOSE.DISASM     emit disassembly for every emulated instruction
        # QL_VERBOSE.DUMP   emit cpu context along with disassembled instructions
        verboseness = QL_VERBOSE.OFF

        # Instantiate a Qiling object using above arguments;
        # Additional settings are read from profile file.
        ql = Qiling(argv, rootfs, verbose=verboseness, profile=profile)

        # https://docs.qiling.io/en/latest/debugger/
        # You can optionally turn on the debugger.
        # ql.debugger = True

        ql.run(timeout=5_000_000)
