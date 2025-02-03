import os
import subprocess
import threading
from io import BytesIO
from typing import Any, List, Tuple

# Add the nzcv register to the map of accessible registers (see emulation/arm64_linux.py for more details)
import qiling.arch.arm64_const  # type: ignore[import-untyped]

# For this 'gdb_remote_client' you need to install the module 'PyGdbRemoteClient';
# However, after implementing debugging into the app, this client does not always detach cleanly, so it is better to not use it.
from gdb_remote_client import GdbRemoteClient  # type: ignore[import-untyped]
from qiling import Qiling  # type: ignore[import-untyped]
from qiling.const import QL_VERBOSE  # type: ignore[import-untyped]
from unicorn.arm64_const import UC_ARM64_REG_NZCV  # type: ignore[import-untyped]

# Update the register map with our new entry.
qiling.arch.arm64_const.reg_map.update({"nzcv": UC_ARM64_REG_NZCV})


def launch_qiling_server(port, argv, rootfs, user_input: str) -> None:
    """Create a qiling instance with given arguments and start emulation with a gdb-server on."""
    mydata = threading.local()
    print("Server assigned to thread: {}".format(threading.current_thread().name))
    print("ID of process running server: {}".format(os.getpid()))
    # This should likely be where you create the temporary directory, so the client can connect to different servers.
    # So this method in the webapp should probably receive the source code, create tempdir, and assemble/link before the qiling steps below.

    # Create qiling instance.
    mydata.ql = Qiling(argv, rootfs, verbose=QL_VERBOSE.OFF)
    # Turn on the debugger.
    mydata.ql.debugger = f"gdb::{port}"
    # Redirect input, output, and error streams.
    mydata.ql.os.stdin = BytesIO(user_input.encode())
    mydata.out = BytesIO()
    mydata.ql.os.stdout = mydata.out
    mydata.err = BytesIO()
    mydata.ql.os.stderr = mydata.err
    # Start the emulation / server starts listening.
    mydata.ql.run()


def debug_start(*, port: int, argv: List[str], rootfs: str, user_input: str) -> None:
    """Create a thread to run the gdb server via qiling."""
    server = threading.Thread(
        group=None, target=launch_qiling_server, args=(port, argv, rootfs, user_input)
    )
    server.start()


def adhoc_gdb_client(
    *, port: int, bin_path: str, commands: List[str]
) -> Tuple[bytes, bytes]:
    # Add detach and quit in case the user didn't include them.
    full_commands = [f"target remote :{port}"] + commands + ["detach", "quit"]
    # Create a process that will use gdb-multiarch to talk to the server.
    with subprocess.Popen(
        ["gdb-multiarch", bin_path, "-quiet"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        # Send each command the user wants to the gdb server.
        for c in full_commands:
            process.stdin.write(f"{c}\n".encode())  # type: ignore
        # Return the standard output/error streams from the gdb client.
        return process.communicate()


def find_line_number(gdb_stdout: bytes) -> int:
    for line in gdb_stdout.decode().split("\n"):
        if line.startswith("(gdb) Line"):
            return int(line.split()[2])
    return -1


def debug_cmd(*, port: int, bin_path: str, cmd: str) -> Any:
    # Read line number from gdb-multiarch:
    gdb_out, _ = adhoc_gdb_client(
        port=port,
        bin_path=bin_path,
        commands=["info line"],
    )
    print(f"Next line to be executed is #{find_line_number(gdb_out)}")

    # Connect to stub running on localhost, TCP port 3333
    gdb_cli = GdbRemoteClient("0.0.0.0", port)
    gdb_cli.connect()

    if cmd != "q":
        # Read some values from the execution.
        print(f"Current values in registers x0/1/2 and nzcv:")
        for reg in ("x0", "x1", "x2", "nzcv"):
            get_reg_cmd = f"i _arch.regs.read({reg})"
            print(f"{reg} -> {gdb_cli.cmd(get_reg_cmd)}")

        if cmd == "s":
            print("stepping over one line of code")
        elif cmd == "c":
            print("continuing execution")
        else:
            print(f"executing command '{cmd}'")

        # Send user command and save its response.
        resp = gdb_cli.cmd(cmd)
        # Then, disconnect so another client can attach later.
        gdb_cli.disconnect()
        # Return response
        return resp

    else:
        # If user wants to quit, first kill process:
        gdb_cli.cmd("k")
        # Then, disconnect so another client can attach later.
        gdb_cli.disconnect()


if __name__ == "__main__":
    # Qiling arguments.
    port = 9999
    binary = "/webassembliss/rootfs/arm64_linux/userprograms/changingFlags"  # For debugging, the binary should be inside rootfs.
    rootfs = "/webassembliss/rootfs/arm64_linux/"
    user_input = "helloHELLO"

    print("Starting the debugging process")
    print(f"\tdebugging '{binary}' through port {port}")
    # Launch a thread that runs the debugger.
    debug_start(port=port, argv=[binary], rootfs=rootfs, user_input=user_input)

    prompt = "What command would you like to run? ([s]tep / [c]ontinue / [q]uit)"

    user_cmd = input(prompt).lower()
    while user_cmd != "q":
        if user_cmd not in "scq":
            print("Invalid command!")
        else:
            print("Return:", debug_cmd(port=port, bin_path=binary, cmd=user_cmd))
        user_cmd = input(prompt).lower()

    print("Quitting now...")
    debug_cmd(port=port, bin_path=binary, cmd=user_cmd)
