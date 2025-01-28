import threading
import os
from qiling import Qiling
from typing import List, Dict, Any
from gdb_remote_client import GdbRemoteClient
from qiling.const import QL_VERBOSE
from io import BytesIO


def launch_qiling_server(port, argv, rootfs, user_input: str) -> None:
    """Create a qiling instance with given arguments and start emulation with a gdb-server on."""
    mydata = threading.local()
    print("Server assigned to thread: {}".format(threading.current_thread().name))
    print("ID of process running server: {}".format(os.getpid()))
    # This should likely be where you create the temporary directory, so the client can connect to different servers.
    # So this method in production should probably receive the source code, create tempdir, and assemble/link before the qiling steps below.

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


def debug_cmd(*, port: int, bin_path: str, cmd: str) -> Dict[str, Any]:
    # Connect to stub running on localhost, TCP port 3333
    gdb_cli = GdbRemoteClient("0.0.0.0", port)
    gdb_cli.connect()

    if user_cmd != "q":
        # Example commands:
        resp = gdb_cli.cmd("qSupported")
        print("The remote stub supports these features: " + resp)
        resp = gdb_cli.cmd("g")
        print("Values of general-purpose registers: " + resp)

        # Send user command and save its response.
        resp = gdb_cli.cmd(cmd)
        # Detach so we can connect to this server again.
        gdb_cli.cmd("detach")
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
    binary = "/webassembliss/rootfs/arm64_linux/userprograms/hello"  # For debugging, the binary should be inside rootfs.
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
