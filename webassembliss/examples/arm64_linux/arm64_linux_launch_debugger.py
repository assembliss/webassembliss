# You can use this script if you just want to try running a gdb server to see how it works.
# Then, in a separate terminal, you can run these two commands to connect to the server:
#         $ gdb-multiarch /webassembliss/rootfs/arm64_linux/userprograms/hello
#   (gdb) $ target remote :9999

from qiling import Qiling
from qiling.const import QL_VERBOSE
from io import BytesIO

# Qiling options.
port = 9999
binary = "/webassembliss/rootfs/arm64_linux/userprograms/hello"
rootfs = "/webassembliss/rootfs/arm64_linux/"
user_input = "helloHELLO"

# Create qiling instance.
ql = Qiling([binary], rootfs, verbose=QL_VERBOSE.DEFAULT)
# Turn on the debugger.
ql.debugger = f"gdb::{port}"
# Redirect input, output, and error streams.
ql.os.stdin = BytesIO(user_input.encode())
out = BytesIO()
ql.os.stdout = out
err = BytesIO()
ql.os.stderr = err
# Start the emulation / server starts listening.
ql.run()
