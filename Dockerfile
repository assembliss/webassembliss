# TODO: update dockerfile to use a newer python version; qiling:1.4.6 uses py3.8, but qiling:latest doesn't quite work;
#       will probably have to move to something like alpine/ubuntu and then install everything it needs.
FROM qilingframework/qiling:1.4.6

# Location of the gdb.py file that needs to be patched.
# Ref: https://github.com/qilingframework/qiling/issues/1377
ARG QL_GDB_PATH="/usr/local/lib/python3.8/site-packages/qiling/debugger/gdb/gdb.py"

# Install zsh + omzsh
RUN apt update && \
    apt install wget -y && \
    sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.2.1/zsh-in-docker.sh)" -- \
    -t candy \
    -p git \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions \
    -p https://github.com/zsh-users/zsh-syntax-highlighting

# Install required python packages
RUN pip install rocher Flask PyGdbRemoteClient --break-system-packages

# Install arm toolchain
RUN apt update && \
    apt install make gcc-aarch64-linux-gnu -y

# Install gdb-multi arch so we can debug the generated binaries.
RUN apt update && \
    apt install gdb-multiarch -y

# Copy a patched version of qiling's gdb server to fix a bug that prevents stepping over the code.
# Ref: https://github.com/qilingframework/qiling/issues/1377
# It also adds the option to allow clients to detach without exiting, so the server accepts multiple clients in sequence.
COPY resources/qiling_debugger_gdb_gdb.py ${QL_GDB_PATH}

# Copy the app code into the container and set the workdirectory to point to that.
COPY webassembliss /webassembliss
WORKDIR /webassembliss

# Container command to serve flask app
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]
