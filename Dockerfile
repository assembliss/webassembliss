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

# Install required tooling.
RUN apt update && \
    apt install -y \
    # arm64 toolchain (assemble/link arm64 assembly code)
    make gcc-aarch64-linux-gnu\
    # gdb-multiarch (for user debugging sessions)
    gdb-multiarch\
    # tmux (for dev debugging in container)
    tmux

# Install required python packages
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt --break-system-packages

# Copy a patched version of qiling's gdb server. It has the following changes:
#   1. fix a bug that prevents stepping over the code (ref: https://github.com/qilingframework/qiling/issues/1377);
#   2. adds the option to allow clients to detach without exiting, so the server accepts multiple clients in sequence;
#   3. adds a special command (i) that can return qiling's variables to the gdb client.
COPY resources/qiling_debugger_gdb_gdb.py ${QL_GDB_PATH}

# Copy the app code into the container and set the workdirectory to point to that.
COPY webassembliss /webassembliss
WORKDIR /webassembliss

# You can uncomment the line below to set the backend to run in debug mode.
# ENV FLASK_DEBUG=1

# Container command to serve flask app
CMD [ "gunicorn", "--config" , "gunicorn_config.py", "app:app"]
