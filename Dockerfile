FROM ubuntu:24.04

ARG PYTHON_VERSION="3.13"

# Location of the gdb.py file that needs to be patched.
# Ref: https://github.com/qilingframework/qiling/issues/1377
ARG QL_GDB_PATH="/usr/local/lib/python${PYTHON_VERSION}/dist-packages/qiling/debugger/gdb/gdb.py"

#
# Install zsh + omzsh for developing in a devcontainer.
#
RUN apt-get update && \
    apt-get install -y wget && \
    sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.2.1/zsh-in-docker.sh)" -- \
    -t candy \
    -p git \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions \
    -p https://github.com/zsh-users/zsh-syntax-highlighting

#
# Install required tooling.
#
RUN apt-get update && \
    apt-get install -y \
    # arm64 toolchain (assemble/link arm64 assembly code)
    make gcc-aarch64-linux-gnu\
    # gdb-multiarch (for user debugging sessions)
    gdb-multiarch\
    # tmux (for dev debugging in container)
    tmux\
    # protobuf to handle project grading config files
    protobuf-compiler\
    # cloc to count source lines and comments
    cloc

#
# Install python and pip for the selected version.
#
RUN apt install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt update && \
    apt install -y python${PYTHON_VERSION} && \
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python${PYTHON_VERSION} get-pip.py

#
# Install python libraries
#

# Need to install keystone from source to avoid errors on macos >= 10.14 host;
# ref: https://docs.qiling.io/en/latest/install/
RUN apt install -y cmake g++ && \
    git clone https://github.com/keystone-engine/keystone && \
    cd keystone && \
    mkdir build && \
    cd build && \
    ../make-share.sh && \
    cd ../bindings/python && \
    pip install setuptools && \
    ln -s /usr/bin/python${PYTHON_VERSION} /usr/bin/python && \
    make install

# Install other requirements.
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt --break-system-packages

# Copy a patched version of qiling's gdb server. It has the following changes:
#   1. fix a bug that prevents stepping over the code (ref: https://github.com/qilingframework/qiling/issues/1377);
#   2. adds the option to allow clients to detach without exiting, so the server accepts multiple clients in sequence;
#   3. adds a special command (i) that can return qiling's variables to the gdb client.
COPY resources/qiling_debugger_gdb_gdb.py ${QL_GDB_PATH}

#
# Copy the app code into the container.
#
COPY webassembliss /webassembliss

# You can uncomment the line below to set the backend to run in debug mode.
# ENV FLASK_DEBUG=1

#
# Container command to serve flask app
#
CMD [ "gunicorn", "--config" , "webassembliss/gunicorn_config.py", "webassembliss.app:app"]
