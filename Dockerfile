# TODO: update dockerfile to use a newer python version; qiling:1.4.6 uses py3.8, but qiling:latest doesn't quite work;
#       will probably have to move to something like alpine/ubuntu and then install everything it needs.
FROM qilingframework/qiling:1.4.6

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
    # riscv64 toolchain (assemble/link riscv64 assembly code)
    make gcc-riscv64-linux-gnu\
    # x8664 linux toolchain (assemble/link x8664 linux assembly code)
    make gcc-x86-64-linux-gnu\
    # tmux (for dev debugging in container)
    tmux\
    # protobuf to handle project grading config files
    protobuf-compiler\
    # cloc to count source lines and comments
    cloc

# Install required python packages
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt --break-system-packages

# Copy the app code into the container and set the workdirectory to point to that.
COPY webassembliss /webassembliss
WORKDIR /

# You can uncomment the line below to set the backend to run in debug mode.
# ENV FLASK_DEBUG=1

# Container command to serve flask app
CMD ["gunicorn", "--config" , "webassembliss/gunicorn_config.py", "webassembliss.app:app"]
