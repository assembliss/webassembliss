FROM qilingframework/qiling:1.4.6

# Install zsh + omzsh
RUN apt update &&\
    apt install wget -y &&\
    sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.2.1/zsh-in-docker.sh)" -- \
    -t candy \
    -p git \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions \
    -p https://github.com/zsh-users/zsh-syntax-highlighting

# Install required python packages
RUN pip install rocher Flask --break-system-packages

# Install arm toolchain
RUN apt update &&\
    apt install make gcc-aarch64-linux-gnu -y

# Mount and change into the directory where the app code is
VOLUME webassembliss
WORKDIR /webassembliss

# Container command to serve flask app
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]
