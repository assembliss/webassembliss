#! /bin/bash

docker build . -t webassembliss_img
docker run -v ./webassembliss:/webassembliss -p 5000:5000 -it webassembliss_img zsh
