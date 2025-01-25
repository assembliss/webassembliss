#! /bin/bash

docker build . -t webassembliss_img
docker run -p 5000:5000 webassembliss_img
