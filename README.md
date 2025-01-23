# webassembliss

Work in progress...

The goal is to have a webapp that allows users to edit, run, and debug ARM64 assembly code.

## Get started
1. install [docker](https://www.docker.com/get-started/)
2. run `buildAndServe.sh`
	- it will create an image from the `Dockerfile`
	- it will then serve `app.py` in port 5000
	- you can then access it through http://localhost:5000/
3. alternatively, you can run `buildAndBash.sh`
	- it will create an image from the `Dockerfile`
	- it will then open a zsh terminal inside the container in the mounted directory

## Milestones
- [ ] change the editor to hilight syntax for arm64 assembly
- [ ] add a button to assemble, link, and run the code from the editor
- [ ] show output of the code in page
- [ ] allow user to provide input to the code
- [ ] generate object and binaries in a temp folder inside rootfs
- [ ] allow user to debug code (run line by line)
- [ ] show registers as they get modified line by line
- [ ] highlight modified register
- [ ] show condition codes / status bits
- [ ] show memory
- [ ] allow testing of code (given input, expected output)
- [ ] measure lines of code
- [ ] measure executed instructions
- [ ] allow multiple files to work together
- [ ] grading workflow
