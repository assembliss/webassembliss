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
4. lastly, you can also use a [dev-container](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) to develop on vs-code within the docker environment

Note that if you use `buildAndServe`, changes to the code will not automatically reflect on the server, you will have to rebuild it. If you're actively working on the code, I suggest using `buildAndBash` and then running `python app.py` which will hot-reload code and templates as you modify them.

## Milestones
- [ ] add auto-format on project
	- https://github.com/jpetrucciani/black-check
- [ ] add auto-lint on project
	- https://github.com/rhysd/actionlint
- [ ] add auto-typehint-checker on project
	- https://github.com/python/mypy
- [x] generate object and binaries in a temp folder inside rootfs
- [x] add a button to assemble, link, and run the code from the editor
- [x] show output of the code in page
- [x] allow user to provide input to the code
- [x] allow user to download code
- [x] allow user to download emulation information
- [x] change the editor to hilight syntax for arm64 assembly
- [x] show registers after execution
- [ ] show condition codes / status bits
- [x] show memory
- [x] highlight modified registers
- [ ] highlight assembler errors in source code (mark line and popup with error)
- [ ] allow user to submit an issue through the webapp
	- https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/creating-an-issue#creating-an-issue-from-a-url-query
- [ ] allow user to debug code (continue, step, set breakpoint)
	- first idea:
		- create a [python generator](https://wiki.python.org/moin/Generators) that mimics [clean_emulation](https://github.ncsu.edu/assembliss/webassembliss/blob/229e172c4e7ad71c09e9c97c452063d1250a1d3b/webassembliss/emulation/utils.py#L399) but keeps the directory and qiling instance alive throghout debugging
		- [turn on gdb](https://github.ncsu.edu/assembliss/webassembliss/blob/229e172c4e7ad71c09e9c97c452063d1250a1d3b/webassembliss/examples/arm64_linux/arm64_linux_emulation.py#L32-L34) through qiling
		- connect to the gdb server ([maybe useful?](https://python3-pwntools.readthedocs.io/en/latest/gdb.html#module-pwnlib.gdb))
		- generator receives command (e.g., continue or step), sends it to the gdb server, and then yields the updated EmulationResullt
- [ ] allow testing of code (given input, expected output)
- [ ] make sure app works with multiple users accessing concurrently
- [ ] add a production deployment server (e.g., [gunicorn](https://rest-apis-flask.teclado.com/docs/deploy_to_render/docker_with_gunicorn/))
- [ ] preserve source code between refreshes (probably in a cookie!)
- [ ] measure lines of code
- [ ] measure executed instructions
- [ ] measure documentation level
- [ ] allow multiple files to work together
- [ ] allow c-driver code
- [ ] allow user to change themes
- [ ] allow user to change timeout
- [ ] allow user to change registers shown
- [ ] allow user to change memory area shown
- [ ] improve the gui -- make everything look nicer :)
- [ ] grading workflow
- [ ] handle multiple architectures
