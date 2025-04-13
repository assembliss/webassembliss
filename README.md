# webassembliss

Work in progress...

The goal is to have a webapp that allows users to edit, run, and trace ARM64 assembly code.

## Get started
1. install [docker](https://www.docker.com/get-started/);
2. cd into the folder for this repo;
3. run `docker compose up --build`

## Roadmap

### General Functionality
- [x] add a button to assemble, link, and run the code from the editor
- [x] show output of the code in page
- [x] allow user to provide input to the code
- [x] show registers after execution
- [x] show memory
- [x] highlight modified registers
- [x] show condition codes / status bits
- [x] handle qiling exception (`qiling.exception.QlErrorCoreHook: _hook_intr_cb : not handled`) when code does not exit or timeout 
- [x] allow user to debug code (continue, step, set breakpoint, see memory)
	- [x] solved with tracing
- [x] make sure app works with multiple users accessing concurrently
- [x] make sure debugging works with multiple users accessing concurrently
	- [x] solved with tracing
- [x] created a sandbox for each user emulation
	- [x] fix sandbox vulnerability with absolute paths
- [x] allow multiple sources to work together
	- [x] backend is able to handle it
	- [x] process all sources from frontend
- [ ] allow user to provide pre-assembled object file(s) to be linked with editor's sources
	- [x] backend is able to handle it
	- [ ] allow user to upload objects
- [ ] remove as/ld and just use gcc
	- have to consider all pros (e.g., can throw sources and objects at it) and cons (some archs might need separate commands)
- [x] remove flask-session
	- [x] store everything client-side with [localstorage](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage)
	- [x] receive all files in the request json body
	- [x] [limit the max request size a user can send](https://flask.palletsprojects.com/en/stable/patterns/fileuploads/#improving-uploads)
	- [x] change all logic that used tab_manager to use local tabs
	- [x] delete tab_manager route and remove flask_session dependencies
- [ ] show user output of a specific file they create/modify with their code
- [ ] add a cooldown period after the user runs code a few times (could be 1min after each run or an exponential backoff)
- [x] refactor backend to have a single run/trace route that receives the arch as parameter
- [x] refactor the frontend so the editor is generic and new archs only need to provide the syntax highlighting and help links
- [ ] handle multiple architectures
	- overview how to do that: https://github.ncsu.edu/assembliss/webassembliss/pull/9
 	- [ ] [8086](https://github.com/qilingframework/rootfs/tree/master/8086)
	- [ ] [x8664_linux](https://github.com/qilingframework/rootfs/tree/master/x8664_linux_glibc2.39)
 	- [ ] [x8664_windows](https://github.com/qilingframework/rootfs/tree/master/x8664_windows/)
	- [ ] [mips](https://github.com/qilingframework/rootfs/tree/master/mips32el_linux)
	- [x] [riscv](https://github.com/qilingframework/rootfs/tree/master/riscv64_linux)
	- [ ] [armv7](https://github.com/qilingframework/rootfs/tree/master/arm_linux)

### Grading Workflow
- [x] allow testing of code (given input, expected output)
- [x] measure lines of code
- [x] measure executed instructions
- [x] measure documentation level
- [ ] allow c-driver code (this could be resolved as a pre-assembled object file)
	- [ ] pre-assembled object files are done... but printf output does not show for some reason.
- [x] create config file that has provided source(s), object(s), and tests
- [x] allow user to upload config file and run tests with their code
- [x] generate a results file containing user info, test results, efficiency metrics
- [x] script to validate that results were generated with correct project config
- [ ] create a GUI app to generate project configs
- [x] move grader protos to the same folder as the tracing ones

### Project Setup
- [x] generate object and binaries in a temp folder inside rootfs
- [x] separated js and css from jinja template
- [ ] add auto-format
	- https://github.com/jpetrucciani/black-check
- [ ] add auto-lint
	- https://github.com/rhysd/actionlint
- [ ] add auto-typehint-checker
	- https://github.com/python/mypy
- [x] add a production deployment server
- [ ] move these TODOs to the projects tab
- [ ] update Dockerfile to use newer python version
- [ ] add unit tests for all methods
	- maybe with [pytest](https://docs.pytest.org/en/stable/getting-started.html)?
- [ ] CI/CD to auto-run tests on open PRs
- [ ] swap flask with [fastapi](https://fastapi.tiangolo.com/)
	- [maybe helpful?](https://testdriven.io/blog/moving-from-flask-to-fastapi/)
	- might need to adapt [rocher](https://github.com/julien-duponchelle/rocher/blob/main/rocher/flask.py)?
- [ ] make run and trace routes and methods async
	- [maybe helpful? (flask)](https://flask.palletsprojects.com/en/stable/async-await/)
	- [maybe helpful? (fastapi)](https://fastapi.tiangolo.com/async/)
- [ ] find best gunicorn config
	- https://docs.gunicorn.org/en/stable/settings.html#worker-class
	- https://docs.gunicorn.org/en/stable/design.html

### User Experience
- [x] change the editor to hilight syntax for arm64 assembly
- [x] allow user to download emulation information
- [x] allow user to download code
- [x] allow user to upload code
- [ ] allow user to upload other files to be processed (e.g., a csv file to be read)
- [x] allow user to submit an issue through the webapp
- [x] highlight assembler errors in source code
- [x] preserve source code between refreshes
- [ ] allow user to change themes
- [ ] allow user to change timeout
- [x] allow user to change registers shown
- [ ] add a button to load code from examples
- [ ] allow user to change memory area shown
- [ ] have a toggle for ascii vs non ascii memory view
- [ ] show instruction information when hovering over it
- [ ] improve the gui -- make everything look nicer :)
	- [maybe helpful?](https://getbootstrap.com/)
