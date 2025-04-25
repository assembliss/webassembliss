# webassembliss

The goal is to have a webapp that allows users to edit, run, and trace assembly code.  
This project is under active development.

## Get started
1. install [docker](https://www.docker.com/get-started/);
2. cd into the folder for this repo;
3. run `docker compose up --build`

## Roadmap

### General Functionality
- [ ] figure out why `printf` isn't working
- [ ] show user output of a specific file they create/modify with their code
	- could allow them to redirect input/output boxes to a filepath
- [ ] add a cooldown period after the user runs code a few times (could be 1min after each run or an exponential backoff)
- [ ] add support for more architectures
	- overview how to do that: https://github.ncsu.edu/assembliss/webassembliss/pull/9
 	- [ ] [8086](https://github.com/qilingframework/rootfs/tree/master/8086)
 	- [ ] [x8664_windows](https://github.com/qilingframework/rootfs/tree/master/x8664_windows/)
	- [ ] [mips](https://github.com/qilingframework/rootfs/tree/master/mips32el_linux)
	- [ ] [armv7](https://github.com/qilingframework/rootfs/tree/master/arm_linux)

### Grading Workflow
- [ ] allow c-driver code (this could be resolved as a pre-assembled object file)
	- [ ] pre-assembled object files are done... but printf output does not show for some reason.
- [ ] create a form to generate project configs

### Project Setup
- [ ] add auto-format
	- https://github.com/jpetrucciani/black-check
- [ ] add auto-lint
	- https://github.com/rhysd/actionlint
- [ ] add auto-typehint-checker
	- https://github.com/python/mypy
- [ ] cleanup the language syntax for each architecture
	- [maybe helpful? (monarch)](https://microsoft.github.io/monaco-editor/monarch.html)
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
- [ ] allow user to change themes
- [ ] allow user to change timeout
- [ ] add a button to load code from examples
- [ ] show instruction information when hovering over it
	- [maybe helpful?](https://stackoverflow.com/a/49450345)

### Completed
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
- [x] allow user to provide pre-assembled object file(s) to be linked with editor's sources
- [x] remove as/ld and just use gcc
	- if we assume that clients use the `trace` method, each arch should be able to choose their build
- [x] remove flask-session
	- [x] store everything client-side with [localstorage](https://developer.mozilla.org/en-US/docs/Web/API/Window/localStorage)
	- [x] receive all files in the request json body
	- [x] [limit the max request size a user can send](https://flask.palletsprojects.com/en/stable/patterns/fileuploads/#improving-uploads)
	- [x] change all logic that used tab_manager to use local tabs
	- [x] delete tab_manager route and remove flask_session dependencies
- [x] refactor backend to have a single run/trace route that receives the arch as parameter
- [x] refactor backend to only have trace; if the user wants to run, simply combine all steps
	- [x] refactor the grader route (and any other calls) to use the trace route
- [x] refactor the frontend so the editor is generic and new archs only need to provide the syntax highlighting and help links
- [x] implemented [riscv](https://github.com/qilingframework/rootfs/tree/master/riscv64_linux)
- [x] implemented [x8664_linux](https://github.com/qilingframework/rootfs/tree/master/x8664_linux_glibc2.39)
- [x] allow testing of code (given input, expected output)
- [x] measure lines of code
- [x] measure executed instructions
- [x] measure documentation level
- [x] create config file that has provided source(s), object(s), and tests
- [x] allow user to upload config file and run tests with their code
- [x] generate a results file containing user info, test results, efficiency metrics
- [x] script to validate that results were generated with correct project config
- [x] move grader protos to the same folder as the tracing ones
- [x] generate object and binaries in a temp folder inside rootfs
- [x] separated js and css from jinja template
- [x] improve the gui
- [x] combine multiple "external trace steps" into a single one, similar to a function step over
- [x] have a toggle for ascii vs non ascii memory view
- [x] allow user to change memory area shown
- [x] change the editor to hilight syntax for assembly
- [x] allow user to download emulation information
- [x] allow user to download code
- [x] allow user to upload code
- [x] allow user to submit an issue through the webapp
- [x] highlight assembler errors in source code
	- [x] update error display for multiple tabs
- [x] preserve source code between refreshes
- [x] allow user to change registers shown
- [x] add a production deployment server
- [x] allow user to upload other files to be processed (e.g., a csv file to be read)
- [x] show instructions executed after running/tracing code
- [x] show instructions written after running/tracing code
