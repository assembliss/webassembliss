# webassembliss

Work in progress...

The goal is to have a webapp that allows users to edit, run, and debug ARM64 assembly code.

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
- [x] make sure app works with multiple users accessing concurrently
- [x] make sure debugging works with multiple users accessing concurrently
- [ ] allow multiple sources to work together
	- [maybe helpful?](https://github.com/microsoft/monaco-editor/issues/604#issuecomment-344214706)
- [ ] allow user to provide pre-assembled object file(s) to be linked with editor's sources
- [ ] handle multiple architectures

### Grading Workflow
- [x] allow testing of code (given input, expected output)
- [x] measure lines of code
- [x] measure executed instructions
- [x] measure documentation level
	- [ ] measure percentage of instruction lines with a comment
- [ ] allow c-driver code (this could be resolved as a pre-assembled object file)
- [x] create config file that has provided source(s), object(s), and tests
- [x] allow user to upload config file and run tests with their code
- [x] generate a results file containing user info, test results, efficiency metrics
- [x] allow (super)user to upload a zip file of result files that can re-run tests to make sure results were achieved through the testing pipeline
	- moved to a separate project as a cli script

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
- [ ] update Dockerfile to use newer python version
- [ ] add unit tests for all methods
	- maybe with [pytest](https://docs.pytest.org/en/stable/getting-started.html)?
- [ ] CI/CD to auto-run tests on open PRs
- [ ] swap flask with [fastapi](https://fastapi.tiangolo.com/)
	- [maybe helpful?](https://testdriven.io/blog/moving-from-flask-to-fastapi/)
	- might need to adapt [rocher](https://github.com/julien-duponchelle/rocher/blob/main/rocher/flask.py)?
- [ ] make debugging route and methods async
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
- [ ] allow user to change registers shown
- [ ] allow user to change memory area shown
- [ ] give user option to delete old debugging session and start a new one
- [ ] handle no available ports for a new debugger session
	- maybe a timer and try again in a minute?
- [ ] handle already active session for user
	- maybe a popup and ask if they want to quit the old one?
- [ ] have a toggle for ascii vs non ascii memory view
- [ ] speedup/optimize steps in debug-mode
- [ ] improve the gui -- make everything look nicer :)
	- [maybe helpful?](https://getbootstrap.com/)
