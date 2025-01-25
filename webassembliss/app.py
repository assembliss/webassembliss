from flask import Flask, render_template, request, redirect
from emulation.arm64_linux import emulate as arm64_linux_emulation

import rocher.flask

app = Flask(__name__)

# Register the editor with the Flask app
# and expose the rocher_editor function to Jinja templates
rocher.flask.editor_register(app)


@app.route("/")
def index():
    # TODO: add a landing page whenever we have more architectures available.
    return redirect("/arm64_linux/")


@app.route("/arm64_linux/")
def arm64_linux_index():
    # Read the source code of this file to highlight it in the editor
    with open("/webassembliss/examples/arm64_linux/hello.S") as file_in:
        return render_template(
            "arm64_linux.html.j2", default_code=file_in.read().split("\n")
        )


@app.route("/arm64_linux/run/", methods=["POST"])
def arm64_linux_run():
    if request.json is None:
        return "No JSON data received", 400
    if "source_code" not in request.json:
        return "No source_code in JSON data", 400
    if "user_input" not in request.json:
        return "No user_input in JSON data", 400
    user_code = request.json["source_code"]
    user_input = request.json["user_input"]
    emu_results = arm64_linux_emulation(user_code, stdin=user_input)
    # TODO: return simply emu_results and do parsing of results on javascript side;
    #        would make it easier/cleaner to add new archs later on in the app.py.
    return {
        "stdout": emu_results.run_stdout,
        "stderr": emu_results.print_stderr(),
        "as_ok": emu_results.assembled_ok,
        "ld_ok": emu_results.linked_ok,
        "ran_ok": emu_results.run_ok,
        "registers": emu_results.print_registers(
            change_token=" <--- changed", byte_split_token="_"
        ),
        "memory": emu_results.print_memory(show_ascii=True),
        "flags": emu_results.flags,
        "all_info": emu_results.print(),
        "info_obj": emu_results,
    }


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
