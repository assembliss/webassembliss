import rocher.flask  # type: ignore[import-untyped]
from emulation.arm64_linux import emulate as arm64_linux_emulation
from emulation.arm64_linux import send_debug_cmd as arm64_linux_gdb_cmd
from emulation.arm64_linux import start_debugger as arm64_linux_gdb_start
from emulation.debugger_db import DebuggerDB
from flask import Flask, redirect, render_template, request, session
from flask_session import Session  # type: ignore[import-untyped]
from redis import Redis

app = Flask(__name__)

# Setup user sessions.
SESSION_TYPE = "redis"
SESSION_REDIS = Redis(host="redis", port=6379)
app.config.from_object(__name__)
Session(app)

# Creates an instance of the debugger db so we can get the user IDs.
ddb = DebuggerDB()

# Register the editor with the Flask app
# and expose the rocher_editor function to Jinja templates
rocher.flask.editor_register(app)


def get_user_signature() -> str:
    """Find user ID from session; if not set, assigns a new one and return."""
    # TODO: validate cookie signature, i.e., make sure it was created during this execution of the server.
    if not "user_num" in session:
        session["user_num"] = ddb.get_next_user_id()
    return f"ID-{session['user_num']:>03}"


@app.route("/")
def index():
    # TODO: add a landing page whenever we have more architectures available.
    return redirect("/arm64_linux/")


@app.route("/arm64_linux/")
def arm64_linux_index():
    # Read the hello world example to use it as the default code in the editor.
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


@app.route("/arm64_linux/debug/", methods=["POST"])
def arm64_linux_debug():
    if request.json is None:
        return "No JSON data received", 400
    if "source_code" not in request.json:
        return "No source_code in JSON data", 400
    if "user_input" not in request.json:
        return "No user_input in JSON data", 400
    if "debug" not in request.json:
        return "No debug information in JSON data", 400

    user_signature = get_user_signature()
    debugInfo = None

    if request.json["debug"].get("start", False):
        debugInfo = arm64_linux_gdb_start(
            user_signature=user_signature,
            code=request.json["source_code"],
            user_input=request.json["user_input"],
        )

    elif request.json["debug"].get("command", False):
        debugInfo = arm64_linux_gdb_cmd(
            user_signature=user_signature,
            cmd=request.json["debug"]["command"],
            breakpoint_source=request.json["debug"].get("breakpoint_source", ""),
            breakpoint_line=request.json["debug"].get("breakpoint_line", 0),
        )

    else:
        return "No valid debug commands in JSON data", 400

    return {
        "debugInfo": debugInfo,
        "registers": debugInfo.print_registers(byte_split_token="_"),
        "flags": debugInfo.flags,
        "all_info": debugInfo.print(),
        "stdout": debugInfo.run_stdout,
        "stderr": debugInfo.print_stderr(),
        "as_ok": debugInfo.assembled_ok,
        "ld_ok": debugInfo.linked_ok,
        "ran_ok": debugInfo.run_ok,
    }


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
