from os import environ

import rocher.flask  # type: ignore[import-untyped]
from flask import Flask, abort, current_app, render_template, request, session
from flask_session import Session  # type: ignore[import-untyped]
from redis import Redis

from .emulation.arm64_linux import emulate as arm64_linux_emulation
from .emulation.arm64_linux import send_debug_cmd as arm64_linux_gdb_cmd
from .emulation.arm64_linux import start_debugger as arm64_linux_gdb_start
from .grader.single_student import grade_form_submission
from .grader.utils import GraderResults

app = Flask(__name__)

# Setup user sessions.
SESSION_TYPE = "redis"
SESSION_REDIS = Redis(
    host=environ.get("REDIS_HOST", "localhost"),
    port=int(environ.get("REDIS_PORT", "6379")),
    password=environ.get("REDIS_PASSWORD", ""),
)
app.config.from_object(__name__)
Session(app)

# Register the editor with the Flask app
# and expose the rocher_editor function to Jinja templates
rocher.flask.editor_register(app)


@app.route("/")
def index():
    return render_template("index.html.j2")


@app.route("/about/")
def about():
    return render_template("about.html.j2")


@app.route("/grader/", methods=["POST", "GET"])
def grader():
    if request.method == "POST":
        # If POST, make sure we got here from the submission form.
        if request.referrer != request.url:
            abort(403)

        # Process the information we received.
        student_name = request.form["name"]
        student_ID = request.form["unityID"]
        user_code = request.files["userCode"]
        project_proto = request.files["projectProto"]
        # Run the grader.
        results = grade_form_submission(
            student_name=student_name,
            student_ID=student_ID,
            student_file=user_code,
            project_proto=project_proto,
        )
        # Send that data to the results page.
        return render_template(
            "grader_results.html.j2",
            results=results,
        )

    # If not POST, show the submission form.
    return render_template("grader.html.j2")


@app.route("/debugdb/<keys>/")
def debugdbvalues(keys):
    """This is a debug route to help see the contents of the debugger_db."""
    # Example route: http://127.0.0.1:5000/debugdb/EXIT*|USER*|PORT*
    # Make sure we're in a debug server.
    if not current_app.debug:
        # If not, abort the request.
        abort(404)
    # Connect to the redis db.
    _db = Redis(
        host=environ.get("REDIS_HOST", "localhost"),
        port=int(environ.get("REDIS_PORT", "6379")),
        password=environ.get("REDIS_PASSWORD", ""),
        decode_responses=True,
    )
    # Parse the values for all the given keys.
    return {k: _db.get(k) for key in keys.split("|") for k in _db.keys(key)}


@app.route("/arm64_linux/")
def arm64_linux_index():
    # If the user has run or debugged code, we have it saved in their session; reload it.
    if "source_code" in session:
        return render_template(
            "arm64_linux.html.j2", default_code=session["source_code"].split("\n")
        )
    # If no code for this user, read the hello world example to use it as the default code in the editor.
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

    session["source_code"] = request.json["source_code"]
    session["user_input"] = request.json["user_input"]
    session["cl_args"] = request.json.get("cl_args", "")
    session["registers"] = request.json.get("registers", "")

    emu_results = arm64_linux_emulation(
        session["source_code"],
        stdin=session["user_input"],
        cl_args=session["cl_args"],
        registers=session["registers"].split(),
    )

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

@app.route("/tab_manager/", methods=["POST", "GET", "DELETE"])
def tab_manager(method):
    if (method == "POST"):
        if request.json is None:
            return "No JSON data received", 400
        if "source_code" not in request.json:
            return "No source_code in JSON data", 400
        if "user_files" not in session:
            session["user_files"] = {}
        
        filename = request.json.get("filename")
        if not filename:
            return "No filename provided", 400

        if (len(request.json["source_code"]) > 5120):
            return "Source code exceeds 5KB", 400

        session["source_code"] = request.json["source_code"]


        # Shouldn't the line below be put AFTER the check for summed user file size?
        # If put after, it isn't updated properly, but then the user can exceed the limit.
        session["user_files"][filename].append(session["source_code"])
        
        if (sum(len(c) for c in session["user_files"].values()) > 1024000):
            return "User exceeded 100KB between all total files", 400
        
        return "Flask server file cookie added", 100


    if (method == "GET"):
        if request.json is None:
            return "No JSON data received", 400
        if "source_code" not in request.json:
            return "No source_code in JSON data", 400
        if "user_files" not in session:
            session["user_files"] = {}

        filename = request.json.get("filename")
        if not filename:
            return "No filename provided", 400

        return session["user_files"][filename], 100
    
    if (method == "DELETE"):

        del session["user_files"][filename]
        return "Deleted flask server file cookie", 100


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

    session["source_code"] = request.json["source_code"]
    session["user_input"] = request.json["user_input"]
    session["cl_args"] = request.json.get("cl_args", "")
    session["registers"] = request.json.get("registers", "")
    # Note that we need to have *something* stored in the session so the sid persists with the same user.
    user_signature = session.sid
    debugInfo = None

    if request.json["debug"].get("start", False):
        debugInfo = arm64_linux_gdb_start(
            user_signature=user_signature,
            code=session["source_code"],
            user_input=session["user_input"],
            cl_args=session["cl_args"],
            registers_to_show=session["registers"].split(),
        )

    elif request.json["debug"].get("command", False):
        # TODO: There is a bug either somewhere here or in this method;
        #       a DDBError('no session') is often raised when executable exits;
        #       is this being called more than once in the js-side?
        debugInfo = arm64_linux_gdb_cmd(
            user_signature=user_signature,
            cmd=request.json["debug"]["command"],
            breakpoint_source=request.json["debug"].get("breakpoint_source", ""),
            breakpoint_line=request.json["debug"].get("breakpoint_line", 0),
            registers_to_show=session["registers"].split(),
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
        "memory": debugInfo.print_memory(show_ascii=True),
    }


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
