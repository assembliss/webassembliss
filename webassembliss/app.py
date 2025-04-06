from os import environ

import rocher.flask  # type: ignore[import-untyped]
from flask import Flask, abort, current_app, jsonify, render_template, request, session
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

# User file storage limits.
MAX_SINGLE_FILE_SIZE = int(environ.get("MAX_SINGLE_FILE_SIZE", "10_240"))
MAX_TOTAL_FILE_SIZE = int(environ.get("MAX_TOTAL_FILE_SIZE", "102_400"))

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
    storage_remaining = MAX_TOTAL_FILE_SIZE - session.get("user_storage", 0)
    if "user_files" in session:
        saved_files = sorted(session["user_files"])
        return render_template(
            "arm64_linux.html.j2",
            default_code=session["user_files"][saved_files[0]].split("\n"),
            tab_names=saved_files,
            storage_remaining=storage_remaining,
        )
    # If no code for this user, read the hello world example to use it as the default code in the editor.
    with open("/webassembliss/examples/arm64_linux/hello.S") as file_in:
        return render_template(
            "arm64_linux.html.j2",
            default_code=file_in.read().split("\n"),
            tab_names=["hello.S"],
            storage_remaining=storage_remaining,
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


@app.route("/tab_manager/<filename>/", methods=["POST", "GET", "DELETE", "PATCH"])
def tab_manager(filename):
    if not filename:
        return jsonify({"error": "No filename provided"}), 400

    if request.method == "GET":
        # For GET method, return the content of the given filename.
        if "user_files" not in session or filename not in session["user_files"]:
            return jsonify({"error": f"Could not find '{filename}'"}), 400
        return (
            jsonify(
                {
                    "filename": filename,
                    "contents": session["user_files"][filename],
                    "user_storage": session["user_storage"],
                }
            ),
            200,
        )

    elif request.method == "PATCH":
        # For PATCH method, save the same contents under a new filename
        # Then delete the same contents under the old filename
        # Validate first!
        if "user_files" not in session or filename not in session["user_files"]:
            return jsonify({"error": f"Could not find '{filename}'"}), 400

        if request.json is None:
            return jsonify({"error": "No JSON data received"}), 400

        if "new_filename" not in request.json:
            return jsonify({"error": "No new_filename in JSON data"}), 400

        old_file_content = session["user_files"][filename]
        # New filename validation is on JS side.
        new_filename = request.json["new_filename"]

        # Delete old file
        session["user_storage"] -= len(session["user_files"][filename])
        del session["user_files"][filename]

        # Create new file
        session["user_files"][new_filename] = old_file_content
        session["user_storage"] += len(old_file_content)

        session.modified = True

        return (
            jsonify(
                {"message": f"Updated file name from '{filename}' to '{new_filename}'"}
            ),
            200,
        )

    elif request.method == "DELETE":
        # For DELETE method, delete the saved contents of the given filename
        if "user_files" not in session or filename not in session["user_files"]:
            return jsonify({"error": f"Could not find '{filename}'"}), 400
        session["user_storage"] -= len(session["user_files"][filename])
        del session["user_files"][filename]
        return (
            jsonify(
                {
                    "message": f"Deleted '{filename}' from the server",
                    "user_storage": session["user_storage"],
                }
            ),
            200,
        )

    elif request.method == "POST":
        # For POST method, store the given contents in the filename passed in the url
        # if, "return_file" is in the json, return the contents of that file in the response.

        # Check json was received.
        if request.json is None:
            return jsonify({"error": "No JSON data received"}), 400

        # Initialize session values to store files.
        if "user_files" not in session:
            session["user_files"] = {}
            session["user_storage"] = 0

        if "contents" not in request.json:
            return jsonify({"error": "No contents in JSON data"}), 400

        content_len = len(request.json["contents"])
        if content_len > MAX_SINGLE_FILE_SIZE:
            return jsonify({"error": "Single file exceeds max size of 10KB"}), 400

        old_len = len(session["user_files"].get(filename, ""))
        delta_len = content_len - old_len
        if (session["user_storage"] + delta_len) > MAX_TOTAL_FILE_SIZE:
            return (
                jsonify({"error": "User will exceed max storage of 100KB"}),
                400,
            )

        # Store the file and update user storage size.
        session["user_files"][filename] = request.json["contents"]
        session["user_storage"] += delta_len

        # Create base response.
        resp = {"message": f"Stored contents of '{filename}'"}

        # Check if the user requested a return file.
        if "return_file" in request.json:
            # If they did, add its contents to the response.
            # If the file does not exist, use an empty string.
            return_filename = request.json["return_file"]
            resp["return_file"] = {
                "filename": return_filename,
                "contents": session["user_files"].get(return_filename, ""),
                "user_storage": session["user_storage"],
            }

        # Return the final response.
        return jsonify(resp), 200

    else:
        return jsonify({"error": f"Cannot handle '{request.method}' method"}), 400


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
