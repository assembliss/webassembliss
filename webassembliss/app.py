from io import BytesIO
from os import environ

import rocher.flask  # type: ignore[import-untyped]
from flask import (
    Flask,
    abort,
    current_app,
    jsonify,
    render_template,
    request,
    send_file,
    session,
)
from flask_session import Session  # type: ignore[import-untyped]
from redis import Redis

from .grader.single_student import grade_form_submission
from .utils import ARCH_MAP

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


@app.route("/tab_manager/<filename>/", methods=["POST", "GET", "DELETE"])
def tab_manager(filename):
    if not filename:
        return jsonify({"error": "No filename provided"}), 400

    if request.method == "GET":
        # For GET method, return the content of the given filename.
        if "user_files" not in session or filename not in session["user_files"]:
            return jsonify({"error": f"Could not find '{filename}'"}), 400
        return (
            jsonify(
                {"filename": filename, "contents": session["user_files"][filename]}
            ),
            200,
        )

    elif request.method == "DELETE":
        # For DELETE method, delete the saved contents of the given filename
        if "user_files" not in session or filename not in session["user_files"]:
            return jsonify({"error": f"Could not find '{filename}'"}), 400
        session["user_storage"] -= len(session["user_files"][filename])
        del session["user_files"][filename]
        return jsonify({"message": f"Deleted '{filename}' from the server"}), 200

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
            }

        # Return the final response.
        return jsonify(resp), 200

    else:
        return jsonify({"error": f"Cannot handle '{request.method}' method"}), 400


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

@app.route("/editor/<arch>/")
def editor_page(arch):
    arch_info = ARCH_MAP.get(arch)
    if arch_info is None:
        return f"Invalid architecture config for editor; valid options are {ARCH_MAP.keys()}", 400
    
    # Retrieve any user code we have stored already.
    source_code = session.get("source_code", {}).get("usrCode.S")
    if source_code is None:
        # If no code for this user, read the default example for the architecture to display.
        with open(arch_info.example_path) as file_in:
            source_code = file_in.read()
    
    # Return the template with the appropriate code to display.
    return render_template(
        arch_info.template_path,
        default_code=session["source_code"]["usrCode.S"].split("\n"),
    )
    

@app.route("/run/", methods=["POST"])
def code_run():
    if request.json is None:
        return "No JSON data received", 400
    if "arch" not in request.json:
        return "No architecture config in JSON data", 400
    if "source_code" not in request.json:
        return "No source_code in JSON data", 400
    if "user_input" not in request.json:
        return "No user_input in JSON data", 400
    
    arch_info = ARCH_MAP.get(request.json["arch"])
    if arch_info is None:
        return f"Invalid architecture config in JSON data; valid options are {ARCH_MAP.keys()}", 400

    session["source_code"] = {"usrCode.S": request.json["source_code"]}
    session["user_input"] = request.json["user_input"]
    session["cl_args"] = request.json.get("cl_args", "")
    session["registers"] = request.json.get("registers", "")

    emu_results = arch_info.emulate(
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
        "exit_code": emu_results.run_exit_code,
        "timed_out": emu_results.run_timeout,
        "all_info": emu_results.print(),
        "info_obj": emu_results,
    }


@app.route("/trace/", methods=["POST"])
def code_trace():
    if request.json is None:
        return "No JSON data received", 400
    if "arch" not in request.json:
        return "No architecture config in JSON data", 400
    if "source_code" not in request.json:
        return "No source_code in JSON data", 400
    if "user_input" not in request.json:
        return "No user_input in JSON data", 400

    arch_info = ARCH_MAP.get(request.json["arch"])
    if arch_info is None:
        return f"Invalid architecture config in JSON data; valid options are {ARCH_MAP.keys()}", 400

    session["source_code"] = {"usrCode.S": request.json["source_code"]}
    session["user_input"] = request.json["user_input"]
    session["cl_args"] = request.json.get("cl_args", "")
    session["registers"] = request.json.get("registers", "")
    emulation_trace = arch_info.trace(
        source_files=session["source_code"],
        stdin=session["user_input"],
        cl_args=session["cl_args"],
        registers=session["registers"],
    )
    return send_file(
        BytesIO(emulation_trace.SerializeToString()),
        mimetype="application/x-protobuf",
    )

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
