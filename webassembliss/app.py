from io import BytesIO

import rocher.flask  # type: ignore[import-untyped]
from flask import Flask, abort, render_template, request, send_file

from .emulation import ARCH_CONFIG_MAP
from .grader.single_student import grade_form_submission
from .utils import b64_to_bytes

app = Flask(__name__)

# Limit requests to be a maximum of 1 MB.
app.config["MAX_CONTENT_LENGTH"] = 1 * 1000 * 1000

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

@app.route("/project-config-builder/", methods=["POST", "GET"])
def project_config_builder():
    if request.method == "POST":
        # If POST, make sure we got here from the submission form.
        if request.referrer != request.url:
            abort(403)
        abort(403)

    # If not POST, show the submission form.
    return render_template("project_config_builder.html.j2")

@app.route("/editor/<arch>/")
def editor_page(arch):
    arch_info = ARCH_CONFIG_MAP.get(arch)
    if arch_info is None:
        return (
            f"Invalid architecture config for editor; valid options are {ARCH_CONFIG_MAP.keys()}",
            400,
        )

    # Load default source code for architecture to populate the template.
    with open(arch_info.example_path) as file_in:
        default_source_code = file_in.read()

    # Return the template with the appropriate code to display.
    return render_template(
        arch_info.template_path,
        default_code=default_source_code.split("\n"),
        default_tab_name=arch_info.example_name,
    )


@app.route("/trace/", methods=["POST"])
def code_trace():
    if request.json is None:
        return "No JSON data received", 400
    if "arch" not in request.json:
        return "No architecture config in JSON data", 400
    if "source_files" not in request.json:
        return "No source_code in JSON data", 400
    if "object_files" not in request.json:
        return "No object_files in JSON data", 400
    if "user_input" not in request.json:
        return "No user_input in JSON data", 400
    if "combine_all_steps" not in request.json:
        return "No combine_all_steps in JSON data", 400

    arch_info = ARCH_CONFIG_MAP.get(request.json["arch"])
    if arch_info is None:
        return (
            f"Invalid architecture config in JSON data; valid options are {ARCH_CONFIG_MAP.keys()}",
            400,
        )

    emulation_trace = arch_info.trace(
        combine_all_steps=request.json["combine_all_steps"],
        combine_external_steps=True,
        source_files=request.json["source_files"],
        object_files={
            n: b64_to_bytes(c) for n, c in request.json["object_files"].items()
        },
        extra_txt_files=request.json.get("extra_txt_files", {}),
        extra_bin_files={
            n: b64_to_bytes(c)
            for n, c in request.json.get("extra_bin_files", {}).items()
        },
        stdin=request.json["user_input"].encode(),
        cl_args=request.json["cl_args"],
        registers=request.json.get("registers", "").split(),
    )

    return send_file(
        BytesIO(emulation_trace.SerializeToString()),
        mimetype="application/x-protobuf",
    )


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
