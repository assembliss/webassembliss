# This file creates example submission results for the example configs.

# Add the grader directory to the path so we can load the proto.
import sys

sys.path.insert(1, "/")
from os.path import join

from webassembliss.grader.project_config_pb2 import WrappedProject
from webassembliss.grader.single_student import grade_student

source_name = "hello.S"
configs = [
    "helloProject_noMustPass_noSkip.pb2",
    "helloProject_noMustPass_yesSkip.pb2",
    "helloProject_yesMustPass_noSkip.pb2",
    "helloProject_yesMustPass_yesSkip.pb2",
]
names = ["Test One", "Test Two", "Test Three", "Test Four"]
IDs = ["tone", "ttwo", "tthree", "tfour"]

for ID, name, config in zip(IDs, names, configs):
    print(f"Creating sample submission for ({name=}, {ID=}) with {config=}")
    config_path = join("configs", config)

    with open(config_path, "rb") as config_fp, open(source_name) as source_fp:
        wp = WrappedProject()
        wp.ParseFromString(config_fp.read())
        results = grade_student(
            wrapped_config=wp,
            student_files={source_name: source_fp.read()},
            student_name=name,
            student_ID=ID,
        )
        user_submission = results.submission

        result_filename = f"{user_submission.project_name.replace(' ', '')}_{user_submission.ID}_results.json"
        with open(result_filename, "w") as file_out:
            file_out.write(user_submission.to_json())
