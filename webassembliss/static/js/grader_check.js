const MAX_SIZE = 1 * 1024 * 1024;

// Attach form to our sendData function below.
document.querySelector("#submission").addEventListener("submit", (event) => {
    event.preventDefault();
    submitFormData();
});

async function submitFormData() {
    // Get files from form.
    let submissions = document.getElementById("submissions");
    let wrappedProjectProto = document.getElementById("wrappedProjectProto");

    // Validate that files have been provided and are acceptable.
    if (wrappedProjectProto.files.length != 1) {
        showMessage("Missing Information", "You need to provide exactly one project configuration file!");
        return false;
    }

    if (!wrappedProjectProto.files[0].name.endsWith(".pb2")) {
        showMessage("Incorrect File Type", "The project configuration file must be a .pb2 file!");
        return false;
    }

    if (wrappedProjectProto.files[0].size > MAX_SIZE) {
        showMessage("Invalid File", "Your project configuration file is too big! Maximum allowed size if 1MB.");
        return false;
    }

    if (!submissions.files.length) {
        showMessage("Missing Information", "You need to provide at least one submission file!");
        return false;
    }

    for (let i = 0; i < submissions.files.length; i++) {
        if (!submissions.files[i].name.endsWith(".json") && !submissions.files[i].name.endsWith(".zip")) {
            showMessage("Incorrect File Type", "The submission files should be either .json for individual submissions or .zip with multiple .json inside!");
            return false;
        }
        if (submissions.files[i].size > MAX_SIZE) {
            showMessage("Invalid File", `Your submission file #${i + 1} is too big! Maximum allowed size if 1MB.`);
            return false;
        }
    }

    // Fields are populated and valid; send form data to the backend.
    let form = document.forms['submission'];
    form.action = '/grader-check';
    form.submit()
    return true;
}
