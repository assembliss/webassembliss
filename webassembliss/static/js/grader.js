const MAX_SIZE = 1 * 1024 * 1024;

// Attach form to our sendData function below.
document.querySelector("#submission").addEventListener("submit", (event) => {
    event.preventDefault();
    submitFormData();
});

async function submitFormData() {
    // Get input values from form.
    let name = document.getElementById("name").value;
    let ID = document.getElementById("unityID").value;
    let userCode = document.getElementById("userCode");
    let projectProto = document.getElementById("projectProto");

    // Validate that fields have been provided and are acceptable.
    if (!name) {
        showMessage("Missing Information", "You need to fill in your name!");
        return false;
    }

    if (!ID) {
        showMessage("Missing Information", "You need to fill in your ID!");
        return false;
    }

    if (!userCode.files.length) {
        showMessage("Missing Information", "You need to provide a source file!");
        return false;
    }

    if (userCode.files[0].size > MAX_SIZE) {
        showMessage("Invalid File", "Your source file is too big! Maximum allowed size if 1MB.");
        return false;
    }

    if (!projectProto.files.length) {
        showMessage("Missing Information", "You need to provide a project configuration file!");
        return false;
    }

    if (!projectProto.files[0].name.endsWith(".pb2")) {
        showMessage("Incorrect File Type", "The project configuration file must be a .pb2 file!");
        return false;
    }

    if (projectProto.files[0].size > MAX_SIZE) {
        showMessage("Invalid File", "Your project configuration file is too big! Maximum allowed size if 1MB.");
        return false;
    }

    // Fields are populated and valid; send form data to the backend.
    let form = document.forms['submission'];
    form.action = '/grader';
    form.submit()
    return true;
}
