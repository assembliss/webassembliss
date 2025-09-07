const MAX_SIZE = 1 * 1024 * 1024;

// Load relevant project protos so we can verify files are available.
protobuf.load("/static/protos/project_config.proto").then(function (root) {
    window.CompressionAlgorithm = root.lookupEnum("CompressionAlgorithm");
    window.ProjectConfig = root.lookupType("ProjectConfig");
    window.WrappedProject = root.lookupType("WrappedProject");
});

// Define which functions can uncompress each algorithm.
const uncompressMap = {
    // Ref: https://github.com/101arrowz/fflate/blob/master/docs/README.md#gunzipsync
    GZIP: fflate.gunzipSync,
}

// Function to validate the project files submitted before sending them to the backend.
function validateProjectConfigProto(pc, sourceFiles) {
    // Check that the user uploaded all required files in the project.
    for (const requiredFile of pc.requiredFiles) {
        // TODO: optimize this check; probably don't need to do N x M loops.
        let fileWasUploaded = false;

        // Check if this file matches any of the files the user uploaded.
        for (const uploadedFile of sourceFiles) {
            if (uploadedFile.name == requiredFile) {
                // If it does match, mark it as found and stop the search.
                fileWasUploaded = true;
                break;
            }
        }

        // If the file was not found, show error to user and return false to not submit the form.
        if (!fileWasUploaded) {
            showMessage("Missing Required File", `This project expects you to submit a file named ${requiredFile}`);
            return false;
        }

    }

    // If we reached here, no issues with the ProjectConfig and the userFiles.
    // Return true to indicate it passed all checks.
    return true;
}

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

    if (projectProto.files.length != 1) {
        showMessage("Missing Information", "You need to provide exactly one project configuration file!");
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

    // Parse the WrappedProject the user uploaded to find out which compression algorithm it used.
    const bytes = new Uint8Array(await projectProto.files[0].arrayBuffer());
    const wp = WrappedProject.decode(bytes);
    const compressionAlg = CompressionAlgorithm.valuesById[wp.compressionAlg];
    console.log(`Uploaded WrappedProject proto used ${compressionAlg} to compress the ProjectConfig`)

    // Check if the browser can uncompress that algorithm.
    if (compressionAlg in uncompressMap) {
        // If it can, we will uncompress compressed_config into a ProjectConfig and validate it before sending to backend.
        console.log(`Browser is able to decompress ${compressionAlg}, will validate ProjectConfig before sending data backend.`);
        const pcBytes = uncompressMap[compressionAlg](wp.compressedConfig);
        const pc = ProjectConfig.decode(pcBytes);

        // Send the ProjectConfig message and the source files the user uploaded to the validate function.
        if (!validateProjectConfigProto(pc, userCode.files)) {
            // If the validate function returns false, we return false to prevent submitting the form.
            console.log("ProjectConfig validation failed, not submitting form.");
            return false;
        }
        console.log("ProjectConfig validation passed, will submit form.");

    } else {
        // If we cannot, we will simply send the WrappedProject to the backend and let it handle errors.
        console.log(`Unable to decompress ${compressionAlg} in browser, sending data to backend without any checks.`);
    }

    // Fields are populated and valid; send form data to the backend.
    let form = document.forms['submission'];
    form.action = '/grader';
    form.submit()
    return true;
}
