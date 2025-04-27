const MAX_SIZE = 1 * 1024 * 1024;

// Populate available TargetArchitecture from the project_config proto.
protobuf.load("/static/protos/project_config.proto").then(function (root) {
    window.TargetArchitecture = root.lookupEnum("TargetArchitecture");
}).then(() => {
    for (const [i, arch] of Object.entries(window.TargetArchitecture.valuesById)) {
        if (i == 0) {
            // Skip TARGETARCHITECTURE_UNSPECIFIED option.
            continue;
        }
        // Add a new option with its enum id and value.
        let newOption = document.createElement('option');
        newOption.value = i;
        newOption.innerText = arch;
        // Add it to the form.
        document.getElementById("arch-select").appendChild(newOption);
    }
});

// Populate available ExecutedInstructionsAggregation from the project_config proto.
protobuf.load("/static/protos/project_config.proto").then(function (root) {
    window.ExecutedInstructionsAggregation = root.lookupEnum("ExecutedInstructionsAggregation");
}).then(() => {
    for (const [i, arch] of Object.entries(window.ExecutedInstructionsAggregation.valuesById)) {
        if (i == 0) {
            // Skip EXECUTEDINSTRUCTIONSAGGREGATION_UNSPECIFIED option.
            continue;
        }
        // Add a new option with its enum id and value.
        let newOption = document.createElement('option');
        newOption.value = i;
        newOption.innerText = arch;
        // Add it to the form.
        document.getElementById("exec-agg-select").appendChild(newOption);
    }
});


// Attach form to our sendData function below.
document.querySelector("#submission").addEventListener("submit", (event) => {
    event.preventDefault();
    submitFormData();
});

let numberOfTests = 0;
const pointsPerTest = [0]; // already has one element so we can access this 1-indexed.
function addTestCase() {
    // TODO: allow user to delete test cases.
    // Increase the number of total tests and get the new number for this new test.
    let testNum = ++numberOfTests;
    // Create new div for the test.
    let newTestDiv = document.createElement("div");
    newTestDiv.innerHTML = `
<div id="test-case-${testNum}-div">        
    <hr/>
    <h5>Test Case #${testNum}</h5>
    <div class="input-group mb-3">
        <span class="input-group-text" for="testCase-${testNum}-input">Test Case #${testNum} Input</span>
        <textarea class="form-control" id="testCase-${testNum}-input" aria-label="Test Case #${testNum} Input" placeholder="input..." required></textarea>
        <span class="input-group-text" for="testCase-${testNum}-output">Test Case #${testNum} Output</span>
        <textarea class="form-control" id="testCase-${testNum}-output" aria-label="Test Case #${testNum} Output" placeholder="output..." required></textarea>
        <span class="input-group-text" for="testCase-${testNum}-points">Test Case #${testNum} Points</span>
        <input type="number" class="form-control" id="testCase-${testNum}-points" name="testCase-${testNum}-points" onchange="updateTotalPoints(${testNum}); return false;" placeholder="0" required>
    </div>
    <div class="form-check">
    <input class="form-check-input" type="checkbox" value="" id="test-case-${testNum}-bytesIO">
    <label class="form-check-label" for="test-case-${testNum}-bytesIO">
        Check I/O for test case #${testNum} as bytes.
    </label>
    </div>
</div>
    `;
    // Add the new test to the form.
    document.getElementById("test-cases-div").appendChild(newTestDiv);
    // Add an entry to store the number of points for this test.
    pointsPerTest.push(0);
    // Update the number of test cases.
    document.getElementById("total-test-cases").value = numberOfTests;
}

function updateTotalPoints(testChanged) {
    // Get the new number of points for this test from the user.
    let newTestPoints = parseInt(document.getElementById(`testCase-${testChanged}-points`).value);
    // Update array with new number of points.
    pointsPerTest[testChanged] = newTestPoints;
    // Update the total points shown on the form.
    document.getElementById("total-test-points").value = pointsPerTest.reduce((accumulator, currentValue) => {
        return accumulator + currentValue
    }, 0);
}

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
