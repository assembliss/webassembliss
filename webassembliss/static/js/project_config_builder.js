const MAX_SIZE = 1 * 1024 * 1024;

// Load protos that will be needed for project creation.
protobuf.load("/static/protos/project_config.proto").then(function (root) {
    window.TargetArchitecture = root.lookupEnum("TargetArchitecture");
    window.ExecutedInstructionsAggregation = root.lookupEnum("ExecutedInstructionsAggregation");
    window.CompressionAlgorithm = root.lookupEnum("CompressionAlgorithm");
    window.TestCase = root.lookupType("TestCase");
    window.MeasureSourceDocumentation = root.lookupType("MeasureSourceDocumentation");
    window.MeasureSourceEfficiency = root.lookupType("MeasureSourceEfficiency");
    window.MeasureExecEfficiency = root.lookupType("MeasureExecEfficiency");
    window.ProjectConfig = root.lookupType("ProjectConfig");
    window.WrappedProject = root.lookupType("WrappedProject");
}).then(() => {
    // Populate available TargetArchitecture from the project_config proto.
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
}).then(() => {
    // Populate available ExecutedInstructionsAggregation from the project_config proto.
    for (const [i, agg] of Object.entries(window.ExecutedInstructionsAggregation.valuesById)) {
        if (i == 0) {
            // Skip EXECUTEDINSTRUCTIONSAGGREGATION_UNSPECIFIED option.
            continue;
        }
        // Add a new option with its enum id and value.
        let newOption = document.createElement('option');
        newOption.value = i;
        newOption.innerText = agg;
        // Add it to the form.
        document.getElementById("exec-agg-select").appendChild(newOption);
    }
});

// Attach form to our sendData function below.
document.querySelector("#submission").addEventListener("submit", (event) => {
    event.preventDefault();
    submitFormData();
});

function updateGradingBreakdown() {
    // Find the number of points for each category.
    let accuracyPoints = parseInt(document.getElementById("weight-points-accuracy").value);
    let sourcePoints = parseInt(document.getElementById("weight-points-source").value);
    let execPoints = parseInt(document.getElementById("weight-points-exec").value);
    let docsPoints = parseInt(document.getElementById("weight-points-docs").value);
    // Find total points for the project.
    let totalPoints = accuracyPoints + sourcePoints + execPoints + docsPoints;
    // Update total in form.
    document.getElementById("total-project-points").innerText = totalPoints;
    // Update percentages for categories.
    document.getElementById("weight-pct-accuracy").innerText = `${(accuracyPoints * 100 / totalPoints).toFixed(2)}%`;
    document.getElementById("weight-pct-source").innerText = `${(sourcePoints * 100 / totalPoints).toFixed(2)}%`;
    document.getElementById("weight-pct-exec").innerText = `${(execPoints * 100 / totalPoints).toFixed(2)}%`;
    document.getElementById("weight-pct-docs").innerText = `${(docsPoints * 100 / totalPoints).toFixed(2)}%`;
}

let numberOfUserFiles = 1;
function addUserFilename() {
    // TODO: allow user to delete user filenames.
    // Increase the number of user files and get the new number for this new file.
    let fileNum = ++numberOfUserFiles;
    // Create new div for the file.
    let newFileDiv = document.createElement("div");
    newFileDiv.innerHTML = `
    <div class="mb-3">
        <label for="user-file-${fileNum}">User File #${fileNum}</label>
        <input type="text" name="user-file-${fileNum}" id="user-file-${fileNum}" class="form-control user-filenames" aria-label="Name of a file the user will need to submit for grading." placeholder="example${fileNum}.S"></textarea>
        <div id="sourceHelp" class="form-text">Name of a file the user will need to submit for grading.</div>
        <div class="invalid-feedback">
            Please enter a valid filename the user will need to submit.
        </div>
    </div>
    `;
    // Add the new file to the form.
    document.getElementById("user-filenames-div").appendChild(newFileDiv);
}

let numberOfTests = 0;
const pointsPerTest = [0]; // already has one element so we can access this 1-indexed.
function addTestCase() {
    // TODO: allow user to delete test cases.
    // Increase the number of total tests and get the new number for this new test.
    let testNum = ++numberOfTests;
    // Create new div for the test.
    let newTestDiv = document.createElement("div");
    newTestDiv.innerHTML = `
<div id="test-case-${testNum}-div" class="test-case-info">        
    <hr/>
    <h5>Test Case #${testNum}</h5>
    <div class="col-md-4">
        <label for="testCase-${testNum}-name">Test Name</label>
        <input type="text" class="form-control" id="testCase-${testNum}-name" placeholder="Test ${testNum}" required>
    </div>
    <div class="col-md-4">
        <label for="testCase-${testNum}-name">Test Points</label>
        <input type="number" class="form-control" id="testCase-${testNum}-points" name="testCase-${testNum}-points" onchange="updateTotalPoints(${testNum}); return false;" placeholder="0" required>
    </div>
    <div class="col-md-4">
        <label for="testCase-${testNum}-clargs">Test Command-Line Arguments</label>
        <input type="text" class="form-control" id="testCase-${testNum}-clargs" placeholder="arg1 arg2 arg3...">
    </div>
    <div class="col-md-6">
        <label for="testCase-${testNum}-input">Test Input</label>
        <textarea class="form-control" id="testCase-${testNum}-input" aria-label="Test Case #${testNum} Input" placeholder="input..." required></textarea>
    </div>
    <div class="col-md-6">
        <label for="testCase-${testNum}-output">Test Output</label>
        <textarea class="form-control" id="testCase-${testNum}-output" aria-label="Test Case #${testNum} Output" placeholder="output..." required></textarea>
    </div>
    <div class="form-check form-switch">
        <input class="form-check-input" type="checkbox" role="switch" value="" id="testCase-${testNum}-bytesIO">
        <label class="form-check-label" for="testCase-${testNum}-bytesIO">
            Check I/O for test case #${testNum} as bytes.
        </label>
    </div>
    <div class="form-check form-switch">
        <input class="form-check-input" type="checkbox" role="switch" value="" id="testCase-${testNum}-hidden">
        <label class="form-check-label" for="testCase-${testNum}-hidden">
            Hide I/O from user when grading submission.
        </label>
    </div>
    <div class="col-md-4">
        <label for="testCase-${testNum}-timeout">Test Timeout</label>
        <div class="input-group">
            <input type="number" class="form-control" id="testCase-${testNum}-timeout" placeholder="500" required>
            <span class="input-group-text">ms</span>
        </div>
    </div>
    <div class="col-md-4">
        <label for="testCase-${testNum}-max-instr">Test Maximum Instructions Executed</label>
        <input type="number" class="form-control" id="testCase-${testNum}-max-instr" placeholder="500" required>
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

let numSourceEffCutoffs = 1;
function addNewSourceEffCutoff() {
    // TODO: allow user to delete cutoffs.
    // Increase the number of source efficiency cutoffs and get the new number for this new one.
    let cutoffNum = ++numSourceEffCutoffs;
    // Create new div for the test.
    let newCutoffDiv = document.createElement("div");
    newCutoffDiv.classList.add("input-group");
    newCutoffDiv.classList.add("mb-3");
    newCutoffDiv.innerHTML = `
    <span class="input-group-text">Up to</span>
    <input type="number" id="source-eff-cutoff-${cutoffNum}-num" class="form-control" placeholder="X" aria-label="Number of instructions" required>
    <span class="input-group-text">written instructions should receive</span>
    <input type="number" id="source-eff-cutoff-${cutoffNum}-pct" class="form-control" placeholder="Y" aria-label="Percentage for this cutoff" required>
    <span class="input-group-text">%</span>
    `;
    // Add the new test to the form.
    document.getElementById("source-eff-cutoffs-div").appendChild(newCutoffDiv);
}

let numExecEffCutoffs = 1;
function addNewExecEffCutoff() {
    // TODO: allow user to delete cutoffs.
    // Increase the number of exec efficiency cutoffs and get the new number for this new one.
    let cutoffNum = ++numExecEffCutoffs;
    // Create new div for the test.
    let newCutoffDiv = document.createElement("div");
    newCutoffDiv.classList.add("input-group");
    newCutoffDiv.classList.add("mb-3");
    newCutoffDiv.innerHTML = `
    <span class="input-group-text">Up to</span>
    <input type="number" id="exec-eff-cutoff-${cutoffNum}-num" class="form-control" placeholder="X" aria-label="Number of instructions" required>
    <span class="input-group-text">aggregated executed instructions should receive</span>
    <input type="number" id="exec-eff-cutoff-${cutoffNum}-pct" class="form-control" placeholder="Y" aria-label="Percentage for this cutoff" required>
    <span class="input-group-text">%</span>
    `;
    // Add the new test to the form.
    document.getElementById("exec-eff-cutoffs-div").appendChild(newCutoffDiv);
}

let numCommentOnlyCutoffs = 1;
function addNewCommentOnlyCutoff() {
    // TODO: allow user to delete cutoffs.
    // Increase the number of exec efficiency cutoffs and get the new number for this new one.
    let cutoffNum = ++numCommentOnlyCutoffs;
    // Create new div for the test.
    let newCutoffDiv = document.createElement("div");
    newCutoffDiv.classList.add("input-group");
    newCutoffDiv.classList.add("mb-3");
    newCutoffDiv.innerHTML = `
    <span class="input-group-text">A ratio of at least</span>
    <input type="number" id="docs-commentonly-cutoff-${cutoffNum}-num" class="form-control" placeholder="X" aria-label="Number of instructions" required>
    <span class="input-group-text">% of comment-only lines to instruction lines should receive</span>
    <input type="number" id="docs-commentonly-cutoff-${cutoffNum}-pct" class="form-control" placeholder="Y" aria-label="Percentage for this cutoff" required>
    <span class="input-group-text">%</span>
    `;
    // Add the new test to the form.
    document.getElementById("docs-commentonly-cutoffs-div").appendChild(newCutoffDiv);
}

let numInlineCommentsCutoffs = 1;
function addNewInlineCommentsCutoff() {
    // TODO: allow user to delete cutoffs.
    // Increase the number of exec efficiency cutoffs and get the new number for this new one.
    let cutoffNum = ++numInlineCommentsCutoffs;
    // Create new div for the test.
    let newCutoffDiv = document.createElement("div");
    newCutoffDiv.classList.add("input-group");
    newCutoffDiv.classList.add("mb-3");
    newCutoffDiv.innerHTML = `
    <span class="input-group-text">A ratio of at least</span>
    <input type="number" id="docs-inlinecomments-cutoff-${cutoffNum}-num" class="form-control" placeholder="X" aria-label="Number of instructions" required>
    <span class="input-group-text">% of inline-commented lines to instruction lines should receive</span>
    <input type="number" id="docs-inlinecomments-cutoff-${cutoffNum}-pct" class="form-control" placeholder="Y" aria-label="Percentage for this cutoff" required>
    <span class="input-group-text">%</span>
    `;
    // Add the new test to the form.
    document.getElementById("docs-inlinecomments-cutoffs-div").appendChild(newCutoffDiv);
}

async function submitFormData() {
    // Make form read-only.
    document.getElementById("control-form-editing").setAttribute("disabled", "disabled");

    // TODO: add a loading bar and update it throughout the process.

    // First, parse the values from the form that need extra handling.

    // Parse filenames the user must submit.
    let requiredFiles = [];
    for (let i = 1; i <= numberOfUserFiles; i++) {
        requiredFiles.push(document.getElementById(`user-file-${i}`).value);
    }

    // Parse the test cases.
    let testCases = [];
    for (let i = 1; i <= numberOfTests; i++) {
        // First, figure out if the I/O should be parsed as text or a sequence of bytes.
        let stdin_s = null;
        let expected_out_s = null;
        let stdin_b = null;
        let expected_out_b = null;
        if (document.getElementById(`testCase-${i}-bytesIO`).checked) {
            // Test I/O is given in bytes.
            // Parse each individual byte from the input.
            stdin_b = [];
            for (const b of document.getElementById(`testCase-${i}-input`).value.split(" ")) {
                stdin_b.push(parseInt(b, 16));
            }
            // Parse each individual byte from the output.
            expected_out_b = [];
            for (const b of document.getElementById(`testCase-${i}-output`).value.split(" ")) {
                expected_out_b.push(parseInt(b, 16));
            }
        } else {
            // Test I/O is given in string.
            stdin_s = document.getElementById(`testCase-${i}-input`).value;
            expected_out_s = document.getElementById(`testCase-${i}-output`).value;
        }

        // Create a new message for this test and add it to the list.
        testCases.push(TestCase.create({
            name: document.getElementById(`testCase-${i}-name`).value,
            stdinS: stdin_s,
            stdinB: stdin_b,
            expectedOutS: expected_out_s,
            expectedOutB: expected_out_b,
            timeoutMs: parseInt(document.getElementById(`testCase-${i}-timeout`).value),
            maxInstrExec: parseInt(document.getElementById(`testCase-${i}-max-instr`).value),
            clArgs: document.getElementById(`testCase-${i}-clargs`).value.split(" "),
            hidden: document.getElementById(`testCase-${i}-hidden`).checked,
            points: parseInt(document.getElementById(`testCase-${i}-points`).value),
        }));

    }

    // Parse source efficiency cutoffs.
    let source_eff_points = {};
    for (let i = 1; i <= numSourceEffCutoffs; i++) {
        let instrCount = parseInt(document.getElementById(`source-eff-cutoff-${i}-num`).value);
        let points = parseInt(document.getElementById(`source-eff-cutoff-${i}-pct`).value) / 100;
        source_eff_points[instrCount] = points;
    }

    let source_eff = MeasureSourceEfficiency.create({
        points: source_eff_points,
        defaultPoints: parseInt(document.getElementById("source-eff-default-points").value),
    });

    // Parse execution efficiency cutoffs.
    let exec_eff_points = {};
    for (let i = 1; i <= numExecEffCutoffs; i++) {
        let instrCount = parseInt(document.getElementById(`exec-eff-cutoff-${i}-num`).value);
        let points = parseInt(document.getElementById(`exec-eff-cutoff-${i}-pct`).value) / 100;
        exec_eff_points[instrCount] = points;
    }

    let exec_eff = MeasureExecEfficiency.create({
        aggregation: parseInt(document.getElementById("exec-agg-select").value),
        points: exec_eff_points,
        default_points: parseInt(document.getElementById("exec-eff-default-points").value),
    });

    // Parse documentation's two sets of cutoffs.

    let comments_ratio_points = {};
    for (let i = 1; i <= numCommentOnlyCutoffs; i++) {
        let ratio = parseInt(document.getElementById(`docs-commentonly-cutoff-${i}-num`).value);
        let points = parseInt(document.getElementById(`docs-commentonly-cutoff-${i}-pct`).value) / 100;
        comments_ratio_points[ratio] = points;
    }

    let inline_comments_points = {};
    for (let i = 1; i <= numInlineCommentsCutoffs; i++) {
        let ratio = parseInt(document.getElementById(`docs-inlinecomments-cutoff-${i}-num`).value);
        let points = parseInt(document.getElementById(`docs-inlinecomments-cutoff-${i}-pct`).value) / 100;
        inline_comments_points[ratio] = points;
    }

    let docs_grading = MeasureSourceDocumentation.create({
        commentsToInstrPctPoints: comments_ratio_points,
        commentsToInstrPctDefault: parseInt(document.getElementById("docs-commentonly-default-points").value),
        inlineCommentsPctPoints: inline_comments_points,
        inlineCommentsPctDefault: parseInt(document.getElementById("docs-inlinecomments-default-points").value),
    });

    // Parse the category weights.
    let weights = {
        accuracy: parseInt(document.getElementById("weight-points-accuracy").value),
        documentation: parseInt(document.getElementById("weight-points-docs").value),
        source_efficiency: parseInt(document.getElementById("weight-points-source").value),
        exec_efficiency: parseInt(document.getElementById("weight-points-exec").value),
    };

    // TODO: load given object files.
    // TODO: load given .txt data files.
    // TODO: load given .bin data files.

    // Then, create a project config message.
    let project_name = document.getElementById("project-name").value;
    var pcMsg = ProjectConfig.create({
        name: project_name,
        arch: parseInt(document.getElementById("arch-select").value),
        requiredFiles: requiredFiles,
        providedObjects: null,
        execName: document.getElementById("executable-name").value,
        asFlags: document.getElementById("assembler-flags").value.split(" "),
        ldFlags: document.getElementById("linker-flags").value.split(" "),
        tests: testCases,
        stopOnFirstTestFail: document.getElementById("tests-stop-on-fail").checked,
        mustPassAllTests: document.getElementById("must-pass-all-tests").checked,
        docs: docs_grading,
        sourceEff: source_eff,
        execEff: exec_eff,
        weights: weights,
        extraTxtFiles: null,
        extraBinFiles: null
    });

    // Check that the config generated is valid.
    let err = ProjectConfig.verify(pcMsg);
    if (err) {
        alert("Error creating project config; check console.");
        console.log(pcMsg);
        console.log(err);
        document.getElementById("control-form-editing").removeAttribute("disabled");
        return;
    }

    // Serialize the message so we can distribute it.
    let spc = ProjectConfig.encode(pcMsg).finish();

    // Next, compress the ProjectConfig so it's canonical.
    let compressed_config = fflate.gzipSync(spc);

    // Calculate its hash so we can validate it later.
    let project_hash = await window.crypto.subtle.digest("SHA-256", compressed_config);

    // Finally, create the WrappedProject message.
    let wrapped_project = WrappedProject.create({
        checksum: new Uint8Array(project_hash),
        compressionAlg: CompressionAlgorithm.values['GZIP'],
        compressedConfig: compressed_config,
    });

    // Lastly, send the wrapped project to the user as a .pb2 file.
    let filename = project_name.replace(
        /\w\S*/g,
        text => text.charAt(0).toUpperCase() + text.substring(1).toLowerCase()
    ).replace(/ /g, '');
    download_file(`${filename}.pb2`, WrappedProject.encode(wrapped_project).finish(), 'application/x-protobuf')

    // After the project has been created and sent to the form user, make form editable again.
    document.getElementById("control-form-editing").removeAttribute("disabled");

}
