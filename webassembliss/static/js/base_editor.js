const WAITING_SYMBOL = "⭕";
const OK_SYMBOL = "✅";
const ERROR_SYMBOL = "❌";
window.lastRunInfo = null;
window.decorations = null;
window.gdb_line_decoration = null;
window.cl_args = "";
window.nextGDBLine = null;

const activeBreakpoints = {};

var coll = document.getElementsByClassName("collapsible");
var i;
for (i = 0; i < coll.length; i++) {
    coll[i].addEventListener("click", function () {
        this.classList.toggle("active");
        var content = this.nextElementSibling;
        if (content.style.display === "block") {
            content.style.display = "none";
        } else {
            content.style.display = "block";
        }
    });
}

// Initialize tooltips.
const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))

document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        // Prevent the Save dialog to open
        e.preventDefault();
        downloadCurrentTab();
    }
});


/* Adds toggle functionality to issue label buttons */
document.querySelector(".feedbackCollapsible").addEventListener("click", function (event) {
    if (event.target.classList.contains("issueLabelButton")) {
        event.target.classList.toggle("issueLabelActive");
    }
});

document.getElementById("fileUpload").addEventListener("change", function (uploadEvent) {
    importCode();
});


const currentTab = {
    num: 1,
    change(target) {
        this.num = target;
    }
};

function downloadCurrentTab() {
    let currentTab_filename = document.getElementById(`tab${currentTab.num}Btn`).value;
    download_file(currentTab_filename, getSource(), "text/plain");
}

function openTab(tabNum) {
    if (currentTab.num == tabNum) {
        // TODO: Implement a tab renaming system (and make it look good... yikes!)
        alert("rename temp");
    } else {
        // Save current tab contents
        localTabStorage.saveCurrentTab();

        // Update button styles.
        let currentTabBtn = document.getElementById(`tab${currentTab.num}Btn`);
        let currentTabBtnX = document.getElementById(`tab${currentTab.num}BtnX`);
        let newTabBtn = document.getElementById(`tab${tabNum}Btn`);
        let newTabBtnX = document.getElementById(`tab${tabNum}BtnX`);
        // For a background tab, make close button clickable and visible.
        currentTabBtn.className = "tabBtn";
        currentTabBtnX.className = "tabBtnX";
        currentTabBtnX.disabled = false;
        currentTabBtnX.removeAttribute("hidden");
        // For the foreground tab, disable the close button and hide it.
        newTabBtn.className = "activeTabBtn";
        newTabBtnX.className = "activeTabBtnX";
        newTabBtnX.disabled = true;
        newTabBtnX.setAttribute("hidden", "hidden");

        // Update the editor contents.
        let newTab_filename = newTabBtn.value;
        let localNewContents = localTabStorage.get(newTab_filename);
        window.editor.setValue(localNewContents);

        // Update active tab number.
        currentTab.change(tabNum);
    }
}

/* TODO: Before closing a tab, a check should occur to make sure the file was saved or otherwise not completely deleted. 
 * TODO: Prevent last tab from being closed.
 */
function closeTab(tabNum) {
    if (currentTab.num == tabNum) {
        // TODO: if current tab is open when this function is ran, swap to another tab.
        // Meanwhile, we just prevent that from happening... this is probably fine behavior.
        return;
    }
    let toBeClosed_filename = document.getElementById(`tab${tabNum}Btn`).value;
    // Delete tab locally.
    localTabStorage.delete(toBeClosed_filename);
    // Remove tab buttons.
    document.getElementById(`tab${tabNum}Btn`).remove();
    document.getElementById(`tab${tabNum}BtnX`).remove();
}

// THE COUNT MAY NEED TO BE SAVED AS A COOKIE.
const tabs = {
    // Start at tab #2. Tab #1 already exists when the webpage is opened
    count: 2,
    addTab() {
        let tabNum = this.count;
        let newTab = document.createElement("input");
        newTab.type = "button";
        newTab.className = "tabBtn";
        newTab.value = `Tab${tabNum}`;
        newTab.id = `tab${tabNum}Btn`;
        newTab.onclick = () => openTab(tabNum);

        let newTabX = document.createElement("input");
        newTabX.type = "button";
        newTabX.className = "tabBtnX";
        newTabX.value = "x";
        newTabX.id = `tab${tabNum}BtnX`;
        newTabX.onclick = () => closeTab(tabNum);


        document.getElementById("tabsDiv").insertBefore(newTab, document.getElementById("addTabBtn"));
        document.getElementById("tabsDiv").insertBefore(newTabX, document.getElementById("addTabBtn"));
        this.count++;
        openTab(tabNum);
    }
};

const localTabStorage = {
    archID: null,
    tabs: null,
    size: null,

    get(filename) {
        // Get the file contents stored; if there are none, use an empty string.
        return (filename in this.tabs) ? this.tabs[filename] : "";
    },

    save(filename, contents) {
        // Check if this is a new file or an update to an existing one.
        if (filename in this.tabs) {
            oldLength = this.tabs[filename].length;
            deltaLength = contents.length - oldLength;
            this.tabs[filename] = contents;
            this.size += deltaLength;
        } else {
            this.tabs[filename] = contents;
            this.size += filename.length + contents.length;
        }
        // Update the tabs in localStorage.
        this.store();
    },

    saveCurrentTab() {
        let currentTabBtn = document.getElementById(`tab${currentTab.num}Btn`);
        let currentTab_filename = currentTabBtn.value;
        let currentTab_contents = window.editor.getValue();
        this.save(currentTab_filename, currentTab_contents);
    },

    rename(oldFilename, newFilename) {
        // Check if file is saved.
        if (!(oldFilename in this.tabs)) {
            return;
        }
        // Check if the new name is not taken.
        if ((newFilename in this.tabs)) {
            return;
        }
        // Copy contents from old name to new one.
        this.tabs[newFilename] = this.tabs[oldFilename];
        // Delete old entry.
        delete this.tabs[oldFilename];
        // Update the size.
        this.size += newFilename.length - oldFilename.length;
        // Update the tabs in localStorage.
        this.store();
    },

    delete(filename) {
        if (filename in this.tabs) {
            contents = this.tabs[filename];
            this.size -= filename.length + contents.length;
            delete this.tabs[filename];
            // Update the tabs in localStorage.
            this.store();
        }
    },

    store() {
        localStorage.setItem(`tabs-${this.archID}`, JSON.stringify(this.tabs));
    },

    load() {
        // Update the architecture.
        this.archID = ARCH_ID;
        // Load saved tabs from localStorage.
        let savedTabs = localStorage.getItem(`tabs-${this.archID}`);
        this.tabs = savedTabs ? JSON.parse(savedTabs) : {};
        // Calculates storage size.
        this.size = 0;
        for (const [filename, contents] of Object.entries(this.tabs)) {
            this.size += filename.length + contents.length;
        }
    },

    init() {
        // Load tabs information stored in localstorage.
        this.load();

        // Display the stored tabs in the editor.
        if (!this.tabs) {
            // If there are no tabs stored, keep the default code on editor.
            return;
        }

        // Find the maximum tab number we need to create.
        // TODO: revisit this logic once tabs are names instead of numbered.
        let firstTab = true;
        let maxTabNum = 0;
        let minTabNum = 0;
        for (const [filename, contents] of Object.entries(this.tabs)) {
            let newTabNum = parseInt(filename.slice(3));
            if (firstTab) {
                maxTabNum = minTabNum = newTabNum;
                firstTab = false;
            } else {
                maxTabNum = (maxTabNum >= newTabNum) ? maxTabNum : newTabNum;
                minTabNum = (minTabNum <= newTabNum) ? minTabNum : newTabNum;
            }
        }

        // Create tabs needed.
        while (tabs.count <= maxTabNum) {
            if (!(`Tab${tabs.count}` in this.tabs)) {
                // If it is not a tab we have contents stored, skip it.
                tabs.count++;
                continue;
            }

            // Add tabs, but don't open them.
            let tabNum = tabs.count;
            let newTab = document.createElement("input");
            newTab.type = "button";
            newTab.className = "tabBtn";
            newTab.value = `Tab${tabNum}`;
            newTab.id = `tab${tabNum}Btn`;
            newTab.onclick = () => openTab(tabNum);

            let newTabX = document.createElement("input");
            newTabX.type = "button";
            newTabX.className = "tabBtnX";
            newTabX.value = "x";
            newTabX.id = `tab${tabNum}BtnX`;
            newTabX.onclick = () => closeTab(tabNum);

            document.getElementById("tabsDiv").insertBefore(newTab, document.getElementById("addTabBtn"));
            document.getElementById("tabsDiv").insertBefore(newTabX, document.getElementById("addTabBtn"));
            tabs.count++;
        }

        // Load the code of the first tab we have saved into the editor.
        // Delay for the editor to load.
        sleep(200).then(() => {
            // Same logic as the openTab method, but it does not save the changes locally.
            // TODO: maybe make this logic a new function that we can call both in here and in openTab; that would make it easier to implement future changes.

            // Update button styles.
            let currentTabBtn = document.getElementById(`tab${currentTab.num}Btn`);
            let currentTabBtnX = document.getElementById(`tab${currentTab.num}BtnX`);
            let newTabBtn = document.getElementById(`tab${maxTabNum}Btn`);
            let newTabBtnX = document.getElementById(`tab${maxTabNum}BtnX`);
            // For a background tab, make close button clickable and visible.
            currentTabBtn.className = "tabBtn";
            currentTabBtnX.className = "tabBtnX";
            currentTabBtnX.disabled = false;
            currentTabBtnX.removeAttribute("hidden");
            // For the foreground tab, disable the close button and hide it.
            newTabBtn.className = "activeTabBtn";
            newTabBtnX.className = "activeTabBtnX";
            newTabBtnX.disabled = true;
            newTabBtnX.setAttribute("hidden", "hidden");

            // Update the editor contents.
            let newTab_filename = newTabBtn.value;
            let localNewContents = localTabStorage.get(newTab_filename);
            window.editor.setValue(localNewContents);

            // Update active tab number.
            currentTab.change(maxTabNum);
        });

        // Check if we should delete the default tab from html template.
        if (!('Tab1' in this.tabs)) {
            // If we don't have contents saved for it, delete it.
            closeTab(1);
        }
    }
}

function importCode() {
    let file = document.getElementById("fileUpload").files[0];

    if (!file) {
        return;
    }

    if (!file.name.endsWith(".S")) {
        alert("Invalid file! Please select a .S file.");
        return;
    }

    let fileReader = new FileReader();
    fileReader.onload = function (onLoadEvent) {
        const fileContents = onLoadEvent.target.result;

        window.editor.setValue(fileContents);
    };

    fileReader.onerror = function () {
        alert("Error reading file.");
    };

    fileReader.readAsText(file);


}

/* Parses through the emulation information JSON and returns the string within quotes following the target.
*/
function parseEmulationJSON(target) {
    let json = JSON.parse(getLastRunInfo());

    return json[target] !== undefined ? json[target] : null;
}

function submitIssue() {
    let title = document.getElementById("issueTitle").value.trim();
    let body = document.getElementById("issueBody").value.trim();

    let source_code = parseEmulationJSON("source_code");
    let as_args = parseEmulationJSON("as_args");
    let as_err = parseEmulationJSON("as_err");
    let ld_args = parseEmulationJSON("ld_args");
    let ld_err = parseEmulationJSON("ld_err");


    // Template literal for body appending
    body += `


----------------------------------------------------------
source_code:
${source_code}
----------------------------------------------------------
as_args: ${as_args}
as_err: ${as_err}
ld_args: ${ld_args}
ld_err: ${ld_err}`;
    // End of template literal

    let bugLabelString = "";
    let helpWantedLabelString = "";
    let enhancementLabelString = "";
    let questionLabelString = "";
    let invalidLabelString = "";

    if (document.getElementById("issueBugLabel").classList.contains("issueLabelActive")) {
        bugLabelString = "bug,";
    }
    if (document.getElementById("issueHelpWantedLabel").classList.contains("issueLabelActive")) {
        helpWantedLabelString = "help+wanted,";
    }
    if (document.getElementById("issueEnhancementLabel").classList.contains("issueLabelActive")) {
        enhancementLabelString = "enhancement,";
    }
    if (document.getElementById("issueQuestionLabel").classList.contains("issueLabelActive")) {
        questionLabelString = "question,";
    }
    if (document.getElementById("issueInvalidLabel").classList.contains("issueLabelActive")) {
        invalidLabelString = "invalid,";
    }

    let fLabelString = `${bugLabelString}${helpWantedLabelString}${enhancementLabelString}${questionLabelString}${invalidLabelString}`;
    fLabelString = fLabelString.substring(0, fLabelString.length - 1);

    let encodedBody = encodeURIComponent(body);
    let encodedTitle = encodeURIComponent(title);
    let encodedLabels = encodeURIComponent(fLabelString);

    if (title == "" || body == "") {
        alert("Issue title and body is required.");
    } else {
        // Generate a URL query
        if (bugLabelString == "" && helpWantedLabelString == "" && enhancementLabelString == "" && questionLabelString == "" && invalidLabelString == "") {
            window.open(`https://github.ncsu.edu/assembliss/webassembliss/issues/new?title=${encodedTitle}&body=${encodedBody}`, "_blank");
        } else {
            window.open(`https://github.ncsu.edu/assembliss/webassembliss/issues/new?title=${encodedTitle}&body=${encodedBody}&labels=${encodedLabels}`, "_blank");
        } ``
    }
}

function BASE_createEditor(default_code, archSyntaxFun) {
    require.config({ paths: { vs: '/static/vs' } });
    require(['vs/editor/editor.main'], function () {
        monaco.languages.register({ id: ARCH_ID });
        monaco.languages.setMonarchTokensProvider(ARCH_ID, archSyntaxFun());
        window.editor = monaco.editor.create(document.getElementById('monaco-container'), {
            // Change "value" to upload files
            value: default_code.join('\n'),
            language: ARCH_ID,
            theme: 'vs-dark',
            glyphMargin: true,
            lineNumbersMinChars: 2,
            folding: false,
        });
        window.decorations = editor.createDecorationsCollection([]);
    });
}

function notImplemented() {
    alert("Not implemented yet...");
}

function clearOutput() {
    document.getElementById("runStatus").innerHTML = WAITING_SYMBOL;
    document.getElementById("asStatus").innerHTML = WAITING_SYMBOL;
    document.getElementById("ldStatus").innerHTML = WAITING_SYMBOL;
    document.getElementById("timeOut").innerHTML = WAITING_SYMBOL;
    document.getElementById("exitCode").innerHTML = WAITING_SYMBOL;
    document.getElementById("outputBox").value = "";
    document.getElementById("errorBox").value = "";
    document.getElementById("emulationInfo").value = "";
    document.getElementById("regValues").value = "";
    document.getElementById("memValues").value = "";
    window.lastRunInfo = null;
    document.getElementById("downloadButton").disabled = true;
}

function detectAndHighlightErrors() {
    // Find errors, parse through
    let as_err = parseEmulationJSON("as_err");
    let lines = as_err.split("\n").map(line => {

        let match = line.match(/usrCode\.S:(\d+): Error: (.+)/);
        if (match) {
            return { lineNumber: match[1], message: match[2] };
        }
        return null;

    }).filter(error => error !== null); // Remove non-error lines

    // Highlight lines for each error
    lines.forEach(line => {
        line.message = line.message.replace(/`/g, '\\`');
        addErrorHighlight(parseInt(line.lineNumber, 10), [{ value: line.message }]);
    });
}

function BASE_runCode() {
    clearOutput();
    // Create a floating message with a running message.
    modal = showLoading('Running your code', 'Please wait for the emulation to finish.', 'Running...');
    // Why not remove highlights at the start of runCode()?
    removeAllHighlights();
    window.editor.updateOptions({ readOnly: true });
    // This source code line should be in a for loop such that it goes through each tab and gets the source of each.
    localTabStorage.saveCurrentTab();
    let user_input = document.getElementById("inputBox").value;
    let registers = document.getElementById("regsToShow").value;
    document.getElementById("runStatus").innerHTML = "⏳";
    fetch('/run/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            arch: ARCH_ID,
            source_files: localTabStorage.tabs,
            user_input: user_input,
            cl_args: window.cl_args,
            registers: registers
        }),
    }).then(response => response.json())
        .then(data => {
            document.getElementById("runStatus").innerHTML = OK_SYMBOL;
            document.getElementById("asStatus").innerHTML = data.as_ok === null ? WAITING_SYMBOL : data.as_ok ? OK_SYMBOL : ERROR_SYMBOL;
            document.getElementById("ldStatus").innerHTML = data.ld_ok === null ? WAITING_SYMBOL : data.ld_ok ? OK_SYMBOL : ERROR_SYMBOL;
            document.getElementById("timeOut").innerHTML = data.timed_out === null ? WAITING_SYMBOL : data.timed_out ? OK_SYMBOL : ERROR_SYMBOL;
            document.getElementById("exitCode").innerHTML = exitCodeToEmoji(data.exit_code);
            document.getElementById("outputBox").value = data.stdout;
            document.getElementById("errorBox").value = data.stderr;
            document.getElementById("emulationInfo").value = data.all_info;
            document.getElementById("regValues").value = data.registers;
            document.getElementById("memValues").value = data.memory;
            lastRunInfo = data.info_obj;
            // Make sure to highlight detection AFTER lastRunInfo is updated!
            detectAndHighlightErrors();
            document.getElementById("downloadButton").disabled = false;
            window.editor.updateOptions({ readOnly: false });
        }).then(() =>
            // TODO: make sure this runs even if the fetch above fails.
            hideLoading(modal)
        );
}

function setCLArgs() {
    new_val = prompt("Set command line arguments:", window.cl_args);
    if (new_val !== null) {
        window.cl_args = new_val;
    }
}

function getSource() {
    return editor.getValue();;
}

function getLastRunInfo() {
    return JSON.stringify(lastRunInfo);
}

function addHighlight(line, options) {
    return decorations.append([
        {
            range: new monaco.Range(line, 1, line, 100),
            options: options
        }
    ]);
}

function addErrorHighlight(line, messages) {
    addHighlight(line, {
        isWholeLine: true,
        className: 'errorLineDecoration',
        hoverMessage: messages,
        glyphMarginClassName: 'fa-regular fa-circle-xmark',
        glyphMarginHoverMessage: messages,
    });
}

function updateNextLine(line) {
    window.gdb_line_decoration = addHighlight(line, {
        isWholeLine: true,
        className: 'nextLineDecoration',
        hoverMessage: [{ value: "Next line to be executed" }],
        glyphMarginClassName: 'fa-solid fa-forward',
        glyphMarginHoverMessage: [{ value: "Next line to be executed" }],

    });
}

function updateLastLine(line) {
    addHighlight(line, {
        isWholeLine: true,
        className: 'lastLineDecoration',
        hoverMessage: [{ value: "Last line executed" }],
        glyphMarginClassName: 'fa-solid fa-backward',
        glyphMarginHoverMessage: [{ value: "Last line executed" }],

    });
}

function updateTraceLinesHighlights(traceStep) {
    // Highlight the next line to be executed.
    if (traceStep + 1 < window.lastTrace.steps.length && window.lastTrace.steps[currentTraceStep.stepNum + 1].lineExecuted !== null) {
        // If it's not the last step and we have line information, highlight the next line.
        // TODO: handle lines in different tabs.
        updateNextLine(window.lastTrace.steps[currentTraceStep.stepNum + 1].lineExecuted.linenum);
    }

    // Highlight the last line that was executed.
    if (traceStep && window.lastTrace.steps[currentTraceStep.stepNum].lineExecuted !== null) {
        // If it's not the first step and we have line information, highlight the last line that was executed.
        // TODO: handle lines in different tabs.
        updateLastLine(window.lastTrace.steps[currentTraceStep.stepNum].lineExecuted.linenum);
    }
}

function addBreakpointHighlight(line) {
    addHighlight(line, {
        isWholeLine: true,
        glyphMarginClassName: 'fa-regular fa-circle-pause',
        glyphMarginHoverMessage: { value: 'breakpoint' },
        glyphMargin: { position: 2 }
    });
}

function addCurrentTabBreakpointsHighlights() {
    if (currentTab.num in activeBreakpoints) {
        for (const [line, active] of Object.entries(activeBreakpoints[currentTab.num])) {
            if (active) {
                addBreakpointHighlight(parseInt(line));
            }
        }
    }
}

function removeAllHighlights() {
    decorations.clear();
}

protobuf.load("/static/protos/trace_info.proto").then(function (root) {
    window.ExecutionTrace = root.lookupType("ExecutionTrace");
});
window.lastTrace = null;
const currentTraceStep = {
    stepNum: null,
    mem_changes: {},
    reg_changes: {},
    stdout: [],
    stderr: [],
};

function BASE_startTracing() {
    // Clear any old information.
    clearOutput();
    // Show the trace menu information and hide the start tracing button.
    document.getElementById("startTraceButtonDiv").classList.add("collapse");
    document.getElementById("statusFlagsDisplay").classList.remove("collapse");
    document.getElementById("traceMenuDiv").classList.remove("collapse");
    // Create a floating message with a running message.
    modal = showLoading('Running your code', 'Please wait for the emulation to finish.', 'Running...');
    removeAllHighlights();
    document.getElementById("traceStart").disabled = true;
    document.getElementById("traceStop").disabled = false;
    window.editor.updateOptions({ readOnly: true });
    // This source code line should be in a for loop such that it goes through each tab and gets the source of each.
    localTabStorage.saveCurrentTab();
    let user_input = document.getElementById("inputBox").value;
    let registers = document.getElementById("regsToShow").value;
    document.getElementById("runStatus").innerHTML = "⏳";
    fetch('/trace/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            arch: ARCH_ID,
            source_files: localTabStorage.tabs,
            user_input: user_input,
            cl_args: window.cl_args,
            registers: registers
        }),
    }).then(response => response.arrayBuffer())
        .then(data => {
            // Parse the protobuf from the backend.
            window.lastTrace = window.ExecutionTrace.decode(new Uint8Array(data));
        }).then(() => {
            // Update the GUI with execution information.
            document.getElementById("runStatus").innerHTML = OK_SYMBOL;
            document.getElementById("asStatus").innerHTML = window.lastTrace.assembledOk === null ? WAITING_SYMBOL : window.lastTrace.assembledOk ? OK_SYMBOL : ERROR_SYMBOL;
            document.getElementById("ldStatus").innerHTML = window.lastTrace.linkedOk === null ? WAITING_SYMBOL : window.lastTrace.linkedOk ? OK_SYMBOL : ERROR_SYMBOL;
            // Mark execution as not exited yet.
            document.getElementById("exitCode").innerHTML = WAITING_SYMBOL;
            // Use the timeout indication to show if the trace reached maximum number of steps.
            document.getElementById("timeOut").innerHTML = window.lastTrace.reachedMaxSteps === null ? WAITING_SYMBOL : window.lastTrace.reachedMaxSteps ? OK_SYMBOL : ERROR_SYMBOL;
            // Allow tracing to be downloaded.
            document.getElementById("traceDownload").disabled = false;
            // Allow user to jump to a specific step.
            document.getElementById("curTraceStepNum").disabled = false;
            // Update the tracing information to show the initial state.
            changeTracingStep(1);
        }).then(() => {
            // TODO: make sure this runs even if the fetch above fails.
            hideLoading(modal);
        });
}

function updateFlagIcon(flagName, set) {
    let flagIconID = flagName.toLowerCase() + "Flag";
    document.getElementById(flagIconID).innerHTML = set ? OK_SYMBOL : ERROR_SYMBOL;
}

const numEmojiMap = {
    0: "0️⃣",
    1: "1️⃣",
    2: "2️⃣",
    3: "3️⃣",
    4: "4️⃣",
    5: "5️⃣",
    6: "6️⃣",
    7: "7️⃣",
    8: "8️⃣",
    9: "9️⃣",
}

function getNumAsEmojis(num) {
    if (!num) {
        return numEmojiMap[0];
    }
    out = "";
    while (num) {
        digit = num % 10;
        num = Math.floor(num / 10);
        out = numEmojiMap[digit] + out
    }
    return out;
}

function exitCodeToEmoji(exitCode) {
    if (exitCode === null) {
        return WAITING_SYMBOL;
    }
    return getNumAsEmojis(exitCode);
}

function advanceOneTraceStep() {
    if (currentTraceStep.stepNum + 1 >= window.lastTrace.steps.length) {
        // At the last step, cannot move any further.
        return false;
    }

    // Advance the current step by one.
    if (currentTraceStep.stepNum === null) {
        // If this is the first step, initialize stepNum.
        currentTraceStep.stepNum = 0;
    } else {
        // If it's not, advance to the next.
        currentTraceStep.stepNum++;
    }

    // Process the information for the current step.
    let stepInfo = window.lastTrace.steps[currentTraceStep.stepNum];

    // Go through flagDelta and update the info.
    for (let flag in stepInfo.flagDelta) {
        updateFlagIcon(flag, stepInfo.flagDelta[flag]);
    }

    // Go through registerDelta and update the info.
    for (let reg in stepInfo.registerDelta) {
        // Store register changes into a stack so we can revert them.
        if (!(reg in currentTraceStep.reg_changes)) {
            // Create a stack for the register the first time we see it.
            currentTraceStep.reg_changes[reg] = [];
        }
        currentTraceStep.reg_changes[reg].push(stepInfo.registerDelta[reg]);
    }

    // Go through memoryDelta and update the info.
    for (let mem in stepInfo.memoryDelta) {
        // Store memory changes into a stack so we can revert them.
        if (!(mem in currentTraceStep.mem_changes)) {
            // Create a stack for the memory address the first time we see it.
            currentTraceStep.mem_changes[mem] = [];
        }
        currentTraceStep.mem_changes[mem].push(stepInfo.memoryDelta[mem]);
    }

    // Keep track of any new data written to stdout.
    if (stepInfo.stdout) {
        currentTraceStep.stdout.push(stepInfo.stdout);
    }

    // Keep track of any new data written to stderr.
    if (stepInfo.stderr) {
        currentTraceStep.stderr.push(stepInfo.stderr);
    }

    // Update the program exit information if this step exits it.
    document.getElementById("exitCode").innerHTML = exitCodeToEmoji(stepInfo.exitCode);

    // Return true to indicate that the move worked.
    return true;
}

function reverseOneTraceStep() {
    if (!currentTraceStep.stepNum) {
        // Cannot move backwards from the initial step.
        return false;
    }

    // Undo any changes from the current step.
    let stepInfo = window.lastTrace.steps[currentTraceStep.stepNum];

    // Go through flagDelta and undo any flags this step has updated.
    for (let flag in stepInfo.flagDelta) {
        // Use the flipped value so we have the flag value from before this step has executed.
        updateFlagIcon(flag, !stepInfo.flagDelta[flag]);
    }

    // Go through registerDelta and update the info.
    for (let reg in stepInfo.registerDelta) {
        // Remove the value this step had pushed for each register.
        currentTraceStep.reg_changes[reg].pop();
    }

    // Go through memoryDelta and update the info.
    for (let mem in stepInfo.memoryDelta) {
        // Remove the value this step had pushed for each memory chunk.
        currentTraceStep.mem_changes[mem].pop();
    }

    // Delete any stdout information from this step.
    if (stepInfo.stdout) {
        currentTraceStep.stdout.pop();
    }

    // Delete any stderr information from this step.
    if (stepInfo.stderr) {
        currentTraceStep.stderr.pop();
    }

    // Reset program exit info since it will not have exited.
    if (stepInfo.exitCode !== null) {
        document.getElementById("exitCode").innerHTML = WAITING_SYMBOL;
    }

    // Decrease the current step number.
    currentTraceStep.stepNum--;

    // Return true to indicate that the move worked.
    return true;
}

function changeTracingStep(stepDelta) {
    if (!stepDelta) {
        // If there is no delta to execute, stop early.
        return;
    }

    if (stepDelta > 0) {
        // Set the move function to move forward.
        changeFun = advanceOneTraceStep;
    } else {
        // Flip stepDelta so we can count down.
        stepDelta = -stepDelta;
        // Set the move function to move backward.
        changeFun = reverseOneTraceStep;
    }

    // Move one step at a time.
    while (stepDelta--) {
        // Move one step and receive a boolean indicating whether that move worked.
        changeOk = changeFun();
        if (!changeOk) {
            // If the last change did not work, we have reached the end of the steps list.
            break;
        }
    }

    // Update the correct controls to show up.
    updateTraceGUI();
}


function showTraceError(message) {
    // Ref: https://getbootstrap.com/docs/5.3/components/alerts/#live-example
    const wrapper = document.createElement('div');
    wrapper.innerHTML = [
        `<div class="alert alert-danger alert-dismissible" role="alert">`,
        `   <div>${message}</div>`,
        '   <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>',
        '</div>'
    ].join('');
    document.getElementById("traceErrorMessageDiv").append(wrapper);
}

function jumpToTracingStep() {
    let stepNum = prompt("What step number do you want to jump to?", "");

    // Check the user entered something.
    if (!stepNum) {
        showTraceError("Invalid step number; it cannot be empty.");
        return;
    }

    // Check the user entered a number.
    let intStepNum = parseInt(stepNum);
    if (Number.isNaN(intStepNum)) {
        showTraceError("Invalid step number; it must be a number.");
        return;
    }

    // From 1-index to 0-index.
    intStepNum--;
    let maxStep = window.lastTrace.steps.length;

    // Check the user entered a number in the valid range.
    if (intStepNum < 0 || intStepNum >= maxStep) {
        showTraceError("Invalid step number; it must be between 1 and " + maxStep + ".");
        return;
    }

    // Move to appropriate step.
    changeTracingStep(intStepNum - currentTraceStep.stepNum);
}

function intToHexBytes(value, bytesToPad, byteSep) {
    let hexValue = value.toString(16);

    while (hexValue.length < bytesToPad * 2) {
        hexValue = "0" + hexValue;
    }

    if (byteSep) {
        let separatedBytes = "";
        for (let i = 0; i < hexValue.length; i += 2) {
            separatedBytes += hexValue[i] + hexValue[i + 1] + byteSep;
        }
        hexValue = separatedBytes.slice(0, -byteSep.length);
    }

    return hexValue;
}

function asciiPrint(thisByte) {
    // Check if the given byte should be displayed as ascii or hex.
    if ((thisByte > 32) && (thisByte < 127)) {
        // If it's printable, we want to display the ascii char.
        return "'" + String.fromCharCode(thisByte) + "'";
    }
    // If it's not printable, return the hex value a space at the beginning for alignment.
    return " " + intToHexBytes(thisByte, 1);
}

function formatMemoryChunk(chunk, chunkShowLength, byteSep, showAscii) {
    let chunkStr = "";

    // Convert each byte in this chunk to a hex value.
    for (let i = 0; i < chunk.length; i++) {
        if (i) {
            chunkStr += byteSep;
        }
        if (!showAscii) {
            chunkStr += intToHexBytes(chunk[i], 1);
        } else {
            chunkStr += asciiPrint(chunk[i]);
        }
    }

    // Fill the chunk with 0-bytes if the chunk is shorter than expected.
    for (let i = 0; i < (chunkShowLength - chunk.length); i++) {
        chunkStr += byteSep;
        chunkStr += "00";
    }

    return chunkStr;
}

function updateTraceGUI() {
    // Clear old editor's highlights.
    removeAllHighlights();

    // Show the combined stdout.
    let combinedStdout = "";
    for (let i in currentTraceStep.stdout) {
        combinedStdout += currentTraceStep.stdout[i];
    }
    document.getElementById("outputBox").value = combinedStdout;

    // Show the combined stderr.
    let combinedStderr = "";
    for (let i in currentTraceStep.stderr) {
        combinedStderr += currentTraceStep.stderr[i];
    }
    document.getElementById("errorBox").value = combinedStderr;

    // Show the register values.
    let registerValues = "";
    for (let reg in currentTraceStep.reg_changes) {
        // Get the stored values we have for this register.
        let regValues = currentTraceStep.reg_changes[reg];
        // Find the most recent one or use a default of 0 if we have none.
        let lastValue = !regValues.length ? 0 : regValues[regValues.length - 1];
        registerValues += reg.padStart(10, " ") + ":  " + intToHexBytes(lastValue, 8, "  ") + "\n";
    }
    document.getElementById("regValues").value = registerValues;

    // Show the memory values.
    let memoryValues = "";
    for (let mem in currentTraceStep.mem_changes) {
        // Get the stored values we have for this register.
        let memValues = currentTraceStep.mem_changes[mem];
        // Find the most recent one or use a default of 0 if we have none.
        let lastValue = !memValues.length ? 0 : memValues[memValues.length - 1];
        // Format the address and chunk values for display.
        let formattedMem = intToHexBytes(parseInt(mem));
        let formattedValue = formatMemoryChunk(lastValue, 16, "  ", true);
        memoryValues += formattedMem + ":  " + formattedValue + "\n";
    }
    document.getElementById("memValues").value = memoryValues;

    // Update the last and next lines to be executed.
    updateTraceLinesHighlights(currentTraceStep.stepNum);

    // Update the progress bar.
    let pctComplete = 100 * (currentTraceStep.stepNum + 1) / window.lastTrace.steps.length;
    document.getElementById("tracingProgressBarAria").setAttribute("aria-valuenow", pctComplete);
    let progressBar = document.getElementById("tracingProgressBar");
    progressBar.style["width"] = pctComplete + "%";
    if (pctComplete < 100) {
        progressBar.classList.add("progress-bar-striped");
        progressBar.classList.remove("bg-success");
    } else {
        progressBar.classList.remove("progress-bar-striped");
        progressBar.classList.add("bg-success");
    }

    // Update the step number display button.
    document.getElementById("curTraceStepNum").innerText = "Step " + (currentTraceStep.stepNum + 1) + " / " + window.lastTrace.steps.length;

    // Disable all controls.
    Array.from(document.getElementsByClassName("trace-actions")).forEach((el) => {
        el.disabled = true;
    });
    if (currentTraceStep.stepNum) {
        // After step 0, can go backwards.
        Array.from(document.getElementsByClassName("trace-actions-back")).forEach((el) => {
            el.disabled = false;
        });
    }
    if (currentTraceStep.stepNum + 1 < window.lastTrace.steps.length) {
        // Before last step, can go forward.
        Array.from(document.getElementsByClassName("trace-actions-forward")).forEach((el) => {
            el.disabled = false;
        });
    }
}

function downloadTracing() {
    let json = window.ExecutionTrace.toObject(window.lastTrace);
    download_file("execution_trace.json", JSON.stringify(json), "application/json");
}

function stopTracing() {
    // Remove any markups on the editor.
    removeAllHighlights();

    // Delete old trace information.
    window.lastTrace = null;
    currentTraceStep.stepNum = null;
    currentTraceStep.mem_changes = {};
    currentTraceStep.reg_changes = {};
    currentTraceStep.stdout = [];
    currentTraceStep.stderr = [];

    // Disable the controls.
    document.getElementById("curTraceStepNum").innerText = "StepNum";
    document.getElementById("curTraceStepNum").disabled = true;
    Array.from(document.getElementsByClassName("trace-actions")).forEach((el) => {
        el.disabled = true;
    });

    // Reset progress bar to zero.
    document.getElementById("tracingProgressBar").style["width"] = "0%";

    // Reset original button states.
    document.getElementById("traceStart").disabled = false;
    document.getElementById("traceStop").disabled = true;
    document.getElementById("traceDownload").disabled = true;

    // Hide the tracing menu and show the start tracing button again.
    document.getElementById("traceMenuDiv").classList.add("collapse");
    document.getElementById("statusFlagsDisplay").classList.add("collapse");
    document.getElementById("startTraceButtonDiv").classList.remove("collapse");

    // Make editor writeable again.
    window.editor.updateOptions({ readOnly: false });
}
