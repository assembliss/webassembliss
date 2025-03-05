const WAITING_SYMBOL = "⭕";
const OK_SYMBOL = "✅";
const ERROR_SYMBOL = "❌";
window.lastRunInfo = null;
window.decorations = null;
window.gdb_line_decoration = null;
window.cl_args = "";

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

        let currentTabBtn = document.getElementById(`tab${currentTab.num}Btn`);
        let currentTabBtnX = document.getElementById(`tab${currentTab.num}BtnX`);
        let newTabBtn = document.getElementById(`tab${tabNum}Btn`);
        let newTabBtnX = document.getElementById(`tab${tabNum}BtnX`);

        let currentTab_filename = currentTabBtn.value;
        let currentTab_contents = window.editor.getValue();

        let newTab_filename = newTabBtn.value;

        // Make a post request that will save the contents of the current tab and return the contents of the new tab.
        fetch('/tab_manager/' + currentTab_filename, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                contents: currentTab_contents,
                return_file: newTab_filename
            }),
        }).then(response => response.json())
            .then(data => {
                // TODO: Validate this response.
                // Update the editor contents.
                window.editor.setValue(data.return_file.contents);
                // Update button styles.
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
                // Update active tab number.
                currentTab.change(tabNum);
            });
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
    fetch('/tab_manager/' + toBeClosed_filename, {
        method: 'DELETE',
    }).then(() => {
        document.getElementById(`tab${tabNum}Btn`).remove();
        document.getElementById(`tab${tabNum}BtnX`).remove();
    });
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
        console.log("added tab")
        openTab(tabNum);
    }
};

function importCode() {
    let file = document.getElementById("fileUpload").files[0];
    console.log(file);

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
        }
    }
}

function createEditor(default_code) {
    require.config({ paths: { vs: '/static/vs' } });
    require(['vs/editor/editor.main'], function () {
        monaco.languages.register({ id: 'arm64' });
        monaco.languages.setMonarchTokensProvider('arm64', getSyntaxHighlighting());
        window.editor = monaco.editor.create(document.getElementById('monaco-container'), {
            // Change "value" to upload files
            value: default_code.join('\n'),
            language: 'arm64',
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
    document.getElementById("execStatus").innerHTML = WAITING_SYMBOL;
    document.getElementById("nFlag").innerHTML = WAITING_SYMBOL;
    document.getElementById("zFlag").innerHTML = WAITING_SYMBOL;
    document.getElementById("cFlag").innerHTML = WAITING_SYMBOL;
    document.getElementById("vFlag").innerHTML = WAITING_SYMBOL;
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

function runCode() {
    clearOutput();
    // Why not remove highlights at the start of runCode()?
    removeAllHighlights();
    window.editor.updateOptions({ readOnly: true });
    // This source code line should be in a for loop such that it goes through each tab and gets the source of each.
    let source_code = getSource();
    let user_input = document.getElementById("inputBox").value;
    let registers = document.getElementById("regsToShow").value;
    document.getElementById("runStatus").innerHTML = "⏳";
    fetch('/arm64_linux/run/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            source_code: source_code,
            user_input: user_input,
            cl_args: window.cl_args,
            registers: registers
        }),
    }).then(response => response.json())
        .then(data => {
            document.getElementById("runStatus").innerHTML = OK_SYMBOL;
            document.getElementById("debugStatus").innerHTML = ERROR_SYMBOL;
            document.getElementById("asStatus").innerHTML = data.as_ok === null ? WAITING_SYMBOL : data.as_ok ? OK_SYMBOL : ERROR_SYMBOL;
            document.getElementById("ldStatus").innerHTML = data.ld_ok === null ? WAITING_SYMBOL : data.ld_ok ? OK_SYMBOL : ERROR_SYMBOL;
            document.getElementById("execStatus").innerHTML = data.ran_ok === null ? WAITING_SYMBOL : data.ran_ok ? OK_SYMBOL : ERROR_SYMBOL;
            document.getElementById("nFlag").innerHTML = "N" in data.flags ? data.flags.N ? OK_SYMBOL : ERROR_SYMBOL : WAITING_SYMBOL;
            document.getElementById("zFlag").innerHTML = "Z" in data.flags ? data.flags.Z ? OK_SYMBOL : ERROR_SYMBOL : WAITING_SYMBOL;
            document.getElementById("cFlag").innerHTML = "C" in data.flags ? data.flags.C ? OK_SYMBOL : ERROR_SYMBOL : WAITING_SYMBOL;
            document.getElementById("vFlag").innerHTML = "V" in data.flags ? data.flags.V ? OK_SYMBOL : ERROR_SYMBOL : WAITING_SYMBOL;
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
        });
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

function updateGdbLine(line) {
    if (window.gdb_line_decoration) {
        // TODO: remove old line decoration so only the updated next one appears.
    }
    window.gdb_line_decoration = addHighlight(line, {
        isWholeLine: true,
        className: 'gdbLineDecoration'
    });
}

function addBreakpointHighlight(line) {
    addHighlight(line, {
        isWholeLine: true,
        glyphMarginClassName: 'fa-regular fa-circle-pause',
        glyphMarginHoverMessage: { value: 'breakpoint' },
        glyphMargin: { position: 2 }
    });
}

function removeAllHighlights() {
    decorations.clear();
}

function updateDebuggingInfo(data) {
    // TODO: only update values if they're not null, e.g., after program quits we probably want to display last memory values read.
    //          - this could also be done python-side.

    document.getElementById("runStatus").innerHTML = OK_SYMBOL;

    if (data.debugInfo.as_ok !== null) {
        document.getElementById("asStatus").innerHTML = data.debugInfo.assembled_ok ? OK_SYMBOL : ERROR_SYMBOL;
    }

    if (data.debugInfo.ld_ok !== null) {
        document.getElementById("ldStatus").innerHTML = data.debugInfo.linked_ok ? OK_SYMBOL : ERROR_SYMBOL;
    }

    if (data.ran_ok !== null) {
        document.getElementById("execStatus").innerHTML = data.ran_ok ? OK_SYMBOL : ERROR_SYMBOL;
    }

    if (data.debugInfo.active !== null) {
        document.getElementById("debugStatus").innerHTML = data.debugInfo.active ? OK_SYMBOL : ERROR_SYMBOL;
    }

    document.getElementById("nFlag").innerHTML = "N" in data.debugInfo.flags ? data.debugInfo.flags.N ? OK_SYMBOL : ERROR_SYMBOL : WAITING_SYMBOL;
    document.getElementById("zFlag").innerHTML = "Z" in data.debugInfo.flags ? data.debugInfo.flags.Z ? OK_SYMBOL : ERROR_SYMBOL : WAITING_SYMBOL;
    document.getElementById("cFlag").innerHTML = "C" in data.debugInfo.flags ? data.debugInfo.flags.C ? OK_SYMBOL : ERROR_SYMBOL : WAITING_SYMBOL;
    document.getElementById("vFlag").innerHTML = "V" in data.debugInfo.flags ? data.debugInfo.flags.V ? OK_SYMBOL : ERROR_SYMBOL : WAITING_SYMBOL;

    document.getElementById("outputBox").value = data.stdout;
    document.getElementById("errorBox").value = data.stderr;
    document.getElementById("regValues").value = data.registers;
    document.getElementById("memValues").value = data.memory;
    document.getElementById("emulationInfo").value = data.all_info;
    lastRunInfo = data.debugInfo;
    document.getElementById("downloadButton").disabled = false;
    if (data.debugInfo.active) {
        removeAllHighlights();
        updateGdbLine(data.debugInfo.next_line);
        for (const line of data.debugInfo.breakpoints) {
            // TODO: handle multiple sources here, would be in format 'source:line'.
            addBreakpointHighlight(parseInt(line));
        }
    } else {
        stopDebugger();
    }
}

function startDebugger() {
    // Clear any old information.
    clearOutput();
    // Enable active debugger buttons.
    document.getElementById("debugStop").disabled = false;
    document.getElementById("debugBreakpoint").disabled = false;
    document.getElementById("debugContinue").disabled = false;
    document.getElementById("debugStep").disabled = false;
    // Disable regular buttons.
    document.getElementById("debugStart").disabled = true;
    document.getElementById("runBtn").disabled = true;
    document.getElementById("resetBtn").disabled = true;
    document.getElementById("saveBtn").disabled = true;
    document.getElementById("loadBtn").disabled = true;
    // Make editor read-only.
    window.editor.updateOptions({ readOnly: true });

    // TODO: actually start a debugging session.
    let source_code = getSource();
    let user_input = document.getElementById("inputBox").value;
    let registers = document.getElementById("regsToShow").value;
    document.getElementById("runStatus").innerHTML = "⏳";
    fetch('/arm64_linux/debug/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ source_code: source_code, user_input: user_input, cl_args: window.cl_args, "debug": { "start": true }, registers: registers }),
    }).then(response => response.json())
        .then(data => {
            updateDebuggingInfo(data);
        });
}

function debuggerCommand(commands) {
    let source_code = getSource();
    let user_input = document.getElementById("inputBox").value;
    let registers = document.getElementById("regsToShow").value;
    fetch('/arm64_linux/debug/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ source_code: source_code, user_input: user_input, "debug": commands, registers: registers }),
    }).then(response => response.json())
        .then(data => {
            updateDebuggingInfo(data);
        });
}

function continueDebug() {
    debuggerCommand({ "command": 1 });
}

function stepDebug() {
    debuggerCommand({ "command": 2 });
}

function toggleBreakpoint() {
    // TODO: handle multiple source files eventually.
    let lineNum = prompt("Line number to toggle breakpoint:", "");
    if (lineNum) {
        lineNum = parseInt(lineNum);
        debuggerCommand({ "command": 3, "breakpoint_line": lineNum });
    }
}

function stopDebugger() {
    // Stop debugging session.
    debuggerCommand({ "command": 4 });
    // Remove any decorations we had added to the editor (i.e., next line, breakpoints).
    removeAllHighlights();
    // Disable active debugger buttons.
    document.getElementById("debugStop").disabled = true;
    document.getElementById("debugBreakpoint").disabled = true;
    document.getElementById("debugContinue").disabled = true;
    document.getElementById("debugStep").disabled = true;
    // Enable regular buttons.
    document.getElementById("debugStart").disabled = false;
    document.getElementById("runBtn").disabled = false;
    document.getElementById("resetBtn").disabled = false;
    document.getElementById("saveBtn").disabled = false;
    document.getElementById("loadBtn").disabled = false;
    // Make editor editable.
    window.editor.updateOptions({ readOnly: false });
}

function getSyntaxHighlighting() {
    return {
        // First draft of an ARM64 assembly syntax.
        // Instructions taken from: https://developer.arm.com/documentation/ddi0602/2024-12/Base-Instructions
        instructions: [
            "ABS", "abs", "ADC", "adc", "ADCS", "adcs", "add", "ADD", "ADDG", "addg", "ADDPT", "addpt", "adds", "ADDS", "ADR", "adr", "ADRP", "adrp", "AND", "and", "ands", "ANDS", "apas", "APAS", "ASR", "asr", "asrv", "ASRV", "at", "AT",
            "AUTDA", "autda", "AUTDB", "autdb", "AUTIA", "autia", "autia171615", "AUTIA171615", "AUTIASPPC", "autiasppc", "autiasppcr", "AUTIASPPCR", "autib", "AUTIB", "AUTIB171615", "autib171615", "AUTIBSPPC", "autibsppc", "autibsppcr", "AUTIBSPPCR", "axflag", "AXFLAG", "b", "B", "bc", "BC", "BFC", "bfc", "BFI", "bfi",
            "bfm", "BFM", "bfxil", "BFXIL", "bic", "BIC", "BICS", "bics", "bl", "BL", "BLR", "blr", "blraa", "BLRAA", "BR", "br", "BRAA", "braa", "BRB", "brb", "brk", "BRK", "bti", "BTI", "cas", "CAS", "CASB", "casb", "CASH", "cash",
            "CASP", "casp", "caspt", "CASPT", "cast", "CAST", "CB", "cb", "cbb", "CBB", "cbble", "CBBLE", "cbblo", "CBBLO", "CBBLS", "cbbls", "cbblt", "CBBLT", "CBGE", "cbge", "cbh", "CBH", "CBHLE", "cbhle", "CBHLO", "cbhlo", "cbhls", "CBHLS", "cbhlt", "CBHLT",
            "cbhs", "CBHS", "CBLE", "cble", "cblo", "CBLO", "cbls", "CBLS", "cblt", "CBLT", "cbnz", "CBNZ", "cbz", "CBZ", "ccmn", "CCMN", "ccmp", "CCMP", "cfinv", "CFINV", "cfp", "CFP", "chkfeat", "CHKFEAT", "CINC", "cinc", "CINV", "cinv", "clrbhb", "CLRBHB",
            "CLREX", "clrex", "cls", "CLS", "CLZ", "clz", "CMN", "cmn", "CMP", "cmp", "CMPP", "cmpp", "cneg", "CNEG", "CNT", "cnt", "COSP", "cosp", "cpp", "CPP", "cpyfp", "CPYFP", "cpyfpn", "CPYFPN", "cpyfprn", "CPYFPRN", "CPYFPRT", "cpyfprt", "cpyfprtn", "CPYFPRTN",
            "CPYFPRTRN", "cpyfprtrn", "CPYFPRTWN", "cpyfprtwn", "CPYFPT", "cpyfpt", "CPYFPTN", "cpyfptn", "cpyfptrn", "CPYFPTRN", "cpyfptwn", "CPYFPTWN", "cpyfpwn", "CPYFPWN", "cpyfpwt", "CPYFPWT", "cpyfpwtn", "CPYFPWTN", "CPYFPWTRN", "cpyfpwtrn", "CPYFPWTWN", "cpyfpwtwn", "CPYP", "cpyp", "cpypn", "CPYPN", "CPYPRN", "cpyprn", "CPYPRT", "cpyprt",
            "CPYPRTN", "cpyprtn", "CPYPRTRN", "cpyprtrn", "CPYPRTWN", "cpyprtwn", "cpypt", "CPYPT", "cpyptn", "CPYPTN", "cpyptrn", "CPYPTRN", "cpyptwn", "CPYPTWN", "cpypwn", "CPYPWN", "cpypwt", "CPYPWT", "CPYPWTN", "cpypwtn", "CPYPWTRN", "cpypwtrn", "CPYPWTWN", "cpypwtwn", "CRC32B", "crc32b", "CRC32CB", "crc32cb", "csdb", "CSDB",
            "csel", "CSEL", "cset", "CSET", "CSETM", "csetm", "csinc", "CSINC", "csinv", "CSINV", "CSNEG", "csneg", "ctz", "CTZ", "DC", "dc", "DCPS1", "dcps1", "dcps2", "DCPS2", "DCPS3", "dcps3", "DGH", "dgh", "dmb", "DMB", "DRPS", "drps", "DSB", "dsb",
            "dvp", "DVP", "eon", "EON", "EOR", "eor", "eret", "ERET", "eretaa", "ERETAA", "esb", "ESB", "EXTR", "extr", "GCSB", "gcsb", "gcspopcx", "GCSPOPCX", "GCSPOPM", "gcspopm", "GCSPOPX", "gcspopx", "GCSPUSHM", "gcspushm", "GCSPUSHX", "gcspushx", "GCSSS1", "gcsss1", "gcsss2", "GCSSS2",
            "GCSSTR", "gcsstr", "gcssttr", "GCSSTTR", "gmi", "GMI", "hint", "HINT", "hlt", "HLT", "HVC", "hvc", "ic", "IC", "irg", "IRG", "ISB", "isb", "LD64B", "ld64b", "LDADD", "ldadd", "ldaddb", "LDADDB", "ldaddh", "LDADDH", "LDAPR", "ldapr", "LDAPRB", "ldaprb",
            "ldaprh", "LDAPRH", "ldapur", "LDAPUR", "ldapurb", "LDAPURB", "ldapurh", "LDAPURH", "ldapursb", "LDAPURSB", "ldapursh", "LDAPURSH", "LDAPURSW", "ldapursw", "ldar", "LDAR", "LDARB", "ldarb", "LDARH", "ldarh", "LDATXR", "ldatxr", "ldaxp", "LDAXP", "ldaxr", "LDAXR", "LDAXRB", "ldaxrb", "ldaxrh", "LDAXRH",
            "LDCLR", "ldclr", "LDCLRB", "ldclrb", "LDCLRH", "ldclrh", "ldclrp", "LDCLRP", "ldeor", "LDEOR", "ldeorb", "LDEORB", "ldeorh", "LDEORH", "LDG", "ldg", "LDGM", "ldgm", "LDIAPP", "ldiapp", "ldlar", "LDLAR", "ldlarb", "LDLARB", "LDLARH", "ldlarh", "ldnp", "LDNP", "ldp", "LDP",
            "ldpsw", "LDPSW", "LDR", "ldr", "LDRAA", "ldraa", "ldrb", "LDRB", "ldrh", "LDRH", "ldrsb", "LDRSB", "ldrsh", "LDRSH", "ldrsw", "LDRSW", "ldset", "LDSET", "ldsetb", "LDSETB", "ldseth", "LDSETH", "ldsetp", "LDSETP", "LDSMAX", "ldsmax", "LDSMAXB", "ldsmaxb", "LDSMAXH", "ldsmaxh",
            "LDSMIN", "ldsmin", "ldsminb", "LDSMINB", "LDSMINH", "ldsminh", "LDTADD", "ldtadd", "ldtclr", "LDTCLR", "ldtnp", "LDTNP", "LDTP", "ldtp", "ldtr", "LDTR", "ldtrb", "LDTRB", "LDTRH", "ldtrh", "LDTRSB", "ldtrsb", "LDTRSH", "ldtrsh", "ldtrsw", "LDTRSW", "LDTSET", "ldtset", "LDTXR", "ldtxr",
            "ldumax", "LDUMAX", "LDUMAXB", "ldumaxb", "LDUMAXH", "ldumaxh", "LDUMIN", "ldumin", "lduminb", "LDUMINB", "lduminh", "LDUMINH", "LDUR", "ldur", "LDURB", "ldurb", "ldurh", "LDURH", "ldursb", "LDURSB", "ldursh", "LDURSH", "LDURSW", "ldursw", "LDXP", "ldxp", "ldxr", "LDXR", "ldxrb", "LDXRB",
            "ldxrh", "LDXRH", "LSL", "lsl", "lslv", "LSLV", "LSR", "lsr", "lsrv", "LSRV", "madd", "MADD", "maddpt", "MADDPT", "mneg", "MNEG", "MOV", "mov", "movk", "MOVK", "movn", "MOVN", "movz", "MOVZ", "MRRS", "mrrs", "MRS", "mrs", "msr", "MSR",
            "MSRR", "msrr", "MSUB", "msub", "MSUBPT", "msubpt", "mul", "MUL", "MVN", "mvn", "neg", "NEG", "NEGS", "negs", "NGC", "ngc", "ngcs", "NGCS", "nop", "NOP", "orn", "ORN", "orr", "ORR", "PACDA", "pacda", "pacdb", "PACDB", "PACGA", "pacga",
            "pacia", "PACIA", "PACIA171615", "pacia171615", "paciasppc", "PACIASPPC", "pacib", "PACIB", "PACIB171615", "pacib171615", "PACIBSPPC", "pacibsppc", "PACM", "pacm", "pacnbiasppc", "PACNBIASPPC", "pacnbibsppc", "PACNBIBSPPC", "prfm", "PRFM", "PRFUM", "prfum", "psb", "PSB", "PSSBB", "pssbb", "rbit", "RBIT", "RCWCAS", "rcwcas",
            "rcwcasp", "RCWCASP", "rcwclr", "RCWCLR", "rcwclrp", "RCWCLRP", "rcwscas", "RCWSCAS", "RCWSCASP", "rcwscasp", "RCWSCLR", "rcwsclr", "RCWSCLRP", "rcwsclrp", "RCWSET", "rcwset", "rcwsetp", "RCWSETP", "rcwsset", "RCWSSET", "RCWSSETP", "rcwssetp", "rcwsswp", "RCWSSWP", "rcwsswpp", "RCWSSWPP", "RCWSWP", "rcwswp", "RCWSWPP", "rcwswpp",
            "ret", "RET", "retaa", "RETAA", "RETAASPPC", "retaasppc", "RETAASPPCR", "retaasppcr", "rev", "REV", "rev16", "REV16", "rev32", "REV32", "REV64", "rev64", "RMIF", "rmif", "ROR", "ror", "rorv", "RORV", "RPRFM", "rprfm", "SB", "sb", "SBC", "sbc", "sbcs", "SBCS",
            "sbfiz", "SBFIZ", "SBFM", "sbfm", "sbfx", "SBFX", "sdiv", "SDIV", "SETF8", "setf8", "SETGP", "setgp", "SETGPN", "setgpn", "SETGPT", "setgpt", "setgptn", "SETGPTN", "setp", "SETP", "SETPN", "setpn", "SETPT", "setpt", "setptn", "SETPTN", "sev", "SEV", "sevl", "SEVL",
            "SMADDL", "smaddl", "SMAX", "smax", "smc", "SMC", "SMIN", "smin", "SMNEGL", "smnegl", "smstart", "SMSTART", "SMSTOP", "smstop", "SMSUBL", "smsubl", "SMULH", "smulh", "smull", "SMULL", "SSBB", "ssbb", "ST2G", "st2g", "st64b", "ST64B", "st64bv", "ST64BV", "st64bv0", "ST64BV0",
            "STADD", "stadd", "STADDB", "staddb", "STADDH", "staddh", "STCLR", "stclr", "STCLRB", "stclrb", "stclrh", "STCLRH", "steor", "STEOR", "steorb", "STEORB", "STEORH", "steorh", "stg", "STG", "stgm", "STGM", "stgp", "STGP", "stilp", "STILP", "stllr", "STLLR", "STLLRB", "stllrb",
            "stllrh", "STLLRH", "stlr", "STLR", "STLRB", "stlrb", "stlrh", "STLRH", "STLTXR", "stltxr", "STLUR", "stlur", "STLURB", "stlurb", "STLURH", "stlurh", "STLXP", "stlxp", "stlxr", "STLXR", "stlxrb", "STLXRB", "STLXRH", "stlxrh", "STNP", "stnp", "stp", "STP", "str", "STR",
            "STRB", "strb", "STRH", "strh", "STSET", "stset", "STSETB", "stsetb", "STSETH", "stseth", "stshh", "STSHH", "stsmax", "STSMAX", "stsmaxb", "STSMAXB", "stsmaxh", "STSMAXH", "stsmin", "STSMIN", "stsminb", "STSMINB", "stsminh", "STSMINH", "STTADD", "sttadd", "sttclr", "STTCLR", "STTNP", "sttnp",
            "STTP", "sttp", "sttr", "STTR", "sttrb", "STTRB", "sttrh", "STTRH", "STTSET", "sttset", "STTXR", "sttxr", "STUMAX", "stumax", "STUMAXB", "stumaxb", "stumaxh", "STUMAXH", "stumin", "STUMIN", "stuminb", "STUMINB", "stuminh", "STUMINH", "stur", "STUR", "sturb", "STURB", "sturh", "STURH",
            "stxp", "STXP", "STXR", "stxr", "STXRB", "stxrb", "stxrh", "STXRH", "stz2g", "STZ2G", "stzg", "STZG", "stzgm", "STZGM", "SUB", "sub", "SUBG", "subg", "SUBP", "subp", "subps", "SUBPS", "subpt", "SUBPT", "subs", "SUBS", "SVC", "svc", "SWP", "swp",
            "swpb", "SWPB", "swph", "SWPH", "swpp", "SWPP", "SWPT", "swpt", "sxtb", "SXTB", "SXTH", "sxth", "SXTW", "sxtw", "sys", "SYS", "sysl", "SYSL", "SYSP", "sysp", "tbnz", "TBNZ", "TBZ", "tbz", "tcancel", "TCANCEL", "tcommit", "TCOMMIT", "TLBI", "tlbi",
            "TLBIP", "tlbip", "trcit", "TRCIT", "TSB", "tsb", "TST", "tst", "tstart", "TSTART", "ttest", "TTEST", "ubfiz", "UBFIZ", "UBFM", "ubfm", "UBFX", "ubfx", "UDF", "udf", "UDIV", "udiv", "UMADDL", "umaddl", "umax", "UMAX", "UMIN", "umin", "UMNEGL", "umnegl",
            "umsubl", "UMSUBL", "UMULH", "umulh", "umull", "UMULL", "UXTB", "uxtb", "UXTH", "uxth", "WFE", "wfe", "WFET", "wfet", "wfi", "WFI", "wfit", "WFIT", "XAFLAG", "xaflag", "xpacd", "XPACD", "yield", "YIELD"
        ],

        // Registers taken from: https://github.com/qilingframework/qiling/blob/master/qiling/arch/arm64_const.py
        registers: [
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
            "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
            "sp", "pc", "lr", "cpacr_el1", "tpidr_el0", "pstate",
            "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9", "b10", "b11", "b12", "b13", "b14", "b15",
            "b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23", "b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31",
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
            "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31",
            "h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10", "h11", "h12", "h13", "h14", "h15",
            "h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23", "h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31",
            "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9", "q10", "q11", "q12", "q13", "q14", "q15",
            "q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23", "q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31",
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "s12", "s13", "s14", "s15",
            "s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31",
            "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15",
            "w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29", "w30",
            "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
        ],

        // Directives taken from:https://developer.arm.com/documentation/den0013/d/Introduction-to-Assembly-Language/Introduction-to-the-GNU-Assembler/Assembler-directives
        directives: [
            ".align", ".ascii", ".asciz", ".byte", ".hword", ".word", ".data", ".end", ".equ", ".extern", ".global", ".include", ".text"
        ],

        // Operators, symbols, and escapes from default monarch example.
        operators: [
            '[', ']', '#', '!', '~', '?', ':', '==', '<=', '>=', '!=',
            '&&', '||', '++', '--', '+', '-', '*', '/', '&', '|', '^', '%',
            '<<', '>>', '>>>', '+=', '-=', '*=', '/=', '&=', '|=', '^=',
            '%=', '<<=', '>>=', '>>>='
        ],
        symbols: /[=><!~?:&|+\-*\/\^%]+\./,
        escapes: /\\(?:[abfnrtv\\"']|x[0-9A-Fa-f]{1,4}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8})/,

        // The main tokenizer for our languages.
        tokenizer: {
            root: [
                // Instructions, directives, registers to color things differently.
                [/(\.)?[a-zA-Z_$][\w$]*(\d+)?/, {
                    cases: {
                        '@instructions': 'keyword',
                        '@directives': 'constant',
                        '@registers': 'number.hex',
                        '@default': 'identifier'
                    }
                }],
                // Numbers to handle possible negative and the leading # sign.
                [/(\#)?\d*\.\d+([eE][\-+]?\d+)?/, 'number'],
                [/(\#)?0[xX][0-9a-fA-F]+/, 'number'],
                [/(\#)?(-)?\d+/, 'number'],

                // Whitespace, delimiters, strings, characters from default monarch exammple.
                // whitespace
                { include: '@whitespace' },
                // delimiters and operators
                [/[{}()\[\]]/, '@brackets'],
                [/[<>](?!@symbols)/, '@brackets'],
                [/@symbols/, {
                    cases: {
                        '@operators': 'operator',
                        '@default': ''
                    }
                }],
                // delimiter: after number because of .\d floats
                [/[;,.]/, 'delimiter'],
                // strings
                [/"([^"\\]|\\.)*$/, 'string.invalid'],  // non-teminated string
                [/"/, { token: 'string.quote', bracket: '@open', next: '@string' }],
                // characters
                [/'[^\\']'/, 'string'],
                [/(')(@escapes)(')/, ['string', 'string.escape', 'string']],
                [/'/, 'string.invalid']
            ],
            // Comments, strings, whitespace taken from default monarch example.
            comment: [
                [/[^\/*]+/, 'comment'],
                [/\/\*/, 'comment', '@push'],    // nested comment
                ["\\*/", 'comment', '@pop'],
                [/[\/*]/, 'comment']
            ],
            string: [
                [/[^\\"]+/, 'string'],
                [/@escapes/, 'string.escape'],
                [/\\./, 'string.escape.invalid'],
                [/"/, { token: 'string.quote', bracket: '@close', next: '@pop' }]
            ],
            whitespace: [
                [/[ \t\r\n]+/, 'white'],
                [/\/\*/, 'comment', '@comment'],
                [/\/\/.*$/, 'comment']
            ]
        }
    };
}