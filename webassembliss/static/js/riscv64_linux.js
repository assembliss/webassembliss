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
        monaco.languages.register({ id: 'riscv64' });
        monaco.languages.setMonarchTokensProvider('riscv64', getSyntaxHighlighting());
        window.editor = monaco.editor.create(document.getElementById('monaco-container'), {
            // Change "value" to upload files
            value: default_code.join('\n'),
            language: 'riscv64',
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
    // Create a floating message with a running message.
    modal = showLoading('Running your code', 'Please wait for the emulation to finish.', 'Running...');
    // Why not remove highlights at the start of runCode()?
    removeAllHighlights();
    window.editor.updateOptions({ readOnly: true });
    // This source code line should be in a for loop such that it goes through each tab and gets the source of each.
    let source_code = getSource();
    let user_input = document.getElementById("inputBox").value;
    let registers = document.getElementById("regsToShow").value;
    document.getElementById("runStatus").innerHTML = "⏳";
    console.log(JSON.stringify({
        source_code: source_code,
        user_input: user_input,
        cl_args: window.cl_args,
        registers: registers
    }));
    console.log("here1");
    fetch('/riscv64_linux/run/', {
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
            console.log("here2");
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
            console.log("here3");
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
    modal = showLoading('Debugger', 'Please wait for a debugging session to be created.', 'Starting...');
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
    fetch('/riscv64_linux/debug/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ source_code: source_code, user_input: user_input, cl_args: window.cl_args, "debug": { "start": true }, registers: registers }),
    }).then(response => response.json())
        .then(data => {
            updateDebuggingInfo(data);
        }).then(() =>
            // TODO: make sure this runs even if the fetch above fails.
            hideLoading(modal)
        );
}

function debuggerCommand(commands, modal) {
    let source_code = getSource();
    let user_input = document.getElementById("inputBox").value;
    let registers = document.getElementById("regsToShow").value;
    fetch('/riscv64_linux/debug/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ source_code: source_code, user_input: user_input, "debug": commands, registers: registers }),
    }).then(response => response.json())
        .then(data => {
            updateDebuggingInfo(data);
        }).then(() =>
            // TODO: make sure this runs even if the fetch above fails.
            hideLoading(modal)
        );
}

function continueDebug() {
    modal = showLoading('Debugger', 'Please wait while we continue until the next breakpoint.', 'Continuing...');
    debuggerCommand({ "command": 1 }, modal);
}

function stepDebug() {
    modal = showLoading('Debugger', 'Please wait while we step over this instruction.', 'Stepping...');
    debuggerCommand({ "command": 2 }, modal);
}

function toggleBreakpoint() {
    // TODO: handle multiple source files eventually.
    let lineNum = prompt("Line number to toggle breakpoint:", "");
    if (lineNum) {
        modal = showLoading('Debugger', 'Please wait while we toggle a breakpoint on line ' + lineNum, 'Toggling breakpoint...');
        lineNum = parseInt(lineNum);
        debuggerCommand({ "command": 3, "breakpoint_line": lineNum }, modal);
    }
}

function stopDebugger() {
    // Stop debugging session.
    debuggerCommand({ "command": 4 }, null);
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
        // First draft of a RISC-V 64 assembly syntax.
        instructions: [
            // Instructions taken from: https://marks.page/riscv/
            "ADD", "add", "ADDI", "addi", "ADDIW", "addiw", "ADDW", "addw", "AND", "and",
            "ANDI", "andi", "AUIPC", "auipc", "BEQ", "beq", "BGE", "bge", "BGEU", "bgeu",
            "BLT", "blt", "BLTU", "bltu", "BNE", "bne", "DIV", "div", "DIVU", "divu",
            "DIVUW", "divuw", "DIVW", "divw", "FENCE", "fence", "FENCE.I", "fence.i", "JAL", "jal",
            "JALR", "jalr", "LB", "lb", "LBU", "lbu", "LD", "ld", "LH", "lh", "LHU", "lhu",
            "LUI", "lui", "LW", "lw", "LWU", "lwu", "MUL", "mul", "MULH", "mulh", "MULHSU", "mulhsu",
            "MULHU", "mulhu", "MULW", "mulw", "OR", "or", "ORI", "ori", "REM", "rem", "REMU", "remu",
            "REMUW", "remuw", "REMW", "remw", "SB", "sb", "SD", "sd", "SH", "sh", "SLL", "sll",
            "SLLI", "slli", "SLLI", "slli", "SLLIW", "slliw", "SLLW", "sllw", "SLT", "slt",
            "SLTI", "slti", "SLTIU", "sltiu", "SLTU", "sltu", "SRA", "sra", "SRAI", "srai",
            "SRAI", "srai", "SRAIW", "sraiw", "SRAW", "sraw", "SRL", "srl", "SRLI", "srli",
            "SRLI", "srli", "SRLIW", "srliw", "SRLW", "srlw", "SUB", "sub", "SUBW", "subw",
            "SW", "sw", "XOR", "xor", "XORI", "xori",
            // Pseudo-instructions taken from: https://marks.page/riscv/asm
            "BEQZ", "beqz", "BGEZ", "bgez", "BGT", "bgt", "BGTU", "bgtu", "BGTZ", "bgtz",
            "BLE", "ble", "BLEU", "bleu", "BLEZ", "blez", "BLTZ", "bltz", "BNEZ", "bnez",
            "FABS.D", "fabs.d", "FABS.S", "fabs.s", "FMV.D", "fmv.d", "FMV.S", "fmv.s",
            "FNEG.D", "fneg.d", "FNEG.S", "fneg.s", "J", "j", "JR", "jr", "LA", "la",
            "LI", "li", "MV", "mv", "NEG", "neg", "NEGW", "negw", "NOP", "nop", "NOT", "not",
            "RET", "ret", "SEQZ", "seqz", "SEXT.W", "sext.w", "SGTZ", "sgtz", "SLTZ", "sltz",
            "SNEZ", "snez",
            // Syscall
            "ECALL", "ecall"
        ],

        // Registers taken from: https://github.com/qilingframework/qiling/blob/master/qiling/arch/riscv_const.py
        registers: [
            "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "fp",
            "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3",
            "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5",
            "t6", "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0",
            "fs1", "fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "fs2",
            "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9", "fs10", "fs11", "ft8",
            "ft9", "ft10", "ft11", "pc", "x0", "x1", "x2", "x3", "x4", "x5", "x6",
            "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
            "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28",
            "x29", "x30", "x31"
        ],

        // Directives taken from: https://marks.page/riscv/asm
        directives: [
            ".text", ".data", ".rodata", ".bss", ".2byte", ".4byte", ".8byte", ".half", ".word",
            ".dword", ".byte", ".dtpreldword", ".dtprelword", ".sleb128", ".uleb128", ".asciz",
            ".string", ".incbin", ".zero", ".align", ".balign", ".p2align", ".globl", ".local",
            ".equ", ".text", ".data", ".rodata", ".bss", ".comm", ".common", ".section", ".option",
            ".macro", ".endm", ".file", ".ident", ".size", ".type", ".ascii", ".global"
        ],

        // Operators, symbols, and escapes from default monarch example.
        operators: [
            '[', ']', '!', '~', '?', ':', '==', '<=', '>=', '!=',
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
                // Numbers to handle possible negative.
                [/\d*\.\d+([eE][\-+]?\d+)?/, 'number'],
                [/0[xX][0-9a-fA-F]+/, 'number'],
                [/(-)?\d+/, 'number'],

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
                [/\#.*$/, 'comment'],
            ],
            string: [
                [/[^\\"]+/, 'string'],
                [/@escapes/, 'string.escape'],
                [/\\./, 'string.escape.invalid'],
                [/"/, { token: 'string.quote', bracket: '@close', next: '@pop' }]
            ],
            whitespace: [
                [/[ \t\r\n]+/, 'white'],
                [/\#.*$/, 'comment']
            ]
        }
    };
}