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
        if (!this.size) {
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
        }).then(() => {
            // Check if we should delete the default tab from html template.
            if (!('Tab1' in this.tabs)) {
                // If we don't have contents saved for it, delete it.
                closeTab(1);
            }
        });
    }
}

function uploadFile(callback) {
    let fileUploadEl = document.createElement('input');
    fileUploadEl.type = 'file';
    fileUploadEl.onchange = e => callback(e.target);
    fileUploadEl.click();
}

function importCode(fileUploadTarget) {
    let file = fileUploadTarget.files[0];

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

function showDisplayCheckboxes(type) {
    // Show all checkboxes.
    Array.from(document.getElementsByClassName(`${type}-display-check`)).forEach((el) => {
        el.removeAttribute("hidden");
    });
    // Show all hidden rows.
    Array.from(document.getElementsByClassName(`${type}-display-hide`)).forEach((el) => {
        el.removeAttribute("hidden");
    });
    // Show changes button.
    document.getElementById(`${type}ShowAll`).removeAttribute("hidden");
    document.getElementById(`${type}HideAll`).removeAttribute("hidden");
    document.getElementById(`${type}ShowAccept`).removeAttribute("hidden");
    // Hide edit selection button.
    document.getElementById(`${type}ShowSelect`).setAttribute("hidden", "hidden");
}

function hideDisplayCheckboxes(type) {
    // Hide all checkboxes.
    Array.from(document.getElementsByClassName(`${type}-display-check`)).forEach((el) => {
        el.setAttribute("hidden", "hidden");
    });
    // Hide all hidden rows.
    Array.from(document.getElementsByClassName(`${type}-display-hide`)).forEach((el) => {
        el.setAttribute("hidden", "hidden");
    });
    // Hide changes button.
    document.getElementById(`${type}ShowAll`).setAttribute("hidden", "hidden");
    document.getElementById(`${type}HideAll`).setAttribute("hidden", "hidden");
    document.getElementById(`${type}ShowAccept`).setAttribute("hidden", "hidden");
    // Show edit selection button.
    document.getElementById(`${type}ShowSelect`).removeAttribute("hidden");
}

function showAllRows(type) {
    // Checks all display checkboxes for the given type and call its toggle function.
    Array.from(document.getElementsByClassName(`${type}-display-check`)).forEach((el) => {
        el.checked = true;
        el.onclick.apply(el);
    });
}

function hideAllRows(type) {
    // Unchecks all display checkboxes for the given type and call its toggle function.
    Array.from(document.getElementsByClassName(`${type}-display-check`)).forEach((el) => {
        el.checked = false;
        el.onclick.apply(el);
    });
}

function toggleRowDisplay(rowID, type) {
    // Check the row exists.
    let rowEl = document.getElementById(rowID);
    if (!rowEl) {
        return;
    }

    // Check the row has a checkbox.
    let checkEl = document.getElementById(`${rowID}-check`);
    if (!checkEl) {
        return;
    }

    let visibilityClass = `${type}-display-hide`
    if (!checkEl.checked) {
        rowEl.classList.add(visibilityClass);
    } else {
        rowEl.classList.remove(visibilityClass);
    }
}

function populateRegisterTable(registers) {
    // Create a starting values with enough zeros for the number of bits given.
    let starting_value = intToHexBytes(0, ARCH_NUM_BITS / 8, "&nbsp;&nbsp;");
    // Create register rows in the template table.
    let tableRows = document.getElementById("regValuesTBody");
    for (const reg of registers) {
        // Create new row and cells.
        let newTr = document.createElement('tr');
        let regName = document.createElement('td');
        let regValue = document.createElement('td');
        // Assign IDs so we can modify them later.
        newTr.id = `regValueRow-${reg}`;
        regName.id = `regNameCell-${reg}`;
        regValue.id = `regValueCell-${reg}`;
        // Assign a class to rows so we can access all of them later.
        newTr.classList.add("regValueRows");
        newTr.classList.add("register-row-displayed");
        regValue.classList.add("regValueCells");
        // Assign the appropriate values.
        regName.innerHTML = `<input class="form-check-input register-display-check" type="checkbox" value="" id="${newTr.id}-check" onclick='toggleRowDisplay("${newTr.id}", "register")' hidden checked> ${reg}`;
        regValue.innerHTML = starting_value;
        // Add the new cells to our new row.
        newTr.appendChild(regName);
        newTr.appendChild(regValue);
        // Add the new row to the template table.
        tableRows.appendChild(newTr);
    }
}

function clearRegTable() {
    // Mark all rows as not changed.
    Array.from(document.getElementsByClassName("register-value-updated")).forEach((el) => {
        el.classList.remove("table-active");
        el.classList.remove("register-value-updated");
    });
    // Set all values as zero.
    Array.from(document.getElementsByClassName("regValueCells")).forEach((el) => {
        el.innerHTML = intToHexBytes(0, ARCH_NUM_BITS / 8, "&nbsp;&nbsp;");
    });
}

function updateRegisterTable(reg_value_map) {
    // Mark all rows as not changed.
    Array.from(document.getElementsByClassName("register-value-updated")).forEach((el) => {
        el.classList.remove("table-active");
        el.classList.remove("register-value-updated");
    });

    // If there are no values, do not update anything.
    if (!reg_value_map) {
        return;
    }

    // Go through the register values we received to update the changed ones.
    for (const [reg, val] of Object.entries(reg_value_map)) {
        let formattedValue = intToHexBytes(val, ARCH_NUM_BITS / 8, "&nbsp;&nbsp;");
        let regValueCell = document.getElementById(`regValueCell-${reg}`);
        if (regValueCell.innerHTML == formattedValue) {
            // If the value has NOT changed, go to next element.
            continue;
        }
        // Update the value with the new one we received.
        regValueCell.innerHTML = formattedValue;
        // Mark this row as changed.
        document.getElementById(`regValueRow-${reg}`).classList.add("table-active");
        document.getElementById(`regValueRow-${reg}`).classList.add("register-value-updated");
    };
}

function parseRegisterValues(emulation_reg_values) {
    // This method extracts the first value of the array of values in the map.
    // For the runCode method, this removes the boolean that indicates if this value has changed or not.
    // TODO: remove the bool from the source; make base_emulation stop keeping track of registers that have changed.

    if (!emulation_reg_values) {
        // If nothing given, simply return.
        return;
    }

    // Creates a new object so we can map the values.
    let reg_map = {};
    for (const [reg, val] of Object.entries(emulation_reg_values)) {
        reg_map[reg] = val[0];
    }
    return reg_map;
}

function parseRegisterDeltaMap(reg_delta) {
    // This functions creates a register map for the tracing deltas.
    // For any registers that do not have values, it adds a zero for it.

    if (!reg_delta) {
        // If nothing given, simply return.
        return;
    }

    // Creates a new object so we can map the values.
    let reg_map = {};
    for (const [reg, values] of Object.entries(reg_delta)) {
        if (values.length == 0) {
            reg_map[reg] = 0;
        } else {
            reg_map[reg] = values[values.length - 1];
        }
    }
    return reg_map;
}

function mapMemoryTableRowsIndices() {
    // Go through the table of memory values and creates an array with all the addresses in it.
    let indices = [];
    Array.from(document.getElementsByClassName("memory-table-address")).forEach((el) => {
        // Convert the hex address to decimal.
        indices.push(el.intMemAddr);
    });
    return indices;
}

function insertMemoryAddressRow(address, index) {
    let tableRows = document.getElementById("memValuesTBody");
    // Create new a row to hold all the new cells.
    let newTr = document.createElement('tr');
    let hexAddr = intToHexBytes(parseInt(address));
    newTr.id = `memValueRow-${hexAddr}`;
    // Create a new node for the address value.
    let addrCell = document.createElement('td');
    addrCell.id = `memAddrCell-${hexAddr}`;
    addrCell.classList.add('memory-table-address');
    addrCell.intMemAddr = address;
    addrCell.innerHTML = `<input class="form-check-input memory-display-check" type="checkbox" value="" id="${newTr.id}-check" onclick='toggleRowDisplay("${newTr.id}", "memory")' hidden checked> ${hexAddr}`;
    newTr.appendChild(addrCell);
    // Add one cell for each byte of the 16-byte memory chunk.
    for (let i = 0; i < 16; i++) {
        let hexOffset = intToHexBytes(i);
        let memValueCell = document.createElement('td');
        memValueCell.id = `memValueCell-${hexAddr}+${hexOffset}`;
        memValueCell.innerHTML = "00";
        memValueCell.intValue = 0;
        memValueCell.classList.add('memory-table-value');
        newTr.appendChild(memValueCell);
    }
    // Add the new row to the table.
    if (index >= tableRows.children.length) {
        tableRows.appendChild(newTr);
    } else {
        tableRows.insertBefore(newTr, tableRows.children[index])
    }
}

function hexBytetoASCIIChar(hexByte) {
    return String.fromCharCode(parseInt(hexByte, 16));
}

function ASCIICharToHexByte(char) {
    return intToHexBytes(char.charCodeAt(0), 1);
}

function updateMemoryTable(mem_values) {
    // Mark all memory values as not changed.
    Array.from(document.getElementsByClassName("memory-value-updated")).forEach((el) => {
        el.classList.remove("table-active");
        el.classList.remove("memory-value-updated");
    });

    // Go over the memory addresses we received and add any new rows to the table.
    let currentAddresses = mapMemoryTableRowsIndices();
    let sortedNewAddresses = Object.keys(mem_values).sort();
    let curIdx = 0;
    let newIdx = 0;
    while (newIdx < sortedNewAddresses.length) {
        if (curIdx >= currentAddresses.length) {
            // We have reached the end of the existing addresses list; insert at the end.
            currentAddresses.splice(curIdx, 0, sortedNewAddresses[newIdx]);
            insertMemoryAddressRow(sortedNewAddresses[newIdx], curIdx);
            curIdx++;
            newIdx++;
        } else if (currentAddresses[curIdx] == sortedNewAddresses[newIdx]) {
            // Element already in the list, skip.
            curIdx++;
            newIdx++;
        } else if (currentAddresses[curIdx] < sortedNewAddresses[newIdx]) {
            // New address is larger than the one in current index, skip to next position to check.
            curIdx++;
        } else {
            // New address should be included in this position.
            currentAddresses.splice(curIdx, 0, sortedNewAddresses[newIdx]);
            insertMemoryAddressRow(sortedNewAddresses[newIdx], curIdx);
            curIdx++;
            newIdx++;
        }
    }

    // Update all the memory values.
    for (const [address, chunk] of Object.entries(mem_values)) {
        let hexAddr = intToHexBytes(parseInt(address));
        let i = 0;
        while (i < 16) {
            let hexOffset = intToHexBytes(i);
            let memValueCell = document.getElementById(`memValueCell-${hexAddr}+${hexOffset}`);
            let newMemValue = (i >= chunk.length) ? 0 : chunk[i];
            if (memValueCell.intValue != newMemValue) {
                memValueCell.intValue = newMemValue;
                let newHexMemValue = intToHexBytes(newMemValue, 1);
                // Update the table if the value has changed.
                memValueCell.innerText = newHexMemValue;
                memValueCell.classList.add("table-active");
                memValueCell.classList.add("memory-value-updated");
                if ((newMemValue > 32) && (newMemValue < 127)) {
                    // If this is a printable value in ASCII, mark the cell.
                    memValueCell.classList.add("ascii-printable-memory-value");
                    if (document.getElementById('asciiMemorySwitch').checked) {
                        // If the user wants to see the ASCII value, convert it.
                        memValueCell.classList.add("memory-value-in-ascii");
                        memValueCell.innerText = hexBytetoASCIIChar(newHexMemValue);
                    }
                } else {
                    // If it is not printable, remove the mark in case it was there
                    memValueCell.classList.remove("ascii-printable-memory-value");
                }
            }
            i++;
        }
    }
}

function parseRunMemoryReport(mem_report) {
    // This functions creates a memory map by parsing the memory report given by base_emulation.
    // TODO: modify base_emulation to output something similar to the mem_delta that we use in the trace proto.

    if (!mem_report) {
        // If nothing given, simply return.
        return;
    }

    // Creates a new object so we can map the values.
    let mem_map = {};

    // The memory report is a string on this format:
    // "[Hex Address]: 'H' 'E' 'Y' 04 05 06 07 08 09 0A 0B 0C 0D 0E 0E"
    for (const line of mem_report.split("\n").slice(1)) {
        // Split line into address and values.
        let tokens = line.split(":");
        if (tokens.length < 2) {
            // Ignore lines that have too few elements.
            continue;
        }

        // Separate the byte values for this chunk.
        let byteValues = tokens[1].split(" ").filter((item) => item);
        if (byteValues.length != 16) {
            // Ignore lines that do not have 16 byte values for that address.
            continue;
        }

        // Parse the hex address into decimal so we can compare it with the table rows.
        let hexAddress = tokens[0].trim();
        let intDecimalAddress = parseInt(hexAddress, 16);

        // Parse the byte values into decimals so we can parse them for the table.
        let bytesArray = [];
        let nonEmptyAddress = false;
        for (const val of byteValues) {
            let trimmedVal = val.trim();
            nonEmptyAddress |= trimmedVal != "00";
            if (trimmedVal.length == 2) {
                // Parse raw byte (value should be in "XY" format).
                bytesArray.push(parseInt(trimmedVal, 16));
            } else {
                // Parse ASCII char (value should be in "'?'" format).
                bytesArray.push(trimmedVal.charCodeAt(1));
            }
        }

        // Assign the byte values to the memory address.
        if (nonEmptyAddress) {
            mem_map[intDecimalAddress] = bytesArray;
        }
    }

    return mem_map;
}

function parseMemoryDeltaMap(mem_delta) {
    // This functions creates a memory map for the memory value deltas.

    if (!mem_delta) {
        // If nothing given, simply return.
        return;
    }

    // Creates a new object so we can map the values.
    let mem_map = {};
    for (const [reg, values] of Object.entries(mem_delta)) {
        if (values.length == 0) {
            mem_map[reg] = 0;
        } else {
            mem_map[reg] = values[values.length - 1];
        }
    }
    return mem_map;
}

function convertMemoryValuesToASCII() {
    Array.from(document.getElementsByClassName("ascii-printable-memory-value")).forEach((el) => {
        if (el.classList.contains("memory-value-in-ascii")) {
            // Value already in ascii, skip it.
            return;
        }
        el.classList.add("memory-value-in-ascii");
        el.innerText = hexBytetoASCIIChar(el.textContent);
    });
}

function convertMemoryValuesToRawBytes() {
    Array.from(document.getElementsByClassName("ascii-printable-memory-value")).forEach((el) => {
        if (!el.classList.contains("memory-value-in-ascii")) {
            // Value already NOT in ascii, skip it.
            return;
        }
        el.classList.remove("memory-value-in-ascii");
        el.innerText = ASCIICharToHexByte(el.textContent);
    });
}

function toggleASCIIMemory() {
    if (document.getElementById('asciiMemorySwitch').checked) {
        convertMemoryValuesToASCII();
    } else {
        convertMemoryValuesToRawBytes();
    }
}

function clearMemoryTable() {
    // Delete all rows containing memory values.
    document.getElementById("memValuesTBody").innerHTML = "";
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
    window.lastRunInfo = null;
    document.getElementById("downloadButton").disabled = true;
    clearRegTable();
    clearMemoryTable();
}

function detectAndHighlightErrors() {
    // Find errors, parse through
    let as_err = parseEmulationJSON("as_err");
    let lines = as_err.split("\n").map(line => {

        // TODO: Update regex to use this format: ".../userprograms/(filename):(linenum): Error: (message)"
        // Then, you would have to make sure that filename matches the active tab to highlight these errors.
        // Probably keep track of error messages per file, so we can show the existing errors on different tabs.
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
            // Update the memory table with new values.
            updateMemoryTable(parseRunMemoryReport(data.memory));
            // Update the register table with new values.
            updateRegisterTable(parseRegisterValues(data.info_obj.registers), data.info_obj.reg_num_bits);
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
    // Show the trace menu information and disable code action buttons.
    document.getElementById("statusFlagsDisplay").classList.remove("collapse");
    document.getElementById("traceMenuDiv").classList.remove("collapse");
    Array.from(document.getElementsByClassName("codeActionBtn")).forEach((el) => {
        el.disabled = true;
    });
    // Create a floating message with a running message.
    modal = showLoading('Running your code', 'Please wait for the emulation to finish.', 'Running...');
    removeAllHighlights();
    document.getElementById("traceStart").disabled = true;
    document.getElementById("traceStop").disabled = false;
    window.editor.updateOptions({ readOnly: true });
    // This source code line should be in a for loop such that it goes through each tab and gets the source of each.
    localTabStorage.saveCurrentTab();
    let user_input = document.getElementById("inputBox").value;
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

    // Update the register table with new values.
    updateRegisterTable(parseRegisterDeltaMap(currentTraceStep.reg_changes), window.lastTrace.arch_num_bits);

    // Update the memory table with new values.
    updateMemoryTable(parseMemoryDeltaMap(currentTraceStep.mem_changes));

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

    // Hide the tracing menu and enable code action buttons.
    document.getElementById("traceMenuDiv").classList.add("collapse");
    document.getElementById("statusFlagsDisplay").classList.add("collapse");
    Array.from(document.getElementsByClassName("codeActionBtn")).forEach((el) => {
        el.disabled = false;
    });

    // Make editor writeable again.
    window.editor.updateOptions({ readOnly: false });
}
