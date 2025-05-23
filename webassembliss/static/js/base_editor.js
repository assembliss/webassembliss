const WAITING_SYMBOL = "⭕";
const OK_SYMBOL = "✅";
const ERROR_SYMBOL = "❌";
window.decorations = null;
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
    name: document.querySelector('.activeTabBtn:not([value="X"])').value,
    change(target) {
        this.name = target;
    }
};

function downloadCurrentTab() {
    let currentTab_filename = document.getElementById(`tab${currentTab.name}Btn`).value;
    download_file(currentTab_filename, getSource(), "text/plain");
}

function downloadWorkspaceJSON() {
    download_file("webassembliss_workspace.json", localFileStorage.exportToJSON(), "application/json");
}

function openTab(tabName) {

    // Goes through all tab titles, creates a element list of all inputs that do not end in "X" or "Rename". 
    const tabTitles = document.querySelectorAll('#tabsDiv input:not([id$="X"]):not([id$="Rename"])');
    // To avoid naming conflictions, tabTitles is a list of input elements.

    let filenameTooltip = null;

    let currentTabBtn = document.getElementById(`tab${currentTab.name}Btn`);


    // Set up data save
    let newTabBtn = document.getElementById(`tab${tabName}Btn`);

    if (currentTab.name == tabName && !document.getElementById(`tab${currentTab.name}Rename`)) {
        // TODO: Extract all this logic into a separate function we can call independently from openTab.
        // TODO(BUG): If user enters renaming functionality, they cannot exit and keep the original name (at least on firefox).
        // TODO(BUG): If user renames a tab, the button's id does not update automatically (at least on firefox).
        // Tab renaming functionality
        // There might need to exist some sort of character check to make sure the filename isn't something illegal?
        // Though it seems that even with special characters, saving files works fine. Not sure if this will matter somewhere else though.
        let renameTextBox = document.createElement('input');
        renameTextBox.type = "text";
        renameTextBox.className = "activeTabBtn";
        renameTextBox.id = `tab${tabName}Rename`;
        renameTextBox.value = currentTabBtn.value;
        renameTextBox.setAttribute("autocomplete", "off");

        currentTabBtn.replaceWith(renameTextBox);
        renameTextBox.focus();
        renameTextBox.select();

        // Prevent redundant running of replaceTabRename() by carefully running only 1 instance of the function.
        let lastKeydownTimestamp = 0;

        // Only run if "Enter" wasn't pressed in the last 50ms.
        document.getElementById(`tab${currentTab.name}Rename`).addEventListener("blur", function () {
            if (Date.now() - lastKeydownTimestamp > 50) {
                replaceTabRename();
            }
        });
        document.getElementById(`tab${currentTab.name}Rename`).addEventListener("keydown", function (event) {
            if (event.key === "Enter") {
                lastKeydownTimestamp = Date.now();
                replaceTabRename();
            }
        });

        function replaceTabRename() {

            if (filenameTooltip) {
                try {
                    filenameTooltip.hide();
                    filenameTooltip.dispose();
                } catch (error) {
                    console.error("Error disposing tooltip:", error);
                }
                filenameTooltip = null;
            }

            let newTabName = renameTextBox.value;
            // Validate new tab names
            // Allowed file extensions in the editor
            const extensions = ['.S', '.s'];
            let tabNameHasExtension = false;
            let tabNameIsDuplicate = false;
            let tabNameIsExtension = false;

            // Make sure newTabName ends with a file extension.
            for (const extension of extensions) {
                if (newTabName.endsWith(extension)) {
                    tabNameHasExtension = true;
                    break;
                }
            }
            // Check if newTabName is just an extension.
            for (const extension of extensions) {
                if (newTabName == extension) {
                    tabNameIsExtension = true;
                    break;
                }
            }

            // Make sure newTabName is unique (not the same value as another existing tab name).
            for (const tabTitle of tabTitles) {
                if (tabTitle.value == newTabName) {
                    tabNameIsDuplicate = true;
                    break;
                }
            }


            // If valid newTabName...
            if (tabNameHasExtension && !tabNameIsDuplicate && !tabNameIsExtension) {
                let renamedTab = document.createElement('input');
                renamedTab.type = "button";
                renamedTab.className = "activeTabBtn";
                renamedTab.id = `tab${currentTab.name}Btn`;
                renamedTab.value = newTabName;
                renamedTab.onclick = () => openTab(tabName);

                renameTextBox.replaceWith(renamedTab);



                // Update python side directly.
                if (currentTabBtn.value != newTabName) {
                    localFileStorage.renameTab(currentTabBtn.value, newTabName);
                }

            } else { // if invalid newTabName
                renameTextBox.setAttribute("data-bs-toggle", "tooltip");
                renameTextBox.setAttribute("data-bs-placement", "top");

                if (tabNameIsDuplicate) {
                    renameTextBox.setAttribute("data-bs-title", "Another tab already has this name. File names must be unique!");
                } else if (!tabNameHasExtension) {
                    renameTextBox.setAttribute("data-bs-title", "File name must contain a valid file extension!");
                } else if (tabNameIsExtension) {
                    renameTextBox.setAttribute("data-bs-title", "File must have a name beyond an extension!");
                }

                filenameTooltip = new bootstrap.Tooltip(renameTextBox);
                filenameTooltip.show();
                renameTextBox.focus();

                renameTextBox.removeEventListener("input", handleInput);
                renameTextBox.addEventListener("input", handleInput);

                function handleInput() {
                    if (filenameTooltip) {
                        filenameTooltip.hide();
                        filenameTooltip.dispose();
                        filenameTooltip = null;
                    }
                    renameTextBox.removeEventListener("input", handleInput);
                }
            }
        }

    } else {
        // Save current tab contents
        localFileStorage.saveCurrentTab();

        // Update button styles.
        let currentTabBtn = document.getElementById(`tab${currentTab.name}Btn`);
        let currentTabBtnX = document.getElementById(`tab${currentTab.name}BtnX`);
        let newTabBtn = document.getElementById(`tab${tabName}Btn`);
        let newTabBtnX = document.getElementById(`tab${tabName}BtnX`);
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
        let localNewContents = localFileStorage.getTab(newTab_filename);
        window.editor.setValue(localNewContents);

        // Update active tab number.
        currentTab.change(tabName);

        // Update highlights.
        showTabHighlights();
    }
}

/* TODO: Before closing a tab, a check should occur to make sure the file was saved or otherwise not completely deleted. 
 * TODO: Prevent last tab from being closed.
 */
function closeTab(tabName, noConfirm) {
    if (currentTab.name == tabName) {
        // TODO: if current tab is open when this function is ran, swap to another tab.
        // Meanwhile, we just prevent that from happening... this is probably fine behavior.
        return;
    }

    if (!noConfirm && !confirm(`Are you sure you want to delete '${tabName}'?`)) {
        return;
    }

    let toBeClosed_filename = document.getElementById(`tab${tabName}Btn`).value;
    // Delete tab locally.
    localFileStorage.deleteTab(toBeClosed_filename);
    // Remove tab buttons.
    document.getElementById(`tab${tabName}Btn`).remove();
    document.getElementById(`tab${tabName}BtnX`).remove();
}

function getCurrentTabName() {
    return currentTab.name;
}

function getTabNumber(tabName) {
    return parseInt(tabName.slice(3), 10);
}

function getTabButtonByName(tabName) {
    return document.getElementById(`tab${tabName}Btn`);
}

const tabs = {
    count: document.getElementsByClassName("tabBtn").length + 1,
    addTab() {
        let tabList = document.querySelectorAll('#tabsDiv input:not([id$="X"])');
        let unnamedTabExists = false;

        for (const tab of tabList) {
            // if we add more available extensions, this will need to be changed
            if (tab.value.startsWith("NewTab") && !(tab.value.endsWith(".S") || tab.value.endsWith(".s"))) {
                unnamedTabExists = true;
                break;
            }
        }

        if (!unnamedTabExists) {
            // New Tabs are now named uniquely.
            let newName = "NewTab" + this.count;
            this.createTabButton(newName);
            openTab(newName);
            setTimeout(() => { openTab(newName); }, 100); // This setTimeout openTab() call will open the rename immediately after creating a new tab. 
            // This time may cause issues if openTab() takes too long to fetch. How can I do .then here?
        }
    },
    createTabButton(newName) {
        let newTab = document.createElement("input");
        newTab.type = "button";
        newTab.className = "tabBtn";
        newTab.value = newName;
        newTab.id = `tab${newName}Btn`;
        newTab.onclick = () => openTab(newName);

        let newTabX = document.createElement("input");
        newTabX.type = "button";
        newTabX.className = "tabBtnX";
        newTabX.value = "x";
        newTabX.id = `tab${newName}BtnX`;
        newTabX.onclick = () => closeTab(newName);

        document.getElementById("tabsDiv").insertBefore(newTab, document.getElementById("addTabBtn"));
        document.getElementById("tabsDiv").insertBefore(newTabX, document.getElementById("addTabBtn"));
        this.count++;
    }
};

const localFileStorage = {
    archID: null,
    tabs: null,
    objs: null,
    size: null,
    txtData: null,
    binData: null,

    getTab(filename) {
        // Get the file contents stored; if there are none, use an empty string.
        return (filename in this.tabs) ? this.tabs[filename] : "";
    },

    saveTab(filename, contents) {
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
        this.storeTabs();
    },

    saveCurrentTab() {
        let currentTabBtn = document.getElementById(`tab${currentTab.name}Btn`);
        let currentTab_filename = currentTabBtn.value;
        let currentTab_contents = window.editor.getValue();
        this.saveTab(currentTab_filename, currentTab_contents);
    },

    renameTab(oldFilename, newFilename) {
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
        this.storeTabs();
    },

    deleteTab(filename) {
        if (filename in this.tabs) {
            contents = this.tabs[filename];
            this.size -= filename.length + contents.length;
            delete this.tabs[filename];
            // Update the tabs in localStorage.
            this.storeTabs();
        }
    },

    storeTabs() {
        localStorage.setItem(`tabs-${this.archID}`, JSON.stringify(this.tabs));
    },

    storeObjs() {
        localStorage.setItem(`objs-${this.archID}`, JSON.stringify(this.objs));
    },

    storeTxtData() {
        localStorage.setItem(`txtData-${this.archID}`, JSON.stringify(this.txtData));
    },

    storeBinData() {
        localStorage.setItem(`binData-${this.archID}`, JSON.stringify(this.binData));
    },

    storeAll() {
        this.storeTabs();
        this.storeObjs();
        this.storeTxtData();
        this.storeBinData();
    },

    loadFromStorage() {
        // Update the architecture.
        this.archID = ARCH_ID;
        // Load saved tabs from localStorage.
        let savedTabs = localStorage.getItem(`tabs-${this.archID}`);
        this.tabs = savedTabs ? JSON.parse(savedTabs) : {};
        // Load saved obj files from localStorage.
        let savedObjs = localStorage.getItem(`objs-${this.archID}`);
        this.objs = savedObjs ? JSON.parse(savedObjs) : {};
        // Load .txt data files from localStorage.
        let savedTxts = localStorage.getItem(`txtData-${this.archID}`);
        this.txtData = savedTxts ? JSON.parse(savedTxts) : {};
        // Load .bin data files from localStorage.
        let savedBin = localStorage.getItem(`binData-${this.archID}`);
        this.binData = savedBin ? JSON.parse(savedBin) : {};
        // Calculates storage size.
        this.size = 0;
        // Adds the space for all filenames and contents of the source files.
        for (const [filename, contents] of Object.entries(this.tabs)) {
            this.size += filename.length + contents.length;
        }
        // Adds the space for all filenames and contents of the object files.
        for (const [filename, contents] of Object.entries(this.objs)) {
            this.size += filename.length + contents.length;
        }
        // Adds the space for all filenames and contents of the data files.
        for (const [filename, contents] of Object.entries(this.txtData)) {
            this.size += filename.length + contents.length;
        }
        for (const [filename, contents] of Object.entries(this.binData)) {
            this.size += filename.length + contents.length;
        }
    },

    loadFromJSON(contents) {
        // Load workspace information from the json object.
        if (!contents.archID) {
            alert("Invalid workspace; no architecture information found.");
            return;
        }
        if (contents.archID != ARCH_ID) {
            alert("The workspace architecture does not match the current editor architecture.");
            return;
        }
        // Delete current contents of the workspace.
        for (const filename of Object.keys(this.tabs)) {
            delete this.tabs[filename];
        }
        for (const filename of Object.keys(this.objs)) {
            delete this.objs[filename];
        }
        for (const filename of Object.keys(this.txtData)) {
            delete this.txtData[filename];
        }
        for (const filename of Object.keys(this.binData)) {
            delete this.binData[filename];
        }
        // If the size is greater than zero, load in the information.
        // This allows the user to reset the workspace by uploading a JSON with size=0.
        if (contents.size > 0) {
            this.archID = contents.archID;
            this.tabs = contents.tabs;
            this.objs = contents.objs;
            this.txtData = contents.txtData;
            this.binData = contents.binData;
        }
        // Update contents in localStorage.
        this.storeAll();
        // Refresh the page so new tabs are properly created.
        location.reload();
    },

    exportToJSON() {
        return JSON.stringify(this);
    },

    reloadTabs(defaultTabName) {
        if (Object.keys(this.tabs).length == 0) {
            // If there are no tabs stored, keep the default code on editor.
            return;
        }

        for (const filename of Object.keys(this.tabs)) {
            if (filename != defaultTabName) {
                tabs.createTabButton(filename);
            }
        }

        // Wait for the editor to load so we can modify its contents.
        sleep(200).then(() => {
            // Check if the user has the default tab stored in their workspace.
            if (defaultTabName in this.tabs) {
                // If they do, update its contents.
                window.editor.setValue(this.tabs[defaultTabName]);
            } else {
                // If they don't, open a different tab and remove the default one.
                let firstFilename = Object.keys(this.tabs)[0];
                openTab(firstFilename);
                closeTab(defaultTabName, true);
            }
        });
    },

    addAssembledObj(filename, contents) {
        // Check if the file does not exist already.
        if (filename in this.objs) {
            alert(`'${filename}' already exists! You must delete it before uploading a new version.`);
            return;
        }
        // Convert file to Base64 so we can send it to the python backend.
        let b64Contents = encodeBase64(contents);
        this.objs[filename] = b64Contents;
        // Update the storage size.
        this.size += filename.length + b64Contents.length;
        // Update the objects in localStorage.
        this.storeObjs();
        // Update table with new object information.
        this.showObjOnTable(filename);
    },

    showObjOnTable(filename) {
        if (!(filename in this.objs)) {
            // File is not in storage.
            return;
        }

        let fileRowID = `uploadedObjTbl-${filename}`;
        let fileSize = formatHumanSize(this.objs[filename].length, 1);

        // Check if the file is already being displayed.
        let existingRow = document.getElementById(fileRowID);
        if (existingRow === null) {
            // This is a new file, create a new row to be inserted into the table.
            let newTr = document.createElement('tr');
            newTr.id = fileRowID;
            // Set the filename for the row.
            let filenameCell = document.createElement('td');
            filenameCell.innerText = filename;
            newTr.appendChild(filenameCell);
            // Set the filesize for the row.
            let filesizeCell = document.createElement('td');
            filesizeCell.id = `${fileRowID}-size`;
            filesizeCell.innerText = fileSize;
            newTr.appendChild(filesizeCell);
            // Add a button for the file to be removed later.
            // TODO: figure out why the tooltips are not working here.
            let fileDeleteCell = document.createElement('td');
            fileDeleteCell.innerHTML = `<i class="fa-solid fa-file-arrow-down" data-bs-toggle="tooltip" data-bs-title="Click here to download ${filename}" onclick='download_localstorage_file("${filename}", "obj")')></i> <i class="fa-regular fa-trash-can" data-bs-toggle="tooltip" data-bs-title="Click here to delete ${filename}" onclick='deleteUploadedFile("${filename}", "obj")'></i>`;
            newTr.appendChild(fileDeleteCell);
            // Add the new row to the table.
            let tbody = document.getElementById("uploadedObjectsTBody");
            tbody.appendChild(newTr);
        } else {
            // This file is overwriting an existing the file, only need to update the size.
            document.getElementById(`${fileRowID}-size`).innerText = fileSize;
        }
    },

    removeObjFromTable(filename) {
        let fileRowID = `uploadedObjTbl-${filename}`;
        let existingRow = document.getElementById(fileRowID);
        if (existingRow !== null) {
            existingRow.remove();
        }
    },

    reloadObjTable() {
        for (const filename of Object.keys(this.objs)) {
            this.showObjOnTable(filename);
        }
    },

    deleteAssembledObj(filename) {
        if (filename in this.objs) {
            // Update the storage size.
            this.size -= filename.length + this.objs[filename].length;
            // Delete the file.
            delete this.objs[filename];
            // Update the objects in localStorage.
            this.storeObjs();
            // Remove this object from the table.
            this.removeObjFromTable(filename);
        }
    },

    addTxtFile(filename, contents) {
        // Check if the file does not exist already.
        if (filename in this.txtData) {
            alert(`'${filename}' already exists! You must delete it before uploading a new version.`);
            return;
        }
        // Store the file in our map.
        this.txtData[filename] = contents;
        // Update the storage size.
        this.size += filename.length + contents.length;
        // Update the text files in localStorage.
        this.storeTxtData();
        // Update table with new data file information.
        this.showDataFileOnTable(filename, true);
    },

    deleteTxtFile(filename) {
        if (filename in this.txtData) {
            // Update the storage size.
            this.size -= filename.length + this.txtData[filename].length;
            // Delete the file.
            delete this.txtData[filename];
            // Update the objects in localStorage.
            this.storeTxtData();
            // Remove this object from the table.
            this.removeDataFileFromTable(filename);
        }
    },

    addBinFile(filename, contents) {
        // Check if the file does not exist already.
        if (filename in this.binData) {
            alert(`'${filename}' already exists! You must delete it before uploading a new version.`);
            return;
        }
        // Convert file to Base64 so we can send it to the python backend.
        let b64Contents = encodeBase64(contents);
        this.binData[filename] = b64Contents;
        // Update the storage size.
        this.size += filename.length + b64Contents.length;
        // Update the text files in localStorage.
        this.storeBinData();
        // Update table with new data file information.
        this.showDataFileOnTable(filename, false);
    },

    deleteBinFile(filename) {
        if (filename in this.binData) {
            // Update the storage size.
            this.size -= filename.length + this.binData[filename].length;
            // Delete the file.
            delete this.binData[filename];
            // Update the objects in localStorage.
            this.storeBinData();
            // Remove this object from the table.
            this.removeDataFileFromTable(filename);
        }
    },

    showDataFileOnTable(filename, isTxt) {
        let collection = isTxt ? this.txtData : this.binData;
        if (!(filename in collection)) {
            // File is not in storage.
            return;
        }

        let fileRowID = `uploadedDataFilesTable-${filename}`;
        let fileSize = formatHumanSize(collection[filename].length, 1);

        // Check if the file is already being displayed.
        let existingRow = document.getElementById(fileRowID);
        if (existingRow === null) {
            // This is a new file, create a new row to be inserted into the table.
            let newTr = document.createElement('tr');
            newTr.id = fileRowID;
            // Set the filename for the row.
            let filenameCell = document.createElement('td');
            filenameCell.innerText = filename;
            newTr.appendChild(filenameCell);
            // Set the filesize and the row.
            let filesizeCell = document.createElement('td');
            filesizeCell.id = `${fileRowID}-size`;
            filesizeCell.innerText = fileSize;
            newTr.appendChild(filesizeCell);
            // Add a button for the file to be removed later.
            // TODO: figure out why the tooltip is not working on the trash can.
            let fileDeleteCell = document.createElement('td');
            if (isTxt) {
                fileDeleteCell.innerHTML = `<i class="fa-solid fa-eye" data-bs-toggle="tooltip" data-bs-title="Click here to see the contents of ${filename}" onclick='show_local_file("${filename}", "txt")')></i> <i class="fa-solid fa-file-arrow-down" data-bs-toggle="tooltip" data-bs-title="Click here to download ${filename}" onclick='download_localstorage_file("${filename}", "txt")')></i> <i class="fa-regular fa-trash-can" data-bs-toggle="tooltip" data-bs-title="Click here to delete ${filename}" onclick='deleteUploadedFile("${filename}", "txt")'></i>`;

            } else {
                fileDeleteCell.innerHTML = `<i class="fa-solid fa-file-arrow-down" data-bs-toggle="tooltip" data-bs-title="Click here to download ${filename}" onclick='download_localstorage_file("${filename}", "bin")')></i> <i class="fa-regular fa-trash-can" data-bs-toggle="tooltip" data-bs-title="Click here to delete ${filename}" onclick='deleteUploadedFile("${filename}", "bin")'></i>`;
            }
            newTr.appendChild(fileDeleteCell);
            // Add the new row to the table.
            let tbody = document.getElementById("uploadedDataFilesTBody");
            tbody.appendChild(newTr);
        } else {
            // This file is overwriting an existing the file, only need to update the size.
            document.getElementById(`${fileRowID}-size`).innerText = fileSize;
        }
    },

    removeDataFileFromTable(filename) {
        let fileRowID = `uploadedDataFilesTable-${filename}`;
        let existingRow = document.getElementById(fileRowID);
        if (existingRow !== null) {
            existingRow.remove();
        }
    },

    reloadDataFileTable() {
        // Show the .txt files stored.
        for (const filename of Object.keys(this.txtData)) {
            this.showDataFileOnTable(filename, true);
        }
        // Show the .bin files stored.
        for (const filename of Object.keys(this.binData)) {
            this.showDataFileOnTable(filename, false);
        }
    },

    init(defaultTabName) {
        // Load tabs information stored in localstorage.
        this.loadFromStorage();
        // Reload tabs in the editor.
        this.reloadTabs(defaultTabName);
        // Reload the table of objects uploaded.
        this.reloadObjTable();
        // Reload the table of data files uploaded.
        this.reloadDataFileTable();
    }
}

function download_localstorage_file(filename, filetype) {
    switch (filetype) {
        case "obj":
            download_Base64File(filename, localFileStorage.objs[filename]);
            break;

        case "bin":
            download_Base64File(filename, localFileStorage.binData[filename]);
            break;

        case "txt":
            download_file(filename, localFileStorage.txtData[filename]);
            break;
    }
}

function show_local_file(filename, filetype) {
    switch (filetype) {
        case "txt":
            showMessage(`Contents of '${filename}'`, localFileStorage.txtData[filename]);
            break;
    }
}

function deleteUploadedFile(filename, filetype) {
    if (!confirm(`Are you sure you want to delete '${filename}'?`)) {
        return;
    }

    switch (filetype) {
        case "obj":
            localFileStorage.deleteAssembledObj(filename);
            break;
        case "txt":
            localFileStorage.deleteTxtFile(filename);
            break;
        case "bin":
            localFileStorage.deleteBinFile(filename);
            break;
    }
}

function encodeBase64(buffer) {
    var binary = '';
    var bytes = new Uint8Array(buffer);
    var len = bytes.byteLength;
    for (var i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
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

    // Check if the file is already stored.
    if (file.name in localFileStorage.tabs) {
        // If it is, confirm the overwite.
        if (!confirm(`This will overwrite the contents of '${file.name}'`)) {
            return;
        }
    }

    let fileReader = new FileReader();
    fileReader.onload = function (onLoadEvent) {
        const fileContents = onLoadEvent.target.result;
        // Figure out if this is a new file or an update.
        let isNewFile = !(file.name in localFileStorage.tabs);
        // Save the contents to our storage.
        localFileStorage.saveTab(file.name, fileContents);
        // If it is a new file, add a button for it.
        if (isNewFile) {
            tabs.createTabButton(file.name);
        } else if (file.name == getCurrentTabName()) {
            // If the file is the one currently opened, update the editor's contents.
            window.editor.setValue(fileContents);
        }
    };

    fileReader.onerror = function () {
        alert("Error reading file.");
    };

    fileReader.readAsText(file);
}

function importDataTxtFile(fileUploadTarget) {
    let file = fileUploadTarget.files[0];

    if (!file) {
        return;
    }

    if (!file.name.endsWith(".txt")) {
        alert("Invalid file! Please select a .txt file.");
        return;
    }

    let fileReader = new FileReader();
    fileReader.onload = function (onLoadEvent) {
        const fileContents = onLoadEvent.target.result;
        localFileStorage.addTxtFile(file.name, fileContents);
    };

    fileReader.onerror = function () {
        alert("Error reading file.");
    };

    fileReader.readAsText(file);
}

function importDataBinFile(fileUploadTarget) {
    let file = fileUploadTarget.files[0];

    if (!file) {
        return;
    }

    if (!(file.name.endsWith(".bin"))) {
        alert("Invalid file! Please select a .bin file.");
        return;
    }

    let fileReader = new FileReader();
    fileReader.onload = function (onLoadEvent) {
        const fileContents = onLoadEvent.target.result;
        localFileStorage.addBinFile(file.name, fileContents);
    };

    fileReader.onerror = function () {
        alert("Error reading file.");
    };

    fileReader.readAsArrayBuffer(file);
}

function importAssembledObject(fileUploadTarget) {
    let file = fileUploadTarget.files[0];

    if (!file) {
        return;
    }

    if (!(file.name.endsWith(".o") || file.name.endsWith(".obj"))) {
        alert("Invalid file! Please select a .o or .obj file.");
        return;
    }

    let fileReader = new FileReader();
    fileReader.onload = function (onLoadEvent) {
        const fileContents = onLoadEvent.target.result;
        localFileStorage.addAssembledObj(file.name, fileContents);
    };

    fileReader.onerror = function () {
        alert("Error reading file.");
    };

    fileReader.readAsArrayBuffer(file);
}

function importWorkspace(fileUploadTarget) {
    let file = fileUploadTarget.files[0];

    if (!file) {
        return;
    }

    if (!file.name.endsWith(".json")) {
        alert("Invalid file! Please select a .json file.");
        return;
    }

    if (!confirm("This will delete all existing tabs!")) {
        return;
    }

    let fileReader = new FileReader();
    fileReader.onload = function (onLoadEvent) {
        const fileContents = onLoadEvent.target.result;
        localFileStorage.loadFromJSON(JSON.parse(fileContents));
    };

    fileReader.onerror = function () {
        alert("Error reading file.");
    };

    fileReader.readAsText(file);
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
        memValueCell.setAttribute("intValue", 0);
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
    // Sort string values based on the integers they hold.
    let sortedNewAddresses = Object.keys(mem_values).sort((a, b) => parseInt(a, 10) - parseInt(b, 10));
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
            if (memValueCell.getAttribute("intValue") != newMemValue) {
                memValueCell.setAttribute("intValue", newMemValue);
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
    document.getElementById("downloadButton").disabled = true;
    document.getElementById("instructions-written").value = "";
    document.getElementById("instructions-executed").value = "";

    // Delete old trace information.
    window.lastTrace = null;
    currentTraceStep.stepNum = null;
    currentTraceStep.mem_changes = {};
    currentTraceStep.reg_changes = {};
    currentTraceStep.stdout = [];
    currentTraceStep.stderr = [];

    // Delete previous errors we had stored.
    for (let key in tabErrorHighlights) {
        delete tabErrorHighlights[key];
    }
    clearRegTable();
    clearMemoryTable();
    removeAllHighlights();
}

const tabErrorHighlights = {};

function detectAndHighlightErrors(stderrContents, onlySummary) {
    // Parse through the given stderr contents to find errors.
    // It assumes that user files are stored in the "userprograms" directory inside rootfs.
    let lines = stderrContents.split("\n").map(line => {
        let match = line.match(/userprograms\/([^:]+):(\d+): (.+)/);
        if (match) {
            return { filename: match[1], lineNumber: match[2], message: match[3] };
        }
        return null;

    }).filter(error => error !== null); // Remove non-error lines
    // Highlight lines for each error
    lines.forEach(line => {
        if (!(line.filename in tabErrorHighlights)) {
            tabErrorHighlights[line.filename] = [];
        }
        let lineNumber = parseInt(line.lineNumber, 10);
        let message = line.message.replace(/`/g, "'");
        tabErrorHighlights[line.filename].push({ lineNumber: 0, message: `Line ${lineNumber}: ${message}` });
        if (!onlySummary) {
            tabErrorHighlights[line.filename].push({ lineNumber: lineNumber, message: message });
        }
    });

    if (Object.keys(tabErrorHighlights).length == 0) {
        // If no errors, nothing to show.
        return;
    } else if (tabErrorHighlights[getCurrentTabName()] != null) {
        // If current tab has errors, show them.
        showTabHighlights();
    } else {
        // If it doesn't, open one tab with errors and show them.
        let tabWithErrors = Object.keys(tabErrorHighlights)[0];
        openTab(tabWithErrors);
    }
}

function runCode() {
    // Use the same logic as the tracing, but asks the backend to combine all the steps into a single one.
    startTracing(true);
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
    addHighlight(line, {
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

function updateTraceLinesHighlights(traceStep, tabName) {
    // Highlight the next line to be executed.
    if (traceStep + 1 < window.lastTrace.steps.length && window.lastTrace.steps[currentTraceStep.stepNum + 1].lineExecuted !== null) {
        // If it's not the last step and we have line information, highlight the next line.
        // Check if the next line to be executed is in the current tab.
        let nextFilenameIdx = window.lastTrace.steps[currentTraceStep.stepNum + 1].lineExecuted.filenameIndex;
        let nextFilename = window.lastTrace.sourceFilenames[nextFilenameIdx];
        if (nextFilename == tabName) {
            // If the current tab is the file that has the next line to be executed, highlight it and scroll to it.
            let linenum = window.lastTrace.steps[currentTraceStep.stepNum + 1].lineExecuted.linenum
            updateNextLine(linenum);
            window.editor.revealLineInCenter(linenum);
        }
    }

    // Highlight the last line that was executed.
    if (traceStep && window.lastTrace.steps[currentTraceStep.stepNum].lineExecuted !== null) {
        // If it's not the first step and we have line information, highlight the last line that was executed.
        let lastFilenameIdx = window.lastTrace.steps[currentTraceStep.stepNum].lineExecuted.filenameIndex;
        let lastFilename = window.lastTrace.sourceFilenames[lastFilenameIdx];
        if (lastFilename == tabName) {
            // If the current tab is the file that has the last line executed, highlight it.
            updateLastLine(window.lastTrace.steps[currentTraceStep.stepNum].lineExecuted.linenum);
        }
    }
}

function removeAllHighlights() {
    decorations.clear();
}

function showTabErrors(tabName) {
    if (!(tabName in tabErrorHighlights)) {
        return;
    }

    let firstError = true;
    for (const error of tabErrorHighlights[tabName]) {
        // Add the error information to the appropriate line.
        addErrorHighlight(error.lineNumber, [{ value: error.message }]);
        if (firstError) {
            // Scroll to the first error in the file.
            firstError = false;
            window.editor.revealLineInCenter(error.lineNumber);
        }
    }
}

function showTabHighlights() {
    let tabName = getCurrentTabName();
    // Remove all highlights.
    removeAllHighlights();
    // Add error highlights.
    showTabErrors(tabName);
    // Update the last and next lines if tracing code.
    if (window.lastTrace != null) {
        updateTraceLinesHighlights(currentTraceStep.stepNum, tabName);
    }
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

function BASE_startTracing(combineAllSteps) {
    // Clear any old information.
    clearOutput();
    // Disable code action buttons and editing.
    disableCodeActions(true);
    // Create a floating message with a running message.
    modal = showLoading('Running your code', 'Please wait for the emulation to finish.', 'Running...');
    // Save any changes in the current tab the user had made.
    localFileStorage.saveCurrentTab();
    let user_input = document.getElementById("inputBox").value;
    document.getElementById("runStatus").innerHTML = "⏳";
    fetch('/trace/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            arch: ARCH_ID,
            source_files: localFileStorage.tabs,
            object_files: localFileStorage.objs,
            extra_txt_files: localFileStorage.txtData,
            extra_bin_files: localFileStorage.binData,
            user_input: user_input,
            cl_args: window.cl_args,
        }),
    }).then(response => response.arrayBuffer())
        .then(data => {
            // Parse the protobuf from the backend.
            window.lastTrace = window.ExecutionTrace.decode(new Uint8Array(data));
        }).then(() => {
            // Mark emulation as completed and parse the information we received.
            document.getElementById("runStatus").innerHTML = OK_SYMBOL;

            // Show all info from the emulation.
            showAllEmulationInfo();

            // Check if the code has assembled.
            if (!window.lastTrace.build.asInfo.statusOk) {
                // If it hasn't, mark if as failed, show errors on the editor, make editor writeable again, enable action buttons, and stop processing.
                document.getElementById("asStatus").innerHTML = ERROR_SYMBOL;
                detectAndHighlightErrors(window.lastTrace.build.asInfo.errors, false);
                document.getElementById("errorBox").value = window.lastTrace.build.asInfo.errors;
                disableCodeActions(false);
                return;
            }
            // Mark assembling as successful.
            document.getElementById("asStatus").innerHTML = OK_SYMBOL;

            // Check if the code has linked.
            if (!window.lastTrace.build.ldInfo.statusOk) {
                // If it hasn't, mark if as failed, show errors on the editor, make editor writeable again, enable action buttons, and stop processing.
                document.getElementById("ldStatus").innerHTML = ERROR_SYMBOL;
                detectAndHighlightErrors(window.lastTrace.build.ldInfo.errors, true);
                document.getElementById("errorBox").value = window.lastTrace.build.ldInfo.errors;
                disableCodeActions(false);
                return;
            }
            // Mark linking as successful.
            document.getElementById("ldStatus").innerHTML = OK_SYMBOL;

            // If the code has assembled and linked, it *should* have been emulated.

            // Use the timeout indication to show if the trace reached maximum number of steps.
            document.getElementById("timeOut").innerHTML = window.lastTrace.reachedMaxSteps === null ? WAITING_SYMBOL : window.lastTrace.reachedMaxSteps ? OK_SYMBOL : ERROR_SYMBOL;

            // Update the efficiency metrics from the run.
            document.getElementById("instructions-written").value = window.lastTrace.instructionsWritten;
            document.getElementById("instructions-executed").value = window.lastTrace.instructionsExecuted;

            // Check if the user wanted to run or trace the code.
            if (combineAllSteps) {
                // If the user wanted to run it, advance trace to last step, remove code highlights, and reset editor to being actionable and do not show step information.
                changeTracingStep(Infinity);
                removeAllHighlights();
                disableCodeActions(false);
                return;
            }

            // Update the tracing information to show the initial state.
            changeTracingStep(1);

            // If the user wanted to trace the code, show menu and allow them to step through it.
            document.getElementById("statusFlagsDisplay").classList.remove("collapse");
            document.getElementById("traceMenuDiv").classList.remove("collapse");
            // Mark execution as not exited yet.
            document.getElementById("exitCode").innerHTML = WAITING_SYMBOL;
            // Allow tracing to be downloaded and stopped.
            document.getElementById("traceDownload").disabled = false;
            document.getElementById("traceStop").disabled = false;
            // Allow user to jump to a specific step.
            document.getElementById("curTraceStepNum").disabled = false;
        }).then(() => {
            // TODO: make sure this runs even if the fetch above fails.
            hideLoading(modal);
        });
}

function showAllEmulationInfo() {
    // Allow user to download the trace.
    document.getElementById("downloadButton").disabled = false;
    // Display emulation info in the text area.
    document.getElementById("emulationInfo").value = JSON.stringify(window.lastTrace, null, 2);
}

function disableCodeActions(disable) {
    // Change code action buttons.
    Array.from(document.getElementsByClassName("codeActionBtn")).forEach((el) => {
        el.disabled = disable;
    });
    // Change editor writeability.
    window.editor.updateOptions({ readOnly: disable });
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
    if (currentTraceStep.stepNum !== null && currentTraceStep.stepNum + 1 >= window.lastTrace.steps.length) {
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

const utf8Decoder = new TextDecoder();
function updateTraceGUI() {
    // Show the combined decoded stdout.
    let combinedStdout = "";
    for (let i in currentTraceStep.stdout) {
        if (currentTraceStep.stdout[i].length == 0) {
            // Skip empty arrays.
            continue;
        }
        // Decode and append the UTF-8 bytes into characters we can display in the output box.
        combinedStdout += utf8Decoder.decode(currentTraceStep.stdout[i]);
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
        // Check if we have information about the next line to be executed.
        // If we do not have information about the line, it means that we do not have the source file in the workspace.
        // TODO: treat such steps as a function call, combine all external steps into a single one and apply all changes together.
        let lineInfo = window.lastTrace.steps[currentTraceStep.stepNum + 1].lineExecuted;
        if (lineInfo !== null) {
            // Check if the next line to be executed exists and is in a different file.
            let nextFilenameIdx = lineInfo.filenameIndex;
            let nextFilename = window.lastTrace.sourceFilenames[nextFilenameIdx];
            if (nextFilename && nextFilename != getCurrentTabName()) {
                // If it isin a different tab, switch to that.
                openTab(nextFilename);
            }
        }
    }

    // Update the editor highlights.
    showTabHighlights();
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
