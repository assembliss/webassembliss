function showMessage(title, content) {
    // TODO: Fix aria warnings from the modal.
    document.getElementById("okMessageModalTitle").innerText = title;
    document.getElementById("okMessageModalBody").innerText = content;
    const okModal = new bootstrap.Modal('#okMessageModal')
    okModal.show();
}

function showLoading(title, content, status) {
    document.getElementById("pleaseWaitModalTitle").innerText = title;
    document.getElementById("pleaseWaitModalBody").innerText = content;
    document.getElementById("pleaseWaitModalStatus").innerText = status;
    const pleaseWaitModal = new bootstrap.Modal('#pleaseWaitModal')
    pleaseWaitModal.show();
    return pleaseWaitModal;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function hideLoading(modal) {
    // Need to sleep at least 500ms from my tests so the modal properly activates and we can then hide it.
    // Emulation is usually faster than this, so this should be very quick for the user.
    // Debugging is usually slower than this, but it seems pretty smooth from my tests.
    // TODO: validate that this really needs to wait 500ms for some reason.
    if (!modal) return;
    sleep(500).then(() => {
        modal.hide();
    });
}

function download_file(name, contents, mime_type) {
    mime_type = mime_type || "text/plain";

    var blob = new Blob([contents], { type: mime_type });

    var dlink = document.createElement('a');
    dlink.download = name;
    dlink.href = window.URL.createObjectURL(blob);
    dlink.onclick = function (e) {
        // revokeObjectURL needs a delay to work properly
        var that = this;
        setTimeout(function () {
            window.URL.revokeObjectURL(that.href);
        }, 1500);
    };
    dlink.click();
    dlink.remove();
}

function download_Base64File(fileName, contentBase64) {
    const linkSource = `data:application/octet-stream;base64,${contentBase64}`;
    const downloadLink = document.createElement('a');
    document.body.appendChild(downloadLink);

    downloadLink.href = linkSource;
    downloadLink.target = '_self';
    downloadLink.download = fileName;
    downloadLink.click();
}

function formatHumanSize(bytes, decimals) {
    // Ref: https://gist.github.com/zentala/1e6f72438796d74531803cc3833c039c
    if (bytes == 0) return '0 Bytes';
    var k = 1024,
        dm = decimals || 2,
        sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'],
        i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

async function syncReadBinaryFile(file) {
    let result = await new Promise((resolve) => {
        let fileReader = new FileReader();
        fileReader.onload = (e) => resolve(fileReader.result);
        fileReader.readAsArrayBuffer(file);
    });
    return result;
}

async function syncReadTextFile(file) {
    let result = await new Promise((resolve) => {
        let fileReader = new FileReader();
        fileReader.onload = (e) => resolve(fileReader.result);
        fileReader.readAsText(file);
    });
    return result;
}
