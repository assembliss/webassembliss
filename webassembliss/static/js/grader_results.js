function parseJSONAndDownload(filename, contents) {
    download_file(filename, JSON.stringify(contents), "application/json");
}