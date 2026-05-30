// Triggers a browser download of bytes produced in .NET. The payload arrives as a streamed
// DotNetStreamReference, so large files do not have to be marshalled as one big string.
window.pqfeDownload = async (fileName, streamRef) => {
    const buffer = await streamRef.arrayBuffer();
    const blob = new Blob([buffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = fileName;
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    URL.revokeObjectURL(url);
};
