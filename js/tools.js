// js/tools.js

function processAsciiHexConvert() {
    const input = document.getElementById("tool-ascii-in").value;
    let res = "";
    for(let i=0; i<input.length; i++) {
        res += input.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0') + " ";
    }
    document.getElementById("tool-ascii-out").textContent = res.trim() || "00";
}

function processXorCompute() {
    let a = parseInt(document.getElementById("tool-xor-a").value, 16) || 0;
    let b = parseInt(document.getElementById("tool-xor-b").value, 16) || 0;
    document.getElementById("tool-xor-out").textContent = (a ^ b).toString(16).toUpperCase().padStart(2, '0');
}

function processSboxFetch() {
    let b = parseInt(document.getElementById("tool-sb-in").value, 16) || 0;
    document.getElementById("tool-sb-out").textContent = SBOX[b].toString(16).toUpperCase().padStart(2, '0');
}