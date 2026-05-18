// js/aes-steps.js

let animGen = 0;

function createAESSteps(text, keyStr) {
    let state = stringToBytes(text);
    let keyBytes = keyStringToBytes(keyStr);
    let w = expandKey256(keyBytes);
    let steps = [];

    function pushStep(title, label, matrix, desc, mapId) {
        steps.push({ title, label, state: [...matrix], desc, mapId });
    }

    // Step 0: Initial State
    pushStep("Input Text State", "Initialization", state, "Plaintext input text transformed to a 4x4 State matrix.", "map-start");

    // Pre-round AddRoundKey
    let rk = [];
    for(let i=0; i<4; i++) rk = rk.concat(w[i]);
    for(let i=0; i<16; i++) state[i] ^= rk[i];
    pushStep("Initial AddRoundKey", "Round 0", state, "Plaintext state bitwise XORed with the initial Round Key (w0-w3).", "map-ark0");

    // Rounds 1 to 13
    for (let r = 1; r <= 13; r++) {
        let rTitle = `Round ${r}`;
        
        // SubBytes
        for(let i=0; i<16; i++) state[i] = SB[state[i]];
        pushStep("SubBytes", rTitle, state, "Each byte in the matrix mapped through the non-linear AES Substitution Box (S-Box).", "map-sb");

        // ShiftRows
        let s = [...state];
        state[1] = s[5]; state[5] = s[9]; state[9] = s[13]; state[13] = s[1];
        state[2] = s[10]; state[6] = s[14]; state[10] = s[2]; state[14] = s[6];
        state[3] = s[15]; state[7] = s[3]; state[11] = s[7]; state[15] = s[11];
        pushStep("ShiftRows", rTitle, state, "Cyclic byte transposition shifts. Row 1: 0 slots; Row 2: 1 slot; Row 3: 2 slots; Row 4: 3 slots.", "map-sr");

        // MixColumns
        let m = [...state];
        for (let c = 0; c < 4; c++) {
            let i = c * 4;
            state[i]   = gm(2,m[i])   ^ gm(3,m[i+1]) ^ m[i+2]       ^ m[i+3];
            state[i+1] = m[i]         ^ gm(2,m[i+1]) ^ gm(3,m[i+2]) ^ m[i+3];
            state[i+2] = m[i]         ^ m[i+1]       ^ gm(2,m[i+2]) ^ gm(3,m[i+3]);
            state[i+3] = gm(3,m[i])   ^ m[i+1]       ^ m[i+2]       ^ gm(2,m[i+3]);
        }
        pushStep("MixColumns", rTitle, state, "Linear algebraic column transformation using modular polynomial arithmetic in GF(2^8).", "map-mc");

        // AddRoundKey
        rk = [];
        for(let i=0; i<4; i++) rk = rk.concat(w[r*4 + i]);
        for(let i=0; i<16; i++) state[i] ^= rk[i];
        pushStep("AddRoundKey", rTitle, state, `Matrix elements XORed with expanded Round Key segment indices w${r*4} to w${r*4+3}.`, "map-ark");
    }

    // Final Round 14 (No MixColumns)
    for(let i=0; i<16; i++) state[i] = SB[state[i]];
    pushStep("SubBytes", "Round 14 (Final)", state, "Final pass byte-by-byte substitution lookup map.", "map-sb");

    let s14 = [...state];
    state[1] = s14[5]; state[5] = s14[9]; state[9] = s14[13]; state[13] = s14[1];
    state[2] = s14[10]; state[6] = s14[14]; state[10] = s14[2]; state[14] = s14[6];
    state[3] = s14[15]; state[7] = s14[3]; state[11] = s14[7]; state[15] = s14[11];
    pushStep("ShiftRows", "Round 14 (Final)", state, "Final pass rows shifted cyclically over offset strides.", "map-sr");

    rk = [];
    for(let i=0; i<4; i++) rk = rk.concat(w[56+i]);
    for(let i=0; i<16; i++) state[i] ^= rk[i];
    pushStep("Final Ciphertext Result", "Complete", state, "AES-256 complete. Final State matrix maps the definitive ciphertext blocks.", "map-end");

    return steps;
}

function renderStateMatrix(bytes, immediate = false) {
    const grid = document.getElementById("matrix-grid");
    grid.innerHTML = "";
    animGen++;
    let currentGen = animGen;

    for (let i = 0; i < 16; i++) {
        let cell = document.createElement("div");
        cell.className = "matrix-cell animate__animated";
        let hexStr = bytes[i].toString(16).toUpperCase().padStart(2, '0');
        cell.textContent = hexStr;
        grid.appendChild(cell);

        if (!immediate) {
            cell.style.visibility = "hidden";
            setTimeout(() => {
                if (currentGen !== animGen) return;
                cell.style.visibility = "visible";
                cell.classList.add("animate__zoomIn");
            }, i * 35); 
        }
    }
}
