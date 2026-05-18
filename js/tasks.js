// js/tasks.js

const THEORY_QUIZZES = [
    {
        q: "How many internal transformation rounds are processed in standard AES-256?",
        options: ["10 Rounds", "12 Rounds", "14 Rounds", "16 Rounds"],
        answer: 2
    },
    {
        q: "Which specific mathematical step is omitted in the definitive terminal round of AES?",
        options: ["SubBytes", "ShiftRows", "MixColumns", "AddRoundKey"],
        answer: 2
    },
    {
        q: "What algebraic Finite Field configuration is utilized for AES byte operations?",
        options: ["GF(2^4)", "GF(2^8)", "GF(2^16)", "Prime Fields p=256"],
        answer: 1
    }
];

const PRACTICE_LABS = [
    {
        title: "S-Box Manual Transform Lookup",
        desc: "Examine the reference tool panels. What hex byte target replaces input standard byte value **0x53** inside the core S-Box array?",
        correct: "ED"
    },
    {
        title: "State Bitwise XOR Matrix Challenge",
        desc: "Perform a logical manual XOR processing value byte **0x32** with round key mask byte **0x88**. Input final calculated hexadecimal response token:",
        correct: "BA"
    },
    {
        title: "Finite Field Multiplication Verification",
        desc: "Calculate structural Galois Field multiplication scaling constant factor elements: evaluate product **0x02 • 0x87** under primitive generator reducible polynomial field polynomial context.",
        correct: "15"
    }
];

function initQuizFramework() {
    const qBox = document.getElementById("quiz-deck");
    qBox.innerHTML = "";
    THEORY_QUIZZES.forEach((item, idx) => {
        let block = document.createElement("div");
        block.className = "quiz-card";
        block.innerHTML = `<h4>Question #${idx + 1}: ${item.q}</h4>`;
        item.options.forEach((opt, oIdx) => {
            block.innerHTML += `
                <label style="display:block; margin:8px 0; cursor:pointer;">
                    <input type="radio" name="q_${idx}" value="${oIdx}"> ${opt}
                </label>`;
        });
        qBox.appendChild(block);
    });
}

function evaluateQuizzes() {
    let score = 0;
    THEORY_QUIZZES.forEach((item, idx) => {
        let chosen = document.querySelector(`input[name="q_${idx}"]:checked`);
        if(chosen && parseInt(chosen.value) === item.answer) score++;
    });
    alert(`Theory Score: ${score} / ${THEORY_QUIZZES.length} answered correctly!`);
    if(score === THEORY_QUIZZES.length) {
        document.getElementById("btn-stage3").style.display = "inline-block";
    }
}

function initPracticeFramework() {
    const pBox = document.getElementById("practice-deck");
    pBox.innerHTML = "";
    PRACTICE_LABS.forEach((item, idx) => {
        let div = document.createElement("div");
        div.className = "quiz-card";
        div.innerHTML = `
            <h4>${item.title}</h4>
            <p>${item.desc}</p>
            <input type="text" id="p_ans_${idx}" placeholder="HEX format (e.g. 4F)" class="custom-input" style="width:200px; margin-top:8px;">
        `;
        pBox.appendChild(div);
    });
}

function evaluatePractice() {
    let valid = true;
    PRACTICE_LABS.forEach((item, idx) => {
        let val = document.getElementById(`p_ans_${idx}`).value.trim().toUpperCase();
        if(val !== item.correct) valid = false;
    });
    if(valid) {
        alert("Verification check complete. Processing stage metrics.");
        document.getElementById("btn-stage4").style.display = "inline-block";
    } else {
        alert("Calculated matrix values mismatch detected. Re-verify hex inputs using the utility lookup components on the left sidebar panel.");
    }
}