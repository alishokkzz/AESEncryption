// js/app.js

let currentStage = 0;
let activeSteps = [];
let stepPointer = 0;
let playLoopId = null;

function navigateToStage(stageNum) {
    document.querySelectorAll(".app-stage").forEach(el => el.classList.remove("active"));
    document.getElementById(`stage-${stageNum}`).classList.add("active");
    currentStage = stageNum;
    window.scrollTo(0,0);
}

function updateNavigationMap(activeElementId) {
    document.querySelectorAll("#aes-map-svg text, #aes-map-svg rect, #aes-map-svg circle").forEach(node => {
        node.setAttribute("fill", "#64748b");
    });
    const node = document.getElementById(activeElementId);
    if(node) {
        node.setAttribute("fill", "#ef4444");
    }
}

function configureSimulationEngine() {
    const text = document.getElementById("pt-input").value;
    const key = document.getElementById("key-input").value;

    if (key.length !== 32) {
        alert(`Configuration Error: Missing components. AES-256 structural specification strictly requires exactly a 32 character key metric. Entered length: [${key.length}/32]`);
        return;
    }

    activeSteps = createAESSteps(text, key);
    stepPointer = 0;
    renderCurrentStepMetrics();
}

function renderCurrentStepMetrics() {
    if(!activeSteps.length) return;
    const item = activeSteps[stepPointer];
    document.getElementById("step-title").textContent = `${item.title} (${item.label})`;
    document.getElementById("step-log").textContent = item.desc;
    
    renderStateMatrix(item.state, false);
    updateNavigationMap(item.mapId);
}

function runStepForward() {
    if(stepPointer < activeSteps.length - 1) {
        stepPointer++;
        renderCurrentStepMetrics();
    } else {
        clearInterval(playLoopId);
    }
}

function runStepBackward() {
    if(stepPointer > 0) {
        stepPointer--;
        renderCurrentStepMetrics();
    }
}

function runContinuousPlayback() {
    clearInterval(playLoopId);
    playLoopId = setInterval(runStepForward, 1200);
}

function haltPlayback() {
    clearInterval(playLoopId);
}

window.addEventListener("DOMContentLoaded", () => {
    navigateToStage(0);
    initQuizFramework();
    initPracticeFramework();
});