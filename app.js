import { detectEnvironment, targetCheck, storageCheck } from "./diagnostics.js";
import { JailbreakStateMachine, STAGES } from "./state-machine.js";
import * as adapter from "../modules/exploit-adapter.js";

const $ = id => document.getElementById(id);
const logBox = $("log");
const button = $("jailbreak");
const demoButton = $("demo");
const result = $("result");

function log(message) {
  const line = `[${new Date().toLocaleTimeString()}] ${message}`;
  logBox.textContent += `${line}\n`;
  logBox.scrollTop = logBox.scrollHeight;
}

function setStage(id, label, state) {
  const row = document.querySelector(`[data-stage="${id}"]`);
  if (!row) return;
  row.className = `stage ${state}`;
  row.querySelector(".stage-state").textContent =
    state === "passed" ? "✓" :
    state === "running" ? "…" :
    state === "demo" ? "DEMO" :
    state === "blocked" ? "BLOCKED" :
    state === "failed" ? "FAIL" : "";
}

function showResult(title, body, kind) {
  result.hidden = false;
  result.className = `result ${kind}`;
  result.querySelector(".result-title").textContent = title;
  result.querySelector(".result-body").textContent = body;
}

async function boot() {
  const env = detectEnvironment();
  $("ua").textContent = env.userAgent;
  $("firmware").textContent = env.firmware || "Unknown";
  $("webkit").textContent = env.webkit ? "Detected" : "Not detected";

  const target = targetCheck(env);
  const storage = await storageCheck();
  $("target").textContent = target.exact ? "14.00 ✓" : "Mismatch";
  $("storage").textContent = storage ? "Ready" : "Unavailable";

  if (!target.exact) {
    button.disabled = true;
    log("Target gate: this host is locked to PS4 firmware 14.00.");
    showResult(
      "14.00 REQUIRED",
      "This host will not attempt an exploit on another firmware.",
      "warning"
    );
  } else {
    log("14.00 target detected.");
    log("Browser runtime: " + (env.webkit ? "WebKit detected." : "WebKit not identified."));
    log("Exploit adapter: checking availability…");
    const avail = await adapter.checkAvailability();
    log(avail.available ? "Verified adapter available." : avail.reason);
  }
}

async function run(demo) {
  button.disabled = true;
  demoButton.disabled = true;
  result.hidden = true;
  logBox.textContent = "";

  const machine = new JailbreakStateMachine({
    onStage: (id, label, state) => {
      setStage(id, label, state);
      log(`${label}: ${state}`);
    },
    onMessage: message => log(message)
  });

  const env = detectEnvironment();
  if (env.firmware !== "14.00") {
    showResult("TARGET BLOCKED", "Exact firmware 14.00 is required.", "warning");
    button.disabled = false;
    demoButton.disabled = false;
    return;
  }

  log(demo ? "Starting UI demonstration mode." : "Starting verified exploit workflow.");
  const r = await machine.run({ diagnostics: env, adapter, demo });

  if (r.ok && r.verified) {
    showResult(
      "GOLDHEN LOADED",
      `Verified handoff reported for ${r.hen || "HEN"} on firmware ${r.firmware || "14.00"}.`,
      "success"
    );
  } else if (r.demo) {
    showResult(
      "DEMO COMPLETE",
      "The staged animation completed, but no jailbreak or HEN was executed.",
      "warning"
    );
  } else {
    showResult(
      "NOT LOADED",
      r.reason || "No verified jailbreak result was reported.",
      "error"
    );
  }

  button.disabled = false;
  demoButton.disabled = false;
}

button.addEventListener("click", () => run(false));
demoButton.addEventListener("click", () => run(true));
boot();
