export const STAGES = [
  ["environment", "Preparing environment"],
  ["browser", "Checking browser runtime"],
  ["module", "Checking exploit module"],
  ["userland", "Userland stage"],
  ["kernel", "Kernel stage"],
  ["hen", "HEN / GoldHEN handoff"],
  ["verify", "Verifying result"]
];

export class JailbreakStateMachine {
  constructor({ onStage, onMessage }) {
    this.onStage = onStage;
    this.onMessage = onMessage;
    this.running = false;
  }

  async run({ diagnostics, adapter, demo = false }) {
    if (this.running) return;
    this.running = true;

    try {
      for (const [id, label] of STAGES.slice(0, 3)) {
        this.onStage(id, label, "running");
        await sleep(350);
        this.onStage(id, label, "passed");
      }

      const availability = await adapter.checkAvailability();

      if (!availability.available && !demo) {
        this.onStage("userland", "Userland stage", "blocked");
        this.onMessage(availability.reason);
        return { ok: false, reason: availability.reason };
      }

      if (demo) {
        for (const [id, label] of STAGES.slice(3, 6)) {
          this.onStage(id, label, "demo");
          await sleep(500);
        }
        this.onStage("verify", "Verifying result", "blocked");
        this.onMessage("Demo complete: no jailbreak was executed.");
        return { ok: false, demo: true };
      }

      const result = await adapter.execute();
      if (!result || !result.ok || !result.verified) {
        this.onStage("userland", "Exploit execution", "failed");
        this.onMessage(result?.reason || "The adapter did not report verified success.");
        return { ok: false, reason: result?.reason };
      }

      this.onStage("userland", "Userland stage", "passed");
      this.onStage("kernel", "Kernel stage", "passed");
      this.onStage("hen", "HEN / GoldHEN handoff", "passed");
      this.onStage("verify", "Verifying result", "passed");
      return result;
    } finally {
      this.running = false;
    }
  }
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}
