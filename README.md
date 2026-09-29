# ZOOF13R 14.00 Host v2

A PS4-browser-oriented host/staging shell for firmware 14.00.

## What this package does
- Detects the PS4 browser/user-agent and attempts to identify firmware.
- Hard-gates the UI to the requested 14.00 target.
- Performs browser/runtime, storage, cache, manifest, and module checks.
- Provides a polished staged "JAILBREAK" workflow.
- Separates exploit execution from the UI through an adapter interface.
- Provides a real-success handoff state: the UI only reports HEN/GoldHEN loaded when a verified adapter explicitly reports success.
- Includes a clearly labeled Demo Mode for testing the UI without an exploit.

## What this package does NOT contain
This package does not contain a WebKit vulnerability, kernel exploit, kernel patching logic, or a fabricated 14.00 exploit. Those components are deliberately isolated behind `modules/exploit-adapter.js`.

Do not treat the Demo Mode result as a jailbreak.

## Browser use
Serve the directory from a normal HTTP(S) web server and open:
`/14/index.html`

For an actual 14.00 exploit implementation, use only a verified, compatible implementation and wire it to the adapter contract. Do not change the success screen to claim success without a genuine success signal.

## Files
- `14/index.html` — main PS4 UI
- `14/app.js` — application controller/state machine
- `14/diagnostics.js` — environment checks
- `14/state-machine.js` — deterministic staged workflow
- `14/manifest.json` — target metadata
- `modules/exploit-adapter.js` — intentionally unimplemented adapter boundary
- `config/firmware.json` — target policy
- `14/EXPLOIT_BOUNDARY.md` — integration contract
