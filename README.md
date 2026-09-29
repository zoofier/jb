# ZOOF13R PS4 14.00 host layer

This directory is intentionally a **verification/staging layer**, not a fake jailbreak.

## Verified target
- PS4 firmware: 14.00
- Public HEN target: Scene-Collective `ps4-hen` has a 14.00 offset layer.
- Public browser chain: current public status does not provide a reproducible 14.00 WebKit -> kernel chain.

## Design
`browser -> WebKit primitive -> native userland -> kernel primitive -> 14.00 kpayload -> HEN`

The missing exploit stages are represented as an explicit boundary. Do not substitute 13.52 offsets or an unverified kernel primitive.

## Safety
This build performs browser-side diagnostics only. It does not patch kernel memory, execute a kernel exploit, or claim jailbreak success.
