# Investigation: <Detection name> (T####)

*Copy this file into `investigations/`, rename it, and fill it in after each
simulation.*

## Alert
- **Rule:** Wazuh 1001xx / Sigma `<file>.yml`
- **ATT&CK:** T#### <technique name> (<tactic>)
- **Severity:** <low/medium/high/critical>
- **Fired at:** <timestamp>  •  **Host:** <victim VM>

## What triggered it
One or two sentences: which log source and field values matched.
(e.g. "Sysmon Event ID 1: powershell.exe launched with `-EncodedCommand`.")

> Screenshot of the alert:
> `![alert](./img/tXXXX-alert.png)`

## Triage: is it malicious?
Walk the analyst questions:
- What is the parent process / who launched it?
- Is the user/host expected to do this?
- Decoded/known-bad indicators? (decode the command, check the domain/hash)
- What happened next on the host?

## Verdict
**True positive / False positive**, and why in one line.

## Response (what a SOC would do)
Isolate host, reset creds, block IOC, or escalate to Tier 2 as appropriate.

## Tuning
Would this rule be noisy in production? Note one realistic false-positive
source and how you'd whitelist it without blinding the detection.
