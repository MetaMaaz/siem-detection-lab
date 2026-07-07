# Investigation — PowerShell Encoded Command (T1059.001)

*Worked example. Replace with your own screenshots once you run the lab; the
prose shows the level of analysis expected.*

## Alert
- **Rule:** Wazuh 100101 / Sigma `win_powershell_encoded_command.yml`
- **ATT&CK:** T1059.001 — PowerShell (Execution)
- **Severity:** High
- **Fired at:** 2026-07-02 14:22:07Z  •  **Host:** WIN10-VICTIM

## What triggered it
Sysmon Event ID 1 (process creation): `powershell.exe` launched with
`-EncodedCommand` by parent `explorer.exe`. The rule matched the
`-enc`/`EncodedCommand` pattern on the command line.

> `![alert](./img/t1059-alert.png)`

## Triage — is it malicious?
- **Parent process:** explorer.exe — i.e. a user double-clicked something, not
  an admin console. Suspicious for an encoded payload.
- **Expected?** This host/user has no automation that uses encoded PowerShell.
- **Decoded the blob** (`[Convert]::FromBase64String` → Unicode): it resolved to
  a `Net.WebClient.DownloadString` cradle pulling from an external host — a
  download-and-execute. Strong malicious indicator.
- **Next events:** followed by an outbound connection (Sysmon Event ID 3) to
  the same host.

## Verdict
**True positive** — encoded download cradle launched from a user context,
consistent with a phishing payload.

## Response
Isolate WIN10-VICTIM from the network, capture the process tree and the
downloaded artefact, block the external host at the proxy/firewall, and
escalate to Tier 2 for scope/containment.

## Tuning
Some legitimate installers and management tools use `-EncodedCommand`.
Rather than dropping severity, baseline known-good parents (SCCM, specific
admin hosts) into a filter so operator-driven encoded commands don't drown the
genuine user-context hits.
