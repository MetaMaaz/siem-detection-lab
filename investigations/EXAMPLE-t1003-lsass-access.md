# Investigation: LSASS Memory Access (T1003.001)

*Worked example. Replace with your own screenshots once you run the lab.*

## Alert
- **Rule:** Wazuh 100107 / Sigma `win_lsass_memory_access.yml`
- **ATT&CK:** T1003.001 LSASS Memory (Credential Access)
- **Severity:** Critical
- **Fired at:** 2026-07-08 09:41:53Z  •  **Host:** WIN10-VICTIM

## What triggered it
Sysmon Event ID 10 (process access): `taskmgr.exe` opened a handle to
`lsass.exe` with `GrantedAccess: 0x1410`. That access mask includes
`PROCESS_VM_READ` (0x10) plus `PROCESS_QUERY_INFORMATION` (0x400), the exact
combination needed to read process memory. It is the signature behind Task
Manager's "Create dump file" and Mimikatz-style dumping alike.

> `![alert](./img/t1003-alert.png)`

## Triage: is it malicious?
- **Source process:** `taskmgr.exe` from `C:\Windows\System32`, a signed and
  legitimate binary. The rule's filter list (`MsMpEng.exe`, `csrss.exe`,
  `wininit.exe`) intentionally does *not* whitelist Task Manager, because it
  is a well-known living-off-the-land way to dump LSASS without dropping a
  tool.
- **Expected?** No scheduled job or admin runbook on this host reads LSASS.
  The access came from an interactive session (`explorer.exe` to `taskmgr.exe`),
  not a service.
- **What happened next:** Sysmon Event ID 11 (file create) showed
  `lsass.DMP` written to `C:\Users\victim\AppData\Local\Temp\` seconds later,
  a memory dump being saved to disk. That artefact is the smoking gun.
- **Access mask check:** `0x1410` is read-oriented, not the `0x1fffff`
  (full access) that some tools request, consistent with a targeted read rather
  than a crash-handler or AV scan.

## Verdict
**True positive.** An interactive user dumped LSASS to disk via Task Manager.
Whether the operator is an attacker who landed on the box or an insider, the
resulting `.DMP` can be carried offline and parsed for cached credentials, so
it is treated as a live credential-theft attempt.

## Response
Isolate WIN10-VICTIM from the network before the dump can be exfiltrated.
Capture and hash `lsass.DMP` for evidence, then delete it. Force a password
reset for every account that had an interactive or service logon on this host
(assume all cached secrets are burned), and rotate any local/service account
credentials. Escalate to Tier 2 to scope how the operator got interactive
access in the first place.

## Tuning
Legitimate crash-diagnostic and EDR tools do read LSASS, which is why the rule
ships with a `filter_known` list rather than firing on every handle. The right
move is *not* to lower the severity, since LSASS access is either expected on a
host or it isn't. Instead, baseline this specific environment: if a sanctioned
EDR agent (e.g. `MsMpEng.exe`, CrowdStrike, SentinelOne) legitimately reads
LSASS, add its signed image path to `filter_known` so operator or attacker
reads still stand out. Never whitelist `taskmgr.exe`, which would blind the
detection to the most common hands-on-keyboard dumping method.
