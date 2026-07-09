# SIEM Detection Lab

A home SOC lab that ingests Windows + Sysmon telemetry into **Wazuh**, then
detects ten real adversary techniques mapped to **MITRE ATT&CK**. Every
detection ships as both a portable **Sigma** rule and a working **Wazuh**
rule, is simulated with **Atomic Red Team**, and is documented with an
investigation writeup. One high-confidence detection is wired to an automated
**active response**.

Built to practise the Tier 1 SOC workflow end to end: *simulate an attack →
watch the telemetry land → detect it → investigate it → tune it.*

---

## Architecture

```
                    ┌─────────────────────────────┐
                    │   Windows 10/11 VM (victim)  │
                    │                              │
                    │   Sysmon  ─┐                 │
                    │   Security ├─ event logs     │
                    │   PowerShell┘                │
                    │        │                     │
                    │   Wazuh Agent                │
                    └────────┼─────────────────────┘
                             │ encrypted 1514/udp
                             ▼
                    ┌─────────────────────────────┐
                    │   Wazuh Manager (Docker /    │
                    │   Ubuntu VM)                 │
                    │                              │
                    │   Decoders → local_rules.xml │
                    │        │                     │
                    │   Alerts → Wazuh Dashboard   │
                    └─────────────────────────────┘

   Attacks simulated on the victim with Atomic Red Team (one command per
   ATT&CK technique). No real malware required.
```

## Detections

| # | Detection | ATT&CK | Log source | Sigma | Wazuh |
|---|-----------|--------|-----------|-------|-------|
| 1 | Brute-force failed logons | T1110 | Security 4625 | `win_bruteforce_failed_logons.yml` | 100100 |
| 2 | PowerShell encoded command | T1059.001 | Sysmon 1 | `win_powershell_encoded_command.yml` | 100101 |
| 3 | Office spawning a shell | T1566.001 | Sysmon 1 | `win_office_spawning_shell.yml` | 100102 |
| 4 | Registry Run-key persistence | T1547.001 | Sysmon 13 | `win_registry_runkey_persistence.yml` | 100103 |
| 5 | New local admin account | T1136.001 | Security 4720/4732 | `win_new_local_admin.yml` | 100104, 100108 |
| 6 | Certutil download (LOLBin) | T1105 | Sysmon 1 | `win_certutil_download.yml` | 100105 |
| 7 | Security log cleared | T1070.001 | Security 1102 | `win_security_log_cleared.yml` | 100106 |
| 8 | LSASS memory access | T1003.001 | Sysmon 10 | `win_lsass_memory_access.yml` | 100107 |
| 9 | Scheduled task created | T1053.005 | Sysmon 1 | `win_scheduled_task_creation.yml` | 100109 |
| 10 | PowerShell outbound connection | T1071.001 | Sysmon 3 | `win_powershell_network_connection.yml` | 100110 |

Rule 100108 adds a locale-independent check for accounts added to the local
Administrators group (4732). It also drives the active response in
`docs/04-active-response.md`, the lab's one automated containment action.

### Validated in the lab

Three of the priority detections were run end-to-end against a live Windows 11
victim and captured with alert screenshots and worked investigations:

| Detection | Rule | ATT&CK | Writeup |
|-----------|------|--------|---------|
| PowerShell encoded command | 100101 | T1059.001 | [t1059-powershell-encoded.md](investigations/t1059-powershell-encoded.md) |
| New local admin account | 100108 | T1136.001 | [t1136-new-local-admin.md](investigations/t1136-new-local-admin.md) |
| LSASS memory access | 100107 | T1003.001 | [t1003-lsass-access.md](investigations/t1003-lsass-access.md) |

Running the lab surfaced two real bugs — a wrong built-in parent rule
(`if_sid 60144` → `60154`) and a Sysmon config gap that stopped LSASS access
from being logged — both fixed and written up in
[docs/06-detection-engineering-notes.md](docs/06-detection-engineering-notes.md).
Rule 100110 (PowerShell outbound) is a documented known-issue pending a
`wazuh-logtest` trace; see the same notes.

## Repo layout

```
siem-detection-lab/
├── README.md
├── rules/                 # 10 portable Sigma rules
├── wazuh/local_rules.xml  # Wazuh equivalents (rule IDs 100100+)
├── docs/
│   ├── 01-lab-setup.md    # build the VMs, install Wazuh + Sysmon
│   ├── 02-simulation.md   # Atomic Red Team command per detection
│   ├── 03-investigation-template.md
│   ├── 04-active-response.md  # auto-disable a rogue admin account
│   ├── 05-lab-walkthrough.md  # full build steps (macOS Apple Silicon)
│   └── 06-detection-engineering-notes.md  # live bugs found + fixed
├── investigations/        # worked investigations + alert screenshots
└── .github/workflows/validate-sigma.yml
```

## Quick start

1. Follow `docs/01-lab-setup.md` to stand up Wazuh + a Windows victim with Sysmon.
2. Append `wazuh/local_rules.xml` to the manager's rules and restart it.
3. Run a simulation from `docs/02-simulation.md`, watch the alert fire.
4. Investigate using `docs/03-investigation-template.md`, save the writeup + screenshots under `investigations/`.

## Skills demonstrated

SIEM (Wazuh) · detection engineering · Sigma · MITRE ATT&CK · Sysmon ·
Windows event log analysis · adversary emulation (Atomic Red Team) ·
incident investigation · alert tuning / false-positive analysis

## License

MIT
