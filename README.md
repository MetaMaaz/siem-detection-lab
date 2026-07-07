# SIEM Detection Lab

A home SOC lab that ingests Windows + Sysmon telemetry into **Wazuh**, then
detects eight real adversary techniques mapped to **MITRE ATT&CK**. Every
detection ships as both a portable **Sigma** rule (industry-standard format)
and a working **Wazuh** rule, is simulated with **Atomic Red Team**, and is
documented with an analyst-style investigation writeup.

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
   ATT&CK technique) — no real malware required.
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

## Repo layout

```
siem-detection-lab/
├── README.md
├── rules/                 # 8 portable Sigma rules
├── wazuh/local_rules.xml  # Wazuh equivalents (rule IDs 100100+)
├── docs/
│   ├── 01-lab-setup.md    # build the VMs, install Wazuh + Sysmon
│   ├── 02-simulation.md   # Atomic Red Team command per detection
│   └── 03-investigation-template.md
├── investigations/        # your writeups + screenshots go here
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
