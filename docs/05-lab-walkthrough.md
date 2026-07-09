# 05: Lab Walkthrough (macOS Apple Silicon)

End-to-end steps to build the lab on an Apple Silicon Mac and capture the alert
screenshots that go in `investigations/`. Budget ~1.5-2 hours the first time.
Needs a 16 GB Mac (Docker manager 4 GB + Windows VM 4 GB run at once). On 8 GB,
stop the dashboard container and read alerts from
`/var/ossec/logs/alerts/alerts.json` instead.

## 1. Wazuh manager (Docker on the Mac)

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Give Docker Desktop at least 4 GB (Settings > Resources). After ~5 min open
`https://localhost`, accept the cert warning, log in `admin` / `SecretPassword`.

## 2. Windows 11 ARM64 victim VM (UTM)

1. Install UTM (free) from mac.getutm.app.
2. Download the official Windows 11 Arm64 ISO:
   https://www.microsoft.com/en-us/software-download/windows11arm64
   (multi-edition ISO, ~5-6 GB, link valid 24h).
3. UTM > Create a New Virtual Machine > Virtualize > Windows. Leave
   **Install drivers and SPICE tools** checked. Point it at the ISO.
4. Resources: 4096 MB RAM, 2 cores, 64 GB disk.
5. Install Windows: choose Pro, "I don't have a product key". At the network
   screen press **Shift+F10** and run `oobe\bypassnro` (or `start ms-cxh:localonly`
   on newer builds) to allow a local account.
6. Install the mounted **spice-guest-tools** ISO for networking/display drivers,
   reboot, confirm the VM can browse the web.
7. **Snapshot the clean VM** (or duplicate it) before going further.

## 3. Sysmon + audit policy + Wazuh agent (in the VM)

Elevated PowerShell:

```powershell
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
.\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Elevated Command Prompt (enable the audit policies the Security-log rules need):

```cmd
auditpol /set /subcategory:"Logon" /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
```

Install the agent: dashboard > Agents > Deploy new agent > Windows, using your
Mac's IP as the manager address (`ipconfig getifaddr en0` on the Mac). Run the
one-line command it generates in the VM's admin PowerShell.

Forward Sysmon: add to `C:\Program Files (x86)\ossec-agent\ossec.conf` inside
`<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

`Restart-Service WazuhSvc`. The agent should show **Active** on the dashboard.

Verify the pipeline: run `whoami` in the VM, then filter
`data.win.system.eventID:1` in the dashboard. If it lands, telemetry flows.

## 4. Load the custom rules

```bash
docker exec -it single-node-wazuh.manager-1 bash
vi /var/ossec/etc/rules/local_rules.xml      # paste contents of wazuh/local_rules.xml
/var/ossec/bin/wazuh-control restart
exit
```

## 5. Run attacks and screenshot the alerts

One detection at a time. Best three for screenshots:

- **PowerShell encoded (100101):** `powershell -enc <base64>` (Base64 helper in `02-simulation.md`).
- **New admin + active response (100108):** `net user hacker P@ss123! /add & net localgroup Administrators hacker /add`, then `net user hacker` and screenshot **Account active: No**.
- **LSASS (100107):** Task Manager > right-click `lsass.exe` > **Create dump file** (safe, no malware).

Per detection: run it, filter the dashboard on `rule.id:1001xx` or
`rule.mitre.id:T####`, click to expand the alert, and screenshot just the alert
detail (Cmd+Shift+4). Save to `investigations/img/` (e.g. `t1059-alert.png`,
`t1003-alert.png`), then roll back the snapshot before the next attack.

## 6. Reset the lab between runs

Capturing the credential-access detection meant disabling several Windows
controls so the attacks would land. Restore them afterwards (or just revert to a
clean snapshot). In the victim's admin PowerShell:

```powershell
net user hacker /delete                         # remove the rogue admin account
Remove-Item $env:TEMP\lsass*.dmp -ErrorAction SilentlyContinue   # delete lsass dumps
Remove-Item "$env:TEMP\Procdump" -Recurse -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force  # re-enable LSA Protection (reboot to apply)
```

Then in Windows Security (GUI), turn **Real-time protection** and **Tamper
Protection** back **On**. Smart App Control only re-enables via a Windows
reinstall (it's one-way), so leave it off on a throwaway lab VM.

Best practice: once the Wazuh agent + Sysmon are installed and working, snapshot
the VM in that clean state. Then reset is a one-click snapshot revert instead of
re-running teardown each time.

## Reusable baselines (skip the Phase 3 rebuild)

Phase 3 is the slow part to redo — especially on ARM64, where Sysmon must be
installed with `Sysmon64a.exe` and Smart App Control / LSA Protection get in the
way. Don't rebuild it from the golden image every time. Keep two baselines:

- **Golden** — pristine Windows, no Sysmon, no agent. The clean-room source.
- **Lab-Ready** — a clone of golden that has completed Phase 3 (Sysmon +
  audit policy + Wazuh agent enrolled + rules loaded) and then been reset with
  the teardown above. This is what you revert to before each attack run.

Workflow: clone golden → do Phase 3 once → run teardown → snapshot as
**Lab-Ready**. From then on, "reset the lab" means revert to the Lab-Ready
snapshot, not rebuild. Rebuild Lab-Ready from golden only when you want a newer
Windows/Sysmon/agent version. When you retire a victim, also delete its stale
agent from the manager (Server management → Endpoints) so it doesn't linger.

## Common gotchas

- Agent won't connect: check the **Mac firewall** isn't blocking port 1514.
- Security-log rules silent: the **auditpol** step was skipped.
- No Sysmon events: the `<localfile>` block wasn't added, or the agent wasn't restarted.
