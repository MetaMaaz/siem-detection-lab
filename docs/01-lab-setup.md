# 01: Lab Setup

Goal: a Wazuh manager receiving Windows + Sysmon telemetry from one victim VM.
Budget ~1 hour. Needs ~8GB free RAM (4GB Windows, 4GB Wazuh).

## 1. Wazuh manager (fastest path: single-node Docker)

On any Linux host (or an Ubuntu VM):

```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0
cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
docker compose up -d
```

Dashboard: `https://<host-ip>`, default login `admin` / `SecretPassword`
(change it in `docker-compose.yml` before starting for anything non-throwaway).

Low on RAM? Run only the manager container and read alerts from
`/var/ossec/logs/alerts/alerts.json` instead of the dashboard.

## 2. Windows victim VM

- Install Windows 10/11 from a free Microsoft evaluation ISO in VirtualBox/VMware.
- **Sysmon** (rich process/registry/network telemetry):
  ```powershell
  # from an elevated PowerShell
  Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
  Expand-Archive Sysmon.zip
  # SwiftOnSecurity config = a sane, well-documented baseline
  Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
  .\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig.xml
  ```
- Enable the audit policies the Security-log rules need:
  ```cmd
  auditpol /set /subcategory:"Logon" /failure:enable
  auditpol /set /subcategory:"User Account Management" /success:enable
  auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
  ```

## 3. Wazuh agent on the victim

Install the agent (Wazuh dashboard → Agents → Deploy new agent gives you a
one-line command with your manager IP). Then tell it to forward Sysmon:
add this to `C:\Program Files (x86)\ossec-agent\ossec.conf` inside `<ossec_config>`:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent service. Confirm it shows **Active** on the dashboard.

## 4. Load the custom rules

Append `wazuh/local_rules.xml` to `/var/ossec/etc/rules/local_rules.xml` on the
manager (Docker: `docker exec -it single-node-wazuh.manager-1 bash`), then:

```bash
/var/ossec/bin/wazuh-control restart
```

## Verify

On the victim run `whoami` in PowerShell, then confirm a Sysmon Event ID 1
appears in the dashboard (Security events, filter `data.win.system.eventID:1`).
If it lands, the pipeline works. Move on to `02-simulation.md`.

A single-node Docker manager plus one victim is the smallest setup that
exercises every rule. Add a domain controller or an attacker Kali VM later if
you want AD-specific detections.
