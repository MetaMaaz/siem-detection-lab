# 06: Detection Engineering Notes

Real issues found and fixed while running the lab end-to-end on 2026-07-09.
These are the parts that don't show up in a clean rule file — the debugging
that makes a detection actually fire against live telemetry.

## Fix 1 — Wrong built-in parent rule for the new-admin detection (100108)

**Symptom.** Adding an account to local Administrators generated Windows Event
4732 on the endpoint (confirmed with `Get-WinEvent`), and the event reached
Wazuh, but rule **100108 never fired**.

**Root cause.** The rule chained off the wrong built-in parent:

```xml
<if_sid>60144</if_sid>   <!-- wrong -->
```

The 4732 event was actually being handled by built-in rule **60154**
("Administrators group changed"), confirmed straight from the manager:

```bash
docker exec <manager> grep -rn "4732" /var/ossec/ruleset/rules/
# 0580-win-security_rules.xml:501: <field name="win.system.eventID">^636$|^4732$</field>
```

Because `if_sid` pointed at a rule that never matched, the child rule was never
evaluated.

**Fix.** Point at the correct parent and pin the event ID so it only matches an
*add* (4732), not a *remove* (4733):

```xml
<if_sid>60154</if_sid>
<field name="win.system.eventID" type="pcre2">^4732$</field>
```

After reloading, 100108 fired at level 12 on the next `net localgroup
Administrators /add`.

**Lesson.** Don't assume a built-in parent SID — verify it against the running
ruleset. A wrong `if_sid` fails silently: no error, just no alert.

## Fix 2 — Sysmon wasn't logging LSASS access, so 100107 couldn't fire

**Symptom.** Dumping lsass (procdump / Task Manager) produced **no Sysmon Event
ID 10**, so the credential-dumping rule 100107 had nothing to match.

**Root cause.** The SwiftOnSecurity Sysmon config ships ProcessAccess
monitoring effectively disabled (it's expensive and noisy), so no handle-access
events were being generated at all:

```xml
<ProcessAccess onmatch="include">
    <!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
</ProcessAccess>
```

**Fix.** Add a targeted include for lsass and reload the config live:

```xml
<ProcessAccess onmatch="include">
    <TargetImage name="T1003_LSASS" condition="end with">lsass.exe</TargetImage>
</ProcessAccess>
```

```powershell
Sysmon64a.exe -c sysmonconfig.xml   # "Configuration updated."
```

The next dump produced Event 10 with `GrantedAccess: 0x1FFFFF`, and 100107 fired
at level 14. This is a targeted enable — it logs handle access to lsass only,
not all ProcessAccess, keeping the volume manageable.

**Lesson.** A detection is only as good as the telemetry underneath it. The
rule was correct the whole time; the data source was off.

## Known issue — PowerShell outbound (100110) not firing

Sysmon logs Event ID 3 for `powershell.exe` outbound connections (confirmed on
the endpoint) and the agent forwards it, but rule 100110 does not fire in the
live lab. The `sysmon_event3` chain isn't matching the way `sysmon_event1` does
for 100101, even after loosening the `image` regex. Left as an open item to
resolve with a `wazuh-logtest` trace. Tracked in the rule comment in
`wazuh/local_rules.xml`. The other three priority detections
(100101 / 100107 / 100108) are validated live with screenshots in
`investigations/`.

## Environment gotchas (Windows 11 ARM64 victim, Apple Silicon host)

- **Sysmon driver blocked.** On ARM64 you must install with **`Sysmon64a.exe`**
  (native ARM64), not `Sysmon64.exe` (x64) — the x64 driver fails with "This
  driver has been blocked from loading" under WHQL/architecture enforcement.
- **Smart App Control** ships in Evaluation mode on a fresh install and blocks
  less-common kernel drivers; had to be turned off
  (`VerifiedAndReputablePolicyState = 0`).
- **A failed Sysmon install** leaves a PPL-protected `Sysmon64` service that
  even `psexec -s` (SYSTEM) can't `sc delete`; remove it via
  `reg delete HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64 /f`.
- **LSA Protection (RunAsPPL)** blocks dumping lsass even as admin — disabled
  for the credential-access test to simulate a post-tamper attacker.
- **Agent-to-manager connectivity** (UTM Emulated VLAN NAT): the VM reached the
  Mac's LAN IP fine once the Wazuh Docker stack was actually running and
  publishing `1514`.
