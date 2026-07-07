# 04: Active Response (detection to response)

Wazuh can react to an alert, not just raise it. This lab wires one response:
when an account is added to the local Administrators group (rule **100108**,
T1136.001), the manager tells the agent to disable that account.

## Configure

On the **manager**, add inside `<ossec_config>` in `/var/ossec/etc/ossec.conf`
(the `disable-account` command ships with Wazuh, so only the trigger block is
usually needed, so check the `<command>` entry already exists):

```xml
<active-response>
  <command>disable-account</command>
  <location>local</location>
  <rules_id>100108</rules_id>
  <timeout>600</timeout>
</active-response>
```

Then restart the manager: `/var/ossec/bin/wazuh-control restart`

- `location: local` runs on the agent that raised the alert (the victim VM).
- `timeout: 600` re-enables the account after 10 minutes (stateful response),
  so a lab mistake doesn't lock you out permanently.

## Test

1. Snapshot the victim VM.
2. `net user hacker P@ss123! /add & net localgroup Administrators hacker /add`
3. Watch rule 100108 fire, then confirm the response:
   `net user hacker` → *Account active: No*
4. Check the response log on the agent:
   `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log`

## Why only one response rule

Auto-response is a scalpel, not a default: disabling accounts or blocking IPs
off a medium-confidence alert is how SOCs cause their own outages. Rule 100108
is chosen because a *new account appearing in Administrators* is high
confidence and the response is reversible. Everything else in this lab stays
detect-and-investigate.
