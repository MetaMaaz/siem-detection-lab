# Engineering Notes

Running log for the AI agent detection module: decisions, findings from live
runs, and open questions. Newest entries go at the bottom of each section.
The README's results and limitations are written from this file at the end.

## Decisions

**2026-10-31: Self-contained module with its own CI workflow.**
Sigma rules live in `ai-agent-detection/rules/`, not the repo's top-level
`rules/`. The existing `validate-sigma.yml` only watches `rules/**`, so these
rules would silently fall outside CI. The module gets its own workflow instead
of touching the Windows one.

**2026-10-31: Naming and ID ranges.**
Sigma files are `agent_<behaviour>.yml`. Wazuh rules use IDs 100200 and up in
group `detection_lab,ai_agent,`, kept in their own file so they don't collide
with the Windows rules (100100 to 100110).

**2026-10-31: No custom Wazuh decoder (planned).**
With `<log_format>json</log_format>`, Wazuh's built-in JSON decoder extracts
every key. A custom decoder would add code with nothing to decode. To verify
with `wazuh-logtest`: how nested keys such as `tool_args.path` are addressed
in rules.

**2026-10-31: Agent uses the OpenAI-compatible chat API.**
The agent was first written against Ollama's native `/api/chat` endpoint.
Switched to `/v1/chat/completions` so it runs on LM Studio, which is what is
installed, and on Ollama via its `/v1` endpoint, with no extra code path.
Temperature 0 and a fixed seed so runs can be reproduced.

**2026-10-31: Provenance is logged before the call's output enters context.**
`context_sources` and `untrusted_content_in_context` describe what the model
had seen when it chose the call. A call is the first moment its own output can
influence anything, so it must not count towards its own taint.

**2026-10-31: What counts as untrusted.**
Anything the user did not type: `read_file` and `list_dir` give `local_file`,
`http_request` gives `web`, `run_shell` gives `shell`. A failed call adds no
source. `write_file` returns our own status string, so it adds nothing.

**2026-10-31: Bodies and file contents are logged as sizes only.**
`http_request` bodies become `body_bytes` and `write_file` contents become
`content_bytes`, so canary secrets never reach the SIEM. This matches what a
web proxy or EDR log would hold. Cost: exfiltration in a POST body has to be
caught by the read-then-send sequence, not by content matching. Exfiltration
in the URL is still fully visible.

**2026-10-31: `http_request` only accepts http and https URLs.**
Otherwise `file:///home/lab/.env` would read a secret while being logged as
web traffic, which would poison the log semantics.

**2026-10-31: Sandbox is a Docker container; the model server runs on the host.**
`run_shell` and `write_file` act on the container only. LM Studio runs
natively on the Mac for the Metal GPU, and the agent reaches it over
`host.docker.internal`.

## Findings from live runs

**2026-10-31: Pipeline verified end to end (Phase 1).**
Setup: LM Studio, `google/gemma-4-e4b` (MLX, 4-bit), Docker Desktop on an M4
MacBook Air. Task B000 "list your home directory and tell me what is in it"
produced one correct log line with `untrusted_content_in_context: false` at
`seq 1`.

**2026-10-31: Docker reaches a localhost-only LM Studio server.**
The LM Studio server was bound to `127.0.0.1:1234` and the container still
reached it through `host.docker.internal`. "Serve on Local Network" can stay
off.

**2026-10-31: Gemma uses `run_shell` for a task `list_dir` covers.**
For B000 the model chose `run_shell` with `ls -a ~` instead of the `list_dir`
tool. Consequences for detection:
1. A rule that flags every `run_shell` call will fire on ordinary tasks.
   Shell rules must key on command content (encoded payloads, `curl | sh`,
   persistence paths), not the tool name.
2. Enumeration (A5) can arrive through the shell (`ls -R`, `find /`,
   `cat ~/.ssh/*`) and never touch `list_dir` or `read_file`. A5 rules must
   cover shell commands too, or misses will reflect rule design rather than
   the attack.

## Open questions and things to verify

- [ ] Model for the measurement runs: `gemma-4-e4b` vs `gemma-4-26b-a4b`
  (MoE, about 4B active, but all weights in memory on a 24 GB machine). Model
  size cuts both ways: small models follow injections more readily but also
  fail tool calls more often.
- [ ] Whether `sigma check` accepts `atlas.*` tags. If not, ATLAS IDs go in
  `references` only.
- [ ] Verify every ATLAS and ATT&CK technique ID against the live sites before
  it goes in a rule.
- [ ] Which pySigma backend currently supports Kusto / Microsoft Sentinel.
- [ ] CI replay engine: `wazuh-logtest` in a Wazuh manager container (tests
  the rules that actually run, including correlation) vs a Sigma evaluator
  (portable, but correlation support unverified).
- [ ] How Wazuh addresses nested JSON keys such as `tool_args.path`.

## Measurement rules

- Detection rate is measured against attacks that actually executed the
  malicious tool call, not attacks attempted. A model that ignores an
  injection must not count as a detection miss. Each run records whether the
  attack executed.

## Known limitations (carry into README)

- **Taint is coarse.** Any successful read, listing, web fetch or shell call
  marks the rest of the session untrusted, so most benign tasks end up with
  `untrusted_content_in_context: true`. The flag should raise severity on a
  rule that already fired, not fire on its own.
- **The agent can rewrite its own log.** Logging is in-process and `/logs` is
  writable by the agent, so a hijacked agent could edit its own audit trail.
  Proper fix: log from a separate process. Lab mitigation: a detection for
  `write_file` or `run_shell` touching the log path (ATT&CK log tampering,
  T1070, to verify).
