# AI Agent Detection

Detecting a hijacked AI agent from its tool-call logs. Work in progress:
Phase 1 (agent, tools, logging) is done. Threat model, detections and
measured results land in later phases.

## Run

Ollama runs natively on the host; the agent runs in a container so
`run_shell` and `write_file` only touch the sandbox.

```bash
ollama pull qwen2.5:7b
docker build -t lab-agent ai-agent-detection
mkdir -p ai-agent-detection/logs/live
docker run --rm -v "$PWD/ai-agent-detection/logs/live:/logs" lab-agent \
  "list your home directory and summarise it" --task-id B000
```

Settings come from environment variables: `AGENT_MODEL`, `OLLAMA_URL`,
`AGENT_ID` and `AGENT_LOG`.

Tests need no Ollama: `python ai-agent-detection/tests/test_agent.py`

## Log schema

One JSON line per tool call. The log is written **before** the call's output
enters the model's context, so provenance describes what the model had seen
when it chose the call.

| Field | Example | Notes |
|---|---|---|
| `timestamp` | `2026-10-31T18:46:15.082Z` | UTC, ms |
| `session_id` | UUIDv4 | one per task run; correlation key |
| `agent_id` | `lab-agent-01` | |
| `model` | `qwen2.5:7b` | to compare susceptibility across models |
| `user_task_id` | `B001`, `A1-03` | links to the payload / benign task set |
| `seq` | `3` | tool call order within the session |
| `tool_name` | `read_file` | `read_file`, `write_file`, `list_dir`, `http_request`, `run_shell` |
| `tool_args` | `{"path": "~/.aws/credentials"}` | see below |
| `context_sources` | `["local_file","user","web"]` | sources of content in context so far |
| `untrusted_content_in_context` | `true` | true once any non-user content is in context |
| `result_status` | `ok` / `error` | non-zero shell exit, HTTP error, refused URL scheme and unknown tool all count as `error` |
| `bytes_returned` | `1342` | size of tool output |

Content sources: `read_file` and `list_dir` give `local_file`, `http_request`
gives `web`, `run_shell` gives `shell`. All three count as untrusted. A failed
call adds no source.

`tool_args` records paths, URLs and commands in full. HTTP bodies and file
contents are recorded only as `body_bytes` / `content_bytes`, so exfiltrated
canary secrets never reach the SIEM. This matches what a web proxy or EDR log
would hold.
