# Sandbox for the lab agent. run_shell and write_file act on this container only.
# Ollama runs natively on the host (Metal GPU on Apple Silicon); the agent reaches it over host.docker.internal.
#
#   docker build -t lab-agent ai-agent-detection
#   mkdir -p ai-agent-detection/logs/live
#   docker run --rm -v "$PWD/ai-agent-detection/logs/live:/logs" lab-agent "list your home directory" --task-id B000
#
# On Linux hosts add: --add-host=host.docker.internal:host-gateway
FROM python:3.12-slim
RUN useradd -m lab && mkdir /logs && chown lab /logs
COPY agent/agent.py /opt/agent/agent.py
USER lab
WORKDIR /home/lab
ENV OLLAMA_URL=http://host.docker.internal:11434 \
    AGENT_LOG=/logs/agent_tool_calls.jsonl \
    PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "/opt/agent/agent.py"]
