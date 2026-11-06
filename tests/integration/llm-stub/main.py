"""OpenAI-compatible chat completions stub for CI integration tests.

Returns canned, parser-friendly verdict JSON. The detectflow agent-job's
LlmClient (`app/operators/llm_client.py`) calls any OpenAI-compatible
`/v1/chat/completions` endpoint with `base_url` from settings; pointing
that at this stub satisfies the contract without burning real OpenAI
credentials in CI.

Verdict shape matches `parse_llm_response` (`app/operators/agent_output.py`)
so tests can assert specific values rather than relying on parser
fallbacks.
"""

import json
import time
import uuid

from fastapi import FastAPI, Request

app = FastAPI(title="detectflow LLM stub")

CANNED_RESPONSE = {
    "verdict": "TRUE",
    "confidence": 0.92,
    "summary": "Stub: APT28-style execution chain confirmed (CI mock)",
    "review": {
        "reasoning": (
            "Integration-test stub. The chain shows the textbook APT28 "
            "execution sequence: archive extraction → mshta → wscript → "
            "powershell encoded → schtasks persistence."
        ),
        "indicators": [
            "WinRAR extraction launched mshta",
            "PowerShell EncodedCommand observed",
            "Scheduled task created under SYSTEM context",
        ],
        "recommended_actions": [
            "Isolate WKST-FIN-05",
            "Capture memory image",
            "Review schtasks for persistence",
        ],
    },
}


@app.get("/healthz")
def health():
    return {"ok": True}


@app.post("/v1/chat/completions")
async def chat_completions(req: Request):
    body = await req.json()
    model = body.get("model", "stub-model")

    content = json.dumps(CANNED_RESPONSE)
    return {
        "id": f"chatcmpl-{uuid.uuid4()}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150,
        },
    }


@app.get("/v1/models")
def list_models():
    """Some OpenAI clients probe this on init."""
    return {
        "object": "list",
        "data": [{"id": "stub-model", "object": "model", "owned_by": "stub"}],
    }
