"""VCR utility for Bedrock responses -- record real, replay deterministic."""
import hashlib
import json
from pathlib import Path
from typing import Any, Optional
from unittest.mock import patch

CASSETTE_DIR = Path(__file__).parent / "fixtures" / "bedrock_responses"


def cassette_path(prompt_hash: str) -> Path:
    return CASSETTE_DIR / f"{prompt_hash}.json"


def compute_prompt_hash(system_msg: str, user_msg: str) -> str:
    return hashlib.sha256((system_msg + user_msg).encode()).hexdigest()[:16]


def record_response(system_msg: str, user_msg: str, response: dict) -> None:
    ph = compute_prompt_hash(system_msg, user_msg)
    path = cassette_path(ph)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "prompt_hash": ph,
        "response": response,
    }, indent=2))


def get_recorded_response(system_msg: str, user_msg: str) -> Optional[dict]:
    ph = compute_prompt_hash(system_msg, user_msg)
    path = cassette_path(ph)
    if path.exists():
        data = json.loads(path.read_text())
        return data["response"]
    return None


class BedrockVCR:
    """Context manager that intercepts BedrockClient.call_with_tools.

    - If a cassette exists for the prompt: replay it (no network call).
    - If no cassette and mode='record': call real Bedrock, save cassette.
    - If no cassette and mode='replay': return None (simulates Bedrock down).
    """
    def __init__(self, mode: str = "replay"):
        assert mode in ("record", "replay")
        self.mode = mode
        self._patcher = None

    def __enter__(self):
        original = None
        try:
            from app.services.bedrock_client import BedrockClient
            original = BedrockClient.call_with_tools
        except ImportError:
            return self

        vcr_mode = self.mode

        def vcr_call(self_client, system_message, user_message, tools, **kwargs):
            recorded = get_recorded_response(system_message, user_message)
            if recorded is not None:
                return recorded
            if vcr_mode == "record" and original:
                result = original(self_client, system_message, user_message, tools, **kwargs)
                if result is not None:
                    record_response(system_message, user_message, result)
                return result
            return None  # replay mode, no cassette = simulate Bedrock down

        self._patcher = patch.object(
            BedrockClient, "call_with_tools", vcr_call
        )
        self._patcher.start()
        return self

    def __exit__(self, *args):
        if self._patcher:
            self._patcher.stop()
