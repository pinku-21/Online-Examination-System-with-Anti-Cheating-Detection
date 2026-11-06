"""Zero-cost, local-only image generation through a self-hosted ComfyUI instance.

This module deliberately has no hosted-provider fallback. It only talks to a
ComfyUI server bound to localhost, so it cannot silently incur API charges.
"""

from __future__ import annotations

import copy
import json
import os
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests


class LocalImageGenerationError(RuntimeError):
    """Raised when local image generation is unavailable or fails."""


_ALLOWED_IMAGE_TYPES = {
    "image/png": b"\x89PNG\r\n\x1a\n",
    "image/jpeg": b"\xff\xd8\xff",
    "image/webp": b"RIFF",
}
_MAX_IMAGE_BYTES = 15 * 1024 * 1024


def _local_base_url(base_url: str | None = None) -> str:
    """Return a safe loopback-only ComfyUI URL; remote hosts are rejected."""
    raw = (base_url or os.getenv("COMFYUI_LOCAL_URL") or "http://127.0.0.1:8188").strip()
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise LocalImageGenerationError(
            "ComfyUI must be an HTTP service on this same machine "
            "(127.0.0.1, localhost, or ::1). Remote image APIs are disabled."
        )
    return raw.rstrip("/")


def _load_workflow(workflow: dict | str | os.PathLike | None) -> dict:
    """Load an API-format ComfyUI workflow from a dict or local JSON file."""
    source = workflow or os.getenv("COMFYUI_WORKFLOW_PATH")
    if isinstance(source, dict):
        graph = copy.deepcopy(source)
    elif source:
        try:
            with Path(source).expanduser().open("r", encoding="utf-8") as handle:
                graph = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise LocalImageGenerationError(f"Could not load ComfyUI workflow: {exc}") from exc
    else:
        raise LocalImageGenerationError(
            "No ComfyUI API workflow configured. Set COMFYUI_WORKFLOW_PATH "
            "to an API-exported workflow JSON file."
        )

    if not isinstance(graph, dict) or not graph:
        raise LocalImageGenerationError("ComfyUI workflow must be a non-empty JSON object.")
    return graph


def _replace_workflow_tokens(value, prompt: str, negative_prompt: str, seed: int):
    """Replace explicit placeholders anywhere in a ComfyUI API workflow."""
    replacements = {
        "{{PROMPT}}": prompt,
        "{{NEGATIVE_PROMPT}}": negative_prompt,
        "{{SEED}}": str(seed),
    }
    if isinstance(value, dict):
        return {key: _replace_workflow_tokens(item, prompt, negative_prompt, seed)
                for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_workflow_tokens(item, prompt, negative_prompt, seed) for item in value]
    if isinstance(value, str):
        return replacements.get(value, value)
    return value


def _find_output_image(history_entry: dict) -> dict:
    outputs = history_entry.get("outputs") or {}
    for node_output in outputs.values():
        if not isinstance(node_output, dict):
            continue
        for image in node_output.get("images", []):
            if isinstance(image, dict) and image.get("filename"):
                return image
    raise LocalImageGenerationError(
        "ComfyUI completed the workflow but did not return an image. "
        "Check that the workflow contains a SaveImage output node."
    )


def generate_image_locally(
    prompt: str,
    *,
    negative_prompt: str = "",
    seed: int = 0,
    workflow: dict | str | os.PathLike | None = None,
    base_url: str | None = None,
    timeout: int = 180,
    poll_interval: float = 1.0,
    session=None,
) -> dict:
    """Generate one image with a local ComfyUI workflow.

    The workflow must be exported using ComfyUI's "Save (API Format)" option.
    Use {{PROMPT}}, {{NEGATIVE_PROMPT}}, and {{SEED}} as exact node-input values
    in the workflow JSON. Returns image bytes, MIME type, filename and prompt ID.
    """
    if not isinstance(prompt, str) or not prompt.strip():
        raise LocalImageGenerationError("An image prompt is required.")
    if len(prompt) > 4000 or len(negative_prompt) > 2000:
        raise LocalImageGenerationError("Image prompt is too long.")
    try:
        seed = int(seed)
    except (TypeError, ValueError) as exc:
        raise LocalImageGenerationError("Seed must be an integer.") from exc
    timeout = max(5, min(int(timeout), 600))
    poll_interval = max(0.2, min(float(poll_interval), 5.0))

    root = _local_base_url(base_url)
    graph = _replace_workflow_tokens(_load_workflow(workflow), prompt.strip(), negative_prompt, seed)
    client = session or requests.Session()

    try:
        queued = client.post(
            f"{root}/prompt",
            json={"prompt": graph},
            timeout=min(timeout, 30),
        )
        queued.raise_for_status()
        prompt_id = (queued.json() or {}).get("prompt_id")
        if not prompt_id or not isinstance(prompt_id, str):
            raise LocalImageGenerationError("ComfyUI did not return a valid prompt ID.")

        deadline = time.monotonic() + timeout
        history_entry = None
        while time.monotonic() < deadline:
            history_response = client.get(f"{root}/history/{prompt_id}", timeout=15)
            history_response.raise_for_status()
            history = history_response.json() or {}
            history_entry = history.get(prompt_id)
            if history_entry:
                status = history_entry.get("status") or {}
                status_text = str(status.get("status_str", "")).lower()
                if status_text in {"error", "failed"} or status.get("completed") is False and status_text == "error":
                    raise LocalImageGenerationError("The local ComfyUI workflow failed.")
                if status.get("completed") or status_text in {"success", "completed"}:
                    break
            time.sleep(poll_interval)
        else:
            raise LocalImageGenerationError("Timed out waiting for local image generation.")

        image_meta = _find_output_image(history_entry or {})
        image_response = client.get(
            f"{root}/view",
            params={
                "filename": image_meta["filename"],
                "subfolder": image_meta.get("subfolder", ""),
                "type": image_meta.get("type", "output"),
            },
            timeout=30,
        )
        image_response.raise_for_status()
        image_bytes = image_response.content
        content_type = image_response.headers.get("Content-Type", "").split(";")[0].lower()
        signature = _ALLOWED_IMAGE_TYPES.get(content_type)
        valid_signature = bool(signature and image_bytes.startswith(signature))
        if content_type == "image/webp":
            valid_signature = valid_signature and len(image_bytes) >= 12 and image_bytes[8:12] == b"WEBP"
        if (
            not valid_signature
            or not image_bytes
            or len(image_bytes) > _MAX_IMAGE_BYTES
        ):
            raise LocalImageGenerationError(
                "ComfyUI returned an unsupported, invalid, or oversized image."
            )

        return {
            "image_bytes": image_bytes,
            "mime_type": content_type,
            "filename": os.path.basename(image_meta["filename"]),
            "prompt_id": prompt_id,
            "provider": "comfyui-local",
            "cost": 0,
        }
    except LocalImageGenerationError:
        raise
    except requests.RequestException as exc:
        raise LocalImageGenerationError(
            "Could not reach the local ComfyUI service. Start ComfyUI and check "
            "COMFYUI_LOCAL_URL; no cloud fallback will be attempted."
        ) from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise LocalImageGenerationError("ComfyUI returned an invalid response.") from exc
