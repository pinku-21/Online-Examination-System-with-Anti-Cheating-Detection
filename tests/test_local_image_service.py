import json

import pytest

from local_image_service import (
    LocalImageGenerationError,
    _local_base_url,
    _replace_workflow_tokens,
    generate_image_locally,
)


class FakeResponse:
    def __init__(self, payload=None, content=b"", headers=None):
        self._payload = payload or {}
        self.content = content
        self.headers = headers or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self.responses.pop(0)

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self.responses.pop(0)


def test_local_url_rejects_remote_hosts_and_https():
    with pytest.raises(LocalImageGenerationError):
        _local_base_url("https://127.0.0.1:8188")
    with pytest.raises(LocalImageGenerationError):
        _local_base_url("http://example.com:8188")


def test_local_url_accepts_loopback():
    assert _local_base_url("http://localhost:8188") == "http://localhost:8188"


def test_workflow_placeholders_are_replaced_recursively():
    graph = {"1": {"inputs": {"text": "{{PROMPT}}", "seed": "{{SEED}}"}}}
    replaced = _replace_workflow_tokens(graph, "A cell", "blur", 42)
    assert replaced["1"]["inputs"] == {"text": "A cell", "seed": "42"}
    assert graph["1"]["inputs"]["text"] == "{{PROMPT}}"


def test_local_generation_submits_polls_and_downloads_png():
    image = b"\x89PNG\r\n\x1a\n" + b"fake-image-data"
    session = FakeSession([
        FakeResponse({"prompt_id": "job-1"}),
        FakeResponse({"job-1": {
            "status": {"completed": True, "status_str": "success"},
            "outputs": {"9": {"images": [{"filename": "generated.png", "type": "output"}]}},
        }}),
        FakeResponse(content=image, headers={"Content-Type": "image/png"}),
    ])

    result = generate_image_locally(
        "A labelled plant cell",
        workflow={"1": {"inputs": {"text": "{{PROMPT}}"}}},
        session=session,
        poll_interval=0.2,
    )

    assert result["image_bytes"] == image
    assert result["mime_type"] == "image/png"
    assert result["provider"] == "comfyui-local"
    assert result["cost"] == 0
    assert session.calls[0][0] == "POST"
    assert session.calls[0][2]["json"]["prompt"]["1"]["inputs"]["text"] == "A labelled plant cell"


def test_local_generation_rejects_non_image_response():
    session = FakeSession([
        FakeResponse({"prompt_id": "job-2"}),
        FakeResponse({"job-2": {
            "status": {"completed": True, "status_str": "success"},
            "outputs": {"9": {"images": [{"filename": "not-image.txt"}]}},
        }}),
        FakeResponse(content=b"not an image", headers={"Content-Type": "text/plain"}),
    ])

    with pytest.raises(LocalImageGenerationError, match="unsupported"):
        generate_image_locally(
            "test prompt",
            workflow={"1": {"inputs": {"text": "{{PROMPT}}"}}},
            session=session,
        )


def test_local_generation_requires_prompt():
    with pytest.raises(LocalImageGenerationError, match="prompt is required"):
        generate_image_locally("  ", workflow={"1": {}})
