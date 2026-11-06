# Free local image generation (ComfyUI)

ExamGuard AI's first image-generation adapter is **local-only**. It does not call
Gemini, Nano Banana, OpenAI, Comfy Cloud, or any hosted image API. If the local
engine is unavailable, the request fails clearly; it never falls back to a
paid provider.

## 1. Install and run ComfyUI locally

Follow the official ComfyUI installation guide for your operating system:
https://github.com/Comfy-Org/ComfyUI

Install a locally runnable open image model compatible with your hardware.
Model downloads may be large and require substantial disk space, RAM, and GPU
memory. Running on CPU is possible for some workflows but may be very slow.

For a strictly offline setup, disable ComfyUI API/partner nodes and do not use
Comfy Cloud or any hosted workflow node. The ComfyUI core supports local
workflows and local API integration.

## 2. Export an API workflow

1. Open ComfyUI and load a text-to-image workflow.
2. Add a SaveImage output node.
3. Set the positive text-encoder input to the exact string `{{PROMPT}}`.
4. Optionally set the negative text-encoder input to `{{NEGATIVE_PROMPT}}`.
5. Optionally set the sampler seed input to `{{SEED}}`.
6. Use **Save (API Format)** / API export and save the JSON file locally.

The workflow should contain a SaveImage node so the adapter can retrieve the
generated image from the local ComfyUI history.

## 3. Configure ExamGuard AI

Set these environment variables in the local development environment:

- `COMFYUI_LOCAL_URL=http://127.0.0.1:8188`
- `COMFYUI_WORKFLOW_PATH=/absolute/path/to/workflow_api.json`

Start ComfyUI first, then start the Flask application. The Python adapter is
available as `generate_image_locally(...)` in `local_image_service.py`.

The adapter deliberately rejects non-loopback hosts, HTTPS/remote URLs, invalid
image responses, and images larger than 15 MB. It uses only the existing
`requests` dependency. There is no paid-provider fallback.

## Cost and privacy notes

- Software and local inference have no per-image API charge.
- Electricity, hardware, internet used to download software/models, and storage
  are not literally free.
- Check the selected model's license before distributing generated outputs.
- Do not expose the unauthenticated ComfyUI port to the public internet.
- Teacher review remains required before generated images are attached to exams.
