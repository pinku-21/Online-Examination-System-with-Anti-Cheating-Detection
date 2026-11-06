# ExamGuard AI — Architecture Decisions

## ADR-001: Zero-cost-first AI architecture
- **Status:** Accepted
- **Decision:** Do not make paid API calls or silently fall back to hosted paid models.
- **Reason:** The project owner requires a zero-cost solution.
- **Consequences:** Prefer local/open-source inference. Free hosted tiers are optional only
  when explicitly configured and verified as free; local operation is the default.

## ADR-002: Local image generation through ComfyUI
- **Status:** Accepted
- **Decision:** Use a self-hosted ComfyUI instance through its local HTTP API as the
  first image-generation backend.
- **Reason:** ComfyUI supports open image models, local execution, and an API workflow.
- **Safety boundary:** The adapter accepts loopback URLs only, has no hosted fallback,
  validates downloaded image bytes and size, and requires an API-exported workflow.
- **Trade-offs:** The user must supply compatible local hardware, install model weights,
  and export a workflow. CPU-only generation may be slow.
- **Reference:** https://github.com/Comfy-Org/ComfyUI
