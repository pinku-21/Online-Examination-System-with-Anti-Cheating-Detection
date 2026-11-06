# ExamGuard AI — Tasks

## Phase 1: Zero-cost local AI foundation
- [x] Add a local-only ComfyUI image-generation adapter.
- [x] Reject remote/hosted image-generation endpoints; no paid fallback.
- [x] Add mocked tests for workflow token substitution, queue/poll/download, and invalid output.
- [x] Document local ComfyUI setup and workflow export.
- [ ] Run the complete test suite in a configured development environment.
- [ ] Integrate teacher-facing image generation and preview into the exam authoring UI.
- [ ] Persist approved generated images using the existing persistent asset layer.

## Phase 2: Local text-model agent
- [ ] Evaluate Ollama/local open-weight text models against existing question-generation tests.
- [ ] Add explicit local-first model routing and a strict no-paid-fallback policy.
- [ ] Add bounded memory, tool permissions, and teacher approval checkpoints.
