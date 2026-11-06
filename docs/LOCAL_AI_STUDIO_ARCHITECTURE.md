# Local AI Studio — Hybrid Architecture

## Goals
- Add a third Local AI Studio workspace to the existing AI Exam & Question Studio.
- Preserve the existing Gemini generation workflow, pasted-paper ingestion, database schema, and Cloudinary media storage.
- Use Ollama-compatible local models without paid inference APIs or automatic paid fallbacks.
- Keep the interface responsive for desktop and mobile.

## Runtime modes
1. **Local PC mode:** Ollama runs on the user's Windows PC. The web application must connect through an explicitly configured, authenticated local bridge or secure tunnel; a Render-hosted Flask process cannot reach the user's `localhost`.
2. **Optional remote mode:** A separately operated Ollama host can serve mobile devices when the PC is unavailable. It must be opt-in, authenticated, and must not be provisioned on a paid plan without explicit approval.
3. **Unavailable mode:** If neither endpoint is reachable, show a clear offline state. Never silently fall back to Gemini, Groq, OpenRouter, or another paid API.

## Security requirements
- Never expose Ollama's unauthenticated port 11434 directly to the public internet.
- Keep endpoint credentials in server-side environment variables or a secrets manager; never put secrets in browser JavaScript, templates, logs, or Git.
- Require HTTPS and authentication for any remote gateway.
- Use request timeouts, response-size limits, and allowlisted model names.
- Do not transmit student answer images or personal data to a remote model unless the user explicitly enables that workflow and the data handling is documented.

## Implementation sequence
1. Add an isolated Local AI Studio page and navigation tab.
2. Add a provider-neutral Ollama connection manager with explicit local/remote selection and health checks.
3. Add chat and model listing after the connection path is validated.
4. Add document intelligence, agents, and memory as separate modules later.

## Deployment boundary
The initial UI and connection abstraction must not alter existing exam generation, pasted-paper parsing, Cloudinary uploads, or database migrations. No deployment, paid infrastructure provisioning, or automatic API fallback is authorized by this plan.
