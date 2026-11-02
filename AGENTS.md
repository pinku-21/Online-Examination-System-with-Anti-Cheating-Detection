# Project Agent Instructions: ExamGuard AI

## Project Overview
ExamGuard AI is a proctored examination platform with multi-sensor anti-cheating detection and AI question generation built using Flask, SQLite/Neon PostgreSQL, TensorFlow.js, MediaPipe, and Gemini/Groq APIs.

## Technology Stack
- **Backend**: Python 3.12/3.13, Flask, Gunicorn
- **Database**: SQLite (dev) / PostgreSQL (Neon production) via `database.py`
- **Frontend**: HTML5, Vanilla JavaScript, Tailwind CSS (CDN), KaTeX, Lucide Icons, SweetAlert2
- **Client AI Proctoring**: TensorFlow.js (BlazeFace, COCO-SSD), MediaPipe FaceMesh
- **Server AI Services**: Google Gemini API, Groq Cloud API via `ai_service.py`
- **Testing**: `pytest`, `locust`

## Continuity Rules
All contributors and AI agents must follow [continuity.md](file:///.agents/rules/continuity.md):
- Maintain `TASKS.md`, `DECISIONS.md`, and `SESSION_LOG.md`.
- Inspect code before editing.
- Verify changes with tests (`python -m pytest tests/`).
- **Auto-Push Policy**: Automatically stage, commit, and push (`git push origin <branch>`) after any code changes without requiring an explicit user prompt.

## Recommended ECC Skills
When executing engineering tasks in ExamGuard AI, prioritize these project-tailored ECC skills:
- **`flask-patterns`**: Flask routing, Jinja2 template blocks, SQLite `sqlite3.Row` vs PostgreSQL dictionary safety, and security middleware.
- **`tfjs-proctoring`**: Client-side TensorFlow.js memory lifecycle (`tf.tidy`), BlazeFace/COCO-SSD detection, MediaPipe FaceMesh, camera gating (video OFF bypass), and MediaRecorder audio handling.
- **`tdd-workflow`**: Test-driven development with pytest, regression isolation, and coverage verification.
- **`python-testing`**: Python and Flask test fixture design, database mocking, and test client assertions.
- **`postgres-patterns`**: PostgreSQL schema design, indexing, connection pooling, and Neon production database query optimization.
- **`database-migrations`**: Safe schema alterations across SQLite development and PostgreSQL production environments.
- **`security-review`**: Web application security auditing, CSRF prevention, session hygiene, and access control validation.
- **`production-audit`**: Pre-deployment verification, environment checks, and defensible security auditing.
- **`backend-patterns`**: Production API design, error response formats, and server architecture.
- **`architecture-decision-records`**: Structured logging of technical and architectural trade-offs in `DECISIONS.md`.
- **`verification-loop`**: Systematic verification of changes with unit, integration, and security test gates.
