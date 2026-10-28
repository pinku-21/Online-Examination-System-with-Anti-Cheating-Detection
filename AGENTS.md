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
