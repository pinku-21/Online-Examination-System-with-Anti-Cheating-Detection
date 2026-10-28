# ExamGuard AI

A web-based examination platform with client-side proctoring, automated question authoring, and cryptographic submission verification.

[Live Demo](https://online-examination-system-with-anti.onrender.com/) • [Portfolio Case Study](https://examguard-portfolio.vercel.app/) • [Report Bug](https://github.com/pinku-21/Online-Examination-System-with-Anti-Cheating-Detection/issues)

---

## Overview

Remote testing platforms often face two recurring problems: authoring quality question sets from course material takes significant instructor time, and basic browser-based tests are trivial to bypass with secondary devices, split screens, or virtual camera streams.

ExamGuard AI addresses both issues:
- **Instructor Tooling**: Ingests lecture PDFs, textbook images, or topical syllabi to generate structured exam papers (MCQ, short conceptual, and long essay formats) with dynamic vector diagrams, KaTeX-formatted formulas, and rubric keys.
- **Client-Side Edge Proctoring**: Uses browser-level computer vision (TensorFlow.js) and audio analysis (Web Audio API) directly on the student machine to flag unauthorized phones, candidate absence, secondary individuals, and spoken communication without streaming raw video back to a central server.
- **Data Integrity**: Signs finalized student submissions with keyed HMAC-SHA256 digests so grades, timestamps, and infraction logs cannot be altered in transit or in the database.

---

## System Architecture

```text
                               +-----------------------------+
                               |     Instructor Portal       |
                               | (Flask + Tailwind + KaTeX)  |
                               +--------------+--------------+
                                              |
                     +------------------------+------------------------+
                     |                                                 |
                     v                                                 v
         [ Syllabus Ingestion ]                             [ Exam Management ]
     (PDF text, diagrams, prompts)                  (Code generation, timer, limits)
                     |                                                 |
                     v                                                 v
+------------------------------------------+       +------------------------------------+
|        AI Generation Gateway             |       |            Database Layer          |
|  - Primary: Google Gemini 2.5/3.8 Flash  | ----> | - Production: Neon PostgreSQL      |
|  - Fallback: Groq Cloud (Qwen/Llama)     |       | - Development: Local SQLite3       |
|  - Output: Questions, SVG, Rubrics       |       +-----------------+------------------+
+------------------------------------------+                         |
                                                                     |
                     +-----------------------------------------------+
                     |
                     v
       +----------------------------+
       |   Candidate Exam Portal    |
       |  (Browser-Sandboxed Room)  |
       +-------------+--------------+
                     |
     +---------------+---------------+
     |                               |
     v                               v
[ Pre-Check Identity ]     [ Edge Monitoring Engine ]
 - Face verification       - TensorFlow.js (COCO-SSD): Mobile device detection
 - Audio device test       - BlazeFace / FaceMesh: Candidate presence & count
 - Fullscreen lock         - Web Audio API: Acoustic energy / voice bandpass
                           - Window & tab blur event tracking
                                     |
                                     v
                        [ Security Event Dispatcher ]
                         - Incident classification (SEC-001..016)
                         - Graduated strike warning engine
                         - Forced termination at threshold
                         - HMAC-SHA256 signature generation
```

---

## Core Capabilities

### 1. Automated Question Generation
- **Supported Formats**: Multiple choice (4 options with distractor rationale), True/False, short conceptual questions, and long descriptive essays.
- **Blueprint Presets**: Standard university-style 80-mark multi-section exams, 50-mark midterms, or instructor-defined mark and question distributions.
- **Figure & Diagram Synthesis**: Generates inline vector SVG figures (geometric shapes with labeled vertices, coordinate points, schematic outlines) when questions reference visual configurations.
- **Provider Redundancy**: Requests route to Gemini first, falling back automatically to Groq Cloud instances if quota or latency thresholds are hit.

### 2. Browser-Level Proctoring
- **Hardware Device Checking**: Detects virtual video loop drivers (`OBS Virtual Camera`, `ManyCam`) during initial device enumeration.
- **Object Recognition**: Identifies mobile phones, tablets, or external computing equipment visible in the webcam stream using COCO-SSD running in WebGL.
- **Presence Tracking**: Logs events when zero faces or multiple faces appear in the webcam bounding box for longer than 3 seconds.
- **Audio Monitoring**: Analyzes microphone RMS energy against human vocal frequencies to catch whispered questions or verbal room assistance.
- **Environment Containment**: Enforces fullscreen mode, intercepts tab-switching, and suppresses standard browser shortcuts (`Ctrl+C`, `Ctrl+V`, `Ctrl+U`, `F12`, and right-click menus).
- **Grace Periods for Handwritten Work**: Uses a file-browsing latch to silence blur violations when students take and upload photos of written step-by-step solutions.

### 3. Submission Verification & SIEM Telemetry
- **HMAC Signatures**: Generates a cryptographic token over student ID, submission status, final score, and strike count on final hand-in.
- **SOC Event Model**: Maps all proctoring infractions to structured codes (`SEC-001` through `SEC-016`) alongside client IP and millisecond timestamps:
  - `SEC-001`: Virtual video driver detected
  - `SEC-002`: Multiple faces detected in frame
  - `SEC-003`: Candidate out of frame (>3s)
  - `SEC-004`: Mobile phone / electronic device identified
  - `SEC-007`: Tab switch or window blur event
  - `SEC-010`: DevTools or console inspection attempt

---

## Technology Stack

| Layer | Component |
| :--- | :--- |
| **Backend** | Python 3.12 / 3.13, Flask 3.x, Gunicorn, Werkzeug |
| **Database** | SQLite (local development), PostgreSQL via Neon (production) |
| **Edge Vision & Audio** | TensorFlow.js, COCO-SSD, BlazeFace, Web Audio API |
| **AI Providers** | Google Gemini API, Groq Cloud API, OpenRouter |
| **Document Processing** | PyPDF, Pillow |
| **Frontend** | HTML5, Vanilla JavaScript, Tailwind CSS, KaTeX, SweetAlert2 |
| **Testing** | Pytest, Locust (load benchmarking) |

---

## Getting Started

### Prerequisites
- Python 3.12 or newer
- Standard build tools and pip
- Modern web browser with webcam and microphone support

### Installation

```bash
# 1. Clone repository
git clone https://github.com/pinku-21/Online-Examination-System-with-Anti-Cheating-Detection.git
cd Online-Examination-System-with-Anti-Cheating-Detection

# 2. Create virtual environment
python -m venv venv

# Windows
.\venv\Scripts\activate
# Linux / macOS
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Environment Configuration

Create a `.env` file in the project root:

```ini
# Core
SECRET_KEY=change-this-to-a-strong-random-key
FLASK_DEBUG=False

# Model Providers (at least one required for live AI generation)
GEMINI_API_KEY=your_gemini_key_here
GROQ_API_KEY=your_groq_key_here

# Database (optional; defaults to local SQLite if left empty)
DATABASE_URL=postgresql://user:password@host/dbname?sslmode=require
```

### Running Locally

```bash
python run.py
```

The application will start on `http://127.0.0.1:5000`.

---

## Verification & Tests

A test suite covers the security classification engine, submission hashing, and endpoint authorization:

```bash
python -m pytest tests/ -v
```

Expected output:
```text
tests/test_anti_cheat.py::test_security_event_classification PASSED
tests/test_anti_cheat.py::test_security_event_fallback PASSED
tests/test_anti_cheat.py::test_cryptographic_integrity_hash_consistency PASSED
tests/test_anti_cheat.py::test_cryptographic_integrity_tamper_detection PASSED
tests/test_anti_cheat.py::test_secondary_camera_security_event_classification PASSED
tests/test_anti_cheat.py::test_mobile_companion_pairing_auth PASSED
tests/test_anti_cheat.py::test_question_bank_api_auth PASSED
============================== 9 passed in 1.15s ==============================
```

---

## Repository Layout

```text
├── app.py                  # HTTP routing, authentication, proctoring endpoints
├── ai_service.py           # Multi-provider generation and diagram handling
├── database.py             # Dual DB abstraction (SQLite / PostgreSQL)
├── run.py                  # Local runner
├── requirements.txt        # Python dependency manifest
├── static/                 # Static assets, KaTeX bundle, vendor JS
├── templates/              # Jinja2 views (exam room, dashboards, admin views)
├── tests/                  # Security and unit test suites
└── TASKS.md                # Development roadmap and tracking
```

---

## License

This project is released under the [MIT License](LICENSE).
