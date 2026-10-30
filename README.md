# ExamGuard AI

A production-grade web examination platform with client-side multi-sensor proctoring, automated AI question generation, persistent media cloud storage, transactional notifications, and cryptographic submission verification.

[Live Demo](https://online-examination-system-with-anti.onrender.com/) • [Portfolio Case Study](https://examguard-portfolio.vercel.app/) • [Report Bug](https://github.com/pinku-21/Online-Examination-System-with-Anti-Cheating-Detection/issues)

---

## Overview

Remote testing platforms often face recurring challenges: authoring quality question sets from course syllabi requires immense instructor time, basic browser-based tests are trivial to bypass with secondary devices or VPNs, and serverless hosting risks data loss when ephemeral local disks restart.

**ExamGuard AI** solves these challenges end-to-end:
- **Instructor Tooling**: Ingests lecture PDFs, textbook images, or topical syllabi to generate structured exam papers (MCQ, short conceptual, and long essay formats) complete with dynamic vector diagrams, KaTeX-formatted formulas, and rubric keys.
- **Client-Side Edge Proctoring**: Uses browser-level computer vision (TensorFlow.js) and audio analysis (Web Audio API) directly on the student machine to flag unauthorized phones, candidate absence, secondary individuals, and spoken communication without streaming raw video back to a central server.
- **Persistent Cloud Architecture**: Integrates Cloudinary for CDN-backed handwritten proofs and forensic snapshots, Resend for automated transactional scorecard emails, and Sentry for real-time 24/7 crash monitoring.
- **Anti-Cheat Geolocation & VPN Hazard Detection**: Analyzes incoming client network signatures via BigDataCloud & ipapi to uncover Tor exit nodes, datacenter IP proxies, and VPNs before tests start.
- **Cryptographic Non-Repudiation**: Signs finalized student submissions with keyed HMAC-SHA256 digests so grades, timestamps, and infraction logs cannot be altered in transit or in the database.

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
|  - Primary: Google Gemini 2.5/Flash-Lite | ----> | - Production: Neon PostgreSQL      |
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
     +---------------+---------------+-------------------------------+
     |                               |                               |
     v                               v                               v
[ Pre-Check Identity ]     [ Edge Monitoring Engine ]      [ Network & Cloud Services ]
 - Face verification       - TensorFlow.js (COCO-SSD):      - BigDataCloud / ipapi:
 - Audio device test         Mobile phone / device detect     VPN, Proxy & Tor detection
 - Fullscreen lock         - BlazeFace / FaceMesh:          - Cloudinary Media CDN:
                             Candidate presence & count       Student answers & snapshots
                           - Web Audio API: Voice bandpass  - Resend Email Service:
                           - Window & tab blur tracking       Instant HTML scorecards
                                     |                      - Sentry SDK:
                                     v                        24/7 Crash telemetry
                        [ Security Event Dispatcher ]
                         - Incident classification (SEC-001..016)
                         - Graduated strike warning engine
                         - Forced termination at threshold
                         - HMAC-SHA256 signature generation
```

---

## Core Capabilities

### 1. Automated Question Generation & AI Evaluation
- **Supported Formats**: Multiple choice (4 options with distractor rationale), True/False, short conceptual questions, and long descriptive essays.
- **Multimodal Handwriting Evaluation**: Google Gemini Vision inspects multi-page handwritten student solutions uploaded directly from mobile phone cameras, assigning step marks per official CBSE/University criteria.
- **Blueprint Presets**: Standard university-style 80-mark multi-section exams, 50-mark midterms, or instructor-defined mark and question distributions.
- **Figure & Diagram Synthesis**: Generates inline vector SVG figures (geometric shapes with labeled vertices, coordinate points, schematic outlines) when questions reference visual configurations.
- **Provider Redundancy**: Requests route to Gemini first, falling back automatically to Groq Cloud instances if quota or latency thresholds are hit.

### 2. Browser-Level Proctoring & Security
- **Hardware Device Checking**: Detects virtual video loop drivers (`OBS Virtual Camera`, `ManyCam`) during initial device enumeration.
- **Object Recognition**: Identifies mobile phones, tablets, or external computing equipment visible in the webcam stream using COCO-SSD running in WebGL.
- **Presence Tracking**: Logs events when zero faces or multiple faces appear in the webcam bounding box for longer than 3 seconds.
- **Audio Monitoring**: Analyzes microphone RMS energy against human vocal frequencies to catch whispered questions or verbal room assistance.
- **Environment Containment**: Enforces fullscreen mode, intercepts tab-switching, and suppresses standard browser shortcuts (`Ctrl+C`, `Ctrl+V`, `Ctrl+U`, `F12`, and right-click menus).
- **Grace Periods for Handwritten Work**: Uses a file-browsing latch to silence blur violations when students take and upload photos of written step-by-step solutions.

### 3. Submission Verification & Cloud Telemetry
- **HMAC Signatures**: Generates a cryptographic token over student ID, submission status, final score, and strike count on final hand-in.
- **IP Geolocation & Threat Intelligence**: Automatically resolves candidate City, State, Country, ISP, and flags Datacenter/VPN/Proxy origins.
- **Cloud Media Persistence**: Automatically uploads student answer photos and violation snapshots to **Cloudinary** CDN, preventing loss on container rebuilds.
- **Transactional Scorecards**: Dispatches styled HTML scorecards to candidate email inboxes via **Resend** upon result publication.
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
| **Cloud Storage** | Cloudinary (Persistent CDN for student handwriting & webcam audit snaps) |
| **Email Delivery** | Resend API (Automated transactional scorecards & report publication) |
| **Error Monitoring** | Sentry SDK (Real-time application crash & exception monitoring) |
| **IP & Threat Intel** | BigDataCloud Hazard API, ipapi.co (VPN, Tor, Proxy, and ISP detection) |
| **Edge Vision & Audio**| TensorFlow.js, COCO-SSD, BlazeFace, Web Audio API |
| **AI Providers** | Google Gemini API (Flash-Lite / Vision), Groq Cloud API, OpenRouter |
| **Document Processing**| PyPDF, Pillow |
| **Frontend** | HTML5, Vanilla JavaScript, Tailwind CSS, KaTeX, SweetAlert2, Lucide Icons |
| **Testing & CI/CD** | Pytest, Locust, Aikido Security (automated CVE scanning) |

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

# Model Providers
GEMINI_API_KEY=your_gemini_key_here
GROQ_API_KEY=your_groq_key_here
OPENROUTER_API_KEY=your_openrouter_key_here

# Cloud Integrations (free-for-dev)
CLOUDINARY_CLOUD_NAME=your_cloud_name
CLOUDINARY_API_KEY=your_cloudinary_api_key
CLOUDINARY_API_SECRET=your_cloudinary_api_secret
RESEND_API_KEY=your_resend_api_key
SENTRY_DSN=your_sentry_dsn
BIGDATACLOUD_API_KEY=your_bigdatacloud_key

# Database (optional; defaults to local SQLite if left empty)
DATABASE_URL=postgresql://user:password@host/dbname?sslmode=require
```

### Running Locally

```bash
python run.py
```

The application will start on `http://127.0.0.1:5000`.

---

## Automated Tests

Run the test suite with pytest:

```bash
python -m pytest tests/
```
