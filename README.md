# ExamGuard AI

A production-ready web examination platform combining client-side multi-sensor proctoring, AI-assisted question generation, cloud media persistence, transactional scorecards, and cryptographic tamper detection.

[Live Demo](https://exam.pinku19.me/) • [GitHub Repository](https://github.com/pinku-21/Online-Examination-System-with-Anti-Cheating-Detection) • [Portfolio Case Study](https://examguard-portfolio.vercel.app/) • [Report Bug](https://github.com/pinku-21/Online-Examination-System-with-Anti-Cheating-Detection/issues)

---

## Purpose & Design Philosophy

Traditional online examination software typically relies on one of two extremes: heavyweight kernel-level proctoring software that compromises student privacy and requires invasive installations, or unmonitored web forms vulnerable to trivial bypasses. Furthermore, authoring balanced, comprehensive question sets with diagrams and grading rubrics demands considerable faculty time.

**ExamGuard AI** was designed to provide a balanced, privacy-conscious alternative:
1. **Privacy-Preserving Edge Proctoring**: Instead of streaming continuous, high-bandwidth webcam video to a central server, lightweight AI models run locally in the candidate's browser via WebGL. The system computes facial landmark geometry and flags anomalies locally; raw webcam video is never continuously broadcast or recorded, and snapshots are only captured upon confirmed violation events or initial identity verification.
2. **Human-in-the-Loop Integrity Assistance**: Automated sensors flag suspicious indicators—such as secondary electronic devices, candidate absence, multiple individuals in frame, or vocal audio spikes—as contextual telemetry for invigilator triage, rather than making unverified automated disqualification decisions.
3. **Faculty Workflow Acceleration**: Ingests lecture syllabi, PDF notes, or textbook extracts to synthesize structured examinations (MCQs, conceptual questions, descriptive essays, and SVG coordinate diagrams) with consistent evaluation rubrics.
4. **Verifiable Auditability**: Ensures all submission records carry tamper-evident cryptographic digests and forensic telemetry for post-exam review.

---

## Overview

ExamGuard AI provides an integrated examination lifecycle for students and instructors:
- **Instructor Authoring Tooling**: Ingests lecture PDFs, textbook images, or topical syllabi to generate structured exam papers (MCQ, short conceptual, and long essay formats) complete with dynamic vector diagrams, KaTeX-formatted formulas, and rubric keys.
- **Client-Side Edge Monitoring**: Uses browser-level computer vision (TensorFlow.js) and audio analysis (Web Audio API) directly on the student machine to flag unauthorized phones, candidate absence, secondary individuals, and acoustic vocal activity without streaming continuous raw video to the server.
- **Cloud Media Persistence**: Integrates Cloudinary for CDN-backed storage of student handwritten answer photos and forensic incident snapshots, mitigating data loss when ephemeral container disks restart.
- **Network Hazard & VPN Telemetry**: Analyzes incoming client network signatures via BigDataCloud & ipapi to detect Tor exit nodes, datacenter IP proxies, and VPN connections.
- **Cryptographic Tamper Detection**: Signs finalized student submissions with keyed HMAC-SHA256 digests, enabling instructors to detect post-submission modifications to grades, timestamps, or infraction logs.

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
|  - Fallback: Groq Cloud (Qwen/Llama)     |       | - Development: Local SQLite3 (WAL) |
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
 - Audio device test         Mobile phone & device detect     VPN, Proxy & Tor telemetry
 - Fullscreen lock         - BlazeFace:                     - Cloudinary Media CDN:
                             Presence & landmark pose         Student proofs & snapshots
                           - Web Audio API:                 - Resend Email Service:
                             Vocal band energy analysis       Instant HTML scorecards
                           - Window & tab blur tracking
                                     |
                        [ Security Event Dispatcher ]
                         - Incident classification (SEC-001..016)
                         - Graduated strike warning engine
                         - Auto-submission at strike threshold
                         - HMAC-SHA256 tamper-evident digest
```

---

## Core Capabilities

### 1. Automated Question Generation & AI Evaluation
- **Supported Formats**: Multiple choice (4 options with distractor rationale), True/False, short conceptual questions, and long descriptive essays.
- **Multimodal Handwriting Evaluation**: Google Gemini Vision inspects multi-page handwritten student solutions uploaded directly from mobile phone cameras, assigning step marks per official rubric criteria.
- **Blueprint Presets**: Standard university-style 80-mark multi-section exams, 50-mark midterms, or instructor-defined mark and question distributions.
- **Figure & Diagram Synthesis**: Generates inline vector SVG figures (geometric shapes with labeled vertices, coordinate points, schematic outlines) when questions reference visual configurations.
- **Provider Redundancy**: Requests route to Gemini first, falling back automatically to Groq Cloud instances if quota or latency thresholds are hit.

### 2. Browser-Level Proctoring & Security
- **Hardware Device Checking**: Detects virtual video loop drivers (`OBS Virtual Camera`, `ManyCam`) during initial device enumeration.
- **Object Recognition**: Identifies mobile phones, tablets, or external electronic devices visible in the webcam stream using COCO-SSD running in WebGL.
- **Presence & Pose Tracking**: Flags events when zero faces or multiple faces appear in the webcam bounding box, or when yaw/pitch angles indicate prolonged gaze deviation.
- **Acoustic Activity Monitoring**: Analyzes microphone RMS energy against human vocal frequency bands to identify suspicious room chatter or whispering for invigilator review.
- **Environment Containment**: Enforces fullscreen mode, intercepts tab-switching, and suppresses standard browser shortcuts (`Ctrl+C`, `Ctrl+V`, `Ctrl+U`, `F12`, and right-click menus).
- **Grace Periods for Handwritten Work**: Uses a file-browsing latch to silence blur violations when students take and upload photos of written step-by-step solutions.

### 3. Submission Verification & Cloud Telemetry
- **Cryptographic Tamper Detection**: Generates an HMAC-SHA256 signature across student ID, submission status, final score, and strike count on final hand-in, allowing verification against unauthorized database alterations.
- **IP Geolocation & Threat Intelligence**: Automatically resolves candidate City, State, Country, ISP, and flags Datacenter/VPN/Proxy origins.
- **Cloud Media Persistence**: Uploads student answer photos and forensic incident snapshots to **Cloudinary** CDN when configured, with seamless fallback to local storage.
- **Transactional Scorecards**: Dispatches styled HTML scorecards to candidate email inboxes via **Resend** upon result publication.
- **SOC Event Model**: Maps proctoring infractions to structured telemetry codes (`SEC-001` through `SEC-016`) alongside client origin IP and millisecond timestamps:
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
| **Database** | SQLite WAL (local development), PostgreSQL via Neon (production) |
| **Cloud Storage** | Cloudinary (Persistent CDN for student handwriting & forensic audit snaps) |
| **Email Delivery** | Resend API (Automated transactional scorecards & report publication) |
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
