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
                                     |
                                     v
                 +---------------------------------------+
                 |   Security Operations Center (SOC)    |
                 |   - Multi-Entity Risk Engine          |
                 |   - Anomaly Detection (5 vectors)     |
                 |   - RFC 6238 TOTP + AES-256-GCM MFA   |
                 |   - Human-in-the-Loop Policy Engine   |
                 |   - Unified Investigation Dossier     |
                 +---------------------------------------+
```

---

## Application Structure

The platform is structured into modular layers separation between presentation, application logic, persistence, and security intelligence:

```text
├── app.py                      # Core Flask application, routing, auth middleware, and API endpoints
├── database.py                 # Unified database layer (SQLite WAL dev & Neon PostgreSQL production)
├── cloud_services.py           # External integrations: Gemini, Groq, Cloudinary, Resend, IP Geolocation
├── run.py                      # Local development application runner
├── Procfile                    # Production Gunicorn worker and thread execution declaration
│
├── security/                   # Adaptive Security & Intelligence Subsystem
│   ├── __init__.py             # Security package interface and facade exports
│   ├── event_collector.py      # Transactional & asynchronous security telemetry collector
│   ├── event_correlator.py     # Cross-entity activity correlation (User, Session, Device, IP)
│   ├── risk_engine.py          # Bounded 5-entity adaptive risk scoring & historical audit logs
│   ├── anomaly_detector.py     # Deterministic behavioral anomaly rules (failed logins, device/alert bursts)
│   ├── incident_manager.py     # Incident creation, lifecycle states, notes, and audit history
│   ├── policy_engine.py        # Configurable security policies & human-approved recommendations
│   ├── incident_intelligence.py# Unified investigation dossier & chronological timeline compiler
│   ├── session_security.py     # Device fingerprinting, token rotation, and multi-session containment
│   └── mfa_service.py          # RFC 6238 TOTP, recovery codes, and AES-256-GCM encryption at rest
│
├── static/                     # Front-end static assets
│   ├── js/
│   │   ├── csrf_guard.js       # Auto-refreshing double-submit CSRF interceptor for fetch/XHR
│   │   ├── sync_engine.js      # Universal multi-tab exam synchronizer and heartbeat
│   │   └── proctor.js          # Client-side TensorFlow.js and MediaPipe edge inference
│   └── extracted_figures/      # Temporary vector diagram assets
│
├── templates/                  # Jinja2 application views
│   ├── base.html               # Master layout containing CSRF synchronizers and theme assets
│   ├── login.html              # Multi-role authentication view with MFA redirect handling
│   ├── mfa_verify.html         # TOTP challenge & emergency recovery code submission portal
│   ├── soc_dashboard.html      # Administrator Security Operations Center interactive console
│   ├── tutor_dashboard.html    # Live invigilator cockpit and ongoing exam monitor
│   ├── student_exam.html       # Sandboxed browser exam room with local proctoring
│   ├── exam_details.html       # Exam policy setup and question inspection
│   └── exam_paused.html        # Multi-device session displacement and reconnection screen
│
└── tests/                      # Automated test suite (202 unit, integration, and E2E tests)
    ├── test_adaptive_security_phase4.py    # Risk engine, anomaly detection, and scoring boundaries
    ├── test_postgres_integration.py       # Live PostgreSQL integration, migrations, and concurrency
    ├── test_browser_soc_dashboard.py      # Playwright browser end-to-end tests for SOC console
    ├── test_csrf_defense.py               # Synchronizer token, IDOR, and session security tests
    ├── test_mfa_and_session_security.py   # TOTP RFC 6238 and AES-256-GCM key rotation verification
    └── test_incident_management.py        # Incident audit trail, notes, and status transition tests
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

### 4. Security Operations Center (SOC) & Adaptive Intelligence
- **Administrator SOC Portal**: Accessible at `/admin/security/soc`, providing administrators with a unified console for active threat telemetry, correlated incident dossiers, risk score distribution, and policy-driven remediation.
- **Multi-Factor Authentication (MFA)**: Built-in RFC 6238 TOTP verification (compatible with Google Authenticator, Authy, 1Password) with single-use SHA-256 hashed emergency recovery codes and AES-256-GCM encryption of stored secrets at rest.
- **Multi-Entity Risk Scoring Engine**: Calculates bounded, non-inflationary risk scores across 5 contextual entities (Account, Session, Device, IP, Examination) with deterministic scoring, diminishing returns, and time-decay weighting.
- **Behavioral Anomaly Detection**: Evaluates deterministic behavioral rules against security event streams:
  - *Failed Login Threshold*: Detects repeated failed authentications (>= 3 attempts within window).
  - *Device Replacement Threshold*: Flags rapid hardware or browser switches (>= 2 switches within window).
  - *Unauthorized Access Threshold*: Identifies broken access control and IDOR attempts (>= 3 violations within window).
  - *Security-Event Density Threshold*: Identifies elevated alert density (>= 15 security alerts generated within 5 minutes) as a proxy for unusual security activity (not API velocity measurement).
  - *Abnormal Examination Activity*: Detects active tampering attempts (answer modification conflicts or state tampering during examinations).
- **Human-in-the-Loop Security Policy Engine**: Evaluates risk thresholds against customizable active policies to generate actionable recommendations (`PENDING_REVIEW`, `APPROVED`, `REJECTED`, `DISMISSED`) that never terminate candidate exams without explicit administrator or proctor approval.
- **Unified Incident Intelligence & Chronological Timeline**: Correlates related security events, risk assessments, session fingerprints, and administrator notes into a comprehensive investigation dossier.
- **CSRF & Session Security**: Robust Double Submit / Synchronizer token defense with auto-refreshing via `/api/csrf-token`, strict Same-Origin verification, and `HttpOnly`, `SameSite=Lax`, and `Secure` cookie boundaries.

---

## System Limitations & Ethical Boundary Disclosures

To prevent misinterpretation of security telemetry, ExamGuard AI enforces clear operational and forensic boundaries:

1. **AI Proctoring Signals are Indicators, Not Proof**:
   Automated sensor events (e.g. absence, face angle deviation, acoustic spikes, object detection bounding boxes) are probabilistic telemetry intended to assist human invigilators. Environmental factors—such as poor lighting, webcam angle, room reflections, or involuntary coughing—can generate false positives. Automated flags must never be treated as definitive proof of academic dishonesty.
2. **Risk Scores Support Investigation, Not Disqualification**:
   The multi-entity risk engine outputs contextual risk scores (0–100) strictly as an analytical priority ranking for investigation queues. High risk scores never trigger automated exam termination, grade cancellation, or punitive actions without human review.
3. **IP Correlation Alone Cannot Establish Identity**:
   Shared IP addresses (e.g. university campus Wi-Fi, dormitories, Carrier-Grade NATs, public libraries) are common. Correlation of activity by IP address provides situational awareness only and must never be used alone to deduce that two disparate accounts belong to the same person.
4. **Security Recommendations Require Human Review**:
   The policy engine produces recommendations (e.g., advising step-up authentication, proctor review, or session containment). Recommendations require explicit triage (`APPROVED`, `REJECTED`, `DISMISSED`) by an authenticated administrator or invigilator before taking administrative effect.
5. **HMAC Audit Features Provide Tamper Evidence, Not Immutability**:
   Keyed HMAC-SHA256 digests bind finalized student answers, scores, and infractions against the server's private secret. While this guarantees tamper-evidence against unauthorized modification in transit or at rest, it represents a cryptographic audit verification mechanism, not a decentralized, distributed, or immutable ledger.

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
# Core Application Configuration
SECRET_KEY=change-this-to-a-strong-random-key
FLASK_DEBUG=False

# MFA Encryption Key (Mandatory in Production/Staging: 32-byte hex string)
MFA_ENCRYPTION_KEY=your_32_byte_hex_encryption_key_here
# MFA_PREVIOUS_KEYS=key1,key2  # Optional: for smooth zero-downtime key rotation

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

# Database Configuration (Defaults to local SQLite WAL if unset or empty)
DATABASE_URL=postgresql://user:password@host/dbname?sslmode=require

# Test Database URL (For isolated PostgreSQL integration testing only)
# TEST_DATABASE_URL=postgresql://user:password@host/examguard_test?sslmode=require
```

### Security & SOC API Endpoints

The Security Operations Center exposes dedicated, authenticated endpoints strictly gated to the `admin` role:

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/admin/security/soc` | `GET` | HTML SOC interactive investigation dashboard |
| `/api/admin/security/overview` | `GET` | Real-time threat metrics, incident counts, and high-risk summaries |
| `/api/admin/security/events` | `GET` | Paginated, redacted security telemetry stream with multi-field filtering |
| `/api/admin/security/risks` | `GET` | On-demand multi-entity risk scoring and historical audit log retrieval |
| `/api/admin/security/incidents` | `GET` | Incident collection with severity, status, and assignment filters |
| `/api/admin/security/incident/<id>` | `GET` | Comprehensive incident dossier with correlated events and assessments |
| `/api/admin/security/incident/<id>/timeline`| `GET` | Chronologically ordered unified investigation activity timeline |
| `/api/admin/security/incident/<id>/status` | `POST` | Incident lifecycle state transition (`INVESTIGATING`, `RESOLVED`, `CLOSED`) |
| `/api/admin/security/incident/<id>/note` | `POST` | Immutable investigator notes with author identity binding |
| `/api/admin/security/recommendations` | `GET` | Active security recommendations requiring human administrator triage |
| `/api/admin/security/recommendation/<id>/review` | `POST` | Administrator decision submission (`APPROVED`, `REJECTED`, `DISMISSED`) |
| `/mfa/verify` | `GET`, `POST` | Two-Factor authentication challenge and emergency recovery entry |
| `/api/admin/mfa/setup` | `GET` | Generates TOTP Base32 secret and QR provisioning URI |
| `/api/admin/mfa/confirm` | `POST` | Confirms code, securely encrypts secret with AES-256-GCM, issues recovery codes |
| `/api/admin/mfa/disable` | `POST` | Revokes MFA enrollment after password and active code re-verification |
| `/api/csrf-token` | `GET` | Synchronizer token refresh for Single Page Application state persistence |

---

### Running Locally

```bash
python run.py
```

The application will start on `http://127.0.0.1:5000`.

---

## Automated Tests

Run the full automated regression suite (202 tests covering unit, integration, browser, and security tests):

```bash
python -m pytest tests/
```

To run only the isolated PostgreSQL integration tests (requires `TEST_DATABASE_URL` pointing to `examguard_test`):

```bash
python -m pytest tests/test_postgres_integration.py -v
```

---

## Staging Release Checklist

Before deploying ExamGuard AI to an isolated staging environment or promoting builds to production, complete the following verification checklist:

### 1. Cloud Infrastructure & Isolation
- [ ] **Dedicated Render Web Service**: Provision a separate web service (`examguard-ai-staging`) distinct from production.
- [ ] **Dedicated Neon PostgreSQL Database**: Create a completely independent Neon database project (`examguard_staging`) with its own compute endpoint.
- [ ] **Zero Credential Sharing**: Verify staging connection strings, API keys, and passwords share zero overlap with production.
- [ ] **Network Separation**: Ensure the staging web service cannot connect to or resolve the production database.

### 2. Environment Variables & Secret Configuration
- [ ] **Independent `SECRET_KEY`**: Generated via `python -c "import secrets; print(secrets.token_hex(32))"` and set exclusively in staging.
- [ ] **Independent `MFA_ENCRYPTION_KEY`**: Dedicated 32-byte hex key generated for staging secret encryption at rest.
- [ ] **Staging-Only `DATABASE_URL`**: Verified connection string formatted with `sslmode=require` pointing to `examguard_staging`.
- [ ] **Production Flags**: `FLASK_ENV=production` and `FLASK_DEBUG=False` configured to prevent debug trace leakage.
- [ ] **Secure Cookies**: `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`, and `SESSION_COOKIE_SAMESITE=Lax` active.

### 3. Database Initialization & Synthetic Data
- [ ] **Automated Migration**: Verify application boot executes `database.init_db()` and `database.run_pg_migrations()` cleanly on Neon staging.
- [ ] **Schema Conformance**: Verify all Phase 4 tables (`security_events`, `security_incidents`, `security_policies`, `security_recommendations`, `risk_audit_log`) and partial unique indexes exist.
- [ ] **Default Policies**: Confirm default security policies are seeded idempotently.
- [ ] **Strict Synthetic Data Policy**: Zero real candidate records, submission histories, or production MFA secrets imported into staging.
- [ ] **Synthetic Accounts Seeded**: Create disposable staging users (`staging_admin@examguard.ai`, `staging_tutor@examguard.ai`, `staging_student@examguard.ai`).

### 4. Health & Security Verification
- [ ] **Liveness Probe**: Verify `GET /health` returns HTTP 200 `{"status": "ok", "database": "connected"}`.
- [ ] **Administrator SOC Access**: Confirm `/admin/security/soc` renders correctly for `admin` role and strictly rejects unauthenticated or `student`/`tutor` requests with HTTP 401/403.
- [ ] **MFA Challenge & Enrollment**: Test TOTP setup via `/api/admin/mfa/setup`, confirm registration, verify AES-256-GCM ciphertext storage in database, and validate emergency recovery code consumption.
- [ ] **CSRF & Session Security**: Verify CSRF token acquisition at `/api/csrf-token`, confirm state-changing requests reject invalid tokens with `SEC-016`, and verify cross-origin requests are blocked.
- [ ] **Single Active Session Enforcement**: Verify that concurrent logins from a secondary device displace the primary session and display resumption notices.

### 5. Examination & Proctoring End-to-End Workflow
- [ ] **Instructor Exam Creation**: Author and publish an exam with questions, time limits, and security integrity policies enabled.
- [ ] **Student Proctoring Room**: Ensure webcam, microphone, and fullscreen permissions request properly without browser crashes.
- [ ] **Edge Infraction Dispatch**: Simulate client events (tab-switch blur, secondary device, absence) and confirm security telemetry arrives at `/api/security-event`.
- [ ] **SOC Incident & Recommendation Triage**: Open generated recommendations in SOC console, execute triage decisions (`APPROVED`, `REJECTED`, `DISMISSED`), and add investigator notes.
- [ ] **Exam Submission & Result Flow**: Complete student submission, verify HMAC-SHA256 signature generation, and confirm scorecard rendering.

### 6. Observability & Log Hygiene
- [ ] **Application Logs**: Verify Gunicorn structured logs in Render dashboard contain no plaintext passwords, session tokens, or unencrypted MFA secrets.
- [ ] **Error Rate Monitoring**: Confirm zero recurring unhandled 500 errors during standard test execution.

