# 🛡️ ExamGuard AI — Smart Online Examination System with Anti-Cheating Detection & AI Question Generation


> **Domain:** BTech & Cybersecurity / Web Application & AI  
> **Target Audience:** Online Tutors, Educators, Academic Institutions, and Students  

---

## 📌 Project Overview
As an online tutor or educator, two major challenges exist in remote education:
1. **Time-consuming question authoring**: Creating high-quality, balanced multiple-choice questions (MCQs) for every chapter, syllabus change, or test.
2. **Online Exam Integrity**: Preventing cheating during exams where students switch tabs to Google answers, communicate on other apps, or use dual screens.

**ExamGuard AI** solves both challenges in an integrated, web-based platform:
- **AI Question Studio**: Upload any chapter **PDF notes** or **textbook photos**. Powered by Google Gemini AI (multimodal vision + text), it automatically extracts concepts and generates MCQs with options, correct answers, and explanations.
- **Multi-Layer Anti-Cheating Engine**: Enforces strict full-screen exam mode, monitors tab switches and window blur, disables copy-paste & inspection shortcuts, and gives a **3-Strike Warning System** before forcefully terminating and auto-submitting the exam.
- **Proctoring Audit Log**: Tutors can review timestamped violation records and student scores.

---

## 🚀 Key Features

### 1. 🤖 Dual AI Question Generator (Google Gemini & Groq Cloud)
- **Multimodal Inputs**: Accepts PDF files (e.g., lecture notes, chapter excerpts), image files (photos of book pages, handwritten notes), and text prompts.
- **Dual-Model Fallback**: Powered by Google Gemini (`gemini-3.5-flash-lite`, `gemini-3.8-flash`) with automatic high-speed failover to Groq (`qwen/qwen3.8-27b`).
- **Customizable Question Banks**: Choose number of questions (3, 5, 10, 15+), difficulty level (*Easy, Medium, Hard*), and question types (*MCQ with 4 choices, True/False*).
- **Interactive Question Editor**: Tutors can review, edit question text, modify choices, toggle the correct answer radio button, or add manual questions before publishing.

### 2. 🛡️ Multi-Sensor Anti-Cheating & AI Proctoring Engine
- **📱 AI Mobile Phone & Device Detection (TensorFlow.js COCO-SSD)**: Detects smartphones, tablets, or unauthorized electronic devices held up in view of the webcam and logs an immediate strike.
- **👤 Real-time Face & Candidate Presence Detection**: 
  - **No Person**: Alerts and logs a strike if the student leaves their seat or obscures the camera for > 3 seconds.
  - **Multiple Persons**: Detects unauthorized assistance if another person appears in the webcam frame.
- **🎙️ Acoustic Speech & Whisper Detection (Web Audio API)**: Real-time microphone audio analyzer that detects speaking or whispering in the exam room.
- **🖥️ Full-Screen & Environmental Enforcement**: Exiting full-screen mode, switching browser tabs, or clicking outside the window triggers instant strikes.
- **🔒 Shortcut & Clipboard Lockdown**: Right-click context menus, `Ctrl+C`, `Ctrl+V`, `Ctrl+U`, and `F12` / DevTools shortcuts are completely blocked.
- **⚠️ Automated 3-Strike Termination**:
  - **Strike 1 & 2**: Instant warning alert modal with audio-visual cue.
  - **Strike 3**: Immediate exam lock, forced auto-submission, and status marked as `TERMINATED`.

### 3. 🔐 Cybersecurity & Anti-Tampering Architecture
- **🔏 Cryptographic Submission Integrity (HMAC-SHA256)**: Implements non-repudiation using keyed SHA-256 digital certificates over candidate score, roll number, strikes, and status. Any backend or in-transit DB tampering immediately breaks cryptographic validation.
- **📹 Virtual Camera & Stream Spoofing Detection**: Hardware driver inspection via `enumerateDevices()` blocks fake webcam feeds, OBS Virtual Camera, ManyCam, and synthetic video loops.
- **🛡️ Client-Side Reverse Engineering & DevTools Traps**: Real-time debugger latency timing traps and synthetic click detection (`e.isTrusted` checks) stop students from opening devtools or script-injecting answers.
- **🚨 SIEM Incident Response Dashboard**: Tutor/Admin Command Center provides a Security Operations Center (SOC) telemetry board classifying events into standardized cyber codes (`SEC-001` through `SEC-013`) with threat severity levels (Critical, High, Medium, Low) and client IP logging.

### 4. 📊 Instant Auto-Evaluation & Tutor Audit Reports
- Objective questions are instantly graded upon submission or termination.
- Tutors can see a complete timestamped audit log of every cheating violation with exact reasons.

---

## 🛠️ Technology Stack
- **Backend**: Python 3.13, Flask
- **Database**: SQLite (built-in, zero external setup required)
- **AI Question Generation**: Google Gemini API & Groq Cloud API
- **Computer Vision & Proctoring**: TensorFlow.js, COCO-SSD, Web Audio API
- **Document Processing**: `pypdf` for PDF text extraction, `Pillow` for image formatting
- **Frontend**: HTML5, Tailwind CSS, SweetAlert2, Lucide Icons

---

---

## 🌐 Live Production Deployment
- **Live Application**: [https://online-examination-system-with-anti.onrender.com/](https://online-examination-system-with-anti.onrender.com/)
- **Project Engineering Portfolio**: [https://examguard-portfolio.vercel.app/](https://examguard-portfolio.vercel.app/)
- **Live Tutor Portal**: [https://online-examination-system-with-anti.onrender.com/tutor](https://online-examination-system-with-anti.onrender.com/tutor)
- **Live Student Exam Portal**: [https://online-examination-system-with-anti.onrender.com/student](https://online-examination-system-with-anti.onrender.com/student)

---

## 💻 How to Run Locally

### 1. Install Dependencies
```bash
python -m pip install -r requirements.txt
```

### 2. Run the Application
```bash
python run.py
```

### 3. Access in Browser
- **Home / Landing Page**: [http://127.0.0.1:5000](http://127.0.0.1:5000) (or [https://online-examination-system-with-anti.onrender.com/](https://online-examination-system-with-anti.onrender.com/))
- **Tutor Portal**: [http://127.0.0.1:5000/tutor](http://127.0.0.1:5000/tutor) (or [https://online-examination-system-with-anti.onrender.com/tutor](https://online-examination-system-with-anti.onrender.com/tutor))
- **Student Exam Portal**: [http://127.0.0.1:5000/student](http://127.0.0.1:5000/student) (or [https://online-examination-system-with-anti.onrender.com/student](https://online-examination-system-with-anti.onrender.com/student))

---

## 🧪 Testing the Complete Workflow

1. Go to the Tutor Portal (`https://online-examination-system-with-anti.onrender.com/tutor` or `http://127.0.0.1:5000/tutor`) and click **"Create Exam with AI"**.
2. Upload a PDF file or enter a topic (e.g. *"Computer Networks - OSI Model and Routing"*), then click **"Generate Questions with AI"**.
3. Review the generated MCQs, set Duration and Max Strikes (e.g., 3 strikes), and click **"Publish Exam"**.
4. Copy the 6-character **Exam Access Code** (e.g. `6D8A92`).
5. Open an Incognito/New tab at `https://online-examination-system-with-anti.onrender.com/student` (or local), enter the code and student details.
6. Click **"Agree & Enter Fullscreen Exam"**.
7. **Test Anti-Cheating**:
   - Press `Alt+Tab` or switch to another browser tab: **Strike 1 Warning** will appear.
   - Switch tabs again: **Strike 2 Warning** will appear.
   - Switch tabs a 3rd time: **Exam Terminated** modal appears and the exam is automatically locked!
8. View the results on the student page and inspect the full audit trail in the Tutor Dashboard!

---

