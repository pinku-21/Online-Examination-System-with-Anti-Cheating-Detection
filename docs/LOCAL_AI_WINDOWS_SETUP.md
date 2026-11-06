# Run ExamGuard with Local Ollama on Windows

This setup runs both the Flask application and Ollama on the same Windows computer. It does not create a cloud server and does not use a paid AI API.

## 1. Check Ollama

Open PowerShell and run:

```powershell
ollama list
```

Confirm that `qwen2.5:3b` appears. If it does not:

```powershell
ollama pull qwen2.5:3b
```

Ollama normally runs as a Windows background application. If needed, start it from the Start menu or run `ollama serve` in a terminal.

## 2. Get the ExamGuard local-AI branch

If you already have a local clone:

```powershell
git fetch origin
git checkout feature/local-ai-studio-foundation
git pull
```

If you do not have a clone, clone the repository and then check out that branch:

```powershell
git clone https://github.com/pinku-21/Online-Examination-System-with-Anti-Cheating-Detection.git
cd Online-Examination-System-with-Anti-Cheating-Detection
git checkout feature/local-ai-studio-foundation
```

## 3. Install and run ExamGuard

Activate your existing virtual environment, or create one and install dependencies:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Open `http://127.0.0.1:5000` on the same computer, sign in as an administrator, and open Tutor Portal → Create Exam → Local AI Studio.

## 4. Test local AI

1. Select **Test local connection**. The status should confirm Ollama is running and `qwen2.5:3b` is installed.
2. Enter a short prompt in **Local Qwen chat** and select **Send to local Qwen**.
3. The response should appear in the Local AI Studio panel.

The Flask endpoints call only `http://127.0.0.1:11434` and use the fixed `qwen2.5:3b` model. The chat endpoint is administrator-protected, limits prompts to 5,000 characters, and has no Gemini/Groq/cloud fallback.

## Important limitations and safety

- The deployed Render application cannot reach Ollama running on your personal Windows computer. Use the local Flask address above for this feature.
- `run.py` binds Flask to `127.0.0.1`, so the app is accessible only from that computer. iPhone/LAN access is a separate networking and security step; do not expose Ollama port 11434 to the internet.
- The local AI chat is text-only in this first implementation. It does not upload student answer sheets or other files to Ollama.
- Keep the Windows computer awake and keep both Flask and Ollama running while using local AI.
- Existing Gemini-based question generation and pasted-paper parsing are unchanged.
