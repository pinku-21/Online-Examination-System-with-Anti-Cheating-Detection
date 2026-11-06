# Run ExamGuard with Local Ollama on Windows

This setup runs the Flask application and Ollama on your Windows computer. It does not create a cloud server and does not use a paid AI API.

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

The Flask server listens on the computer's network interfaces (port 5000). On the laptop, open `http://127.0.0.1:5000`. Sign in as an administrator and open Tutor Portal → Create Exam → Local AI Studio.

## 4. Allow access from your iPhone on the same Wi-Fi

1. Connect both the Windows laptop and iPhone to the same trusted private Wi-Fi network.
2. On Windows, open PowerShell and run `ipconfig`.
3. Find the active Wi-Fi adapter's **IPv4 Address**, for example `192.168.1.25`. Use your actual address, not this example.
4. If Windows Firewall asks whether Python may communicate on a network, allow it only on **Private networks**, not Public networks. If no prompt appears, create a Windows Defender Firewall inbound rule for TCP port 5000 limited to the **Private** profile.
5. On your iPhone, open Safari and visit `http://YOUR-PC-IP:5000`, replacing `YOUR-PC-IP` with the laptop's IPv4 address. For example: `http://192.168.1.25:5000`.
6. Sign in and open Tutor Portal → Create Exam → Local AI Studio.

If the laptop's local IP changes after reconnecting to Wi-Fi, check `ipconfig` again and use the new address.

## 5. Test local AI

1. Select **Test local connection**. The status should confirm Ollama is running and `qwen2.5:3b` is installed.
2. Enter a short prompt in **Local Qwen chat** and select **Send to local Qwen**.
3. The response should appear in the Local AI Studio panel.

The Flask endpoints call only `http://127.0.0.1:11434` for Ollama and use the fixed `qwen2.5:3b` model. The chat endpoint is administrator-protected, limits prompts to 5,000 characters, and has no Gemini/Groq/cloud fallback.

## Important limitations and safety

- This is same-local-network access only. It does not make ExamGuard available over mobile data or from another Wi-Fi network.
- Keep the Windows computer awake and keep both Flask and Ollama running while using local AI. The current setup still requires starting the application with `python run.py`; automatic startup is not configured.
- Allow inbound TCP port 5000 only on trusted **Private** networks. Do not create a Public-profile firewall rule or forward port 5000 on your router.
- Ollama remains addressed through `127.0.0.1:11434`; do not expose port 11434 to your LAN or the internet.
- Use only a trusted Wi-Fi network. The Flask site is served over HTTP on the local network, not HTTPS.
- The local AI chat is text-only in this first implementation. It does not upload student answer sheets or other files to Ollama.
- The deployed Render application cannot reach Ollama running on your personal Windows computer.
- Existing Gemini-based question generation and pasted-paper parsing are unchanged.
