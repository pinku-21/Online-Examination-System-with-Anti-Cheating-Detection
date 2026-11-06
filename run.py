import os
import sys
from app import app, init_db

if __name__ == '__main__':
    init_db()
    port = 5000
    host = os.environ.get("EXAMGUARD_HOST", "0.0.0.0")
    print("=" * 60)
    print(" [ExamGuard AI] - Online Examination & Anti-Cheat System ")
    print("=" * 60)
    print(f"Server is listening on: {host}:{port}")
    print(f"On this computer:       http://127.0.0.1:{port}")
    print("On another device:      http://<THIS-PC-LAN-IP>:%s" % port)
    print(f"Tutor Portal:           http://127.0.0.1:{port}/tutor")
    print(f"Student Portal:         http://127.0.0.1:{port}/student")
    print("=" * 60)
    print("Keep this computer on the trusted private Wi-Fi network.")
    print("Do not expose Flask or Ollama ports to the public internet.")
    print("Press Ctrl+C to stop the server.")
    # Listen on LAN interfaces so trusted devices on the same Wi-Fi can connect.
    # Restrict inbound TCP/5000 to the Windows Private network profile.
    app.run(host=host, port=port, debug=False)
