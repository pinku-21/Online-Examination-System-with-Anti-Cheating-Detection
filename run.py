import os
import sys
from app import app, init_db

if __name__ == '__main__':
    init_db()
    port = 5000
    print("=" * 60)
    print(" [ExamGuard AI] - Online Examination & Anti-Cheat System ")
    print("=" * 60)
    print(f"Server is running on: http://127.0.0.1:{port}")
    print(f"Tutor Portal:        http://127.0.0.1:{port}/tutor")
    print(f"Student Portal:      http://127.0.0.1:{port}/student")
    print("=" * 60)
    print("Press Ctrl+C to stop the server.")
    # Run server without debug reloader in background daemon mode to avoid subprocess fork issues
    app.run(host='127.0.0.1', port=port, debug=False)
