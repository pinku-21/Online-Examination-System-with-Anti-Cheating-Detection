ExamGuard Neon PostgreSQL migration package

Files:
- database.py: replacement database layer. Uses Neon/PostgreSQL when DATABASE_URL is set; otherwise it falls back to local SQLite for local development.
- app.py: unchanged copy of the app.py file supplied for review. It is included only for reference; you do not need to replace your existing app.py with it.

Before using on Render:
1. Keep a backup of your current database.py.
2. Replace the project's database.py with the included database.py.
3. Confirm requirements.txt includes: psycopg[binary]
4. In Render Environment, set DATABASE_URL to your Neon connection string (keep it secret; do not paste it into chat or commit it to GitHub).
5. In Render Environment, set ADMIN_INITIAL_PASSWORD to a strong new admin password. The updated database layer creates a first admin account only if no admin exists and this variable is configured. The username for this initial account is: admin
6. Deploy only after the merge conflicts in Git have been resolved and the updated files have been pushed.

Important:
- This creates/migrates the database schema; it does not copy existing records from examguard.db into Neon. If you already have student/exam data in SQLite that you need to preserve, do not switch production traffic until that data has been migrated separately.
- Uploaded PDFs and images stored in local folders are not persisted by Render's ephemeral filesystem. Plan separate persistent file storage for those uploads.
- Test locally first. Without DATABASE_URL, the app uses SQLite. With DATABASE_URL, it uses PostgreSQL.
- This file was syntax-checked, but a live Neon connection could not be tested here. Verify the deployment logs and test registration, login, exam creation, submission, results, and violation logging before using it with real students.
