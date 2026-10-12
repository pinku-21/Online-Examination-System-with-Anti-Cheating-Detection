import sqlite3

conn = sqlite3.connect('examguard.db')
conn.row_factory = sqlite3.Row
c = conn.cursor()

print('=== STUDENTS ===')
c.execute('SELECT id, username, full_name, class_name, role FROM users ORDER BY id DESC LIMIT 8')
for r in c.fetchall():
    print(f"  ID:{r['id']} | {r['role']:7} | {r['username']:25} | class={r['class_name']}")

print()
print('=== EXAMS (last 5) ===')
c.execute('SELECT id, exam_code, title, access_type, assigned_class, schedule_type FROM exams ORDER BY id DESC LIMIT 5')
for r in c.fetchall():
    print(f"  ID:{r['id']} [{r['exam_code']}] {r['title'][:35]:35} | access={r['access_type']:8} class={r['assigned_class']} | sched={r['schedule_type']}")

print()
print('=== ASSIGNMENTS ===')
c.execute('SELECT ea.exam_id, e.title, ea.user_id, u.username FROM exam_assignments ea JOIN exams e ON ea.exam_id=e.id JOIN users u ON ea.user_id=u.id ORDER BY ea.id DESC LIMIT 10')
for r in c.fetchall():
    print(f"  exam:{r['exam_id']} ({r['title'][:30]:30}) -> user:{r['user_id']} ({r['username']})")

conn.close()
