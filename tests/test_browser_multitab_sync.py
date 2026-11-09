import asyncio
from playwright.async_api import async_playwright

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()

        # Tab A
        tab_a = await context.new_page()

        # Login Tab A
        await tab_a.goto("http://127.0.0.1:5000/login")
        await tab_a.fill('input[name="identifier"]', "admin")
        await tab_a.fill('input[name="password"]', "admin123")
        await tab_a.click('button[type="submit"]')
        await tab_a.wait_for_url("**/tutor")
        print("Tab A logged in.")

        # Tab B in same context
        tab_b = await context.new_page()
        await tab_b.goto("http://127.0.0.1:5000/tutor")
        print("Tab B opened.")

        # Create a temporary exam to test deletion
        import database, uuid
        code = 'D' + uuid.uuid4().hex[:6].upper()
        conn = database.get_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO exams (exam_code, title, duration_minutes) VALUES (?, ?, 30)", (code, f'Playwright Delete Test {code}'))
        test_exam_id = cur.lastrowid
        conn.commit()
        conn.close()
        print(f"Created test exam with ID: {test_exam_id}, Code: {code}")

        # Reload both tabs so the exam is in their DOM
        await tab_a.reload()
        await tab_b.reload()

        card_a = await tab_a.locator(f"#exam-card-{test_exam_id}").count()
        card_b = await tab_b.locator(f"#exam-card-{test_exam_id}").count()
        print(f"Initial DOM state: Tab A has card: {card_a > 0}, Tab B has card: {card_b > 0}")

        # Monitor Tab B console and events
        events_received_in_b = []
        await tab_b.expose_function("onExamDeletedEvent", lambda detail: events_received_in_b.append(detail))
        await tab_b.evaluate("""
            () => {
                window.addEventListener('examguard:exam_deleted', (e) => {
                    console.log('[Tab B Received examguard:exam_deleted]', JSON.stringify(e.detail));
                    window.onExamDeletedEvent(e.detail);
                });
            }
        """)

        # Delete the exam using Tab A via API call directly from page context
        print("Deleting exam in Tab A via fetch...")
        del_result = await tab_a.evaluate(f"""
            async () => {{
                const resp = await fetch('/api/admin/delete-exam/{test_exam_id}', {{ method: 'DELETE' }});
                return await resp.json();
            }}
        """)
        print("Delete API response:", del_result)
        # Also remove from Tab A DOM as deleteExam does
        await tab_a.evaluate(f"""
            () => {{
                const card = document.getElementById('exam-card-{test_exam_id}');
                if (card) card.remove();
            }}
        """)
        print("Exam removed from Tab A DOM.")

        # Now monitor Tab B for up to 8 seconds to see if sync event arrives and card disappears
        print("Waiting for Tab B to sync and remove card...")
        for i in range(16):
            await asyncio.sleep(0.5)
            card_count_b = await tab_b.locator(f"#exam-card-{test_exam_id}").count()
            if card_count_b == 0:
                print(f"SUCCESS: Exam card detached in Tab B after { (i+1)*0.5 }s!")
                break
        else:
            card_count_b = await tab_b.locator(f"#exam-card-{test_exam_id}").count()
            print(f"FAILURE: Exam card still exists in Tab B (count: {card_count_b})")

        print("Events received by Tab B listener:", events_received_in_b)
        cursor_b = await tab_b.evaluate("() => window.ExamGuardSync ? window.ExamGuardSync.getCursor() : null")
        print("Final Cursor on Tab B:", cursor_b)

        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
