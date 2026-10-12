import unittest
from app import app
from database import init_db, get_connection
import json

class ExamGuardTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        init_db()

    def test_index_page(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'ExamGuard', response.data)

    def test_tutor_dashboard(self):
        response = self.app.get('/tutor')
        self.assertEqual(response.status_code, 200)

    def test_mock_question_generation(self):
        response = self.app.post('/api/generate-questions', data={
            'topic_text': 'Operating Systems Concepts',
            'num_questions': 3,
            'difficulty': 'Medium',
            'question_type': 'mcq',
            'use_mock': 'true'
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get('success'))
        self.assertGreaterEqual(len(data.get('questions', [])), 1)

    def test_save_and_take_exam_flow(self):
        # 1. Save Exam
        exam_payload = {
            "title": "Computer Networks Quiz",
            "description": "Test on OSI layers",
            "duration_minutes": 10,
            "max_warnings": 3,
            "passing_percentage": 50.0,
            "questions": [
                {
                    "question_text": "Which layer is responsible for routing?",
                    "question_type": "mcq",
                    "options": ["Network Layer", "Transport Layer", "Session Layer", "Physical Layer"],
                    "correct_answer": "Network Layer",
                    "explanation": "Routers work at Layer 3 (Network Layer).",
                    "points": 1.0
                }
            ]
        }
        save_resp = self.app.post('/api/save-exam', json=exam_payload)
        self.assertEqual(save_resp.status_code, 200)
        save_data = save_resp.get_json()
        self.assertTrue(save_data.get('success'))
        exam_code = save_data.get('exam_code')
        exam_id = save_data.get('exam_id')

        # 2. Student starts exam
        start_resp = self.app.post('/student/start', data={
            'exam_code': exam_code,
            'student_name': 'Alice Smith',
            'roll_number': 'CS2026-01'
        }, follow_redirects=False)
        self.assertEqual(start_resp.status_code, 302)
        # Extract submission_id from redirect url
        redirect_url = start_resp.headers['Location']
        submission_id = int(redirect_url.split('/')[-1])

        # 3. Simulate 3 Cheating Violations (Strikes)
        v1 = self.app.post(f'/api/submission/{submission_id}/violation', json={'type': 'tab_switch', 'details': 'Switched tab'})
        self.assertEqual(v1.get_json()['warnings_count'], 1)
        self.assertFalse(v1.get_json()['is_terminated'])

        v2 = self.app.post(f'/api/submission/{submission_id}/violation', json={'type': 'fullscreen_exit', 'details': 'Exited fullscreen'})
        self.assertEqual(v2.get_json()['warnings_count'], 2)
        self.assertFalse(v2.get_json()['is_terminated'])

        v3 = self.app.post(f'/api/submission/{submission_id}/violation', json={'type': 'window_blur', 'details': 'Lost focus'})
        v3_data = v3.get_json()
        self.assertEqual(v3_data['warnings_count'], 3)
        self.assertTrue(v3_data['is_terminated'], "Exam should terminate on 3rd strike!")

        # 4. Check result page loads
        res_page = self.app.get(f'/student/result/{submission_id}')
        self.assertEqual(res_page.status_code, 200)
        self.assertIn(b'Terminated', res_page.data)

if __name__ == '__main__':
    unittest.main()
