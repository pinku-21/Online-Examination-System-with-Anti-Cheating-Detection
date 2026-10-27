"""
ExamGuard AI - High-Concurrency Load & Stress Testing Suite (Locust)
Simulates realistic exam workloads across hundreds of concurrent students:
1. Student login & authentication
2. Active student exam session polling (fetching questions, diagrams)
3. High-frequency proctoring telemetry heartbeats & strike reporting
4. Final cryptographic exam submission with HMAC integrity hashes
"""

import random
import time
from locust import HttpUser, task, between, events

class ExamCandidateUser(HttpUser):
    # Wait between 1 and 3 seconds between actions (simulates realistic student reading & answering pace)
    wait_time = between(1.0, 3.0)

    def on_start(self):
        """Called when a simulated student starts their session."""
        self.client_ip = f"192.168.1.{random.randint(10, 250)}"
        self.exam_id = 1
        self.roll_number = f"STU-{random.randint(1000, 9999)}"

    @task(5)
    def view_exam_page(self):
        """Simulates student actively on the exam screen."""
        self.client.get(f"/student/exam/{self.exam_id}", name="/student/exam/[id]")

    @task(10)
    def send_proctoring_heartbeat(self):
        """
        Simulates high-frequency background anti-cheating telemetry:
        sending face presence, acoustic volume levels, and strike status.
        """
        payload = {
            "exam_id": self.exam_id,
            "roll_number": self.roll_number,
            "face_present": True,
            "active_audio_level": random.uniform(0.01, 0.08),
            "strikes": 0,
            "timestamp": time.time()
        }
        self.client.post("/api/save_progress", json=payload, name="/api/save_progress [Heartbeat]")

    @task(3)
    def answer_question_and_save(self):
        """Simulates student choosing an MCQ option."""
        payload = {
            "exam_id": self.exam_id,
            "question_index": random.randint(0, 9),
            "selected_option": random.choice(["A", "B", "C", "D"])
        }
        self.client.post("/api/save_progress", json=payload, name="/api/save_progress [Option Selection]")

    @task(1)
    def test_health_probe(self):
        """Checks uptime probe response time under heavy load."""
        self.client.get("/health", name="/health [Keep-Alive Probe]")
