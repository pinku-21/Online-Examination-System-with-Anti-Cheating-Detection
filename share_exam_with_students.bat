@echo off
title ExamGuard AI - Remote Student Public Access Tunnel
cls
echo ==============================================================================
echo         [ExamGuard AI] - Instant Free Public Link for Remote Students
echo ==============================================================================
echo.
echo 1. Ensure your ExamGuard app is running in another terminal (python run.py)
echo 2. Generating your instant public HTTPS URL below...
echo    Students can access this link from ANY phone, laptop, or remote location!
echo.
echo ==============================================================================
echo.
ssh -p 443 -R0:localhost:5000 -o StrictHostKeyChecking=no -o ServerAliveInterval=30 a.pinggy.io
pause
