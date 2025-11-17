@echo off
REM Run Flask app in development mode on Windows

cd /d %~dp0..
call .venv\Scripts\activate

python -m app.main
