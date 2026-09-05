$ErrorActionPreference = 'Stop'
$python = 'python'
if (Test-Path 'backend\.venv\Scripts\python.exe') { $python = (Resolve-Path 'backend\.venv\Scripts\python.exe').Path }
& $python -m pip install -r backend\requirements.txt
& $python -m uvicorn backend.server:app --host 127.0.0.1 --port 8000
