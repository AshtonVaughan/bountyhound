@echo off
echo Starting local web server to view flowcharts...
echo.
echo Opening browser at http://localhost:8000/flowchart-master.html
echo.
echo Press Ctrl+C to stop the server when done.
echo.
cd /d "C:\Users\vaugh\Projects\bountyhound-agent"
start http://localhost:8000/flowchart-master.html
python -m http.server 8000
