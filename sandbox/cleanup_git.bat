@echo off
echo ── Cleaning up misplaced files from sandbox root ──

cd /d D:\Projects\Sandbox\sandbox_v2\sandbox

REM Delete files that should only be in frontend/templates or backend/
REM These got pushed to the wrong location

git rm --cached app.py 2>nul
git rm --cached detector.py 2>nul
git rm --cached explainer.py 2>nul
git rm --cached simulator.py 2>nul
git rm --cached timeline.py 2>nul
git rm --cached report_generator.py 2>nul
git rm --cached response_engine.py 2>nul
git rm --cached requirements.txt 2>nul
git rm --cached README.md 2>nul
git rm --cached .gitignore 2>nul
git rm --cached index.html 2>nul
git rm --cached dashboard.html 2>nul

echo Done. Now copy the new dashboard.html then run:
echo   git add .
echo   git commit -m "fix: remove duplicate root files, update dashboard"
echo   git push origin main
pause
