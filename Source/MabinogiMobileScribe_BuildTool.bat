@echo off
REM ============================================================
REM  MM Scribe - Build Dev + Release EXE
REM  Usage: double-click, or run in cmd
REM ============================================================
setlocal
cd /d %~dp0

REM ---- Locate source: filename no longer carries a version, so name it directly ----
REM      Fall back to the old "newest MabinogiMobileScribe_*.py" scan so a working
REM      copy that still holds an old versioned filename keeps building.
set "SCRIPT="
if exist "MabinogiMobileScribe_Beta.py" set "SCRIPT=MabinogiMobileScribe_Beta.py"
if not defined SCRIPT (
    for /f "delims=" %%f in ('dir /b /o-d "MabinogiMobileScribe_*.py" 2^>nul') do (
        if not defined SCRIPT set SCRIPT=%%f
    )
)

if not defined SCRIPT (
    echo [ERROR] Cannot find MabinogiMobileScribe_Beta.py in current directory.
    pause
    exit /b 1
)

echo Detected source: %SCRIPT%
echo.

REM ---- Auto-detect icon files. Use set "VAR=..." form to avoid trailing spaces ----
REM     ICON_*     : sets the EXE file icon (--icon)
REM     ADD_ICON_* : bundles the .ico into the EXE so runtime iconbitmap() can load it
set "ICON_DEV="
set "ICON_REL="
set "ADD_ICON_DEV="
set "ADD_ICON_REL="
if exist "icon_dev.ico" set "ICON_DEV=--icon=icon_dev.ico"
if exist "icon_dev.ico" set "ADD_ICON_DEV=--add-data=icon_dev.ico;."
if exist "icon.ico"     set "ICON_REL=--icon=icon.ico"
if exist "icon.ico"     set "ADD_ICON_REL=--add-data=icon.ico;."
if exist "icon.ico" if not defined ICON_DEV     set "ICON_DEV=--icon=icon.ico"
if exist "icon.ico" if not defined ADD_ICON_DEV set "ADD_ICON_DEV=--add-data=icon.ico;."

if defined ICON_DEV     echo Icon for Dev     : %ICON_DEV%
if not defined ICON_DEV echo Icon for Dev     : none - using default
if defined ICON_REL     echo Icon for Release : %ICON_REL%
if not defined ICON_REL echo Icon for Release : none - using default
echo.

REM ---- Clean previous build artifacts so PyInstaller does not reuse cached spec ----
if exist "build" rmdir /s /q "build" >nul 2>&1
if exist "MM Scribe.spec" del "MM Scribe.spec" >nul 2>&1
if exist "MM Scribe Dev.spec" del "MM Scribe Dev.spec" >nul 2>&1

echo ============================================================
echo  Step 1/3 : Build DEV version (with developer options)
echo ============================================================
python -m PyInstaller --onefile --noconsole ^
    --collect-data customtkinter ^
    %ICON_DEV% ^
    %ADD_ICON_DEV% ^
    --name "MM Scribe Dev" ^
    "%SCRIPT%"
if errorlevel 1 goto :error

echo.
echo ============================================================
echo  Step 2/3 : Create release marker
echo ============================================================
type nul > RELEASE.marker
echo Marker created.

echo.
echo ============================================================
echo  Step 3/3 : Build RELEASE version (developer options hidden)
echo ============================================================
python -m PyInstaller --onefile --noconsole ^
    --collect-data customtkinter ^
    --add-data "RELEASE.marker;." ^
    %ICON_REL% ^
    %ADD_ICON_REL% ^
    --name "MM Scribe" ^
    "%SCRIPT%"
if errorlevel 1 goto :error

REM ---- Cleanup: remove temporary marker ----
del RELEASE.marker >nul 2>&1

echo.
echo ============================================================
echo  DONE!
echo    Dev     : dist\MM Scribe Dev.exe
echo    Release : dist\MM Scribe.exe
echo ============================================================
pause
exit /b 0

:error
echo.
echo ============================================================
echo  BUILD FAILED - Check error messages above
echo ============================================================
if exist RELEASE.marker del RELEASE.marker >nul 2>&1
pause
exit /b 1
