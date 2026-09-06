@echo off
REM ============================================================
REM  MM Scribe - Build Dev + Release EXE + Graph viewer
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

REM ---- Graph viewer (optional): built only if the source is present ----
set "GRAPH="
if exist "MabinogiMobileScribeGraph_Beta.py" set "GRAPH=MabinogiMobileScribeGraph_Beta.py"
if defined GRAPH     echo Detected graph : %GRAPH%
if not defined GRAPH echo Detected graph : none - skipping graph build
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

REM ---- Monster name table: the target bar can only show a monster name instead
REM      of a raw entityId when this is bundled. Missing it degrades to hex, so a
REM      missing file is not a build failure. Main program only - the graph viewer
REM      reads target names out of the save file.
set "ADD_MOBNAMES="
if exist "..\Note\Ref\notice_monster_names_tw.json" set "ADD_MOBNAMES=--add-data=..\Note\Ref\notice_monster_names_tw.json;."
if defined ADD_MOBNAMES     echo Monster names    : bundled
if not defined ADD_MOBNAMES echo Monster names    : NOT FOUND - target bar will show hex only

if defined ICON_DEV     echo Icon for Dev     : %ICON_DEV%
if not defined ICON_DEV echo Icon for Dev     : none - using default
if defined ICON_REL     echo Icon for Release : %ICON_REL%
if not defined ICON_REL echo Icon for Release : none - using default
echo.

REM ---- Clean previous build artifacts so PyInstaller does not reuse cached spec ----
if exist "build" rmdir /s /q "build" >nul 2>&1
if exist "MM Scribe.spec" del "MM Scribe.spec" >nul 2>&1
if exist "MM Scribe Dev.spec" del "MM Scribe Dev.spec" >nul 2>&1
if exist "MM Scribe Graph.spec" del "MM Scribe Graph.spec" >nul 2>&1

echo ============================================================
echo  Step 1/4 : Build DEV version (with developer options)
echo ============================================================
python -m PyInstaller --onefile --noconsole ^
    --collect-data customtkinter ^
    %ICON_DEV% ^
    %ADD_ICON_DEV% ^
    %ADD_MOBNAMES% ^
    --name "MM Scribe Dev" ^
    "%SCRIPT%"
if errorlevel 1 goto :error

echo.
echo ============================================================
echo  Step 2/4 : Create release marker
echo ============================================================
type nul > RELEASE.marker
echo Marker created.

echo.
echo ============================================================
echo  Step 3/4 : Build RELEASE version (developer options hidden)
echo ============================================================
python -m PyInstaller --onefile --noconsole ^
    --collect-data customtkinter ^
    --add-data "RELEASE.marker;." ^
    %ICON_REL% ^
    %ADD_ICON_REL% ^
    %ADD_MOBNAMES% ^
    --name "MM Scribe" ^
    "%SCRIPT%"
if errorlevel 1 goto :error

REM ---- Cleanup: remove temporary marker ----
del RELEASE.marker >nul 2>&1

echo.
echo ============================================================
echo  Step 4/4 : Build Graph viewer (no Dev variant needed)
echo ============================================================
if not defined GRAPH (
    echo Skipped - graph source not found.
    goto :done
)

REM  Version follows the main program's VERSION_STR. The graph reads it from the
REM  source next door, so importing it here gives the same single source of truth;
REM  PyInstaller bundles the result so the packed EXE knows its version too.
python -c "import MabinogiMobileScribeGraph_Beta as g;open('VERSION.txt','w').write(g.VERSION_STR)"
if errorlevel 1 goto :error
set /p GRAPH_VER=<VERSION.txt
echo Graph version : %GRAPH_VER%

python -m PyInstaller --onefile --noconsole ^
    --collect-data customtkinter ^
    --add-data "VERSION.txt;." ^
    %ICON_REL% ^
    %ADD_ICON_REL% ^
    --name "MM Scribe Graph" ^
    "%GRAPH%"
if errorlevel 1 goto :error
del VERSION.txt >nul 2>&1

:done
echo.
echo ============================================================
echo  DONE!
echo    Dev     : dist\MM Scribe Dev.exe
echo    Release : dist\MM Scribe.exe
if defined GRAPH echo    Graph   : dist\MM Scribe Graph.exe
echo ============================================================
pause
exit /b 0

:error
echo.
echo ============================================================
echo  BUILD FAILED - Check error messages above
echo ============================================================
if exist RELEASE.marker del RELEASE.marker >nul 2>&1
if exist VERSION.txt del VERSION.txt >nul 2>&1
pause
exit /b 1
