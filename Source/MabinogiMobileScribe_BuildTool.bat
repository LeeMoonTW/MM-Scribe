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
set "GRAPH=MabinogiMobileScribeGraph_Beta.py"
if not exist "%GRAPH%" (
    echo [ERROR] Cannot find %GRAPH%.
    echo         The release build packs both programs into ONE shared folder,
    echo         so the graph source is no longer optional. See MM_Scribe_Release.spec.
    pause
    exit /b 1
)
if not exist "MM_Scribe_Release.spec" (
    echo [ERROR] Cannot find MM_Scribe_Release.spec - it is tracked in git, not generated.
    pause
    exit /b 1
)
echo Detected graph : %GRAPH%
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
if exist "notice_monster_names_tw.json" set "ADD_MOBNAMES=--add-data=notice_monster_names_tw.json;."
if defined ADD_MOBNAMES     echo Monster names    : bundled
if not defined ADD_MOBNAMES echo Monster names    : NOT FOUND - target bar will show hex only

if defined ICON_DEV     echo Icon for Dev     : %ICON_DEV%
if not defined ICON_DEV echo Icon for Dev     : none - using default
if defined ICON_REL     echo Icon for Release : %ICON_REL%
if not defined ICON_REL echo Icon for Release : none - using default
echo.

REM ---- Clean previous build artifacts so PyInstaller does not reuse cached spec ----
REM      Only the specs PyInstaller GENERATES from command-line flags are deleted.
REM      MM_Scribe_Release.spec is hand-written and tracked in git - the underscore
REM      name keeps it out of the "MM Scribe*.spec" pattern below on purpose.
if exist "build" rmdir /s /q "build" >nul 2>&1
if exist "MM Scribe.spec" del "MM Scribe.spec" >nul 2>&1
if exist "MM Scribe Dev.spec" del "MM Scribe Dev.spec" >nul 2>&1
if exist "MM Scribe Graph.spec" del "MM Scribe Graph.spec" >nul 2>&1

echo ============================================================
echo  Step 1/3 : Build DEV version (with developer options)
echo ============================================================
REM  Dev stays on its own folder - it differs from Release only by RELEASE.marker,
REM  so sharing one output folder with Release would make them overwrite each other.
call :mkversion version_info.txt "MM Scribe Dev.exe" "MM Scribe Dev"
if errorlevel 1 goto :error
python -m PyInstaller --onedir --noconfirm --noconsole --noupx ^
    --version-file=version_info.txt ^
    --collect-data customtkinter ^
    %ICON_DEV% ^
    %ADD_ICON_DEV% ^
    %ADD_MOBNAMES% ^
    --name "MM Scribe Dev" ^
    "%SCRIPT%"
if errorlevel 1 goto :error

echo.
echo ============================================================
echo  Step 2/3 : Prepare release inputs
echo ============================================================
REM  Release marker: the program hides the developer options when this is bundled.
type nul > RELEASE.marker
echo Marker created.

REM  Graph version follows the main program's VERSION_STR. Delete any stale
REM  VERSION.txt first - the graph module reads it back when present, which would
REM  otherwise pin the version to whatever the previous build wrote.
if exist VERSION.txt del VERSION.txt >nul 2>&1
python -c "import MabinogiMobileScribeGraph_Beta as g;open('VERSION.txt','w').write(g.VERSION_STR)"
if errorlevel 1 goto :error
set /p GRAPH_VER=<VERSION.txt
echo Graph version : %GRAPH_VER%

REM  One version resource per exe - they differ in product / original filename.
call :mkversion version_info_main.txt "MM Scribe.exe" "MM Scribe"
if errorlevel 1 goto :error
call :mkversion version_info_graph.txt "MM Scribe Graph.exe" "MM Scribe Graph"
if errorlevel 1 goto :error

echo.
echo ============================================================
echo  Step 3/3 : Build RELEASE + Graph into one shared folder
echo ============================================================
REM  Driven by the hand-written spec: one COLLECT holding both EXEs, so the
REM  Python runtime / tk / PIL are shipped once instead of twice. Command-line
REM  build options are IGNORED when a spec is given - everything lives in the
REM  spec (upx=False, version=..., icon, bundled data).
python -m PyInstaller --noconfirm MM_Scribe_Release.spec
if errorlevel 1 goto :error

REM ---- Cleanup: remove temporary build inputs ----
del RELEASE.marker >nul 2>&1
del VERSION.txt >nul 2>&1

echo.
echo ============================================================
echo  DONE!
echo    Dev     : dist\MM Scribe Dev\MM Scribe Dev.exe
echo    Release : dist\MM Scribe\MM Scribe.exe
echo    Graph   : dist\MM Scribe\MM Scribe Graph.exe
echo.
echo  Release and Graph share dist\MM Scribe\_internal - ship the WHOLE folder.
echo ============================================================
if exist version_info.txt del version_info.txt >nul 2>&1
if exist version_info_main.txt del version_info_main.txt >nul 2>&1
if exist version_info_graph.txt del version_info_graph.txt >nul 2>&1
pause
exit /b 0

:error
echo.
echo ============================================================
echo  BUILD FAILED - Check error messages above
echo ============================================================
if exist RELEASE.marker del RELEASE.marker >nul 2>&1
if exist VERSION.txt del VERSION.txt >nul 2>&1
if exist version_info.txt del version_info.txt >nul 2>&1
if exist version_info_main.txt del version_info_main.txt >nul 2>&1
if exist version_info_graph.txt del version_info_graph.txt >nul 2>&1
pause
exit /b 1

REM ============================================================
REM  :mkversion <output file> <exe filename> <product name>
REM
REM  Writes the PE version resource consumed by --version-file above.
REM  An exe with blank metadata (no company / product / copyright) scores badly
REM  in Defender's ML heuristics; that plus UPX packing is what got the release
REM  zip flagged as Trojan:Win32/Wacatac.B!ml, hence --noupx on every build too.
REM  Version numbers come from the main program's VERSION_STR, as everywhere else.
REM ============================================================
:mkversion
python make_version_file.py %1 %2 %3
exit /b %errorlevel%
