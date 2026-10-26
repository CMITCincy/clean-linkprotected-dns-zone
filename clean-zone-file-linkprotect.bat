@echo off
setlocal
REM Drag one or more zone .txt files onto this .bat.
REM Each file is cleaned to "<name>-clean<ext>" next to the original; the original is untouched.
REM The .ps1 must sit in the same folder as this .bat.

set "SCRIPT=%~dp0clean-zone-file-linkprotect.ps1"
if not exist "%SCRIPT%" (
    echo Script not found: "%SCRIPT%"
    pause
    exit /b 1
)

if "%~1"=="" (
    echo Drag a zone file onto this .bat to clean it.
    pause
    exit /b 1
)

REM Prefer PowerShell 7 if installed, otherwise Windows PowerShell 5.1
where pwsh >nul 2>&1 && (set "PS=pwsh") || (set "PS=powershell")

:next
if "%~1"=="" goto done
echo Cleaning: "%~nx1"
%PS% -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" -InputPath "%~f1" -OutputPath "%~dpn1-clean%~x1"
if errorlevel 1 echo   FAILED: "%~nx1"
shift
goto next

:done
echo.
pause
