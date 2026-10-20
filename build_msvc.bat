@echo off
setlocal

REM Build script for MSVC (Developer Command Prompt for VS, x64)
REM Usage:
REM   build_msvc.bat
REM Output: build\msvc-local\eh_unwind_analyzer.exe

where cl >nul 2>nul
if errorlevel 1 (
  echo cl.exe not found. Run this inside "x64 Native Tools Command Prompt for VS".
  exit /b 1
)

if not exist build\msvc-local mkdir build\msvc-local

cl /nologo /O2 /W4 /WX /permissive- /std:c17 /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /I include ^
  src\main.c src\app_info.c src\pe.c src\unwind.c src\heuristics.c src\report.c src\util.c src\dynamic_win.c ^
  /Fe:build\msvc-local\eh_unwind_analyzer.exe

if errorlevel 1 (
  echo Build failed.
  exit /b 1
)

echo Built build\msvc-local\eh_unwind_analyzer.exe
