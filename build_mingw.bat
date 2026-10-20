@echo off
setlocal enableextensions enabledelayedexpansion

REM Build script for MinGW-w64 GCC (Windows x64)
REM Usage:
REM   build_mingw.bat
REM Output: build\mingw-local\eh_unwind_analyzer.exe

if not defined GCC set GCC=gcc

if exist "%GCC%" (
  set GCC_CMD="%GCC%"
) else (
  where %GCC% >nul 2>nul
  if errorlevel 1 (
    echo gcc not found. Either add gcc to PATH or set GCC to the full path.
    exit /b 1
  )
  set GCC_CMD=%GCC%
)

if not exist build\mingw-local mkdir build\mingw-local

%GCC_CMD% -std=c17 -O2 -g -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Werror ^
  -D__USE_MINGW_ANSI_STDIO=1 -DWIN32_LEAN_AND_MEAN=1 ^
  -I include ^
  src\main.c src\app_info.c src\pe.c src\unwind.c src\heuristics.c src\report.c src\util.c src\dynamic_win.c ^
  -o build\mingw-local\eh_unwind_analyzer.exe

if errorlevel 1 (
  echo Build failed.
  exit /b 1
)

echo Built build\mingw-local\eh_unwind_analyzer.exe
