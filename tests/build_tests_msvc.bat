@echo off
setlocal

REM Build small test binaries that exercise SEH/VEH.
REM Run from "x64 Native Tools Command Prompt for VS".

where cl >nul 2>nul
if errorlevel 1 (
  echo cl.exe not found. Run this inside "x64 Native Tools Command Prompt for VS".
  exit /b 1
)

cl /nologo /O2 /W4 /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS seh_test.c /Fe:seh_test.exe
if errorlevel 1 exit /b 1
cl /nologo /O2 /W4 /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS veh_test.c /Fe:veh_test.exe
if errorlevel 1 exit /b 1
cl /nologo /O2 /W4 /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS uef_test.c /Fe:uef_test.exe
if errorlevel 1 exit /b 1
cl /nologo /O2 /W4 /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS vch_test.c /Fe:vch_test.exe
if errorlevel 1 exit /b 1
cl /nologo /O2 /W4 /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS rtl_ftable_test.c /Fe:rtl_ftable_test.exe
if errorlevel 1 exit /b 1

echo Built: seh_test.exe, veh_test.exe, uef_test.exe, vch_test.exe, rtl_ftable_test.exe
