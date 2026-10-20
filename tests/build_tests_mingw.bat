@echo off
setlocal

REM Build MinGW-compatible Windows dynamic smoke targets.
REM Uses gcc from PATH by default, or %%GCC%% if already set.

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

%GCC_CMD% -std=c17 -O2 -Wall -Wextra -Wpedantic -DWIN32_LEAN_AND_MEAN -D__USE_MINGW_ANSI_STDIO=1 veh_test_mingw.c -o veh_test_mingw.exe
if errorlevel 1 exit /b 1

%GCC_CMD% -std=c17 -O2 -Wall -Wextra -Wpedantic -DWIN32_LEAN_AND_MEAN -D__USE_MINGW_ANSI_STDIO=1 uef_test_mingw.c -o uef_test_mingw.exe
if errorlevel 1 exit /b 1

%GCC_CMD% -std=c17 -O2 -Wall -Wextra -Wpedantic -DWIN32_LEAN_AND_MEAN -D__USE_MINGW_ANSI_STDIO=1 vch_test.c -o vch_test_mingw.exe
if errorlevel 1 exit /b 1

%GCC_CMD% -std=c17 -O2 -Wall -Wextra -Wpedantic -DWIN32_LEAN_AND_MEAN -D__USE_MINGW_ANSI_STDIO=1 rtl_ftable_test.c -o rtl_ftable_test_mingw.exe
if errorlevel 1 exit /b 1

echo Built: veh_test_mingw.exe, uef_test_mingw.exe, vch_test_mingw.exe, rtl_ftable_test_mingw.exe
