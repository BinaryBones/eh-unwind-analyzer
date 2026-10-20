@echo off
setlocal

if "%~1"=="" (
  echo Usage: %~nx0 ^<path-to-eh_unwind_analyzer.exe^>
  exit /b 2
)

set TOOL=%~f1
pushd "%~dp0.."

set VEH_TARGET=tests\veh_test.exe
if not exist "%VEH_TARGET%" set VEH_TARGET=tests\veh_test_mingw.exe

set UEF_TARGET=tests\uef_test.exe
if not exist "%UEF_TARGET%" set UEF_TARGET=tests\uef_test_mingw.exe

set VCH_TARGET=tests\vch_test.exe
if not exist "%VCH_TARGET%" set VCH_TARGET=tests\vch_test_mingw.exe

set RTL_TARGET=tests\rtl_ftable_test.exe
if not exist "%RTL_TARGET%" set RTL_TARGET=tests\rtl_ftable_test_mingw.exe

if not exist "%VEH_TARGET%" (
  echo VEH smoke target not found. Build tests first with build_tests_msvc.bat or build_tests_mingw.bat.
  goto :fail
)

if not exist "%UEF_TARGET%" (
  echo UEF smoke target not found. Build tests first with build_tests_msvc.bat or build_tests_mingw.bat.
  goto :fail
)

if not exist "%VCH_TARGET%" (
  echo VCH smoke target not found.
  goto :fail
)

if not exist "%RTL_TARGET%" (
  echo Runtime function-table smoke target not found.
  goto :fail
)

echo [1/4] VEH smoke test using %VEH_TARGET%
"%TOOL%" "%VEH_TARGET%" --heuristics --dynamic --timeout-ms 8000 --trace-steps 32 --json tests\veh_dynamic_report.json > tests\veh_dynamic_console.txt 2>&1
if errorlevel 1 goto :fail

echo [2/4] UEF smoke test using %UEF_TARGET%
"%TOOL%" "%UEF_TARGET%" --heuristics --dynamic --timeout-ms 8000 --trace-steps 32 --json tests\uef_dynamic_report.json > tests\uef_dynamic_console.txt 2>&1
if errorlevel 1 goto :fail

echo [3/4] VCH smoke test using %VCH_TARGET%
"%TOOL%" "%VCH_TARGET%" --heuristics --dynamic --timeout-ms 8000 --trace-steps 32 --json tests\vch_dynamic_report.json > tests\vch_dynamic_console.txt 2>&1
if errorlevel 1 goto :fail

echo [4/4] Runtime function-table smoke test using %RTL_TARGET%
"%TOOL%" "%RTL_TARGET%" --heuristics --dynamic --timeout-ms 8000 --trace-steps 0 --json tests\rtl_dynamic_report.json > tests\rtl_dynamic_console.txt 2>&1
if errorlevel 1 goto :fail

where py >nul 2>nul
if not errorlevel 1 (
  py -3 tests\validate_dynamic_reports.py --schema docs\report.schema.json --veh tests\veh_dynamic_report.json --uef tests\uef_dynamic_report.json --vch tests\vch_dynamic_report.json --rtl tests\rtl_dynamic_report.json
) else (
  python tests\validate_dynamic_reports.py --schema docs\report.schema.json --veh tests\veh_dynamic_report.json --uef tests\uef_dynamic_report.json --vch tests\vch_dynamic_report.json --rtl tests\rtl_dynamic_report.json
)
if errorlevel 1 goto :fail

echo Dynamic smoke validation: OK
popd
exit /b 0

:fail
echo Dynamic smoke validation: FAILED
popd
exit /b 1
