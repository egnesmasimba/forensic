@echo off
setlocal
rem Locate a Visual Studio x64 environment without assuming an edition.
set "VCVARS="
for %%E in (Community Professional Enterprise BuildTools) do (
  if not defined VCVARS if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat" (
    set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not defined VCVARS (
  echo build-windows: no Visual Studio 2022 vcvars64.bat found 1>&2
  exit /b 1
)
call "%VCVARS%" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
rem Objects must go under build\ or they land in the caller's working directory.
cl /nologo /std:c11 /W4 /WX /D_CRT_SECURE_NO_WARNINGS pam_ticket.c /Fobuild\ /Febuild\pam-ticket.exe winhttp.lib
if errorlevel 1 exit /b 1
rem The redeem client has no stdin ticket here, so only the offline checks run.
build\pam-ticket.exe --self-test
exit /b %errorlevel%