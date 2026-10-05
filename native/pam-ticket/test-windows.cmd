@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /W4 /WX /std:c11 /D_CRT_SECURE_NO_WARNINGS /DFORENSIC_PAM_TEST /Itests\stubs pam_forensic_ticket.c tests\unit.c /Fobuild\ /Febuild\pam-unit.exe
if errorlevel 1 exit /b 1
build\pam-unit.exe
exit /b %errorlevel%
