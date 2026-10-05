@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
cl /nologo /std:c++17 /EHsc /W4 main.cpp /Fobuild\main.obj /Febuild\evidence-hash.exe /link bcrypt.lib
exit /b %errorlevel%
