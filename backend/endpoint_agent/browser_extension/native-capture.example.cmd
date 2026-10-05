@echo off
set "ENDPOINT_AGENT_CONFIG=C:\ProgramData\ZANAQ\agent_config.json"
"C:\Program Files\ZANAQ\python.exe" -m endpoint_agent.native_capture %*
