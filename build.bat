@echo off
if not exist build mkdir build
gcc -o build/sniffle.exe src/*.c -I./include -I"C:/npcap-sdk/Include" -L"C:/npcap-sdk/Lib" -lwpcap -lws2_32
if %ERRORLEVEL% EQU 0 (
  echo Build successful!
) else (
  echo Build failed with error %ERRORLEVEL%
)
