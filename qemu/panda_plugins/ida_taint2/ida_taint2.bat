:: ida_taint2.bat
:: Paths with spaces must be surrounded by quotes
:: Assumes everything (ida_taint2.bat, ida_taint2.py, pandalog_pb2.py, pandalog,
:: binary) is in the same directory
:: If file arguments aren't in the current directory, then the absolute path
:: must be used

@echo off

SET defaultIda="C:\Program Files (x86)\IDA 6.7\idaq.exe"

if "%~3" == "" (
    call:usage
    exit /b
)
%COMSPEC% /C "%defaultIda% -S"%CD%\ida_taint2.py \"%~1\" \"%~2\"" "%~3"
goto:eof

:usage
echo "Usage: ida_taint.bat <pandalog file> <process name> <binary>"
goto:eof

