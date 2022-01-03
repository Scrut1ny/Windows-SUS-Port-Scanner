::--------------------------------------
:: Author: 0x00 | Scrut1ny
:: Project: Windows-SUS-Port-Scanner
:: Version: 1.0
::
:: Link: https://github.com/Scrut1ny/Windows-SUS-Port-Scanner
::--------------------------------------

@echo off
setlocal enabledelayedexpansion
title Bad Port Scanner
cls

>nul 2>&1 net sess||(powershell saps '%0'-Verb RunAs&exit /b)

set "portlist=:22 :1080 :2745 :3127 :3389 :4444 :5554 :8866 :9898 :9988 :12345 :27374 :31337"

:portscan
echo [1;1H
netstat -ano | findstr "%portlist%" | find /v "[" >nul
if "!errorlevel!"=="0" (
    color 04
    echo   [+] Suspicious connections found:
    for /f "tokens=3" %%A in ('netstat -ano ^| findstr "%portlist%" ^| find /v "["') do (
        for /f "tokens=1,2 delims=:" %%B in ("%%~A") do (
            echo        IP: %%~B    Port: %%~C
            powershell "[console]::beep(3000,100)"
            netsh advfirewall firewall add rule name="SUS CONNECTION: %%~B" protocol=TCP dir=in remoteip=%%~B remoteport=%%~C action=block
            netsh advfirewall firewall add rule name="SUS CONNECTION: %%~B" protocol=TCP dir=out remoteip=%%~B remoteport=%%~C action=block
			
			netsh advfirewall firewall add rule name="SUS CONNECTION: %%~B" protocol=TCP dir=in localip=%%~B localport=%%~C action=block
            netsh advfirewall firewall add rule name="SUS CONNECTION: %%~B" protocol=TCP dir=out localip=%%~B localport=%%~C action=block
        )
    )
) else (
    color 02
    echo   [-] Connection Clean
)

choice /c:cq /d c /t 1 /n >nul
if "!errorlevel!"=="2" exit /b
goto :portscan
