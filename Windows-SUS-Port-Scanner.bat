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

>nul 2>&1 net sess || (powershell saps '%0' -Verb RunAs & goto :eof)

set "portlist=:22 :1080 :2745 :3127 :3389 :4444 :5554 :8866 :9898 :9988 :12345 :27374 :31337"

:portscan
echo [1;1H
set "tmpfile=%temp%\portscan.tmp"
netstat -ano | findstr "%portlist%" | find /v "[" >"%tmpfile%"
if not errorlevel 1 (
    color 04
    echo   [+] Suspicious connections found:
    for /f "tokens=3" %%A in (%tmpfile%) do (
        for /f "tokens=1,2 delims=:" %%B in ("%%~A") do (
            set "ip=%%~B"
            set "port=%%~C"
            echo    IP: !ip!    Port: !port!
            powershell "[console]::beep(3000,100)"
            netsh advfirewall firewall add rule name="SUS CONNECTION: !ip!,!port!" protocol=TCP dir=inout localip=!ip! remoteip=!ip! localport=!port! remoteport=!port! action=block
        )
    )
) else (
    color 02
    echo   [-] Connection Clean
)

del "%tmpfile%"
timeout /t 1 >nul
goto :portscan
