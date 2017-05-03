@ECHO OFF

SET PowerShellScriptPath=C:\FDT\KundSetup\Client\Setup.ps1
echo %PowerShellScriptPath%
mkdir C:\FDT\KundSetup\Client
bitsadmin.exe /transfer "FDT SETUP" https://raw.githubusercontent.com/fdtteknik/KundSetup/Client-Server-XML/Client/Setup.ps1 %PowerShellScriptPath%
PowerShell -NoProfile -noexit -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -noexit -ExecutionPolicy Unrestricted -File ""%PowerShellScriptPath%""' -Verb RunAs}";
