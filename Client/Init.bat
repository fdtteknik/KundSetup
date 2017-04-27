@ECHO OFF

SET PowerShellScriptPath=C:\FDT\KundSetup\Setup.ps1
echo %PowerShellScriptPath%
mkdir C:\FDT\KundSetup\
bitsadmin.exe /transfer "FDT SETUP" https://raw.githubusercontent.com/fdtteknik/KundSetup/master/Client/Setup.ps1
PowerShell -NoProfile -noexit -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -noexit -ExecutionPolicy Unrestricted -File ""%PowerShellScriptPath%""' -Verb RunAs}";
