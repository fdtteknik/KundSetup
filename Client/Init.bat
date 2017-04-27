@ECHO OFF

SET PowerShellScriptPath=C:\FDT\FDT-3pcauto\Setup.ps1
echo %PowerShellScriptPath%
mkdir C:\FDT\FDT-3pcauto\
bitsadmin.exe /transfer "FDT SETUP" https://raw.githubusercontent.com/nomikem/FDT-3pcauto/master/Setup.ps1 C:\FDT\FDT-3pcauto\Setup.ps1
PowerShell -NoProfile -noexit -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList '-NoProfile -noexit -ExecutionPolicy Unrestricted -File ""%PowerShellScriptPath%""' -Verb RunAs}";
