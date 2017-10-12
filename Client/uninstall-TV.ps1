#Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine

function UninstallTV () {
    # http://lifeofageekadmin.com/how-to-uninstall-programs-using-powershell/
    $app = Get-WmiObject -Class Win32_Product | Where-Object {
        $_.Vendor -match “TeamViewer”
    }
    $app.Uninstall()
}


function CleanRegistryFromTV () {
    # https://msdn.microsoft.com/en-us/powershell/scripting/getting-started/cookbooks/working-with-registry-keys
    $path='HKLM:\SOFTWARE\Wow6432Node\TeamViewer'
    Remove-Item -path $path -Recurse 
} 


function FindAndStopTV () {
    # https://superuser.com/questions/873601/powershell-script-to-find-the-process-and-kill-the-process
    Get-Process | Where-Object { $_.Name -eq "TeamViewer" } | Select-Object -First 1 | Stop-Process -Force
    Get-Process | Where-Object { $_.Name -eq "tv_w32" } | Select-Object -First 1 | Stop-Process -Force
    Get-Process | Where-Object { $_.Name -eq "tv_x64" } | Select-Object -First 1 | Stop-Process -Force
    Get-Process | Where-Object { $_.Name -eq "TeamViewer_Service" } | Select-Object -First 1 | Stop-Process -Force
}

# OBS - for prod the master branch shall be used
$url = "https://raw.githubusercontent.com/fdtteknik/KundSetup/master"
$fpath = "C:\temp\"

Write-Host "Stopping any running TeamViewer sessions"
FindAndStopTV

Write-Host "Removing TeamViewer from computer"
UninstallTV

Write-Host "Scrubbing registry from TeamViewer keys"
CleanRegistryFromTV

#$name = "{0}-{1}-{2}" -f $kundnr, $typ, $seq
#Write-Host "InstallTeamViewerHost with alias: "$name
#InstallTeamViewerHost -name $name

Exit