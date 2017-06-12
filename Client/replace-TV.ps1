param ( 
   [string]$kundnr = $( Read-Host "Mata in kundnr:" ), 
   [string]$dtyp = $( Read-Host "Mata in typ [K(ASSA)/B(ACKOFFICE)/O(RDER)]:" ).ToUpper(),
   [string]$seq = $( Read-Host "Mata in sekvensnummer fˆr typ:" )
)

#Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine

# Constants ..................................................................
$KASSA = "KASSA"
$BO = "BACKOFFICE"
$ORDER = "ORDER"

function ValidateDTyp ($dtyp)
{
   if ($dtyp -eq $KASSA -Or $dtyp -eq "K") 
   {
      return "K"
   }
   ElseIf ($dtyp -eq $BO -Or $dtyp -eq "B") 
   {
      return "B"
   }
   ElseIf ($dtyp -eq $ORDER -Or $dtyp -eq "O") 
   {
      return "O"
   }
   Else {
      Write-Host $dtyp" Not a valid computer type! Should be KASSA, ORDER or BO" 
      Start-Sleep 20
      Exit
   }
}

function GetFileFromWeb ( $baseurl, $dst, $file ) {
   if (!(Test-Path -Path $dst)) {
      New-Item -ItemType directory -Path $dst
   }

   $WebClient = New-Object System.Net.WebClient
   try {
      $WebClient.DownloadFile( $baseurl+'/'+$file, $dst+'\'+$file )
   } catch [System.Net.WebException] {
      Write-Host "FATAL ERROR: Couldnt find "$baseurl'/'$file
      Exit
   }
}

function UninstallTV () {
    # http://lifeofageekadmin.com/how-to-uninstall-programs-using-powershell/
    $app = Get-WmiObject -Class Win32_Product | Where-Object {
        $_.Name -match ìHP ProLiant Health Monitor Service (X64)î
    }
    $app.Uninstall()
}


function CleanRegistryFromTV () {
    # https://msdn.microsoft.com/en-us/powershell/scripting/getting-started/cookbooks/working-with-registry-keys
    $path='HKLM:\SOFTWARE\Wow6432Node\TeamViewer'
    Remove-Item -path $path -Recurse 
} 


function InstallTeamviewerHost ($tvtoken, $name) {
   # This i a Ugly one with a lot of requirements other wise the AssignmnetData.json wont be generated'
   # To use the new Silent Host Roll Out feature, a few requirements exist:
   ## TeamViewer 12 Corporate license activated on your account
   ## Custom TeamViewer 12 Host with Allow account assignment without confirmation‚Äù activated
   ## Custom Host is deployed with the Configuration ID in the file name
   ## Device is not already assigned to an existing account when the new Host is deployed
   ## Only works for Host, not for TeamViewer full version
   # AND ...
   # To change the assignment you need to uninstall the Host. You can keep all the settings but you have to delete two registry values:
   # [HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\TeamViewer]
   # "Device_Auto_Assigned_To_Account"
   # [HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\TeamViewer\DeviceManagement]
   # "Managers"

   Write-Host "Installing TeamViewer Host ..."
   $msifile= $fpath+'TeamViewer_Host-idcfv2nduh.msi' 
   $arguments= ' /quiet' 
   Start-Process `
        -file  $msifile `
        -arg $arguments `
        -passthru | wait-process
   Start-Sleep 30
   Write-Host "Performing TeamViewer Assignment..."
   $mcmd =$fpath+'TeamViewer_Assignment.exe -apitoken {0} -datafile "{1}\TeamViewer\AssignmentData.json" -devicealias {2} -wait "30"' -f $tvtoken, ${env:ProgramFiles(x86)}, $name
   cmd /c $mcmd /S
}


function FindAndStopTV () {
    # https://superuser.com/questions/873601/powershell-script-to-find-the-process-and-kill-the-process
    Get-Process | Where-Object { $_.Name -eq "myprocess" } | Select-Object -First 1 | Stop-Process
}


$typ = ValidateDTyp -dtyp $dtyp

# OBS - for prod the master branch shall be used
$url = "https://raw.githubusercontent.com/fdtteknik/KundSetup/master"
$dst = 'C:\FDT\KundSetup\Client'
$tvmsi = "TeamViewer_Host-idcfv2nduh.msi"
$tvass = "TeamViewer_Assignment.exe"
$fpath = "C:\temp\"

$kundurl = $url+'/Kund/'+$kundnr
Write-Host "Retrieving "$kundnr'.xml'
GetFileFromWeb -baseurl $kundurl -dst $dst -file $kundnr'.xml'

Write-Host "ReadAndValidateXMLFile"
$xmlKund =  ReadAndValidateXMLFile -xmlFile $fpath$kundnr'.xml'

$tvmsiurl = $url+'/Client/assets/TeamViewerMSI'
Write-Host "Retrieving "$tvmsi
GetFileFromWeb -baseurl $tvmsiurl -dst $dst -file $tvmsi

$tvassurl = $url+'/Client/assets/TeamViewer_Host_Assignment/Win'
Write-Host "Retrieving "$tvass
GetFileFromWeb -baseurl $tvassurl -dst $dst -file $tvass

Write-Host "Sleeping 30 seconds to allow abort"
Start-Sleep 30

Write-Host "Stopping any running TeamViewer sessions"
FindAnsStopTV

$name = "{0}-{1}-{2}" -f $kundnr, $typ, $seq
Write-Host "InstallTeamViewerHost"
InstallTeamViewerHost -tvtoken $xmlKund.tvtoken -name $name