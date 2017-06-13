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

function ReadAndValidateXMLFile($xmlFile) {

    If($XmlFile){
        If(!(Test-Path $XmlFile)){
            "Fel: XML-filen $XmlFile finns inte!" | Write-Host -ForegroundColor Red
            Avsluta
        } else {
            $InputXML = $XmlFile
        }
    } else {
        $InputXML = Select-FileDialog -Title "V√§lj XML-fil"
    }
    "InputXMLFile: $InputXML" | Write-Host 
    Try{
        [xml]$xmlContent = [xml](Get-Content -Path $InputXML)
        [System.Xml.XmlElement] $xmlRoot = $xmlContent.get_DocumentElement()
        [System.Xml.XmlElement] $xmlKunder = $XmlRoot.Kunder
    } Catch {
        "Fel: kontrollera XML-filen! $($_.Exception.Message)" | Write-Host -ForegroundColor Red
        Exit
    }
    if ($xmlKunder.ChildNodes.Count -ne 1) {
        "Fel: The XML file should contain one and only one Kund" | Write-Host -ForegroundColor Red
        Exit
    }
    return $xmlKunder.Kund
}


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
        $_.Vendor -match ìTeamViewerî
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
   Write-Host "Sleepinh 30 seconds to allow TeamViewer to do registration & book keeping"
   Start-Sleep 30
   Write-Host "Performing TeamViewer Assignment..."
   $mcmd =$fpath+'TeamViewer_Assignment.exe -apitoken 2223529-gKHel3wekMqjcs9AHfga -datafile "{0}\TeamViewer\AssignmentData.json" -devicealias {1} -wait "30"' -f ${env:ProgramFiles(x86)}, $name
   cmd /c $mcmd /S
}


function FindAndStopTV () {
    # https://superuser.com/questions/873601/powershell-script-to-find-the-process-and-kill-the-process
    Get-Process | Where-Object { $_.Name -eq "TeamViewer" } | Select-Object -First 1 | Stop-Process -Force
    Get-Process | Where-Object { $_.Name -eq "tv_w32" } | Select-Object -First 1 | Stop-Process -Force
    Get-Process | Where-Object { $_.Name -eq "tv_x64" } | Select-Object -First 1 | Stop-Process -Force
}


$typ = ValidateDTyp -dtyp $dtyp

# OBS - for prod the master branch shall be used
$url = "https://raw.githubusercontent.com/fdtteknik/KundSetup/master"
$tvmsi = "TeamViewer_Host-idcfv2nduh.msi"
$tvass = "TeamViewer_Assignment.exe"
$fpath = "C:\temp\"

$tvmsiurl = $url+'/Client/assets/TeamViewerMSI'
Write-Host "Retrieving "$tvmsi
GetFileFromWeb -baseurl $tvmsiurl -dst $fpath -file $tvmsi

$tvassurl = $url+'/Client/assets/TeamViewer_Host_Assignment/Win'
Write-Host "Retrieving "$tvass
GetFileFromWeb -baseurl $tvassurl -dst $fpath -file $tvass

Write-Host "Sleeping 5 seconds to allow abort"
Start-Sleep 5

Write-Host "Stopping any running TeamViewer sessions"
FindAndStopTV

Write-Host "Removing TeamViewer from computer"
UninstallTV

Write-Host "Scrubbing registry from TeamViewer keys"
CleanRegistryFromTV

$name = "{0}-{1}-{2}" -f $kundnr, $typ, $seq
Write-Host "InstallTeamViewerHost with alias: "$name
InstallTeamViewerHost -tvtoken $xmlKund.tvtoken -name $name

Write-Host "Installation Completed!!!"
Exit