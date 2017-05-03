param ( 
   [string]$kundnr = $( Read-Host "Mata in kundnr:" ), 
   [string]$dtyp = $( Read-Host "Mata in typ [K(ASSA)/B(O)/O(RDER)]:" ).ToUpper(),
   [string]$seq = $( Read-Host "Mata in sekvensnummer för typ:" )
)

#Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine

# Constants ..................................................................
$KASSA = "KASSA"
$BO = "BO"
$ORDER = "ORDER"
$LASERSKRIVARE = "LASERSKRIVARE"
$KVITTOSKRIVARE = "KVITTOSKRIVARE"

function ValidateDTyp ($dtyp)
{
   if ($dtyp -eq $KASSA -Or $dtyp -eq "K") 
   {
      return "K"
   }
   ElseIf ($dtyp -eq $BO -Or $dtyp -eq "B") 
   {
      retrun "B"
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

$typ = ValidateDTyp -dtyp $dtyp

# OBS - for prod the master branch shall be used
$url = "https://raw.githubusercontent.com/fdtteknik/KundSetup/master"

$dst = 'C:\FDT\KundSetup\Client'
$initb = "Init.bat"
$init = "Init.ps1"
$logon = "Logon.ps1"
$erif = "ERIF_Certificate_Authority.p7b"
$tvmsi = "TeamViewer_Host-idcfv2nduh.msi"
$tvass = "TeamViewer_Assignment.exe"

Write-Host "Retrieving "$initb
GetFileFromWeb -baseurl $url"/Client" -dst $dst -file $initb
Write-Host "Retrieving "$init
GetFileFromWeb -baseurl $url"/Client" -dst $dst -file $init
Write-Host "Retrieving "$logon
GetFileFromWeb -baseurl $url"/Client" -dst $dst -file $logon

$kundurl = $url+'/Kund/'+$kundnr
Write-Host "Retrieving "$kundnr'.json'
GetFileFromWeb -baseurl $kundurl -dst $dst -file $kundnr'.json'

$tvmsiurl = $url+'/Client/assets/TeamViewerMSI'
Write-Host "Retrieving "$tvmsi
GetFileFromWeb -baseurl $tvmsiurl -dst $dst -file $tvmsi

$tvassurl = $url+'/Client/assets/TeamViewer_Host_Assignment/Win'
Write-Host "Retrieving "$tvass
GetFileFromWeb -baseurl $tvassurl -dst $dst -file $tvass

Write-Host "Retrieving "$erif
GetFileFromWeb -baseurl $url"/Client" -dst $dst -file $erif

# Pull the ERCert
if ($typ -eq "K" -Or $typ -eq "O") {
   $thacert = $kundnr+'_'+$typ+'_'+$seq+'.p12'
   Write-Host "Retrieving "$thacert
   GetFileFromWeb -baseurl $kundurl -dst $dst -file $thacert
}

Write-Host "Sleeping 30 seconds to allow abort"
Start-Sleep 30

#Invoke-Expression $dst'\'$init "-kundnr $kundnr -dtyp $typ -seq $seq"
$argstr = "-kundnr $kundnr -dtyp $typ -seq $seq -noexit"
Invoke-Expression $dst"\Init.ps1 $argstr"