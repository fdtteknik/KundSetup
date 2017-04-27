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

$dst = 'C:\FDT\FDT-3pcauto'
$url = "https://raw.githubusercontent.com/nomikem/FDT-3pcauto/master"
$initb = "Init.bat"
$init = "Init.ps1"
$logon = "Logon.ps1"
$erif = "ERIF_Certificate_Authority.p7b"
$tvmsi = "TeamViewer_Host-idcfv2nduh.msi"
$tvass = "TeamViewer_Assignment.exe"

GetFileFromWeb -baseurl $url -dst $dst -file $initb
GetFileFromWeb -baseurl $url -dst $dst -file $init
GetFileFromWeb -baseurl $url -dst $dst -file $logon

$kundurl = $url+'/kund/'+$kundnr
GetFileFromWeb -baseurl $kundurl -dst $dst -file $kundnr'.json'

$tvmsiurl = $url+'/assets/TeamViewerMSI'
GetFileFromWeb -baseurl $tvmsiurl -dst $dst -file $tvmsi

$tvassurl = $url+'/assets/TeamViewer_Host_Assignment/Win'
GetFileFromWeb -baseurl $tvassurl -dst $dst -file $tvass

GetFileFromWeb -baseurl $url -dst $dst -file $erif

# Pull the ERCert
if ($typ -eq "K" -Or $typ -eq "O") {
   $thacert = $kundnr+'_'+$typ+'_'+$seq+'.p12'
   GetFileFromWeb -baseurl $kundurl -dst $dst -file $thacert
}

#Invoke-Expression $dst'\'$init "-kundnr $kundnr -dtyp $typ -seq $seq"
$argstr = "-kundnr $kundnr -dtyp $typ -seq $seq -noexit"
Invoke-Expression "C:\FDT\FDT-3pcauto\Init.ps1 $argstr"