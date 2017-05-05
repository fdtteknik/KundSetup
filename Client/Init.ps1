param ( 
   [string]$kundnr = "", 
   [string]$dtyp = "",
   [string]$seq = ""
)

#Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine

# Constants ..................................................................
$KASSA = "KASSA"
$K = "K"

$BO = "BO"
$B = "B"

$ORDER = "ORDER"
$O = "O"

$LASERSKRIVARE = "LASERSKRIVARE"
$KVITTOSKRIVARE = "KVITTOSKRIVARE"

$fpath = "C:\FDT\KundSetup\Client\"

# Functions ..................................................................
function DtypGetShort ($dtyp) {
    If ($dtyp -eq $KASSA -Or $dtyp -eq $K) {
       return $K
    } ElseIf ($dtyp -eq $BO -Or $dtyp -eq $B) {
       return $B
    } ElseIf ($dtyp -eq $ORDER -Or $dtyp -eq $O) {
       return $O
    } 
    return $dtyp
}

function DtypGetLong ($dtyp) {
    If ($dtyp -eq $KASSA -Or $dtyp -eq $K) {
       return $KASSA
    } ElseIf ($dtyp -eq $BO -Or $dtyp -eq $B) {
       return $BO
    } ElseIf ($dtyp -eq $ORDER -Or $dtyp -eq $O) {
       return $ORDER
    } 
    return $dtyp
}


function IsKassa($dtyp) {
   $lDtyp = DtypGetLong($dtyp)
   if ($lDtyp -eq $KASSA) {
      return $true
   }
   return $false
}

function IsOrder($dtyp) {
   $lDtyp = DtypGetLong($dtyp)
   if ($lDtyp -eq $ORDER) {
      return $true
   }
   return $false
}

function IsBO($dtyp) {
   $lDtyp = DtypGetLong($dtyp)
   if ($lDtyp -eq $BO) {
      return $true
   }
   return $false
}

function ValidateDTypAndSequence ($dtyp, $seq, $json) {
   if (IsKassa($dtyp)) {
      if ($seq -lt 1 -Or $seq -gt $json.kassor.Count) {
         Write-Host -ForegroundColor Red "The sequence number for KASSA must be between 1 and "$json.kassor.Count 
         Start-Sleep 20
          Exit
      }
   } ElseIf (IsBO($dtyp)) {
      if ($seq -lt 1 -Or $seq -gt $json.bos.Count) {
         Write-Host -ForegroundColor Red "The sequence number for BO must be between 1 and "$json.bos.Count 
         Start-Sleep 20
         Exit
      }
   } ElseIf (IsOrder($dtyp))  {
      if ($seq -lt 1 -Or $seq -gt $json.order.Count) {
         Write-Host "The sequence number for ORDER must be between 1 and "$json.order.Count 
         Start-Sleep 20
         Exit
      }
   } Else {
      Write-Host -ForegroundColor Red $dtyp" Not a valid computer type! Should be KASSA, ORDER or BO" 
      Start-Sleep 20
      Exit
   }
}


function ValidateDTypAndSequenceXML ($dtyp, $seq, $xml) {
   if (IsKassa($dtyp)) {
      if ($seq -lt 1 -Or $seq -gt $xml.Kassor.ChildNodes.Count) {
         Write-Host -ForegroundColor Red "The sequence number for KASSA must be between 1 and "$xml.Kassor.ChildNodes.Count 
         Start-Sleep 20
          Exit
      }
   } ElseIf (IsBO($dtyp)) {
      if ($seq -lt 1 -Or $seq -gt $xml.Backofficeplatser.ChildNodes.Count) {
         Write-Host -ForegroundColor Red "The sequence number for BO must be between 1 and "$xml.Backofficeplatser.ChildNodes.Count 
         Start-Sleep 20
         Exit
      }
   } ElseIf (IsOrder($dtyp))  {
      if ($seq -lt 1 -Or $seq -gt $xml.Orderplatser.ChildNodes.Count) {
         Write-Host -ForegroundColor Red "The sequence number for ORDER must be between 1 and "$xml.Orderplatser.ChildNodes.Count 
         Start-Sleep 20
         Exit
      }
   } Else {
      Write-Host -ForegroundColor Red $dtyp" Not a valid computer type! Should be KASSA, ORDER or BO" 
      Start-Sleep 20
      Exit
   }
}

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

function InstallA4Printers ($kundnr, $dtyp, $printers) {
    Write-Host -ForegroundColor Red "Installing A4 printer(s)"
    for ($i=0; $i -lt $printers.length; $i++) {
        if ($printers[$i].type.ToUpper() -eq $LASERSKRIVARE) {
            $pname = "{0}-{1}-{2}" -f $kundnr, $dtyp, $printers[$i].type.ToUpper() 
            $url = "{0}{1}" -f $printers[$i].url, $printers[$i].ip
            Add-Printer -Name $pname -DriverName "HP Universal Printing PCL 6" -DeviceURL $url -Location $dtyp
        }
    }
}

function NameComputer ($kundnr, $dtyp, $seq) {
    Write-Host "Changing name of computer"
    $typ = DtypGetLong -dtyp $dtyp

    $name = "{0}-{1}-{2}" -f $kundnr, $typ, $seq
    Rename-Computer -NewName $name
    return $name
}


function SetupUser ($name) {
   $uname = DtypGetLong -dtyp $name
   Write-Host "SetupUser" $uname

   $ComputerName = $env:COMPUTERNAME
   $Computer = [adsi]"WinNT://$ComputerName"
   $user = $Computer.psbase.Children.Find($uname)
   $user.LoginScript = $fpath+"Logon.ps1"
   $user.SetInfo()

   # Add new user to its groups (Users, Administrators)
   Add-LocalGroupMember -Group Users -Member $uname
   Add-LocalGroupMember -Group Administrators -Member $uname
}

function DisableUser($usrname, $Computer) {
   $EnableUser = 512
   $DisableUser = 2 
   $EnableUser = 512 
   $PasswordNotExpire = 65536 
   $PasswordCantChange = 64 

   $user = $Computer.psbase.Children.Find($usrname)
   $user.description = ‚ÄúDisabled Account‚Äù
   $user.UserFlags = $DisableUser + $PasswordNotExpire + $PasswordCantChange
   $user.SetInfo()
}

function DisableUnwantedUsers($dtyp) {
   # Users are enabled from start - this will disable pre-created accounts 
   $userkind = DtypGetLong -dtyp $dtyp

   $ComputerName = $env:COMPUTERNAME
   $Computer = [adsi]"WinNT://$ComputerName"   
   if ($userkind -ne $KASSA) {
      DisableUser -usrname "Kassa" -Computer $Computer
   } 
   if ($userkind -ne $Order) {
      DisableUser -usrname "Order" -Computer $Computer
   }
   if ($userkind -ne $BO) {
      DisableUser -usrname "Backoffice" -Computer $Computer
   }
}

function getKassaBySeq($xmlKassor, $seq) {
    foreach ($kassa in $xmlKassor.ChildNodes) {
        if ($kassa.nummer -eq $seq) {
            return $kassa
        }
    }
    "Unknown sequence nymber $seq specified for Kassa - Terminating" | Write-Host -ForegroundColor Red
    Exit
}

function getOderplatsBySeq($xmlOrderplatser, $seq) {
    foreach ($order in $xmlOrderplatser.ChildNodes) {
        if ($order.nummer -eq $seq) {
            return $order
        }
    }
    "Unknown sequence nymber $seq specified for Orderplats - Terminating" | Write-Host -ForegroundColor Red
    Exit
}

function getBackofficeplatserBySeq($xmlBackofficeplatser, $seq) {
    foreach ($bo in $xmlBackofficeplatser.ChildNodes) {
        if ($bo.nummer -eq $seq) {
            return $bo
        }
    }
    "Unknown sequence nymber $seq specified for Backofficeplats - Terminating" | Write-Host -ForegroundColor Red
    Exit
}

function Create-RDP($dtyp, $seq, $name, $xml) {
   Write-Host "Creating RDP Shortcuts"
   $resWidth = 1024
   $resHgt = 768

   $destination = $xml.RDS

   if (IsKassa($dtyp)) {
      $dator = getKassaBySeq -xmlKassor $xml.Kassor -seq $seq
   } ElseIf (IsBO($dtyp)) {
      $dator = getBackofficeplatserBySeq $xml.Backofficeplatser -seq $seq
   } ElseIf (IsOrder($dtyp)) {
      $dator =getOderplatsBySeq $xml.Orderplatser -seq $seq
   } Else {
      Write-Host -ForegroundColor Red $dtyp" Not a valid computer type! Should be KASSA, ORDER or BO" 
      Start-Sleep 20
      Exit
   }

$domain = $dator.domain
$username = $dator.rdp

#####################
$hereString = @"

audiomode:i:2
authentication level:i:0
autoreconnection enabled:i:1
bitmapcachepersistenable:i:1
compression:i:1
disable cursor setting:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:1
disable wallpaper:i:1
displayconnectionbar:i:1
keyboardhook:i:2
redirectclipboard:i:1
redirectcomports:i:0
redirectdrives:i:0
redirectprinters:i:0
redirectsmartcards:i:0
session bpp:i:16
prompt for credentials:i:0
promptcredentialonce:i:1
"@

$out = @()
$out += "full address:s:" + $destination
$out += "screen mode id:i:1"
$out += "desktopwidth:i:" + $resWidth
$out += "desktopheight:i:" + $resHgt
$out += "username:s:" + $domain + "\" + $username
$out += $hereString
$outFileName = $fpath+"Avance" + "-" + $username + ".rdp"
$out | out-file $outFileName
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


function MyImport-PfxCertificate {
   param([String]$certPath,[String]$certRootStore = "CurrentUser"ù,[String]$certStore = "My"ù,$pfxPass = $null)
   $pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2
   if ($pfxPass -eq $null) {$pfxPass = read-host "Enter the pfx password"ù -assecurestring}
   $pfx.import($certPath,$pfxPass,"Exportable,PersistKeySet"ù)
   $store = new-object System.Security.Cryptography.X509Certificates.X509Store($certStore,$certRootStore)
   $store.open("MaxAllowed")
   $store.add($pfx)
   $store.close()
}

function InstallERPosCert ($kundnr, $dtyp, $seq) {
   Write-Host "Setting up certificate import on user logon"
   $typ = DtypGetShort -dtyp $dtyp

   $cname = $kundnr + "_" + $typ + "_" + $seq + ".p12"
   $output = $fpath+$cname
   $FileExists = Test-Path $output
   If ($FileExists -eq $False) {
      Write-Host -ForegroundColor Red "The certificate " + $output + " does not exist"
      Exit
   }

   MyImport-PfxCertificate $output "CurrentUser" "My" $kundnr
   Import-Certificate -FilePath $fpath"ERIF_Certificate_Authority.p7b" -CertStoreLocation "Cert:\CurrentUser\Root"

   Add-Content $fpath+'Logon.ps1' "`n"
  
   $setcert = 'MyImport-PfxCertificate $output "CurrentUser" "My" $json.kundnr'
   $logonfile = $fpath+'Logon.ps1'
   Add-Content $logonfile $setcert
   Add-Content $logonfile "`n"
  
   $setcert = 'Import-Certificate -FilePath $fpath+"ERIF_Certificate_Authority.p7b" -CertStoreLocation "Cert:\CurrentUser\Root"'
   Add-Content $logonfile $setcert
   Add-Content $logonfile "`n"
}

function InstallERPos ($erurl) {
   Write-Host "Installing Exellence Retail..."
   #$output = "$PSScriptRoot\setup.exe"
   $output = $fpath+"setup.exe"
   $wc = New-Object System.Net.WebClient
   $wc.DownloadFile($erurl, $output)

   # TODO - run install now or later
   # To be defined - how
   # Olle claims best  done on first logon

}

function SetIP ($dtyp, $seq, $xml) {
   $myip = "127.0.0.1"
   if (IsKassa($dtyp)) {
      $dator = getKassaBySeq -xmlKassor $xml.Kassor -seq $seq
   } ElseIf (IsBO($dtyp)) {
      $dator = getBackofficeplatserBySeq $xml.Backofficeplatser -seq $seq
   } ElseIf (IsOrder($dtyp)) {
      $dator =getOderplatsBySeq $xml.Orderplatser -seq $seq
   } Else {
      Write-Host -ForegroundColor Red $dtyp" Not a valid computer type! Should be KASSA, ORDER or BO" 
      Start-Sleep 20
      Exit
   }
   $myip = $dator.butiksip
    
   $ifaces = Get-NetAdapter -physical | select Name
   foreach ($iface in $ifaces) {
      Write-Host $iface.name
      if ($iface.name.StartsWith("ethernet","CurrentCultureIgnoreCase")) {
         New-NetIPAddress -InterfaceAlias $iface.name -IPAddress $myIp -PrefixLength 24 -DefaultGateway $xml.butiksgw
      }
   }
}
 
# Main .......................................................................

# VERIFY THAT INPUT AND DATA MATCH 
Write-Host "ReadAndValidateXMLFile"
$xmlKund =  ReadAndValidateXMLFile -xmlFile $fpath$kundnr'.xml'

Write-Host "ValidateKundnr"
ValidateKundnr -iknr $kundnr -jknr $xmlKund.Kundnummer

Write-Host "ValidateDTypAndSequence"
ValidateDTypAndSequenceXML -dtyp $dtyp -seq $seq -xml $xmlKund

# Give Computer its name
# OK - 
$typ = DtypGetLong -dtyp $dtyp
Write-Host "NameComputer: $kundnr-$typ-$seq"
$name = NameComputer -kundnr $kundnr -dtyp $typ -seq $seq

# Skapa anv‰ndare
# OK - 
# Users already created in image - RIP this
#SetupUser -name $name
DisableUnwantedUsers -dtyp $dtyp

# Install printer
# TODO
# InstallA4Printers -kundnr $kundnr -dtyp $dtyp -printers $json.printers

# Skapa och L‰gg RDP pÂ skrivbordet
# OK - 
Write-Host "Create-RD"
Create-RDP -dtyp $dtyp -seq $seq -name $name -xml $xmlKund

# TeamViewer Host Konfigurera
# OK - 
Write-Host "InstallTeamViewerHost"
InstallTeamViewerHost -tvtoken $xmlKund.tvtoken -name $name

# Install Cert
# TODO
Write-Host "InstallERPosCert"
InstallERPosCert -kundnr $xmlKund.Kundnummer -dtyp $dtyp -seq $seq

# Install ERPOS
# OK - 
#Write-Host "InstallERPos"
#InstallERPos -erurl $xmlKund.erurl

# Set static IP
#Write-Host "SetIP"
#SetIP -dtyp $dtyp -seq $seq -xml $xmlKund