## Script för att skapa nya kunder i AD
# Kräver input-fil i xml-format
# XML-fil kan antingen anges direkt, eller så öppnas en dialog för att välja filen
# Exempel: <script> -XMLFile C:\Xmlfile.xml

[CmdletBinding()]
param(
    [string]$XmlFile
)


Function Write-Log{

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory=$True,
            Position=1,
            ValueFromPipeLine=$True)]
            [string[]]$Object,
        [Parameter(
            Position=2)]
            [string]$LogFile,
        [switch]$Passthru
    )
    Begin
    {
        If(!($LogFile)){
            Return
        }
        else{
            If(!(Test-Path -Path $LogFile)){
                New-Item -Path $LogFile -ItemType File -Force -Whatif:$False | Out-Null
            }
        }
    }

    Process
    {
        $Object | Out-File -FilePath $LogFile -Append -WhatIf:$false
        If($Passthru){
            $Object
        }
    }
}


Function Select-FileDialog {
    param([string]$Title,[string]$Directory,[string]$Filter="XML-fil (*.xml)|*.xml")
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    $objForm = New-Object System.Windows.Forms.OpenFileDialog
    $objForm.InitialDirectory = $Directory
    $objForm.Filter = $Filter
    $objForm.Title = $Title
 
    $Show = $objForm.ShowDialog()
 
    If ($Show -eq 2){ #If user press cancel in dialog
        exit
    }
    else{
        Return $objForm.FileName
    }
}


Function SetACLonHomeDir($UserID,$Server)
{
    $User = Get-ADUser $UserID -Properties * -Server $Server
    $Homedir = $User.HomeDirectory
        
    $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation = [system.security.accesscontrol.PropagationFlags]"None"  
    $colRights = [System.Security.AccessControl.FileSystemRights]"Modify,DeleteSubdirectoriesAndFiles, Write, ReadAndExecute, Synchronize"
    $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($User.SID,$colRights,$inherit,$propagation,"Allow")

    $NewAcl = Get-Acl $Homedir
    $NewAcl.AddAccessRule($accessrule)
    Set-Acl -aclobject $NewAcl $Homedir
}

Function SetACLonSharedFolder{
    [CmdLetBinding()]
    param(
    [string]$Group,
    [string]$Dir,
    [string]$Server
    )

    If(!([bool](Get-ADGroup -Filter {samaccountname -eq $Group} -Server $Server))){
        Write-Error "$Group finns inte!"
        break
    }

    If(!(Test-Path -Path $Dir)){
        Write-Error "$Dir finns inte!"
        break
    }

    $ADGroup = Get-ADGroup -Identity $Group -Properties * -Server $Server
    $ACL = Get-Acl $Dir

    $DomainAndUserString = (Get-ADDomain).NetBiosName + "\" + $ADGroup.SamaccountName

    If($acl.Access.IdentityReference.value -notcontains $DomainAndUserString){
        $inherit = [system.security.accesscontrol.InheritanceFlags]"ContainerInherit, ObjectInherit"
        $propagation = [system.security.accesscontrol.PropagationFlags]"None" 
        $colRights = [System.Security.AccessControl.FileSystemRights]"Modify,DeleteSubdirectoriesAndFiles, Write, ReadAndExecute, Synchronize"
        $NewAcl = Get-Acl $dir
        $accessrule = New-Object system.security.AccessControl.FileSystemAccessRule($ADGroup.SID,$colRights,$inherit,$propagation,"Allow")
        $NewAcl.AddAccessRule($accessrule)
        Set-Acl -aclobject $NewAcl $dir
    }
    else{
        Write-Error "$Group har redan rättigheter på $Dir"
        break
    }
}

Function TestIfElevated{
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()  
$principal = new-object Security.Principal.WindowsPrincipal $identity 
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)  
  
    If($elevated){  
        return $true
    }
    else{
        return $false
    }
}

Function New-PrinterPermissionSDDL{
# Genererar SDDL för att lägga till behörighet på skrivare
# Exempel:
# $SDDL = Get-Printer "Canon Inkjet 0253" -Full | New-PrinterPermissionSDDL -Account user01 -AccessMask PrintPermissions
# Set-Printer "Canon Inkjet 0253" -PermissionSDDL $SDDL

[cmdletbinding(  
    ConfirmImpact = 'Low',
    SupportsShouldProcess = $false
)]  

[OutputType('System.String')]

param(
    [Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$False)]
    [String]$Account,

    [Parameter(Position=1,Mandatory=$True,ValueFromPipelineByPropertyName)]
    [String]$PermissionSDDL,

    [Parameter(Position=2,Mandatory=$True,ValueFromPipeline=$False)]
    [ValidateSet('Takeownership','ReadPermissions','ChangePermissions','ManageDocuments','ManagePrinters','PrintPermissions')]
    [String]$AccessMask
)

BEGIN {

    #Set-StrictMode -Version Latest

    ${CmdletName} = $Pscmdlet.MyInvocation.MyCommand.Name

    Switch ($AccessMask){
        "Takeownership"{
            $Mask = 524288
            $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
            $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
            Break}
        "ReadPermissions"{
            $Mask = 131072
            $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
            $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
            Break}
        "ChangePermissions"{
            $Mask = 262144
            $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
            $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
            Break}
        "ManageDocuments"{
            $Mask = 983088
            $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::InheritOnly
            Break}
        "ManagePrinters"{
            $Mask = 983052
            $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
            $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
            Break}
        "PrintPermissions"{
            $Mask = 131080
            $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
            $PropagationFlags = [System.Security.AccessControl.PropagationFlags]::None
            Break}
    }
}

PROCESS {
    Try{
        $isContainer = $true
        $isDS = $false
        $SecurityDescriptor = New-Object -TypeName `
            Security.AccessControl.CommonSecurityDescriptor `
            $isContainer, $isDS, $PermissionSDDL

        Write-Verbose "Adding permission for $Account"
        #get the SID and add it to the SDDL
        $NTAccount = New-Object Security.Principal.NTAccount $Account
        $NTAccountSid = $NTAccount.Translate([Security.Principal.SecurityIdentifier]).Value

        $SecurityDescriptor.DiscretionaryAcl.AddAccess(
            [System.Security.AccessControl.AccessControlType]::Allow,
            $NTAccountSid,
            $Mask,
            $InheritanceFlags,
            $PropagationFlags) | Out-Null


        return $SecurityDescriptor.GetSddlForm("All")
    }
    Catch [Exception] {
        Write-Error -Message "Failed To Generate SDDL:`n $_.Message" -Exception $_.Exception
    }
}
END{Write-Verbose "Function ${CmdletName} finished."}
}

Function New-RandomPassword{

    Function Get-Seed{
        # Generate a seed for randomization
        $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
        $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
        $Random.GetBytes($RandomBytes)
        [BitConverter]::ToUInt32($RandomBytes, 0)
    }

    $InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789')
    $Password = @{}
    # Create char arrays containing groups of possible chars
    [char[][]]$CharGroups = $InputStrings

    # Create char array containing all chars
    $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

    # Set password length
    $PasswordLength = 8


    # Randomize one char from each group
    Foreach($Group in $CharGroups){
        if($Password.Count -lt $PasswordLength) {
            $Index = Get-Seed
            While ($Password.ContainsKey($Index)){
                $Index = Get-Seed                        
            }
            $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
        }
    }

    # Fill out with chars from $AllChars
    for($i=$Password.Count;$i -lt $PasswordLength;$i++){
        $Index = Get-Seed
        While ($Password.ContainsKey($Index)){
            $Index = Get-Seed                        
        }
        $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
    }

    Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))      
}

Function Avsluta{
    Write-Host "Tryck Enter för att avsluta..." -ForegroundColor Yellow -NoNewline; Read-Host
    exit
}



##### Start script #####


$Timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$LogFile = "$PSScriptRoot\Logs\FDT_Skapa_Kund-$Timestamp.log"

"$Timestamp - Executing $($MyInvocation.MyCommand.Name)" | Write-Log -LogFile $LogFile -Passthru | Write-Verbose

If(!(TestIfElevated)){
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptPath = '"' + $scriptPath + '"'

    [string[]]$argList = @('-NoLogo -NoProfile', '-ExecutionPolicy Bypass', '-File', $scriptPath)

    $argList += $MyInvocation.BoundParameters.GetEnumerator() | Foreach {"-$($_.Key)", "$($_.Value)"}
    $argList += $MyInvocation.UnboundArguments

    Try{    
        Start-Process PowerShell.exe -Verb Runas -WorkingDirectory $pwd -ArgumentList $argList
        exit
    }
    Catch {
        "Fel: $($_.Exception.Message)" | Write-Log -Logfile $Logfile -Passthru | Write-Host -ForegroundColor Red
        Avsluta
    }
}
Try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
Catch{
    "Fel: $($_.Exception.Message)" | Write-Log -Logfile $Logfile -Passthru | Write-Host -ForegroundColor Red
    Avsluta
}

$DomainController = (Get-ADDomainController).hostname
"Domaincontroller: $DomainController" | Write-Log -LogFile $Logfile -Passthru | Write-Verbose


#FDT-variabler
$OU_Kund_Container = "OU=Kund,DC=FDTCLOUD,DC=AD"
$VPNGroup = "rg-kunder-vpn"
$GPOTemplate = "Logon_template"
$ShareHomedir = "\\fdtcloudvfs002\users$"
$ShareGemensam = "\\fdtcloudvfs001\Gemensamma"
$PolicyFolder = "\\fdtcloud.ad\SYSVOL\FDTCLOUD.AD\Policies"
$StandardPrinterSDDL = "G:SYD:(A;;LCSWSDRCWDWO;;;S-1-5-21-1873536365-2480965478-889475739-500)(A;OIIO;RPWPSDRCWDWO;;;S-1-5-21-1873536365-2480965478-889475739-500)(A;;LCSWSDRCWDWO;;;BA)(A;OIIO;RPWPSDRCWDWO;;;BA)(A;;LCSWSDRCWDWO;;;S-1-5-21-1873536365-2480965478-889475739-1126)(A;OIIO;RPWPSDRCWDWO;;;S-1-5-21-1873536365-2480965478-889475739-1126)" #Standard printer permissions. Administrator, administrators, FDTCLOUD\support permissions.
$FDTiniTemplate = @"
[Katalog]
Program=C:\Program Files (x86)\FDT\Avance
Rapport=D:\Rapport
Data=D:\Data\<KUNDNUMMER>
KL=D:\Data\<KUNDNUMMER>
Dokument=H:\
Sie=H:\

[Allmänt]
RödaTråden=Ja
Klient=000
Användare=
Läsmig=2016-05-19
Lagerställe=1
Tips=NEJ
TipsNr=42
Report=2016-05-30|8.6.23
Verktyg=V1V0V2
Komihåg=Nej
Handdator=NONE
handdatorfil=H:\Handdator

[Databas]
sqlserver=fdtcloudsql01
sqllogin=fdt<KUNDNUMMER>
sqlpwd=<SQLPWD>
datakälla=sql
sqlTrusted=nej
SQLPrefix=fdt<KUNDNUMMER>
DatakällaFakt=sql
DatakällaBok=jet
DatakällaLev=sql
DatakällaLic=sql

[Fakturering]
TipsNr=45

[Leverantör]
TipsNr=13

[Rapport]
Egenfakturering_1=Lagerlista artikelgrupp|art04g|Art
Egenfakturering_2=Lagerlista stående|art04s|Art
Egenfakturering_3=Lagerlista stående artikelgrupp|art04sg|Art
Egenfakturering_4=Egensatta priser|art60|Art
Egenfakturering_5=Försäljning dag och butik|art07b|StatArt
Egenfakturering_6=Referens månad|kund09c|Statkund
Egenfakturering_7=Statistik per referens|kund09b|Statkund
Egenfakturering_8=Totalt Artikelgrupp|art61|StatArt
Egenfakturering_9=Totalt Varugrupp|art62|StatArt
Egenfakturering_10=Underl.lista det-ej offert|fakt12|Fakth||{fakth.status}>1
Egenfakturering_11=Underl.lista sum-ej offert|fakt22|Fakth||{fakth.status}>1

[Terminaler]
Vänster=1792
Topp=2960
Bredd=16875
Höjd=5000

[AliasLista]
Vänster=3900
Topp=3690
Bredd=8610
Höjd=4000
ArtSort=1

[LagerÄndra]
Blankett_11=Zebra etikett|EtikettGK420d
Normal=EtikettGK420d
Blankett_12=Zebra etikett (utan pris)|EtikettGK420d||VisaPris=0
blankett_1=Prisetikett A5 (övrigt)|lager01a5*1
blankett_2=Prisetikett A5|lager01a5b*1
blankett_3=Prisetikett A6|lager01a6*1
blankett_4=Prisetikett A7|lager01a7*1

[Inköp]
Blankett_1=Zebra etikett|EtikettLevGK420d|LEV

[LagerInfo]
Vänster=5835
Topp=2430
Bredd=9525
Höjd=4320
Delning=4762

[Spåra]
Vänster=-120
Topp=-465
Bredd=28980
Höjd=14850

[Leverantörsreskontra]
Vänster=0
Topp=0
Bredd=13350
Höjd=7800

[Prisinfo]
Vänster=1560
Topp=1560
Bredd=4755
Höjd=4245

[Handdator]
katalog=H:\Handdator
Automatisk=0
Inventering=Nej

[InköpPriser]
Vänster=0
Topp=5805
Bredd=9000
Höjd=2600

[Skrivare]

[Faktura]
blankett_21=Hemlån|fakt02hemlån
SvarNyKundRäknaOm=NEJ

[Utbetalning]
Sökväg=H:\
"@



If($XmlFile){
    If(!(Test-Path $XmlFile)){
        "Fel: XML-filen $XmlFile finns inte!" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Red
        Avsluta
    }
    else{
        $InputXML = $XmlFile
    }
}
else{
    $InputXML = Select-FileDialog -Title "Välj XML-fil"
}
"InputXMLFile: $InputXML" | Write-Log -LogFile $Logfile -Passthru | Write-Verbose
Try{
    [xml]$xmlContent = [xml](Get-Content -Path $InputXML)
    [System.Xml.XmlElement] $xmlRoot = $xmlContent.get_DocumentElement()
    [System.Xml.XmlElement] $xmlKunder = $XmlRoot.Kunder
}
Catch{
    "Fel: kontrollera XML-filen! $($_.Exception.Message)" | Write-Log -LogFile $LogFile | Write-Host -ForegroundColor Red
    Avsluta
}


Foreach($xmlKund in $xmlKunder.ChildNodes){

    [int]$Kundnummer = $xmlKund.Kundnummer
    [int]$Filialnummer = $xmlKund.Filialnummer
    $RDServer = $xmlKund.Server
    $IP = $xmlkund.IP
    $SQLPWD = $xmlkund.SQLPWD

    #Kontrollera XML
    If($Kundnummer -notmatch "^[0-9]{5}$"){
        "Felaktigt kundnummer: $Kundnummer" | Write-Log -LogFile $Logfile -Passthru | Write-Host -ForegroundColor Red
        Avsluta
    }
    else{
        "Kundnummer: $Kundnummer" | Write-Log -LogFile $Logfile -Passthru | Write-Host
    }
    If($Filialnummer -notmatch "^[0-9]{1,3}$"){
        "Felaktigt filialnummer: $Filialnummer" | Write-Log -LogFile $Logfile -Passthru | Write-Host -ForegroundColor Red
        Avsluta
    }
    else{
        "Filialnummer: $Filialnummer" | Write-Log -LogFile $Logfile -Passthru | Write-Host
    }
    If($RDServer -notmatch "^FDTCLOUDV?RD[0-9]{3}$"){
        "Felaktig server: $RDServer" | Write-Log -LogFile $Logfile -Passthru | Write-Host -ForegroundColor Red
        Avsluta
    }
    else{
        "Server: $RDServer" | Write-Log -LogFile $Logfile -Passthru | Write-Host
    }
    If($IP -notmatch "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}0$"){
        "Felaktigt IP: $IP" | Write-Log -LogFile $Logfile -Passthru | Write-Host -ForegroundColor Red
        Avsluta
    }
    else{
        "IP: $IP" | Write-Log -LogFile $Logfile -Passthru | Write-Host
    }
    If($SQLPWD -eq ""){
        "Kontrollera SQLPWD i XML-filen!" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Red
        Avsluta
    }
    If($XmlKund.Printers.ChildNodes.Count -gt 9){
        "För många skrivare: $($XmlKund.Printers.ChildNodes.Count) (max 9)" | Write-Log -LogFile $Logfile -Passthru | Write-Host -ForegroundColor Red
        Avsluta
    }

    #Butiksvariabler
    $Butiksnummer = "$Kundnummer-$Filialnummer"
    $Butiksgrupp = "$($Butiksnummer)GRP"
    $OU_Kund = "OU=$Kundnummer,$OU_Kund_Container"
    $RDServerGroup = "Remote-Desktop-Users_$RDServer"
    $RDServerMapp = "\\$RDServer\d$\Data\$Kundnummer"
    $RDServerDataZip = "\\$RDServer\d$\Data\Support\fdtovning.zip"
    $KundGPO = "$($Kundnummer)logon"
    $KundGemensam = "$ShareGemensam\$Kundnummer"
    $OutputFileHTML = "$PSScriptRoot\$($Butiksnummer)_$Timestamp.html"
    $FDTini = $FDTiniTemplate.Replace("<KUNDNUMMER>",$Kundnummer).Replace("<SQLPWD>",$SQLPWD)

    #Skapa OU
    If(!(Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$OU_Kund'" -Server $DomainController)){
        "Skapar OU: $OU_Kund" | Write-Log -LogFile $Logfile -Passthru | Write-Host -ForegroundColor Green
        New-ADOrganizationalUnit -Name $Kundnummer -Path $OU_Kund_Container -Server $DomainController
    }
    else{
        "OU existerar: $OU_Kund" | Write-Log -LogFile $Logfile -Passthru | Write-Host -ForegroundColor Green
    }

    #Skapa grupp
    If(!(Get-ADGroup -Filter {samaccountname -eq $Butiksgrupp} -Server $DomainController)){
        "Skapar grupp: $Butiksgrupp" | Write-Log -LogFile $Logfile -Passthru | Write-Host -ForegroundColor Green
        New-ADGroup -Name $Butiksgrupp -Path $OU_Kund -GroupScope Global -Server $DomainController
        If([bool](Get-ADGroup -Filter {samaccountname -eq $RDServerGroup} -Server $DomainController)){
            "Lägger till $Butiksgrupp i $RDServerGroup" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Green
            Add-ADGroupMember -Identity $RDServerGroup -Members $Butiksgrupp -Server $DomainController            
        }
        else{
            "Varning: $RDServerGroup existerar inte! Skapa gruppen och lägg till $Butiksgrupp som medlem manuellt." | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Yellow
        }
    }
    else{
        "Grupp existerar: $Butiksgrupp" | Write-Log -LogFile $Logfile -Passthru | Write-Host -ForegroundColor Red
        Avsluta        
    }



    #Skapa användare
    $UserIncrement = 1
    $OutputUsers = @()

    Foreach($User in $XmlKund.Users.ChildNodes){
    
        $Username = "$($Butiksnummer)U$($UserIncrement)"

        If($User.Firstname -eq ""){
            "Kontrollera Firstname för användare nummer $UserIncrement i XML-filen!" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Red
            Avsluta
        }
        If($User.Lastname -eq ""){
            "Kontrollera Lastname för användare nummer $UserIncrement i XML-filen!" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Red
            Avsluta
        }

        If([bool](Get-ADUser -Filter {samaccountname -eq $Username})){
            "Fel: Användaren $Username finns redan!" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Red
            Avsluta
        }

        "Skapar användare: $Username" | Write-Log -LogFile $Logfile -Passthru | Write-Host -ForegroundColor Green

        $Password = New-RandomPassword
        $Homedir = "$ShareHomedir\$Username"

        New-ADUser -Path $OU_Kund `
            -SamAccountName $Username `
            -Name $Username `
            -Surname $User.Lastname `
            -GivenName $User.Firstname `
            -DisplayName "$($User.Firstname) $($User.Lastname)" `
            -Enabled $True `
            -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
            -ChangePasswordAtLogon $false `
            -CannotChangePassword $true `
            -PasswordNeverExpires $true `
            -HomeDrive "H:" `            -HomeDirectory $Homedir `
            -UserPrincipalName "$Username@FDTCLOUD.AD" `
            -Server $DomainController

        New-Item -Type Directory -Path $Homedir | Out-Null
        SetACLonHomeDir -UserID $Username -Server $DomainController    
        $FDTini | Out-File -FilePath "$Homedir\fdt.ini" -Encoding default

        Add-ADGroupMember -Identity $Butiksgrupp -Members $Username -Server $DomainController

        If($User.'VPN-access' -eq 1){
            "Lägger till användaren $Username i $VPNGroup" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Green
            Add-ADGroupMember -Identity $VPNGroup -Members $Username        
        }

        #Ge CCC-genväg till Kassa 1
        If($UserIncrement -eq 1){
            Set-GPPermission -Name Shortcut_CCC -PermissionLevel GpoApply -TargetName $Username -TargetType User -Server $DomainController | Out-Null
        }

        $OutputUser = New-Object PSObject -Property @{
                    'Domän\användarnamn' = "FDTCLOUD\$Username"
                    Namn = "$($User.Firstname) $($User.Lastname)"
                    Lösenord = $Password
                    'VPN-användare' = "$(Switch($User.'VPN-access'){
                    "1"{"$Username"}
                    "0"{"-"}
                    })"
                }


        $OutputUsers += @($OutputUser)

        $UserIncrement++
    }

    #Skapa skrivare på RDServer
    $PrinterIncrement = 220
    $OutputPrinters = @()
    Foreach($Printer in $XmlKund.Printers.ChildNodes){

        $PrinterName = "$Butiksnummer - $($Printer.Location) - $($Printer.Description)"
        $PrinterIP = "$($IP.Substring(0,$IP.LastIndexOf(".")+1))$PrinterIncrement"
    
        "Skapar skrivare på $($RDServer): $PrinterName / port: $PrinterIP" | Write-Log -LogFile $Logfile -Passthru | Write-Host -ForegroundColor Green
        If(!(Get-PrinterPort -Name $PrinterIP -ComputerName $RDServer -ErrorAction SilentlyContinue)){
            Add-PrinterPort -Name $PrinterIP -PrinterHostAddress $PrinterIP -ComputerName $RDServer
        }
        else{
            "Varning: Printerport $PrinterIP finns redan" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Yellow
        }
        Add-Printer -Name $PrinterName -PortName LPT1: -DriverName "HP Universal Printing PCL 6" -ComputerName $RDServer
        $PrinterSDDL = New-PrinterPermissionSDDL -Account $Butiksgrupp -PermissionSDDL $StandardPrinterSDDL -AccessMask PrintPermissions
        $PrinterSDDL = New-PrinterPermissionSDDL -Account $Butiksgrupp -PermissionSDDL $PrinterSDDL -AccessMask ManageDocuments
        Set-Printer -Name $PrinterName -PermissionSDDL $PrinterSDDL -PortName $PrinterIP -ComputerName $RDServer


        $OutputPrinter = New-Object PSObject -Property @{
                    Skrivare = $PrinterName
                    "IP-adress" = $PrinterIP
                }


        $OutputPrinters += @($OutputPrinter)

        $PrinterIncrement++
    }


    #Skapa kundmapp på RDServer
    If(!(Test-Path -Path $RDServerMapp)){
        "Skapar mapp: $RDServerMapp" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Green
        New-Item -Path $RDServerMapp -ItemType Directory | Out-Null
        SetACLonSharedFolder -Dir $RDServerMapp -Group $Butiksgrupp -Server $DomainController
    }
    else{
        "Mapp $RDServerMapp finns redan, lägger till rättigheter för $Butiksgrupp" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Yellow
        SetACLonSharedFolder -Dir $RDServerMapp -Group $Butiksgrupp -Server $DomainController
    }
    #Kopiera fdtovning.zip till kundmappen
    If(!(Test-Path -Path $RDServerDataZip)){
        "Fdtovning.zip ($RDServerDataZip) saknas! Kontrollera detta och lägg till den manuellt i: $RDServerMapp" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Red
    }
    elseif(Test-Path -Path "$RDServerMapp\fdtovning.zip"){
        "Fdtovning.zip finns redan i $RDServerMapp" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Yellow
    }
    else{
        "Kopierar $RDServerDataZip till kundkatalog." | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Green
        Copy-Item -Path $RDServerDataZip -Destination $RDServerMapp
    }


    #Skapa gemensam på filserver
    If(!(Test-Path -Path $KundGemensam)){
        "Skapar mapp: $KundGemensam" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Green
        New-Item -Path $KundGemensam -ItemType Directory | Out-Null
        SetACLonSharedFolder -Dir $KundGemensam -Group $Butiksgrupp -Server $DomainController
    }
    else{
        "Mapp $KundGemensam finns redan, lägger till rättigheter för $Butiksgrupp" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Yellow
        SetACLonSharedFolder -Dir $KundGemensam -Group $Butiksgrupp -Server $DomainController
    }


    #Skapa policy för mappning av gemensam
    If(!([bool](Get-GPO -Name $KundGPO -ErrorAction SilentlyContinue -Server $DomainController))){
        "Skapar GPO: $KundGPO" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Green 

        Switch($xmlKund.Gemensam){
                    "1"{$GemensamEnabled = [Microsoft.GroupPolicy.EnableLink]::Yes;break}
                    "0"{$GemensamEnabled = [Microsoft.GroupPolicy.EnableLink]::No;break}
                    default{$GemensamEnabled = [Microsoft.GroupPolicy.EnableLink]::No}
        }

        If($GemensamEnabled -eq [Microsoft.GroupPolicy.EnableLink]::No){
            "Gemensam är inaktiverad/inte specifierad - inaktiverar GPO-länken" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Yellow
        }

        $GPO = Copy-GPO -SourceName $GPOTemplate -TargetName $KundGPO -SourceDomainController $DomainController

        $GPO | New-GPLink -Target $OU_Kund -Server $DomainController -LinkEnabled $GemensamEnabled | Out-Null

        $ScriptFile = "$PolicyFolder\{$($GPO.ID)}\User\Scripts\Logon\Logon.cmd"
        
        $Script = Get-Content $ScriptFile

        $Script.Replace("<kundnummer>",$Kundnummer) | Out-File $ScriptFile
    }
    else{
        "GPO $KundGPO finns redan" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Yellow
    }

    #Applicera policy för Avance-genvägar till gruppen
    Set-GPPermission -Name Shortcut_Avance -PermissionLevel GpoApply -TargetName $Butiksgrupp -TargetType Group -Server $DomainController | Out-Null


    #Skapa HTML-output
    $Logga = "iVBORw0KGgoAAAANSUhEUgAAAIgAAAAsCAYAAAHJMMA8AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAABr`
            VSURBVGhD7ZsHfFXl+ccBlSVDRAIyFAFFURx1/N1UraO4lSq1raO1alu1KksJIWyFsEcgEEgCJCSsDAhhhLBBlkzZSEFxz2rV3Htzn//3d865MWTQ`
            G03oB9vn8/l93nPPPffcc9739z7rfd4qP1b8c+790jt05FrwOHgCTAbNwLegHdB5QceFYrtnmH2yw2zOveadqvK510omeG2pYltmmmV3N1sdbbY71`            Wza/5l/ZMO1+u5T0B5cCsq8iSV3Nvtwt9n6yWZjIkAjszd/b7a1m/M0YT2JDWhsNvk+s8GXmHWpav4B9ftbXgezVQ87N/E5V7kyFOjJ1E8lxLpWNX`
            uliln0aYV98aMlkNGpc0HSNbHeR0deAhoByVUgdKxW/xj67IjN62T26dtmb083G3XGcZ8owWsLL7Kc3mZv8cOsRxkZRmnFa3TuWYXfa2SEovIHr/3`            hJtvnmH2w3Szl12ajG5rFtzHbM9Rs0eVlPs1Gr/3hJsOv4ocdzXrWczs37sratuFps/ktS9zke1D0ZOFxMPqsC6wLP+YG3qkTL7a8m9nOaWY7kszy`            XjZLaG/545qJ4IXyhdcWl9LIe9RrQ1Lmm1kyTBDBY29kujE7NKCfMmvEjl0pZnP5Dobkj6gT4/2kXA8iZVFUSjyIzX3CbPtcpuoeCIGy2JhglslDz`            filWQZtxsOQhIdLvhpycG7RtYX3KDqFi0ppD/KM14ak5IOMutZsQS+ojdbayDCkv2A2pJ3ZwBpmMczeoaeaJbU02/Sc2SG+3/W6We71zn3K8yAve2`            1ISjxIcFSbGta9plnkGTC7vll3HqBLNZfhkacUXp+f3CLG5rdgHja2QFJEpHe68oUnqBpI77TOl3zLkX/GXXCWd/rESiD70S22aSTDgG3YONwlalL`            zksMKpH2k/4TbgEQW7DzQBnwEWgPJk0DXqf2Nd1ycxIUSSLrpCVuFOnxvjdlne82OrHTVYXxb8w2ve8S7zJG7vba4dPHakDzstSE51WtLSEFix3RL`            YnaMv40ZcqvZ2v5mR9eZfb6fB1ptthIyx19oNvxYk3OP1xaX4g8i6eq1klIfxJ/6+y9s3USmMPp8BcMx/3GzHFTw1jizfenMpnEQ9BGzCeeZjax3z`            IPc5LXFpbQHWe61khIPYlalquUyHY+sN/t4n9mBZWZLe5il3mI2G/sgSzULQzMVHZJ1Azqkg/lnX1Go0KQbQlZLaA4kpT3IMq+VlHgQ3/gbe9vSQW`            aH3+RB4MP+PLN5XdCwbbFyZ4KzzMbiUsxHoW1neHYPwcF52PwpLVfr9+UZmsVeKynxIP6hFwy16Y/BifFm21Dpy2PMJtET/TC1g09BoaFPRtSll9C`            oe4aZvYPWXf8k2raFM0TleZAOXispOTQJHWrawFYuSac8yNvfZNa3mVm36q5C6+EqQMu+2GwNPFn/R7Ml11kwNaJcD3LQa0NSKlmt7+lmr/LWkQ1o`            6/AQqHS8Oj1IfvQZhdbW1arN6Y0fvJqOXltcdIEM4r/ADp0oJqd4bQmx3qh49UARfN+3zoPe1/8d4svo3MuWYWhXoTRXMSGW4/Ev+rOrzZOvMV/ce`            Ue+jmkV4V1epmjGajrHlYFXQEguAXJqNZMVTqwDq8AYcDEoLhr5SaD4PXV98XMTwb2g3FIws2O2LXnebPNotEaW2burUOZokSMrXD0qU7foWdwigo`            8J5+DqMpETqtT0fn6MvA8ecw/DEnkpRTuouNwIRPMWzqfSpRoonCvlEYu74Rz/2KvG54+45FsbKmtFpJV0PSryd2brUKX75Btucq3al4dcM/s+en7`            PLBRGH9w0lMpk3LTRzOmxtQiw6p/h3bpQ5J6VpUhKE3VIaZquuHwNzncPS4gUULk6xD/3ia8t4yWzhQS8i/vhi/bEeP2FaYDxmn0/dgR1voLpsXUS`            6nqByw51zNG1GLx5rqUVg9J+ZTaRaAqv3YbVMP/Qek7QXFQqq0NeBBnuYQkJu0MC0zu9ZvN40TfjzfYuNPuHpsFGXpopsQM2rBxBB/Gimb9xRz8bl`            yPvFQxpX5cxyhjk/t21+jPwABIvd/2gyXRKfEsLTGqz3furQvkAHACbjoP5ICThdog8z6IeQ1EJq0OC429tZ6kY5mXExm/Px7F7y+yTA0wDpsJHhE`            yHcPQ2E4wvgS1zH2DqXOl4nzaZF57SHh1xqdtOYYpomqQQMi+5082EbIRdG1C2a+jIpTeaP73dJ97fVhpDfnKH+Ef/YrLF383odmW0cTx3MRUOMQU`            OoxMOoCy3zaazcKtmPIXTga83GmU5EpvPVLBhp7kYgZ4Yhb5IhBFLcUw2/xWmEUMcmgrLEnHL3sAR4feEd8H0c51nqqwOGQDGuYclJLwOef2cW+11`            XmQMntVUKJ/+IrojCmvBdJj/qtlMvPH4e3jxK8z64HnJ8emO49MLx6cPfsdAEMPniXRIaisLLvo/Ova3dCQmWf6p4twtml4Pcc/LLDD37AL9b2V0i`
            DS3XljWpDQJW4fk92uQ68TO0U14QdzPN5gSgy8yG3SBWX8YEYUj7niAsEGxtecFCv7I06QOCiV/eus/Ww6/W8TUyoVRS7BOC+nMeYQ0mY0smNDIid`            k+A2UFeaWJOuQp97CEKDT6Bkx3PpUtYXeIJDig3lXWm2nQlQBArq9e3nGB+dzV64QiHWGvVjVfVK2/ej8vIUejz67tS4zo6ZvWeLovsWEPe+bK07y`            vfpLUAHU81NKJEyGBvnW7BnpWDwS6VCsIdq1qQTok8Eq1Ap0r6FMzLjis+Ql7lpNGvs7s3Lgg/dHxvrkPveub2fGrQPLNq/1JVz3kff3fI/9Ku7uZ`            b8FT79kKgv3VxDGrIrEs+CDzUaRpt5pNb2++secVz/39PCWY1ukaW45vsaa/660qjyxsiXNd9gVP4NXejMU5zwKxEZu9n5UpT4PigVYI8aBoENQby`            FFTQKfATtDn4unfkIwHxe+pdRWZ5OLnp4ByyzfT7jzb8v4AK3jxt6fhzea6WTq57YcW49Hib6yELcpzJ1xGDNPI8kc0zPF+XkK+ArmgaE6zOGQVQi`
            LroJynVua0YidcDxTR6rviFub3oOi9fgfk0uuBip4PfVcusegONQMzb/vGFj1HvDIWZysHL3aL2acEdZ/hzX642ewgXu5GXPycPzFtrjOLbYpvc7o`            FhzYoNQCV2S2P/DtzuQYsdQ/LlP5giHtYPgnEXtc5MOryzTaCKDcGf2QcfsTMu9AVL+NwMVUO57lLL1+8Aw7i6u90GbMllpiHTkvByRvfnCi5FoFd`            3V3ebY+RY5yXMCQc/0ELwUoDlCXyYgvTqeFIcNK9N9gMgjclsBNoJ/4a6qMT4nnBOffSIXixWyYwRRaZfbwVduwz+xyILWLN5lE4YcQuyThj4/Fqn`            Q6pGfBuf4x86LXhSjgdIo9vv3tYqpSrQwLTOr1i84hBsnG5F6M0FxHBZmJJZhD4peJ2Z8j1foagjbhkz0w3KfQBEbEgxki5KvpVxJv0C1h1thvjjF`            M+pF11728KpTI6RKLrqrqHJSTsDvGnPHi75RBvLB9mtgmFuW0OVoSXXh+P603nzGcazOtMSwSrpdINRMY7Cdz2zgVcK4X6JjGLdMzMO4h6L3Y7RPm`            QCWeYvFbvrwqlMjukRDbKk7A6xGb+5hSbB83zBpttJ7I9uJLR3+BGu3uxHht42TyCvQWPu7mQTBigF1/R02ztQAK5ARz3cJXpHILAaQR3U+iQyecD`            4qKprezbcReXUKzveW24Em6HfAcauYclJKwOCSbe/7STJVNySKsr7293l3yUC1GSaEcGzheM0BrULBRrSgdYQIg/936mxyPuFNFx2i1uZ2hJaPa1T`            D2uW3yLBRfeYL7MK7/OT7nsmFywCj3Wg9ISQ4KcmPogJOF2iApoflKH+BM6fu3kQjYqd7HaLXlRckhJoqMozt0L0A0oy2w6RJ2h0VeCSAkhJYfkcz`            jnsEaJfM5EAa9E32yAMUoQvQmzVtCRy660wPTWoUKOKh+DomtmxXEZKKoLTkiHWHR0NYtnzmdgPd7EnO5bCkO2uWtxH9ExmjpiSB6KdBZOWdI16IQ`            WbgWKsz4XWqOLwO/gfAqds5xps/l5nLdBbpJoZz83a7YMt35xWwvGND5d/11ZOuQndYhTSxB7Ay/CKOby0lKk+5e7C5SH8EL3LHSn0vzu6APM7lhY`            MaqRaz2GVfcyZjXMRtahQ1Ci6VgXLdPtQOccpIMPTTc7gG+ytRus4fc5F1n+tBbZ+u/K6hDZ+IbuYQn59wxZ1uFUZ4khDkrPYVSXxUDzJF4gDX9jB`            koTn2Nhb/wKrMtovM8B55j14+XfONVsSDV34TTmFDqlJh0CSzIvp0M60SEEfQcn0iFYrP3juB9TciXMWUCHTG+qlYJKtTJl5SbC0iH2xrlmQ6G6Vo`            jTmPfzsRhKH+YwylK204hix+GcDcJqRDJFVJHyKh3Ru4pZfzCoKi46jJkihqBLVtyJ6UZ37MRc70YZ78CfWc99837pZM3ykxup5KJSOkT1HMe7Lqw`            OKRjQONb6EncM1sISClEdM+UBcB/64namB1ZjYBuzKPRGD168q7JoXuasSxXz9apZ8M3Yc5voXv4ZbUfY4ithw92uMpXuWPc79Ap6Kqc9DGpivsQm`            f9G1ldEhs0F397BUCatDgiMjGlvf+ma9eOF+KEYxQfnUNy5086vRdFZPHKweTAulF4umEXtUNX907bu8WzkSyGxTYDlMwyWY4NwbaVHE2dyPzgjMi`            Ch04yu6Q24FTvb6OBJWh0j8/c4YZq9qKpzuFmqprECd8Fo9lxXdUaBFmeEhEFWzxALU53Gt6vvTW3xsC9A381R+QIfOjzB/6pnvW8K5hSmOiuoQea`            WKYPX9uTpxHClXtOuPqrPNuimhHEowAx07rCiZZPb1rK7SiTLFn9DkLv+0xnHfT200wT+lsQbwGPmn14YremFBGlmpAyF0ThW84cggMMo9DE98vWu`            nWc/QtDiWDYXoVlXM2On95ISK1lsUFIWy7mWtv1SoBPvXax2IqvGWv+upBUGYEYK/S7WC/MjqHwWj69zsXfo/+RlL1eCszpcWZD0+2J/1+MHAwj8F`            QIEQJIYLZj9pwazfWjD9IQvMvKPAn9KhwJ94dcCfcOn+gsnt+gcntFW08T/5uUl+2v3tC7Iey7G8Z3GdtKqCU77udZx1QrBNownJxgLaDcM4P5Bre`            uJJvOAuLqgQQpUfKoZIJNaNb2kFcc0y8mOaq/jrpBCtpMqpD6lkxZgVsrp6skt+6t2X+NMf3m3LnyF6gxhrB0AEIi7tZVH+70C22TuL3MWVQ4S3qo`            1SsZjygiLMGuL33BfxsojwVBSsLJDKg2Kb0Ta2wOgz37LhEa28vwtbtBiyG8ibCTkU5YWiotJifXlfflDab74HSqupLXpe5QPvgjlAZQllJWZVoDo`            VFP1tRaOsApcKlejoKtUCqbe8ZlkPElj9EXJ0J+okvN+R4JZQ/mOpu/KmRaaPlRRS6pD2g01uAb8Is2e2uw4jTaOaMiWZZxHNTr2KILA1UXBjAkJc`            feAb3qBoefxxJQ2oI5KByhsqWlRLovtr10K4ooE/G2jjiIp59Hstmx6zh+9HSDege73ufDqBEhx2bS0b266JjWh3uT/mwod8MW2eCwxr+6JvWNsuv`            rFXJPsTr/3O5jCYygHnPu+tT8ehNdAOWmRTWan2K6rE9PMDZl8AlZ1qP5TI4izZoll2p7mrl6tUZYV5krlJvsFNoUqLjCYGHFnL/CNqF/iH1Q2rHx`            TGaOHu186nipcQQcIpSStLlFpR4Kr7KFQqsa4UhmhpWgG27hFWkP1T5OvY2yMCk277S2DSrWss/jZm8K1mEzowi1UXiNofgX+gsrgRvzAbzwxPusl`            s9t3mbITTiqyqSaUN9qI9DqM9tN6mFVktRGp19ktvlVaEEXHefxMiLXHX6LZgktaolPc5d2VGK7cqwNTqrWqVh9eCJNXNN7TG59+OrK+tRscVzVAF`            /+UpuSuPVARBJHWBCiV0r8Gg1Ar148gJIYgv6YHn/DM6v+NsPpz1Z8AgzfmbmxFWzfVMzqXwneopJ99vNkV+wl2cp01ntst3WML1q9EA8inke+zHz`            zi8HBJscM2KiKKl/E9ptWotcohE+yGTTNL6IeZs+yTCcTYpTbvGbOIFkLOpW5zqpOBPMxtTE5LUy/IevUw5WQgiUcZJRem63zF5wTCkUgkSTOv8nD`            /9qX9Z9ksMjCIKIosVI5jJsTiamIp1YDXHq0a6i0jaC52FnzAXM5D+B7OMR8ypS8/qTCSCDyJHUyTZSJSyPR7NgOmQQypf4x95Zke0FkMrs7IvEyK`            pTGqC63/If5Efkw4BpT20WjfxPExME1eDjDzd1SKxtTE1ddYHR51Zz3uNUuVkIoikD9D9VHpVYsX+OFIpBPk2/qFzA2md8yxb1dXaqEQYun6Ku6Cm`            unwtxu9jIIW9mIBdRCEqRd+QBFnQELkq6yBayUGzaGtLpogC5nG88Gm3WFAbNp0QF8Kp4EemZxuk2TbR3d2hUHct0Ys2SS1GS2lHyBzMlcjh1P1jX`            uJwUsefAynQIuMgyphGnG9CVNN0hfcqZUqIID9qA1MYUtEEUV2goqIloDybkCucIMHJndr5Zzz6rmVgElS7sxrnUNvItfb+zkqzd/EbjuJAfoApEF`            S08C5Rh9brtQK7Ba2wjlm/Em2TizbJecrVIqrYUBHDLMyDihZEmGy0jAqfFvNf0i4ijvIeiyCEtIXIlf4QJgVTlfpLs+nXu0UOSfg5SZfxGcy4HFM`            GZqlFq8xqb77kdv785EtHWFzZRdwiiJxUhbqKjy/4EWgLzgSlSUUTRMUKWj7X5uGyltBLkwoliMXe2KAg6Z4cm4mdz0IDhFac38YMaEvTe4SjH+7C`            XyDS+AyHUtCx6hWO4jcc4hppk83TIBZmZylmSVpERWFpOLXJ17nhqQq/pqIFlM9QVVzKzQw0BNAmaCXDVPyhKEXfJ3F9oggB9JtUzmWgRRb9iueDd`            KtwWFd3ApBQxyvvseAyvluqpbqrLZDZfksg5aJHvFcslKNAy2uhxRURpjzQRlqVGqpqtwEoLpVFEO1I+o8RJDDxV49YotQ4M1tVf3k4hhtxEHdmmR`            1cgaaAIB/gSH5C1PGZog3VhUIQkeboWy6JdmGCNk3FV8Es5bzKYKJBZjGQKQx4Qnv8BpmFFm54KuhYZkJbSSecC1q6bRyf49S2wmzgjE5FO8y9Fm3`            D4K+CcNoj/hZO8lZM0DbMlTaxa6OQNghtfAbzhMOsaqFcSLmkvfnnnv+BL/mCwtJRDbJIUnTPeEXKz44gKt/0j716rMUpnf0wap1IRTtEV8nEJLsm`            RiQ5jIl5byumRWEoJuYoEUho0+TuHK5NxYnFh1BZh6Kc6QxUAtojHg0wQYktz6kcVZfIA8dSGO61Duq43ym3MaYhJDqbqIjfzeL3i9EyIsdG/JhtE`            GOXtu3i86geRkVCB8bjE6lyqg/PgblaR/S0AvOkRf8FF1rB7JbmT2rl7BoRQU4mJ1Vl8Mq+/scIogov/8hLJtlo1HgsJElEbSucXRCJKsdhVHXXFg`            Zf2mQ3vsbeXAYH7CHikAlySmtxZJer5J5IRWGwwt7xzHjlRWLaAMgRw8APrU1IWp2WsFRbBlUIVQivUmw414ysz7PwmyQIksE98rjXWiKiTRBvJ+T`            dhxl7ZzIREGHzYSIe7bs8gP+j7YZbe+Do/glC4e9ot11OOwumn2O+lCbKZp90BHkJ6H5Kw5dVClyaVKiJ8Q1u9Xcbcj6DhCkYTadOwtxMx1FUrkPF`            XqqrXj6UTtf6CJGHsGoM5yDQkgE4nZgUEUNVcdpLOhZfIQZHcgADHN3YLJIB70koGgUJ+kCGAdXcorA3qgDawWAIEFGGQqDhaJNxRCZJmJoMnmkp9`            9OAr8eBVeXc2zjCe0e5pDiAFtnP8+xRIRnh9mac3rWqn7rT8UUsGzOV3szykyOcQpKTiSAaZG3A0f3+phPlkAolSLB/0xb+Ac0O2cDmZgMZ1Bjsvs`            ofpQWUAJNG0G6ENCXLnnWhJJl2Was6cArXxN3hkmsYUYXqw/pyLxXIvYbZ6K66MMgRqgDqJkCOHqAn6AX6n2q+QbV9geH15wVGRfQOjGv+gn9Kq/j`            8tLZ+y+GeDkkgn4rnNqHhtmjPDMTciv+h+tPNREGqMtR2dhXXLcapxbxYVgvzz4oo8CdFrNS7nkwEeQJoYU/l5f+uTKu4VChBJMFBTTraQGatBlUb`            q/sxe51CwEuY0aj5kdhzkWYMJBhDpDCaKGQkg6DvhnCNs/ma30TjO0Sd+UOdnFMihmYoLA+DDEUro14G0ZCjV+1Ui/6hFi4k301t18Y3q/VRW9gO/`            wZ/ZCn/r2hlBVpu1QMuVt7n+hx5mEgVHarycj5Ez2yKBmpk/qkRu4OxrSJ0v5OFINo8rvscAlfoRDmlwgki8fdteH9gQP3vLBI/QDvsVRgpwvSOwD`            RAGpXV9iUCccCxyNAbE6Id+ZEqnkRb9OC3qjHuDjFCG9SL1Q0WQmSJPs38vWrFW3TZlWtaHCyY0XJ4IKtlwBYS3SyAuNIO+BeWczHHF4G2mBO+y0J`            zZfCs886ywOyz8gumNu5r0R3UX46cKIK84nwqn2iZX8v92hqoeySB8iTHikqlEETyXf9GrfOj6i6zvsx+Z5CBM+CYCQc6D5wqWn3mu274DU5BqVdM`            2lXaomRB6TF4rar5XqvxVX706Z29vw5Lvo9vcV9gWtMcf2rj92wm5JwHGbJFiAgrmHGW+VMaHfYlNcr0J0Rob20Jkcr+BGiXYGXIZKBBmQYeAw+Aj`            uAOcDvQQ6lVJlclAf3AXPAp0O+kMZReLysRF64oUyhi6J5jdKKiJX9A/cv9UbXXWG8RgMFW8awz6KXBI4IDEYC2NFIIPU8xX2T1z3zR9f7q/dUJFc`            W6yqIW3TJWkXIekHlQbYfqD8YCbZWXNpDDGYJ2gQ8ELwAtxCk7W1ah0I+VC8Gz4Jj9dBUtXw1q2pDBfD7Qq+Y2i4Is2p7SlYEWEYr6E/IlihJB0HX`            dIUvkqeaPrP55QZ86Y/J7naEdbP+Tn6vY6/UbBPvWuz2/T52YQFStZf5etQ/k96z+SX6vmv/Mj6z5pS+q+pFAVO1Nvl51pgb61X2S61tueqbstZET`            J1Wq/D96zZzw/Vp9zwAAAABJRU5ErkJggg=="

    $HTMLStyle = "<style>
                TABLE{border-width: 1px;border-color: black;border-collapse: collapse;}
                TH{border-width: 1px;padding: 5px;border-style: solid;border-color: black;text-align: left;}
                TD{border-width: 1px;padding: 5px;border-style: solid;border-color: black;text-align: left;}
              </style>"

    "Skapar HTML-fil: $OutputFileHTML" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Green
    $OutputPrintersHTML = $OutputPrinters | ConvertTo-Html Skrivare,IP-adress -Fragment
    $OutputUsersHTML = $OutputUsers | ConvertTo-Html 'Domän\användarnamn',Namn,Lösenord,VPN-användare -Fragment
    ConvertTo-Html -Head $HTMLStyle -Body "<H1><img src=""data:image/png;base64,$Logga"">&emsp;&emsp;&emsp;&emsp;$Butiksnummer</H1><br><b>Server: $RDServer</b><br><br>$OutputUsersHTML<br>$OutputPrintersHTML<br><br>$(Get-Date -Format "yyyyMMdd HH:mm")" -Title "$Butiksnummer $(Get-Date -Format "yyyyMMdd HH:mm")" | Out-File -FilePath $OutputFileHTML -Encoding utf8

}

"Script färdigt, kolla resultat i html-filer under $PSScriptRoot" | Write-Log -LogFile $LogFile -Passthru | Write-Host -ForegroundColor Green
Avsluta