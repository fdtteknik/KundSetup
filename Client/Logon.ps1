$basePath = "C:\FDT\Init\"
$dp = [Environment]::GetFolderPath("Desktop")

$created = Test-Path $dp
if ($created -eq $False) {
   do {
      Start-Sleep 10
      $created = Test-Path $dp
   } until ($created -eq $true)
}

# Check if RDP already copied to user, if so continue with shortcuts
# else copy RDP

Get-ChildItem $basePath -filter *.lnk | foreach {

 $present = Test-Path $dp"\"$_.name 
 if ($present -eq $False) {
    Write-Host "NOT Present "$_.name
    $dst = $dp+"\."
    Copy-Item $_.FullName $dst
 }
}
# Check if ERPos shortcut copied, if 
# Check that ERPos shortcut is install or run
# else copy Shortcut ERPos
Get-ChildItem $basePath -filter *.rdp | foreach {

 $present = Test-Path $dp"\"$_.name 
 if ($present -eq $False) {
    Write-Host "NOT Present "$_.name
    $dst = $dp+"\."
    Copy-Item $_.FullName $dst
 }
}

function MyImport-PfxCertificate {
   param([String]$certPath,[String]$certRootStore = “CurrentUser”,[String]$certStore = “My”,$pfxPass = $null)
   $pfx = new-object System.Security.Cryptography.X509Certificates.X509Certificate2
   if ($pfxPass -eq $null) {$pfxPass = read-host “Enter the pfx password” -assecurestring}
   $pfx.import($certPath,$pfxPass,“Exportable,PersistKeySet”)
   $store = new-object System.Security.Cryptography.X509Certificates.X509Store($certStore,$certRootStore)
   $store.open(“MaxAllowed”)
   $store.add($pfx)
   $store.close()
}

