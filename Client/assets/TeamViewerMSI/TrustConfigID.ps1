param
(
    [Parameter(Mandatory=$False)]
    [string]$Add,
    [Parameter(Mandatory=$False)]
    [string]$Path,
    [Parameter(Mandatory=$False)]
    [string]$Name,
    [Parameter(Mandatory=$False)]
    [string]$Remove,
    [Parameter(Mandatory=$False)]
    [switch]$List,
    [Parameter(Mandatory=$False)]
    [switch]$Merge
)

If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{   
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    Break
}

function Load-Module($name)
{
    if (-not(Get-Module -Name $name))
    {
        if (Get-Module -ListAvailable | Where-Object { $_.name -eq $name })
        {
            Import-Module $name  

            return $true
        }
        else
        {   
            return $false
        }
    }
    else
    {
        return $true
    }
}

$moduleName = "ActiveDirectory"

if (-not(Load-Module $moduleName))
{
    Write-Host "Failed to load $moduleName"
    Write-Host "Please download the Active Directory Module from microsoft.com"
    Read-Host
    Break
}


[string]$TV_GUID = "B15CB251-377F-46FB-81E9-4B6F12D6A15F"
[int]$StringCutStartIndex = 6


###########################
#Functions
###########################

################
#PRIVATE
################

#The Main function, checks how many TeamViewer ADObjects exists and process the input
function Main
{
    #If more than one TV SCP were found -> error
    if((Count-TV_SCPs) -gt 1 -and !$Merge)
    {
        Write-Error "Too many ServerConnectionPoints with TeamViewer keywords are existing!"
        List-TV_SCPs
    }
    else
    {
        $HasSomethingDone = $False
        if($Add)
        {
            Add-ConfigurationID -ConfigurationID $Add -Name $Name -Path $Path
            $HasSomethingDone = $True
        }
        if($Remove)
        {
            Remove -ConfigurationID $Remove
            $HasSomethingDone = $True
        }
        if($List)
        {
            List-ConfigurationIDs
            $HasSomethingDone = $True
        }
        if($Merge)
        {
            Merge -Name $Name -Path $Path
            $HasSomethingDone = $True
        }
        if(!$HasSomethingDone)
        {
            do
            {
                $ConfigurationID = Read-Host "Please enter a ConfigurationID to add"
            }while(!$ConfigurationID)
            Add-ConfigurationID -ConfigurationID $ConfigurationID
            Read-Host "Enter any key to continue..."
        }
    }
    
}

#Returns the TV SCP(s)
function Get-TV_SCPs
{
    return Get-ADObject -Filter {objectClass -like "serviceConnectionPoint" -and keywords -like 'TeamViewer' -and keywords -like $TV_GUID}
}

#Lists all ServiceConnectionPoints with TeamViewer keyword
function List-TV_SCPs
{
    if($TeamViewerTV_SCPs = Get-TV_SCPs)
    {
        foreach($CurTV_SCP in $TeamViewerTV_SCPs)
        {
            $CurTV_SCP
        }
    }
    return 
}

#Counts all ServiceConnectionPoints with TeamViewer keyword
function Count-TV_SCPs
{
    $Counter = 0
    if($TeamViewerTV_SCPs = Get-TV_SCPs)
    {
        foreach($CurTV_SCP in $TeamViewerTV_SCPs)
        {
            $Counter++
        }
    }
    return $Counter
}

#Counts all ConfigurationIDs saved in the TeamViewer ServiceConnectionPoint
function Count-ConfigurationIDs
{
    $Counter = 0
    if($TeamViewerTV_SCP = Get-TV_SCPs)
    {
        [string]$ServiceBindingInformation = (Get-ADObject $TeamViewerTV_SCP -Properties serviceBindingInformation | select @{name="SBI";expression={$_.serviceBindingInformation -join “;”}})
        if($ServiceBindingInformation)
        {
            $ServiceBindingInformation = $ServiceBindingInformation.Substring($StringCutStartIndex, $ServiceBindingInformation.Length - $StringCutStartIndex - 1)
            $SplittedSBI = $ServiceBindingInformation.Split(';')
            foreach($CurValue in $SplittedSBI)
            {
                if($CurValue.Length -gt 1)
                {
                    $Counter++
                }
            }
        }
    }
    return $Counter
}

#Creates the ServiceConnenctionPoint with the TeamViewer keywords
function Create-TV_SCP
{
    param
    (
        [string]$Name,
        [string]$SCP_Path,
        [switch]$Automatic
    )
    if(!$Name)
    {
        $Name = Read-Host "Name"
    }
    if(!$SCP_Path)
    {
        $SCP_Path = Read-Host "Path"
    }
    $ContainerPath = $SCP_Path
    $ContainerFullName = $SCP_Path
    if(!$SCP_Path)
    {
        $SCP_Path = Get-ADDomain
        $ContainerPath =  "CN=System,"+$SCP_Path
        $ContainerFullName = "CN=TeamViewer,"+$ContainerPath
        $SCP_Path = $ContainerFullName
    }
    if(!$Name)
    {
        $Name = "TeamViewer"
    }
    if(!(Get-ADObject -Filter { distinguishedName -like $ContainerFullName -and objectClass -like "container"}))
    {
        $ContainerName = "TeamViewer"
        New-ADObject -Name $ContainerName -Path $ContainerPath -Type container
        "Container with name '"+$ContainerName+"' was created because the TeamViewer-ServiceConnectionPoint must be in a container."
    }
    #Create the TV SCP
    New-ADObject -Name $Name -Path $SCP_Path -Type serviceConnectionPoint -OtherAttributes @{'keywords'=$TV_GUID,"TeamViewer"}
    "TeamViewer-ServiceConnectionPoint with name '"+$Name+"' was created"
    return $SCP_Path
}

################
#ACTIONS
################

#Lists all ConfigurationIDs saved in the TeamViewer ServiceConnectionPoint
function List-ConfigurationIDs
{
    if($TeamViewerTV_SCP = Get-TV_SCPs)
    {
        [string]$ServiceBindingInformation = (Get-ADObject $TeamViewerTV_SCP -Properties serviceBindingInformation | select @{name="SBI";expression={$_.serviceBindingInformation -join “;”}})
        if($ServiceBindingInformation)
        {
            $ServiceBindingInformation = $ServiceBindingInformation.Substring($StringCutStartIndex, $ServiceBindingInformation.Length - $StringCutStartIndex - 1)
            $SplittedSBI = $ServiceBindingInformation.Split(';')
            foreach($CurValue in $SplittedSBI)
            {
                $CurValue
            }
        }
    }
    return
}

#Merge all ServiceConnectionPoints with TeamViewer keyword to one and combine their saved ConfigurationIDs
function Merge
{
    if(!$Path -and $Name)
    {
        $Path = Get-ADDomain
        $Path = "CN="+$Name+"_Container,"+$Path
    }
    if($TeamViewerTV_SCPs = Get-TV_SCPs)
    {
        #Declare $FirstTV_SCP for further using
        $FirstTV_SCP
        [bool]$FirstChosen = $false

        #Check if TV_SCP with given name already exists
        $CurTV_SCP = Get-TV_SCPs
        $CurTV_SCP = $CurTV_SCP | Where-Object {$_.Name -like $Name}
        if($CurTV_SCP)
        {
            $FirstTV_SCP = $CurTV_SCP
            $FirstChosen = $true
        }
        #If not but name and path are given, create a new
        if($Name -and $Path -and !$FirstChosen)
        {
            $Path = Create -Name $Name -Path $Path
            $FirstTV_SCP = "CN="+$Name+","+$Path
            $FirstChosen = $true
        }
        
        foreach($CurTV_SCP in $TeamViewerTV_SCPs)
        {
            #If no TV_SCP was chosen, use the first found
            if(!$FirstChosen)
            {
                $FirstTV_SCP = $CurTV_SCP
                $FirstChosen = $true
            }
            else
            {
                if(!($CurTV_SCP -like $FirstTV_SCP))
                {
                    [string]$ServiceBindingInformation = (Get-ADObject $CurTV_SCP -Properties serviceBindingInformation | select @{name="SBI";expression={$_.serviceBindingInformation -join “;”}})
                    if($ServiceBindingInformation)
                    {
                        $ServiceBindingInformation = $ServiceBindingInformation.Substring($StringCutStartIndex, $ServiceBindingInformation.Length - $StringCutStartIndex - 1)
                        $SplittedSBI = $ServiceBindingInformation.Split(';')
                        foreach($CurValue in $SplittedSBI)
                        {
                            Set-ADObject -Identity $FirstTV_SCP -Add @{'serviceBindingInformation' = $CurValue}
                        }
                    }
                    Remove-ADObject -Identity $CurTV_SCP
                }
            }

        }
    }
}



#Creates a TeamViewer ServiceConnectionPoint if it doesn't exits and adds a ConfigurationID to it
function Add-ConfigurationID
{
    param
    (
        [Parameter(Mandatory=$True)]
        [string]$ConfigurationID,
        [Parameter(Mandatory=$False)]
        [string]$Path,
        [Parameter(Mandatory=$False)]
        [string]$Name            
    )
    if((Count-TV_SCPs) -lt 1)
    {
        Create-TV_SCP -Name $Name -SCP_Path $Path
    }
    $TV_SCP = Get-TV_SCPs
    Set-ADObject -Identity $TV_SCP -Add @{'serviceBindingInformation' = $ConfigurationID}
    Write-Host "Successfully added Configuration ID: ",$ConfigurationID
}

#Removes a ConfigurationID from the TeamViewer ServiceConnectionPoint and destroy it if it was the last ConfigurationID
function Remove
{
    param
    (
        [Parameter(Mandatory=$False)]
        [string]$ConfigurationID       
    )
    
    if((Count-TV_SCPs) -eq 1)
    {
        [string]$UpperCasedOptions = $ConfigurationID.ToUpper()
        $TV_SCP = Get-TV_SCPs
        if($UpperCasedOptions -eq "ALL")
        {
            Remove-ADObject -Identity $TV_SCP
        }
        else
        {
            Set-ADObject -Identity $TV_SCP -Remove @{'serviceBindingInformation' = $ConfigurationID}
            Write-Host "Successfully removed Configuration ID: ",$ConfigurationID
            if((Count-ConfigurationIDs) -lt 1)
            {
                Remove-ADObject -Identity $TV_SCP
            }
        }
    }
    else
    {
        Write-Host "No TeamViewer ServiceConnectionPoint was found!"
    }
}


#Call the Main function
Main


     




# SIG # Begin signature block
# MIIbmgYJKoZIhvcNAQcCoIIbizCCG4cCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC2Qjk/T2ihxijF
# J0RRR6VuRty9C+R+hHPtR0Fyf9y38aCCCjwwggTbMIIDw6ADAgECAhBpKdUvAVa1
# /Sj4nhSrxqJsMA0GCSqGSIb3DQEBCwUAMH8xCzAJBgNVBAYTAlVTMR0wGwYDVQQK
# ExRTeW1hbnRlYyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3Qg
# TmV0d29yazEwMC4GA1UEAxMnU3ltYW50ZWMgQ2xhc3MgMyBTSEEyNTYgQ29kZSBT
# aWduaW5nIENBMB4XDTE2MTEyODAwMDAwMFoXDTE4MDMwMzIzNTk1OVowczELMAkG
# A1UEBhMCREUxGzAZBgNVBAgMEkJhZGVuLVd1ZXJ0dGVtYmVyZzETMBEGA1UEBwwK
# R29lcHBpbmdlbjEYMBYGA1UECgwPVGVhbVZpZXdlciBHbWJIMRgwFgYDVQQDDA9U
# ZWFtVmlld2VyIEdtYkgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCw
# nHLdJJuDENcd6xygDqCd16wbVOiQjGwkbPtN7Yl7Y3zFrj0E32J62jhnRB8Y+ONJ
# eqxZhr2ycyOZeW9ML9REVX8fdqMj6ucBu7alDsbyMj1o3caLonqasyShKCthtVP6
# XxKeeyWSZKU/g4P+b8y6NxsURk/dEN3G6IGgVU9fLPzjzoio8/OfSLzv4WGk67oO
# Z4QG9gMi6ZYMfxr2MwDHaTf0pS0XUMo5OG8RO5EFXy5a+CKfJTnjupxeZEtMiC07
# jDMIv5NJa7qA2CgtjgynWyrCz6HNpHRq7J/Um+kPnbikQyvN1qhHar/OUVRk6OYM
# 1n6NpwhBlva2F1uhOPJ1AgMBAAGjggFdMIIBWTAJBgNVHRMEAjAAMA4GA1UdDwEB
# /wQEAwIHgDArBgNVHR8EJDAiMCCgHqAchhpodHRwOi8vc3Yuc3ltY2IuY29tL3N2
# LmNybDBhBgNVHSAEWjBYMFYGBmeBDAEEATBMMCMGCCsGAQUFBwIBFhdodHRwczov
# L2Quc3ltY2IuY29tL2NwczAlBggrBgEFBQcCAjAZDBdodHRwczovL2Quc3ltY2Iu
# Y29tL3JwYTATBgNVHSUEDDAKBggrBgEFBQcDAzBXBggrBgEFBQcBAQRLMEkwHwYI
# KwYBBQUHMAGGE2h0dHA6Ly9zdi5zeW1jZC5jb20wJgYIKwYBBQUHMAKGGmh0dHA6
# Ly9zdi5zeW1jYi5jb20vc3YuY3J0MB8GA1UdIwQYMBaAFJY7U/B5M5evfYPvLivM
# yreGHnJmMB0GA1UdDgQWBBQd5jHI7sTuLAUe63v8UdbPH0xKWzANBgkqhkiG9w0B
# AQsFAAOCAQEAdoG8vMKKmcyVOf7VRgV4sEthFQpwVEiBLxfycY1LAP5nA3gN/eZC
# VV3QxnnP4AwitrNNc516LPJY6+pwgNlGJSM8kpOIzZYjXUK0LVUwwoR3Ap9wGDwC
# 4oAda+USBJa2S8NQH/ILIlKFIAoaWOicT5/z/QjTxxXK6QeWVeJSPmfx6NVJ5HFj
# MMcsefk36LGYlHxHxZyJ/W5VMgrhIgl+v8A0Wqjm+JEENGf37RIs7kLB/O2KpbDQ
# WxluXzEiaLhc53lG8UcGrDI7JCniZpEPM5vnKst6xk40tsgRUW/XTF69Ht+tG8tg
# dDViWgeoTPN5mL+ngz1uQUGOLLcIycbyZjCCBVkwggRBoAMCAQICED141/l2SWCy
# YX308B7KhiowDQYJKoZIhvcNAQELBQAwgcoxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5WZXJpU2lnbiwgSW5jLjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29y
# azE6MDgGA1UECxMxKGMpIDIwMDYgVmVyaVNpZ24sIEluYy4gLSBGb3IgYXV0aG9y
# aXplZCB1c2Ugb25seTFFMEMGA1UEAxM8VmVyaVNpZ24gQ2xhc3MgMyBQdWJsaWMg
# UHJpbWFyeSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEc1MB4XDTEzMTIxMDAw
# MDAwMFoXDTIzMTIwOTIzNTk1OVowfzELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5
# bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3
# b3JrMTAwLgYDVQQDEydTeW1hbnRlYyBDbGFzcyAzIFNIQTI1NiBDb2RlIFNpZ25p
# bmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCXgx4AFq8ssdII
# xNdok1FgHnH24ke021hNI2JqtL9aG1H3ow0Yd2i72DarLyFQ2p7z518nTgvCl8gJ
# cJOp2lwNTqQNkaC07BTOkXJULs6j20TpUhs/QTzKSuSqwOg5q1PMIdDMz3+b5sLM
# WGqCFe49Ns8cxZcHJI7xe74xLT1u3LWZQp9LYZVfHHDuF33bi+VhiXjHaBuvEXga
# mK7EVUdT2bMy1qEORkDFl5KK0VOnmVuFNVfT6pNiYSAKxzB3JBFNYoO2untogjHu
# Zcrf+dWNsjXcjCtvanJcYISc8gyUXsBWUgBIzNP4pX3eL9cT5DiohNVGuBOGwhud
# 6lo43ZvbAgMBAAGjggGDMIIBfzAvBggrBgEFBQcBAQQjMCEwHwYIKwYBBQUHMAGG
# E2h0dHA6Ly9zMi5zeW1jYi5jb20wEgYDVR0TAQH/BAgwBgEB/wIBADBsBgNVHSAE
# ZTBjMGEGC2CGSAGG+EUBBxcDMFIwJgYIKwYBBQUHAgEWGmh0dHA6Ly93d3cuc3lt
# YXV0aC5jb20vY3BzMCgGCCsGAQUFBwICMBwaGmh0dHA6Ly93d3cuc3ltYXV0aC5j
# b20vcnBhMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9zMS5zeW1jYi5jb20vcGNh
# My1nNS5jcmwwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMDMA4GA1UdDwEB
# /wQEAwIBBjApBgNVHREEIjAgpB4wHDEaMBgGA1UEAxMRU3ltYW50ZWNQS0ktMS01
# NjcwHQYDVR0OBBYEFJY7U/B5M5evfYPvLivMyreGHnJmMB8GA1UdIwQYMBaAFH/T
# ZafC3ey78DAJ80M5+gKvMzEzMA0GCSqGSIb3DQEBCwUAA4IBAQAThRoeaak396C9
# pK9+HWFT/p2MXgymdR54FyPd/ewaA1U5+3GVx2Vap44w0kRaYdtwb9ohBcIuc7pJ
# 8dGT/l3JzV4D4ImeP3Qe1/c4i6nWz7s1LzNYqJJW0chNO4LmeYQW/CiwsUfzHaI+
# 7ofZpn+kVqU/rYQuKd58vKiqoz0EAeq6k6IOUCIpF0yH5DoRX9akJYmbBWsvtMkB
# TCd7C6wZBSKgYBU/2sn7TUyP+3Jnd/0nlMe6NQ6ISf6N/SivShK9DbOXBd5EDBX6
# NisD3MFQAfGhEV0U5eK9J0tUviuEXg+mw3QFCu+Xw4kisR93873NQ9TxTKk/tYuE
# r2Ty0BQhMYIQtDCCELACAQEwgZMwfzELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5
# bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3
# b3JrMTAwLgYDVQQDEydTeW1hbnRlYyBDbGFzcyAzIFNIQTI1NiBDb2RlIFNpZ25p
# bmcgQ0ECEGkp1S8BVrX9KPieFKvGomwwDQYJYIZIAWUDBAIBBQCggbIwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIMr2NAujNRyKB4Nj+xhoWRyVuu20hxSe9REEgIBD
# z18JMEYGCisGAQQBgjcCAQwxODA2oBaAFABUAGUAYQBtAFYAaQBlAHcAZQByoRyA
# Gmh0dHA6Ly93d3cudGVhbXZpZXdlci5jb20gMA0GCSqGSIb3DQEBAQUABIIBAGC1
# sdSSk/Ft2HP6ad9cLRv8TEmOE9U+T2uNDc/SOY6UeUWxDSF+/Fv6errwGB8TCxBk
# HKTtZBB3MJRhXgAsSEEdxrveYgxog30vQ8vUa4e60R9fT3qKPQNyNmS8ChnOG+WZ
# pCR3V1AEn0/YYQn5XTT4e6yfe1+b/Le5Z9Dls6SMaXjdaIx30tiedbupYtrhzwMN
# spOAZ/3JrHsA1ABc0nK31l6YUjeJl/iENjZTwVGSzCcoYHQJcCEB/z2buYI17rW2
# IxOVY8WoWbeYQViLkq51fWDoC8B1JGUZ15MjDgw23lQMYDGiTngjbm+CJl09VI5/
# 5pSKZ91KX+EQUkDrYTChgg48MIIOOAYKKwYBBAGCNwMDATGCDigwgg4kBgkqhkiG
# 9w0BBwKggg4VMIIOEQIBAzENMAsGCWCGSAFlAwQCATCCAQ4GCyqGSIb3DQEJEAEE
# oIH+BIH7MIH4AgEBBgtghkgBhvhFAQcXAzAxMA0GCWCGSAFlAwQCAQUABCDDMElm
# L9ySb4MPC+OmaBeqMjZw8XrHMtrNJd4wE6moXgIUbKPZzvmoleDdR66lY4V565Xy
# VtMYDzIwMTcwMzE3MTUzMDQzWjADAgEeoIGGpIGDMIGAMQswCQYDVQQGEwJVUzEd
# MBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVj
# IFRydXN0IE5ldHdvcmsxMTAvBgNVBAMTKFN5bWFudGVjIFNIQTI1NiBUaW1lU3Rh
# bXBpbmcgU2lnbmVyIC0gRzGgggqLMIIFODCCBCCgAwIBAgIQewWx1EloUUT3yYnS
# nBmdEjANBgkqhkiG9w0BAQsFADCBvTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZl
# cmlTaWduLCBJbmMuMR8wHQYDVQQLExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTow
# OAYDVQQLEzEoYykgMjAwOCBWZXJpU2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVk
# IHVzZSBvbmx5MTgwNgYDVQQDEy9WZXJpU2lnbiBVbml2ZXJzYWwgUm9vdCBDZXJ0
# aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0xNjAxMTIwMDAwMDBaFw0zMTAxMTEyMzU5
# NTlaMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3JhdGlv
# bjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEoMCYGA1UEAxMfU3lt
# YW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBALtZnVlVT52Mcl0agaLrVfOwAa08cawyjwVrhponADKXak3J
# ZBRLKbvC2Sm5Luxjs+HPPwtWkPhiG37rpgfi3n9ebUA41JEG50F8eRzLy60bv9iV
# kfPw7mz4rZY5Ln/BJ7h4OcWEpe3tr4eOzo3HberSmLU6Hx45ncP0mqj0hOHE0Xxx
# xgYptD/kgw0mw3sIPk35CrczSf/KO9T1sptL4YiZGvXA6TMU1t/HgNuR7v68kldy
# d/TNqMz+CfWTN76ViGrF3PSxS9TO6AmRX7WEeTWKeKwZMo8jwTJBG1kOqT6xzPnW
# K++32OTVHW0ROpL2k8mc40juu1MO1DaXhnjFoTcCAwEAAaOCAXcwggFzMA4GA1Ud
# DwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMGYGA1UdIARfMF0wWwYLYIZI
# AYb4RQEHFwMwTDAjBggrBgEFBQcCARYXaHR0cHM6Ly9kLnN5bWNiLmNvbS9jcHMw
# JQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9kLnN5bWNiLmNvbS9ycGEwLgYIKwYBBQUH
# AQEEIjAgMB4GCCsGAQUFBzABhhJodHRwOi8vcy5zeW1jZC5jb20wNgYDVR0fBC8w
# LTAroCmgJ4YlaHR0cDovL3Muc3ltY2IuY29tL3VuaXZlcnNhbC1yb290LmNybDAT
# BgNVHSUEDDAKBggrBgEFBQcDCDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGlt
# ZVN0YW1wLTIwNDgtMzAdBgNVHQ4EFgQUr2PWyqNOhXLgp7xB8ymiOH+AdWIwHwYD
# VR0jBBgwFoAUtnf6aUhHn1MS1cLqBzJ2B9GXBxkwDQYJKoZIhvcNAQELBQADggEB
# AHXqsC3VNBlcMkX+DuHUT6Z4wW/X6t3cT/OhyIGI96ePFeZAKa3mXfSi2VZkhHEw
# Kt0eYRdmIFYGmBmNXXHy+Je8Cf0ckUfJ4uiNA/vMkC/WCmxOM+zWtJPITJBjSDlA
# IcTd1m6JmDy1mJfoqQa3CcmPU1dBkC/hHk1O3MoQeGxCbvC2xfhhXFL1TvZrjfdK
# er7zzf0D19n2A6gP41P3CnXsxnUuqmaFBJm3+AZX4cYO9uiv2uybGB+queM6AL/O
# ipTLAduexzi7D1Kr0eOUA2AKTaD+J20UMvw/l0Dhv5mJ2+Q5FL3a5NPD6itas5VY
# VQR9x5rsIwONhSrS/66pYYEwggVLMIIEM6ADAgECAhBU832hcWdRvGqNCtJ0sosT
# MA0GCSqGSIb3DQEBCwUAMHcxCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRl
# YyBDb3Jwb3JhdGlvbjEfMB0GA1UECxMWU3ltYW50ZWMgVHJ1c3QgTmV0d29yazEo
# MCYGA1UEAxMfU3ltYW50ZWMgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0xNjAx
# MTIwMDAwMDBaFw0yNzA0MTEyMzU5NTlaMIGAMQswCQYDVQQGEwJVUzEdMBsGA1UE
# ChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0
# IE5ldHdvcmsxMTAvBgNVBAMTKFN5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcg
# U2lnbmVyIC0gRzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCf+9+P
# H6fPnj4ay+torc8nHO6BVamHCFjlgU0JFODt0PPUDz8hth4ONNTxaApvfY+J2fLq
# p9glOKSMNsruKM8z+HU92J3Pkt1W4/aweVRmtUWCQ0TSarGrF6LD5e8A6ifzJ4gO
# hzz2bryp7Pa7Lmp3BiK9+rh/wyQH9z+7TLD/Q8uTyhKqlSQAkLIrNqLS3dKz0Zky
# 3c/0zHMWSYN/JOvteEbT7l9sQmUbZ43wJhoOXoduWo+ggn5un80m3r1h70ReRYuo
# lNMcBDKh/6Snoqp3Adsq3g9MkjbGaaxchICtJfXtMMNoHRfbCk2aNHhZAZtrAoU4
# 4idxohRUMGCTIEgjAgMBAAGjggHHMIIBwzAMBgNVHRMBAf8EAjAAMGYGA1UdIARf
# MF0wWwYLYIZIAYb4RQEHFwMwTDAjBggrBgEFBQcCARYXaHR0cHM6Ly9kLnN5bWNi
# LmNvbS9jcHMwJQYIKwYBBQUHAgIwGRoXaHR0cHM6Ly9kLnN5bWNiLmNvbS9ycGEw
# QAYDVR0fBDkwNzA1oDOgMYYvaHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20v
# c2hhMjU2LXRzcy1jYS5jcmwwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0P
# AQH/BAQDAgeAMHcGCCsGAQUFBwEBBGswaTAqBggrBgEFBQcwAYYeaHR0cDovL3Rz
# LW9jc3Aud3Muc3ltYW50ZWMuY29tMDsGCCsGAQUFBzAChi9odHRwOi8vdHMtYWlh
# LndzLnN5bWFudGVjLmNvbS9zaGEyNTYtdHNzLWNhLmNlcjAoBgNVHREEITAfpB0w
# GzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtNDAdBgNVHQ4EFgQU7WtgzztY+D4y
# zL+k6Kvo6qJQQn8wHwYDVR0jBBgwFoAUr2PWyqNOhXLgp7xB8ymiOH+AdWIwDQYJ
# KoZIhvcNAQELBQADggEBAKKNXl0d7k7Sk/1P5fRtpvCJRVW7CMqrJKEWJMlPF8Gf
# 9N0CmsJHwKnciIl3wYaG8dVJlvP7HpjWyR01I4iZimLhdahNeKc97CSAFZ5o1Dqk
# wkzccWyWnY4eDC5sUgGeVpA/ol6SzbbaQRokg6F6o1/+jTtvOdE/QV9WHCcM5XwF
# 2Gc2iOWwwsMEo1pWuBIEjtScJGsbZrS+oBrhtc3s40SksTznkvNY3d/osVhLcEvO
# kADM3KPR0m51FlREAu8bVERj6LVwyLlHmltFxG52mhix9xAzyAtR9VWM/SEeQY9O
# PpBdgAHIvCR+hmgUFRQ0NXRJt4dSKdaWXqKjFtSw03sxggJaMIICVgIBATCBizB3
# MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAd
# BgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFudGVj
# IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEFTzfaFxZ1G8ao0K0nSyixMwCwYJYIZI
# AWUDBAIBoIGkMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0B
# CQUxDxcNMTcwMzE3MTUzMDQzWjAvBgkqhkiG9w0BCQQxIgQgmjvZpvNwxFn4VWN+
# dsJtNnqCTz/uHT6u3WIVYfhlnJUwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQggtVW
# 29tdrV+ge7YHJqbYbnMLW7cpiFu23k/ydSkCLPwwCwYJKoZIhvcNAQEBBIIBAHnL
# k9gUCmbQekgTcBNeuLgQ/NblWKzgQQa1p1/KaO4us8AV02MNwKXHr0Emi30sfbp5
# IvBe9HDXG0kd4dgdkhP6HgMGoi8NqnwHvVht7nAxhfeartwKlnSC+WdzfR4Z0puw
# Co0/gn8dy8Rq9sMcjJbmjuroD+4OA/yUsCMVWFAD3gxyxmZ6oPPx8Nocwe3aE1Xp
# fgjvIs5a9XNa4LudaR4ApV96TyGBbGrDikb6rUf0Qfs1jX7+swohnH00o6VhOER9
# F/a1m94Ph/x5L4YuVRVvS5QKGmZnvRQoQAPfomkI1C/c//bo2/yHJjcPkwfgxILU
# GPtpqlyd6b8sQ3R34AI=
# SIG # End signature block
