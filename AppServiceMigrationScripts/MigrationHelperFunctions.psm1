#App Service Migration Assistant Scripts - Helper functions module

#Get the script configuration info
function Get-ScriptConfig() {
    $ScriptConfigPath = Join-Path $PSScriptRoot "ScriptConfig.json"
    if (!(Test-Path -Path $ScriptConfigPath)) {
        Write-Host "Script configuration file not found!" -ForegroundColor Red -BackgroundColor Black
        exit
    }

    return (Get-Content -Path $ScriptConfigPath | ConvertFrom-Json)
}

function Send-TelemetryEventIfEnabled() {
#Logs an anonymized event in App Insights
param(
    [Parameter(Mandatory)]
    [string]$TelemetryTitle,

    [Parameter(Mandatory)]
    [string]$EventName,

    [Parameter(Mandatory)]
    [ValidateSet("info", "warn", "action", "error")]
    [string]$EventType,

    [Parameter()]
    [string]$EventMessage,

    [Parameter()]
    [Hashtable]$ExceptionData,

    [Parameter()]
    [string]$Subscription,

    [Parameter()]
    [string]$ResourceGroup,

    [Parameter()]
    [string]$AzureSite
)

    try {       
        $ScriptConfig = Get-ScriptConfig
        if ($ScriptConfig.EnableTelemetry) {
            Add-Type -Path (Join-Path $PSScriptRoot "Microsoft.ApplicationInsights.dll")
            $EventData =  New-Object "System.Collections.Generic.Dictionary[string,string]"
        
            if (!$MigrationScriptsTelemetryClient) {
                $InstrumentKey = $ScriptConfig.TelemetryInstrumentKey
        
                #Gets the machine's crypto GUID, hashes it (SHA256), and reformats it
                $MachineGUID = (Get-ItemProperty "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography").MachineGuid
                $StringAsStream = [System.IO.MemoryStream]::new()
                $Writer = [System.IO.StreamWriter]::new($StringAsStream)
                $Writer.write($MachineGUID)
                $Writer.Flush()
                $StringAsStream.Position = 0
                $MachineGUID = (Get-FileHash -InputStream $StringAsStream).Hash
                $MachineGUID = ($MachineGUID.Substring(0, 8) + '-' + $MachineGUID.Substring(8, 4) + '-4' + $MachineGUID.Substring(13, 3) + '-' + $MachineGUID.Substring(16, 4) + '-' + $MachineGUID.Substring(20, 12))
        
                #Gets the hashed MachineGUID and appends PS Session/Instance ID to it ($PID)
                $SessionGUID = New-Guid
        
                #Create new TelemetryClient from Microsoft.ApplicationInsights.dll library
                $Global:MigrationScriptsTelemetryClient = New-Object Microsoft.ApplicationInsights.TelemetryClient
                $MigrationScriptsTelemetryClient.InstrumentationKey = $InstrumentKey
        
                #Set allowed tags and zero out those that aren't
                $TagAllowList = @(
                    'Location.Ip',
                    'Component.Version',
                    'User.Id',
                    'Session.Id',
                    'Operation.ParentId',
                    'Operation.Name',
                    'Device.OperatingSystem',
                    'Device.Type'
                );
        
                #Remove unnecessary/unwanted telemetry info
                foreach ($Section in $MigrationScriptsTelemetryClient.Context) {
                    foreach ($Tag in $Section) {
                        if (!$TagAllowList.Contains("$Section.$Tag")) {
                            $Tag = ""
                        }
                    }
                }
        
                #Set various information for the event to be logged
                $MigrationScriptsTelemetryClient.Context.Location.Ip = "127.0.0.1"
                $MigrationScriptsTelemetryClient.Context.Component.Version = $ScriptConfig.ScriptsVersion
                $MigrationScriptsTelemetryClient.Context.User.Id = $MachineGUID
                $MigrationScriptsTelemetryClient.Context.Session.Id = $SessionGUID
            }
        
            $MigrationScriptsTelemetryClient.Context.Operation.ParentId = $TelemetryTitle
            $MigrationScriptsTelemetryClient.Context.Operation.Name = $EventType
        
            #Add Azure info to the event if it was passed
            if ($Subscription) {
                $EventData["subscriptionId"] = $Subscription
            }
        
            if ($ResourceGroup) {
                $EventData["resourceGroupName"] = $ResourceGroup
            }
        
            if ($AzureSite) {
                $EventData["siteName"] = $AzureSite
            }
        
            if ($EventMessage) {
                $EventData["message"] = $EventMessage
            }
        
            if ($ExceptionData) {
                $EventData["HResult"] = $ExceptionData["HResult"]
                $EventData["ExceptionMessage"] = $ExceptionData["ExceptionMessage"]
                $EventData["StackTrace"] = $ExceptionData["StackTrace"]
            }
        
            $MigrationScriptsTelemetryClient.TrackEvent($EventName, $EventData, $null)
        }
    }
    catch {
        #fail without blocking. Logging is best-effort and should never block local functionality
        #Write-HostInfo -Message "Error logging telemetry : $($_.Exception.Message)"  
    }
}


function Write-HostError() {
    param(
        [Parameter()]
        [string]$Message
    )
    Write-Host "[ERROR] $Message" -ForegroundColor Red -BackgroundColor Black
}

function Write-HostInfo() {
    param(
        [Parameter()]
        [string]$Message,

        [Parameter()]
        [switch] $MakeTextGreen
    )

    if ($MakeTextGreen) {
        Write-Host "[INFO] $Message" -ForegroundColor Green
    } else {
        Write-Host "[INFO] $Message" 
    }
    
}

function Write-HostWarn() {
    param(
        [Parameter()]
        [string]$Message
    )
    Write-Host "[WARN] $Message" -ForegroundColor Yellow -BackgroundColor Black
}


#Used to read assessment data and site config from the site .zip
function Get-ZippedFileContents() {
    param(
        [Parameter()]
        [string]$ZipPath,

        [Parameter()]
        [string]$NameOfFile
    )

    $ZipFile = [IO.Compression.ZipFile]::OpenRead((Convert-Path $ZipPath))
    $File = $ZipFile.Entries | Where-Object {$_.Name -eq $NameOfFile}
    if ($File) {
        $Stream = $File.Open()
    
        $Reader = New-Object IO.StreamReader($Stream)
        $Content = $Reader.ReadToEnd()
    
        $Reader.Close()
        $Stream.Close()
        $ZipFile.Dispose()
    
        return $Content
    }
 
}

function Initialize-LoginToAzure {
    try {
        if (!((Get-AzContext).Account)) {
            $LoginToAzure = Connect-AzAccount           
        }
    }
    catch {
        Write-HostError $_.Exception.Message 
        Write-HostError "You must have Azure PowerShell to run this script: https://go.microsoft.com/fwlink/?linkid=2133508"
        Send-TelemetryEventIfEnabled -TelemetryTitle "MigrationHelperFunctions.psm1" -EventName "Azure PowerShell wasn't installed" -EventType "error" -ErrorAction SilentlyContinue
        exit 1
    }
}

function Test-InternetConnectivity {
    try {
        [void] (Get-AzureAccessToken -ErrorAction Stop)
    }
    catch {
        if(Test-Connection bing.com -Quiet) {
            return;
        }
        else {
            Write-HostError "Outgoing connections may be limited. Please connect to an internet network and try again. May also try running Get-AzContext in same session before running script."
            exit 1
        }
    }
}

#Below is the current method of obtaining an ARM access token through a logged-in Azure PS session
function Get-AzureAccessToken() {
    $AzureProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $AzureContext = Get-AzContext
    $ProfileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($AzureProfile)
    return ($ProfileClient.AcquireAccessToken($AzureContext.Tenant.TenantId)).AccessToken
}

function Get-AzureSiteNameAvailability() {
    param(
        [Parameter()]
        [string]$SiteName,

        [Parameter()]
        [string]$AzureSubscriptionId
    )

    $AccessToken = Get-AzureAccessToken
    $Uri = "https://management.azure.com/subscriptions/$AzureSubscriptionId/providers/microsoft.web/checknameavailability?api-version=2019-08-01"
    $ReqHeader = @{
        'Content-Type' = 'application/json'
        'Authorization' = "Bearer $AccessToken"
    }

    $ReqBody = "{ ""name"": ""$SiteName"", ""type"": ""Microsoft.Web/sites""}"

    $ARMNameAvailabilityResponse = Invoke-RestMethod -Uri $Uri -Headers $ReqHeader -Body $ReqBody -Method "POST"
    
    return $ARMNameAvailabilityResponse
}

function Get-ExceptionData() {
    param(
        [Parameter()]
        $Exception
    )

    $ExceptionData = @{}
    if ($Exception.StackTrace) {
        $ExceptionData.Add("StackTrace" , $Exception.StackTrace)
    }
    if ($Exception.HResult) {
        $ExceptionData.Add("HResult", $Exception.HResult.ToString('X'))
    } 
   
    return $ExceptionData
}

function Get-AzExceptionMessage() {
    param(
        [Parameter()]
        $Exception
    )

    if ($Exception.Response -and $Exception.Response.Content) {
        $ExceptionMsg = ($Exception.Response.Content | ConvertFrom-Json).error.message
        if (!$ExceptionMsg) {
            $ExceptionMsg = ($Exception.Response.Content | ConvertFrom-Json).message
        }
    }
    else {
        $ExceptionMsg = $Exception.Message
    }
   
    return $ExceptionMsg
}

function Test-AzureResources {
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,

        [Parameter()]
        [string]$Region,

        [Parameter()]
        [string]$AppServiceEnvironment,

        [Parameter()]
        [string]$ResourceGroup,
        
        [Parameter()]
        [switch]$SkipWarnOnRGNotExists
    )

    Test-InternetConnectivity

    if ($Region) {
        try {
            $AllRegions = Get-AzLocation -ErrorAction Stop 
            $Regions = $AllRegions | Select-Object Location 
            if (!($Regions | Where-Object {$_.Location -eq $Region})) {
                Write-HostError -Message "Region $Region is not valid. Possible region values may be viewed by running an Az Powershell command :
                Get-AzLocation | select Location"
                exit 1  
            }
        }
        catch {
            Write-HostError -Message "Error verifying if $Region is valid Azure Region : $($_.Exception.Message)"  
            exit 1  
        }
    }
   
    if ($SubscriptionId) {
        try {
            $context = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction Stop | Set-AzContext
        } catch {
            Write-HostError "Error setting subscription Id : $($_.Exception.Message)"
            Write-HostError "Run Get-AzSubscription on powershell to get all valid subscriptions"
            exit 1  
        }
    }   
    
    if ($AppServiceEnvironment) {
        try {
            $ASEDetails = Get-AzResource -Name $AppServiceEnvironment -ResourceType Microsoft.Web/hostingEnvironments -ErrorAction Stop
            if (!$ASEDetails) {
                Write-HostError "App Service Environment $AppServiceEnvironment doesn't exist in Subscription $SubscriptionId"
                Write-HostError "Please provide an existing App Service Environment in Subscription $SubscriptionId"
                exit 1  
            } elseif($Region -and $ASEDetails.location -ne $Region) {               
                Write-HostWarn -Message "Specified Region ($Region) does not match App Service Environment location ($($ASEDetails.location)), App Service Environment location will be used during migration"
                #exit 1  # warn on this only, migration will work with the described behavior
            }
        }
        catch {
            Write-HostError -Message "Error verifying if App Service Environment is valid : $($_.Exception.Message)"
            exit 1  
        }
    }

    if ($ResourceGroup) {
        try {
            [void](Get-AzResourceGroup -Name $ResourceGroup -ErrorVariable RscGrpError -ErrorAction Stop)            
        }
        catch {
            #non terminating error as a Resource group is created if not present during the migration
            if ($RscGrpError -and $RscGrpError.Count -gt 0 -and $RscGrpError[0].ToString().Contains("does not exist")) {
                if(!$SkipWarnOnRGNotExists) {   
                    Write-HostWarn "Resource Group $ResourceGroup not found in Subscription $SubscriptionId"
                    Write-HostWarn "Resource Group $ResourceGroup will be created during migration"
                }                   
            } else {
                Write-HostError -Message "Error verifying Resource Group name : $($_.Exception.Message)"    
                exit 1
            }
        }
    }
}
# SIG # Begin signature block
# MIIjhQYJKoZIhvcNAQcCoIIjdjCCI3ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD54PFTftnA3tpH
# iFaw+JmN54rwQqb4UkBQMHEignvL1qCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWjCCFVYCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg/Md1uu8U
# PlOO9q04+mj6+k4zu2RE/I7VJqKSm31rnLQwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQADNZtZHdFaZgBPi/ZD23FTdrnoS+J1tTtb3gLTnSYK
# 2spvBHz2lpxLqcQgwO2Ag6MvelbgyjpakIIPY0QUY61KIXmQsSmRefPM2BGgHuq9
# d4tqLr0m+TlVpt8RLyCpyZl34loiEsd6XC1XEmus2wv/HGnWOdYFRsGGLLi0XzGH
# mztjxR6SWIcNaZgLJKD+hX3rprglUsBt3l3d3TU8dilGGugDvEmPA7lQ4EUAXqB2
# C1lWyzrLwkgathKq1JhdbvchTZbKOM9PKn4cJQNtTLI/wHXzE44RFasongg0Gmvf
# 2VFdAoqMmP7NFSnchedSachXLoy6IZK0SJxYzGbbn0PGoYIS5DCCEuAGCisGAQQB
# gjcDAwExghLQMIISzAYJKoZIhvcNAQcCoIISvTCCErkCAQMxDzANBglghkgBZQME
# AgEFADCCAVAGCyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIPFZSSg+6JCudEyfbNNgZWalqtEOPAzyypWbFqO4
# GOtwAgZg+YRA/58YEjIwMjEwNzIyMTcxNjQ3LjM2WjAEgAIB9KCB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MjI2NC1FMzNFLTc4MEMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2Wggg48MIIE8TCCA9mgAwIBAgITMwAAAUqk9zHE/yKiSQAAAAABSjAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MDExMTIxODI1NThaFw0yMjAyMTExODI1NThaMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoyMjY0LUUzM0UtNzgw
# QzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAN7KKGZkolgsvVEaNKMTVZZgEl8ohsLg
# HR4gUFWLZvWzLbegDoRItpfFd+9maW2hPFlgT+wv7lxf6OB4HFYZgHfIpcZhGU6/
# ebsymXYAmAKzKph71pxJU5F228YTSTLcoSAIUNBZVdTEIZILEPT5gI77Ysu7YKMu
# fSmiZPzqYlkEX2/dHhOcoo90zgIJRTG1u2kF7w6a7D50yHKE46eGEwqwjExERCCN
# tFBDQrTfYID/Icj0zKikYjiJRaaPNjnvBaRJ/eFkGz8gD2XyYXjlsNjDGPaGPQTt
# /Rm3nrxcyXGyCIIhWdBMXMTLl7BMDKKeLBQ0d6pFfS1LRJo+paKKBiUCAwEAAaOC
# ARswggEXMB0GA1UdDgQWBBRxjGEYMfrAhjWKk/99frgmKqk/4TAfBgNVHSMEGDAW
# gBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0Ff
# MjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBDQV8yMDEw
# LTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4IBAQBRC67dRjgFFS9kv72Vfe8gQ+Hg3FpX2TYyOq4nrtPq
# 9D36Udydr2ibZy5n7LphXvW20bDTugUHiwuyfWnmyc2oEevo+SrNCzxXcj59Wv9l
# QpBgtL6OM56x+v1zbNzp/moMwk3UvysE5af5rktfFtPx6apqcjU1IDt09hX80ZAz
# qPflPPyC5Cj3J8DQilQz2/TzSZvcbgCM9vuwLu9p9bZhJemNP++3LrHkdycfHZf3
# jv7QBAigEvyVb2mrnlomFIKCyJW1cOrBjIqyntQt5PK8zKxX/yZlyiRbr8c0DQw8
# tYpXeyorgoVet9sAF+t3g/cYzVogW4qwhuyZmEmTlTSKMIIGcTCCBFmgAwIBAgIK
# YQmBKgAAAAAAAjANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0
# NjU1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX7
# 7XxoSyxfxcPlYcJ2tz5mK1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM
# 1024OAizQt2TrNZzMFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHP
# k0ySwcSmXdFhE24oxhr5hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3Ws
# vYpCTUBR0Q+cBj5nf/VmwAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw
# 6ZnNPOcvRLqn9NxkvaQBwSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHi
# MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVt
# VTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0T
# AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNV
# HR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEE
# TjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2Nl
# cnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGS
# MIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4y
# IB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAu
# IB0wDQYJKoZIhvcNAQELBQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+
# zwXiqf76V20ZMLPCxWbJat/15/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKK
# dsxAQEGb3FwX/1z5Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/Uv
# eYFl2am1a+THzvbKegBvSzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4z
# u2JfmttXQOnxzplmkIz/amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHim
# bdLhnPkd/DjYlPTGpQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlX
# dqJxqgaKD4kWumGnEcua2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHh
# AN/nMQekkzr3ZUd46PioSKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A
# +xuJKlQ5slvayA1VmXqHczsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdC
# osnPGUFN4Ib5KpqjEWYw07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42ne
# V8HR3jDA/czmTfsNv11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nf
# j950iEkSoYICzjCCAjcCAQEwgfihgdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9w
# ZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjIyNjQtRTMzRS03ODBD
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYF
# Kw4DAhoDFQC8BO6GhSDKwTN3KQTVtEHiiHprmKCBgzCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5KQCwDAiGA8yMDIx
# MDcyMjIyNDQxNloYDzIwMjEwNzIzMjI0NDE2WjB3MD0GCisGAQQBhFkKBAExLzAt
# MAoCBQDkpALAAgEAMAoCAQACAgCEAgH/MAcCAQACAhEzMAoCBQDkpVRAAgEAMDYG
# CisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEA
# AgMBhqAwDQYJKoZIhvcNAQEFBQADgYEApCoemagsAMsDa/fYepSV1d7VvUQkNUOE
# wr/ZhLo9eTqYixoIqc//j6dePcN1eRotrTg+e8zDVegy/qGzVNzfpgvAApGKOKEq
# WEUt44tCxap2WdM8Q/JC2o1ITKFIAMfL4sDmMult/2DnA/fE3Cou+u5UPsBWhm8X
# U0VcNaskzRAxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAUqk9zHE/yKiSQAAAAABSjANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCCATjqJVb9z
# AA7rbzZEdDMD4IN6fefgI/gyCiX003yWBzCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EIGwdktetudtX/kn7Yq/AVYiBWZBq+n4EFVQ8zUD3IlEDMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFKpPcxxP8iokkAAAAA
# AUowIgQgAh2jt+smCUTiV9lhWT3Xhhs88Kn3uF//iWUQrCThY/YwDQYJKoZIhvcN
# AQELBQAEggEAXOAhaMdUoJCD63TJ3FhDz/RLlonaBrC34QmNInvmmvtDksUmOnWe
# MPsuCZjTTyBZcdQJ+7bQ3xXBgFT//qAHXyNcAIRp2QV+TPNpgizewYodh2ThM0Lb
# dIQzWoqQL1N6DctjdiXWNTNfuoslIBcRIENcgA8ZI2dcAoif7wxe5U8mzdwB5ea5
# zVkObVTCZks9Y6DscimR+GX1DAhOHuMXprDlfVG9mkn8UY/ueG4ABFiBCoXgCmmF
# tmbZXvEe76AoxVMProFWV2BXaaVON//LUOD1lz8KfHIaUouAEnFpvWVdUL5GOqpk
# ly+bGMVkkijMKmkUhoOemi+6rfs/0q9iPQ==
# SIG # End signature block
