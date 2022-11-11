<#
  .SYNOPSIS
  Builds a JSON file containing migration settings

  .DESCRIPTION
  Generates default values for settings required for sites migration based on parameters passed for use with Invoke-SiteMigration

  .PARAMETER SitePackageResultsPath
  Specifies the path to a file containing sites packaging details
  Settings are generated for all sites in this SitePackageResultsPath that specify a package path 
  
  .PARAMETER Region
  Specifies a region to be used for all sites migration   

  .PARAMETER SubscriptionId
  Specifies an Azure subscription to use for all sites migration

  .PARAMETER ResourceGroup
  Specifies a Resource Group to use for all sites migration

  .PARAMETER AppServiceEnvironment
  Specifies App Service Environment to use for all sites migration

  .PARAMETER MigrationSettingsFilePath
  Specifies the path where the migration settings file will be saved

  .PARAMETER Force
  Overwrites the migrations settings file if already exists

  .OUTPUTS
  Generate-MigrationSettings.ps1 outputs the path to a file containing Default settings for migration

  .EXAMPLE
  C:\PS> .\Generate-MigrationSettings -SitePackageResultsPath PackageResults.json -Region "West US" -SubscriptionId "01234567-3333-4444-5555-111111111111" -ResourceGroup "MyResourceGroup"  

  .EXAMPLE
  C:\PS> .\Generate-MigrationSettings -SitePackageResultsPath PackageResults.json -Region "West US" -SubscriptionId "01234567-3333-4444-5555-111111111111" -ResourceGroup "MyResourceGroup" -AppServiceEnvironment "MyASE" -MigrationSettingsFilePath "C:\Migration\MyMigrationSettings.json"
#>

#Requires -Version 4.0
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory)]
    [string]$SitePackageResultsPath,

    [Parameter(Mandatory)]
    [string]$Region,

    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [Parameter()]
    [string]$AppServiceEnvironment,

    [Parameter()]
    [string]$MigrationSettingsFilePath,

    [Parameter()]
    [switch]$Force
)
Import-Module (Join-Path $PSScriptRoot "MigrationHelperFunctions.psm1")

$ScriptConfig = Get-ScriptConfig
$MigrationSettings = [System.Collections.ArrayList]::new()

Send-TelemetryEventIfEnabled -TelemetryTitle "Generate-MigrationSettings.ps1" -EventName "Started script" -EventType "action" -ErrorAction SilentlyContinue

if  (!$MigrationSettingsFilePath) {
    $MigrationSettingsFilePath = $ScriptConfig.DefaultMigrationSettingsFilePath
}

if (Test-Path $MigrationSettingsFilePath) {
    if($Force) {
        Write-HostInfo -Message "Existing $MigrationSettingsFilePath file will be overwritten"
    } else {
        Write-HostError -Message  "$MigrationSettingsFilePath already exists. Use -Force to overwrite or specify alternate location with MigrationSettingsFilePath parameter"
        exit 1
    }
} 

Initialize-LoginToAzure

#validations on azure parameters before adding them as part of settings file
try {
    Test-AzureResources -SubscriptionId $SubscriptionId -Region $Region -AppServiceEnvironment $AppServiceEnvironment -ResourceGroup $ResourceGroup 
} catch {
    #non termination error as validations are carried in migration (Invoke-SiteMigration.ps1) step too
    Write-HostError "Error in validating Azure parameters: $($_.Exception.Message)"
}

function Get-IfP1V3Available {
    try {
        $AccessToken = Get-AzureAccessToken
        $Headers = @{
            'Content-Type' = 'application/json'
            'Authorization' = "Bearer $AccessToken"
        }
        $RegionsForSkuURI = "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.Web/geoRegions?api-version=2020-10-01&sku=PremiumV3"
        $RegionsForP1V3 = Invoke-RestMethod -Uri $RegionsForSkuURI -Method "GET" -Headers $Headers
        $RegionsData = $RegionsForP1V3.value
        foreach ($SkuRegion in $RegionsData) {
            $RegionName = $SkuRegion.name -replace '\s',''
            if ($RegionName -eq $Region) {
                return $true
            }
        }
    }
    catch {
        Write-HostWarn -Message "Error finding if PremiumV3 Tier is available for region  $Region : $($_.Exception.Message)"  
        Send-TelemetryEventIfEnabled -TelemetryTitle "Generate-MigrationSettings.ps1" -EventName "Error in finding P1V3 availability" -EventType "error" -ErrorAction SilentlyContinue
    }
    
    return $false
}

try {
    $PackageResults = Get-Content $SitePackageResultsPath -ErrorAction Stop | ConvertFrom-Json
}
catch {
    Write-HostError "Error reading Site package results file: $($_.Exception.Message)"
    $ExceptionData = Get-ExceptionData -Exception $_.Exception
    Send-TelemetryEventIfEnabled -TelemetryTitle "Generate-MigrationSettings.ps1" -EventName "Error reading migration settings file" -ExceptionData $ExceptionData -EventType "error" -ErrorAction SilentlyContinue
    exit 1
}

$SitesPackageResults = @($PackageResults | Where-Object {($null -ne $_.SitePackagePath)})

if (!$SitesPackageResults -or ($SitesPackageResults.count -eq 0)) {
    Write-HostError -Message "No succesfully packaged site found in $SitePackageResultsPath"
    Write-HostInfo -Message "Run Get-SitePackage.ps1 to package site contents"
    exit 1
}

if ($AppServiceEnvironment) {
    try {
        $AseDetails = Get-AzResource -Name $AppServiceEnvironment -ResourceType Microsoft.Web/hostingEnvironments -ErrorAction Stop
        if (!$AseDetails) {
            Write-HostError "App Service Environment $AppServiceEnvironment doesn't exist in Subscription $SubscriptionId"
            Write-HostError "Please provide an existing App Service Environment in Subscription $SubscriptionId"
            exit 1  
        }

        #Warning so that user can choose to modify Region parameter and make sure all their resources are within one region if they want to
        if($Region -and $AseDetails.Location -ne $Region) {
            Write-HostWarn "Region '$Region' provided is different from App Service Environment '$AppServiceEnvironment' region $($AseDetails.Location)"
            Write-HostWarn "Setting Region as '$($AseDetails.Location)' for migration"
            $Region = $AseDetails.Location
        }
    }
    catch {
        Write-HostError -Message "Error verifying if App Service Environment is valid : $($_.Exception.Message)"
        exit 1  
    }
}

$TotalSites = $SitesPackageResults.count
$SitesPerASP = 8
$Tier = "PremiumV2"

if ($AppServiceEnvironment) {
    $SitesPerASP = 8
    $Tier = "Isolated"  
} elseif (Get-IfP1V3Available) {
    $SitesPerASP = 16
    $Tier = "PremiumV3"
} 

Write-HostInfo -Message "Setting Default Tier as $Tier"
$ASPsToCreate = [int][Math]::Ceiling($TotalSites/$SitesPerASP)
$SiteIndex = 0;
while ($ASPsToCreate -gt 0) {
    $RandomNumber = Get-Random -Maximum 999999 -Minimum 000000
    $tStamp = Get-Date -format yyyyMMdd
    $ASPName = "Migration_ASP_" + $tStamp+ "_" + $RandomNumber

    $MigrationSetting = New-Object PSObject

    Add-Member -InputObject $MigrationSetting -MemberType NoteProperty -Name AppServicePlan -Value $ASPName
    Add-Member -InputObject $MigrationSetting -MemberType NoteProperty -Name SubscriptionId -Value $SubscriptionId
    Add-Member -InputObject $MigrationSetting -MemberType NoteProperty -Name Region -Value $Region
    Add-Member -InputObject $MigrationSetting -MemberType NoteProperty -Name ResourceGroup -Value $ResourceGroup
    Add-Member -InputObject $MigrationSetting -MemberType NoteProperty -Name Tier -Value $Tier
    Add-Member -InputObject $MigrationSetting -MemberType NoteProperty -Name NumberOfWorkers -Value $ScriptConfig.ASPNumberOfWorkers
    Add-Member -InputObject $MigrationSetting -MemberType NoteProperty -Name WorkerSize -Value $ScriptConfig.ASPWorkerSize
    if ($AppServiceEnvironment) {
        Add-Member -InputObject $MigrationSetting -MemberType NoteProperty -Name AppServiceEnvironment -Value $AppServiceEnvironment
    }
    
    $SitesSettings = [System.Collections.ArrayList]::new()
    
    $ASPCapacity = $SitesPerASP
    while ($ASPCapacity -gt 0 -and $SiteIndex -lt $TotalSites) {
        $Site = $SitesPackageResults[$SiteIndex]
        $SitePackagePath = $Site.SitePackagePath
        # get full path to package files, if path is relative should be relative to package results file 
        if(-not ([System.IO.Path]::IsPathRooted($SitePackagePath))) {       
            $packageFileFullPath = $SitePackageResultsPath
            if(-not ([System.IO.Path]::IsPathRooted($packageFileFullPath))) {
                $packageFileFullPath = Join-Path (Get-Location).Path $SitePackageResultsPath
            }
            $SitePackagePath = Join-Path (Split-Path -Path $packageFileFullPath) $Site.SitePackagePath
        }
        $SiteSetting = New-Object PSObject

        Add-Member -InputObject $SiteSetting -MemberType NoteProperty -Name IISSiteName -Value $Site.SiteName
        Add-Member -InputObject $SiteSetting -MemberType NoteProperty -Name SitePackagePath -Value $SitePackagePath
        Add-Member -InputObject $SiteSetting -MemberType NoteProperty -Name AzureSiteName -Value $Site.SiteName
        [void]$SitesSettings.Add($SiteSetting)

        $ASPCapacity--
        $SiteIndex++

    }
    Add-Member -InputObject $MigrationSetting -MemberType NoteProperty -Name Sites -Value $SitesSettings
    [void]$MigrationSettings.Add($MigrationSetting)
    $ASPsToCreate--
}

try {
    ConvertTo-Json $MigrationSettings -Depth 10 | Out-File (New-Item -Path $MigrationSettingsFilePath -ErrorAction Stop -Force)
}
catch {
    Write-HostError -Message "Error creating migration settings file: $($_.Exception.Message)" 
    Send-TelemetryEventIfEnabled -TelemetryTitle "Generate-MigrationSettings.ps1" -EventName "Error in creating migration settings file" -EventType "error" -ErrorAction SilentlyContinue
    exit 1
}

Write-HostInfo "Migration settings have been successfully created and written to $MigrationSettingsFilePath"
Send-TelemetryEventIfEnabled -TelemetryTitle "Generate-MigrationSettings.ps1" -EventName "Script end" -EventType "action" -ErrorAction SilentlyContinue
return  $MigrationSettingsFilePath
# SIG # Begin signature block
# MIIjhQYJKoZIhvcNAQcCoIIjdjCCI3ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBxxvwri8CeC3FH
# WWuW3xr9JhdKSlEdwACiIkhZ7E5svaCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgEtG5aLKD
# 3jlaZ1H6OEBYYyXTAIDU0tlUiOyi9QLuPBUwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBM8mSUOWylGLUbwVhYeS4wUH5dOXJMA9Kcilo9ur5D
# fv0UPi+pWZaeORACFMUKGUWTsIMdLu85Egr/steFhLm3x5PRGci+bM92Skp1Zoog
# vbFTywEBiGh5UodY1scAPT0yUh+43MvFNgPzwQcn7LWxVJBNcjXPOrOamqoWP4AW
# r9GP0iAhPjy3ZTrKMZ9qEFNg+cbhUjD+KsBNnZBvHFQ2uTvIeBhxFngde6Qg1fim
# njCIWI63xDrJJdca5hNODqVAXOZi8NJLIkqFfzIeQFFGV4FB2Xi03klvEKE3/QOy
# XmkhXxBz/Fhfnjl7SOP1qbKk8lDjhdVqkaycsVXV9deFoYIS5DCCEuAGCisGAQQB
# gjcDAwExghLQMIISzAYJKoZIhvcNAQcCoIISvTCCErkCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIKTT81krWxJv5tM0/Howg+62iZMHdPdFvUfGUOk1
# OhsdAgZg+YRNJ8IYEzIwMjEwNzIyMTcxNjQ3LjI3NFowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkFFMkMtRTMyQi0xQUZDMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOOzCCBPEwggPZoAMCAQICEzMAAAFIoohFVrwvgL8AAAAAAUgw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjAxMTEyMTgyNTU2WhcNMjIwMjExMTgyNTU2WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046QUUyQy1FMzJCLTFB
# RkMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD3/3ivFYSK0dGtcXaZ8pNLEARbraJe
# wryi/JgbaKlq7hhFIU1EkY0HMiFRm2/Wsukt62k25zvDxW16fphg5876+l1wYnCl
# ge/rFlrR2Uu1WwtFmc1xGpy4+uxobCEMeIFDGhL5DNTbbOisLrBUYbyXr7fPzxbV
# kEwJDP5FG2n0ro1qOjegIkLIjXU6qahduQxTfsPOEp8jgqMKn++fpH6fvXKlewWz
# dsfvhiZ4H4Iq1CTOn+fkxqcDwTHYkYZYgqm+1X1x7458rp69qjFeVP3GbAvJbY3b
# Flq5uyxriPcZxDZrB6f1wALXrO2/IdfVEdwTWqJIDZBJjTycQhhxS3i1AgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUhzLwaZ8OBLRJH0s9E63pIcWJokcwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAZhKWwbMnC9Qywcrlgs0qX9bhxiZGve+8JED27hOi
# yGa8R9nqzHg4+q6NKfYXfS62uMUJp2u+J7tINUTf/1ugL+K4RwsPVehDasSJJj+7
# boIxZP8AU/xQdVY7qgmQGmd4F+c5hkJJtl6NReYE908Q698qj1mDpr0Mx+4LhP/t
# TqL6HpZEURlhFOddnyLStVCFdfNI1yGHP9n0yN1KfhGEV3s7MBzpFJXwOflwgyE9
# cwQ8jjOTVpNRdCqL/P5ViCAo2dciHjd1u1i1Q4QZ6xb0+B1HdZFRELOiFwf0sh3Z
# 1xOeSFcHg0rLE+rseHz4QhvoEj7h9bD8VN7/HnCDwWpBJTCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAs0wggI2AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpBRTJDLUUzMkItMUFG
# QzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAhyuClrocWf4SIcRafAEX1Rhs6zmggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOSkAswwIhgPMjAy
# MTA3MjIyMjQ0MjhaGA8yMDIxMDcyMzIyNDQyOFowdjA8BgorBgEEAYRZCgQBMS4w
# LDAKAgUA5KQCzAIBADAJAgEAAgEDAgH/MAcCAQACAhEcMAoCBQDkpVRMAgEAMDYG
# CisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEA
# AgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAOK64o+1kj5jIWlHzHCtZ8Tv1W8nr8XGz
# SdDFmNtSctWi6/ZVN1+PSrJf1j39LZy/SxgZQ2AIEgzbEJ6dF+t3DSkgSEsXvqbQ
# 0NMQ6o+e9qs0vPX91lH1Y9APji9a9noO7hugBr1OgdSXHFws6gJJRJjpmm0pNfZA
# BSS99zWbUu0xggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAUiiiEVWvC+AvwAAAAABSDANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCDGQV1wDBHn
# 9xw5a9XlCQ8Zfw2OQ6Q6Kclb2KmwDpHRgjCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EIKmQGuqMeaG/Jh/m1NxO8Pljhr5Xv1PBVXpPVoDB22jYMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFIoohFVrwvgL8AAAAA
# AUgwIgQgyCKGFOZ8JpyiYoCUiYZzP4UAZN+gtH7yBsQRZtEcIhgwDQYJKoZIhvcN
# AQELBQAEggEAe3PZzV+MCC+bBMMfn3fjuHzGXMXwaT25UWJLjVKDO9C27P192UWY
# mS9lWihkgIawhPOa9XobwVwy7EE8gDxGk9XGY2mCjAV2wBNFqi9A1V87FDp6ZMa1
# nLVN7AJrroRYsIiZo1JhneOe7SamVf/v+P3FmlWAGNsMQcEgxzwBAuRU/mL5iok+
# TIHxFTJVIaOT252KvRynd08p6KJweGKuChD+HwhCbtMX1dl32dSGqR06P7ebdhVl
# pPbTWzmJb8ZKn/0ZMQwv/TWkOy1Mhoq7YRWbDEorvKKXjH3SKezy08Gxa29mQ+g3
# A05gz4rdGFxUk4E9iyhnLr5ACp1OWzDtgQ==
# SIG # End signature block
