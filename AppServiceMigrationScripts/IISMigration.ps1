param(
	[Parameter()]
	[string]$targetSiteName,

    [Parameter()]
    [string]$zipOutputFilePath,

	[Parameter()]
    [string]$localSiteConfigFile
)

if(-not $targetSiteName) { $targetSiteName = "%%SITENAME%%" }
Write-Output "targetSiteName value is: $targetSiteName" 
Write-Output "Process Is64BitProcess: $([Environment]::Is64BitProcess)"
#Test-WSMan -ErrorVariable errorvar -ErrorAction SilentlyContinue
#if(!$errorvar) {
#    $maxMemoryInMBValue = (Get-Item WSMan:\localhost\Shell\MaxMemoryPerShellMB).Value
#    Write-Output "Max memory (MB): $maxMemoryInMBValue"
#}
Write-Output "PS version is: $($PSVersionTable.PSVersion)"

function GetZipRelativePath {
	param($fullPhysicalPath, $siteHomeDirectory)

	$relativePath = "";

	if($fullPhysicalPath.ToLower() -eq $siteHomeDirectory.ToLower()) {
		return "site\wwwroot";
	} elseif ($fullPhysicalPath.ToLower().StartsWith($siteHomeDirectory.ToLower())) {
		$relativePath = "site\wwwroot\$($fullPhysicalPath.Substring($siteHomeDirectory.Length + 1))";
	} else {
		$relativePath = "site\";
		$PathRoot = [System.IO.path]::GetPathRoot($fullPhysicalPath).ToUpper().TrimEnd('\');
		foreach($char in $PathRoot.toCharArray()) {
			if($char -eq ':') {
				$relativePath += "_C";
			} elseif($char -eq '\') {
				$relativePath += "_S";
			} elseif($char -eq '_') {
				$relativePath += "_N";
			} else {
				$relativePath += $char;
			}
		}
		$relativePath += $fullPhysicalPath.Substring($PathRoot.Length);
	}
	return $relativePath;
}       

function GetContentPathsAndZip {
	$sm = New-Object Microsoft.Web.Administration.ServerManager; 
    $Config = $sm.GetApplicationHostConfiguration();	     
    $SitesSection = $Config.GetSection("system.applicationHost/sites"); 	 	

	$foundUNCPath = $false;
	$errorId = "";
	$errorMsg = "";
	$siteMatchFound = $false;    
 
 	$maxBytesSize = 2 * 1024 * 1024 * 1024; # 2GB		
 	$targetSiteInfo = $null;

    foreach($siteSection in $SitesSection.GetCollection()) {          
 		$siteName = $siteSection['name'];
 		if($siteName -ne $targetSiteName) {
 			continue;
 		}       
 		Write-Output "Found site on server";
		$siteMatchFound = $true; 		 				 		
 		$runningContentSize = 0; 		
 		$siteRootVDir = ($siteSection.GetCollection() | Where-Object {$_['path'] -eq '/'}).GetCollection() | Where-Object {$_['path'] -eq '/'}
 		$siteRootPhysicalPath = [System.Environment]::ExpandEnvironmentVariables($siteRootVDir['physicalPath'])

		$dirPathsToZip = @{} 

 		foreach($appPool in $siteSection.GetCollection()) {		
		
 			foreach($vdir in $appPool.GetCollection()) {							
 				$expandedFullPath = [System.Environment]::ExpandEnvironmentVariables($vdir['physicalPath']);
 				
 				if($vdir['physicalPath'].StartsWith("\\") -and (-not($vdir['physicalPath'].StartsWith("\\?\")) -or $vdir['physicalPath'].StartsWith("\\?\UNC\"))){	
					$foundUNCPath = $true 		
					break;					
 				} else {
					$isSubPathOfExistingZipPath = $false;
					$removePaths = @{};
 					# check if vdirs already has parent of path or is a parent or a path in vdirs, add or not accordingly
					# ex: could have vdirs like /photos = c:\foo\photos, /app2/photos = c:\foo\photos, /icons = c:\foo\photos\bar\icons, should end up with single c:\foo\photos in vdirs 
					foreach($dirPath in $dirPathsToZip.Keys) {
						if($expandedFullPath.ToLower().StartsWith($dirPath.ToLower())) {
							$isSubPathOfExistingZipPath = $true;
							break;
						} elseif($dirPath.ToLower().StartsWith($expandedFullPath.ToLower())){
							$removePaths.Add($dirPath, "");
						}
					}
					#only add unique directories to .zip package
					if(-not($dirPathsToZip.ContainsKey($expandedFullPath)) -and -not($isSubPathOfExistingZipPath)) {
						$dirPathsToZip.Add($expandedFullPath, "");
					}
					if($removePaths.Count > 0) {
						foreach($k in $removePaths.Keys) {
							$dirPathsToZip.Remove($k);
						}
					}			
 				}
 			}
			
 		}		


		# if no UNC issues, start iterating through vdirs to create .zip - do running content size check and stop if exceeds 2GB with error
		if($foundUNCPath) {
			$errorId = "IISWebAppUNCContentDirectory" 
			$errorMsg = "UNC directory encountered in web app content. UNC directories are not currently supported for migration."			
 		} else {
			if($zipOutputFilePath) {				
				# no validation of directory pre-existing or accessible
				$targetZipPath = $zipOutputFilePath
			} else {
				$timeId = (Get-Date).ToString("yyyyMMddhhmmss")
				$targetZipPath = "$($Env:temp)\$($timeId)_tempZipFile.zip"
			}
 			Write-Output "Target zip path: $targetZipPath" 
						
			$sm = $null
			$Config = $null     
			$SitesSection = $null
			[GC]::Collect()
			Write-Output "memory use: $([System.GC]::GetTotalMemory($false))"
			 			
			try {	
				# System.Io.Compression.ZipFile is .NET Fx 4.5+, this likely requires PSv4 minimum version
 				[System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.ZipArchive') | Out-Null
 				[System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.ZipFile') | Out-Null
 				[System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem') | Out-Null
 				[System.Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.ZipFileExtensions') | Out-Null
 				$zipArch = [System.IO.Compression.ZipFile]::Open($targetZipPath,1) 	
 										
				foreach($vdir in $dirPathsToZip.Keys) {							
 					$expandedFullPath = $vdir
 					$zipPath = GetZipRelativePath -fullPhysicalPath $expandedFullPath -siteHomeDirectory $siteRootPhysicalPath					
					if($runningContentSize -gt $maxBytesSize) {
						Write-Output "Running content size exceeded limit";
						break;
					}
					
					# piping ForEach uses significantly less memory than foreach with index, which will hit max memory limits for large number of files
					Get-ChildItem $expandedFullPath -recurse | ForEach {
						if($_.PSIsContainer) {
							# Currently completely empty directories will be lost during the copy as they never have a CreateEntryFromFile occur							
 						} else { 
 							$runningContentSize += $_.Length	
 							if( $runningContentSize -le $maxBytesSize) {								
 								$fileRelativePath = $zipPath + $_.FullName.Substring($expandedFullPath.Length); 									
 								$a = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($ziparch, $_.FullName, $fileRelativePath)			
 							} else {
								break;
							}
 						}
					}
 				}
				
				if($localSiteConfigFile -and (Test-Path -Path $localSiteConfigFile)) {
					[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($ziparch, $localSiteConfigFile, "SiteConfig.json")
				}
					
 				$zipArch.Dispose()
			} catch {
				$errorId = "IISWebAppFailureCompressingSiteContent" 
				$errorMsg = "Exception occurred compressing site content: $($_.Exception)"
 				Write-Output "Exception zipping content: $($_.Exception)"						
				break;
 			}
 		
		} 	
 
 		if($runningContentSize -gt $maxBytesSize) { 			
			$errorId = "IISWebAppExceededMaxContentSize"
			$errorMsg = "Content size exceeded max content size (2 GB) for migration using this tool."
 		} 
 		       
 		break;
    }        

	if(-not $siteMatchFound) {
		$errorId = "IISWebAppNotFoundOnServer"
		$errorMsg = "Web application with name '$targetSiteName' not found on web server"
	}
  	
	Write-Output "targetZipPath: '$targetZipPath', ErrorId: '$errorId', ErrorOccurred: '$errorMsg'"

	$ServerInfo = New-Object -TypeName PSObject 
	$ServerInfo | Add-Member -MemberType NoteProperty -Name appContentZipPath -Value $targetZipPath		
 	 
 	if($errorId) {
		$errorObj = New-Object -TypeName PSObject
 		$errorObj | Add-Member -MemberType NoteProperty -Name code -Value $errorId
		if($errorMsg){
			$errorObj | Add-Member -MemberType NoteProperty -Name message -Value $errorMsg
		}		
		$ServerInfo | Add-Member -MemberType NoteProperty -Name error -Value $errorObj 	
	}  

	$ServerInfo | ConvertTo-Json -depth 5 | Write-Output
 }

 function GetErrorInfoObjFromException {
	param($errorId, $exception )
	
	$hresultString = "";
	if($exception.HResult) {
		$hresultString = $exception.HResult.ToString("X");
	}	
	$errorObject = New-Object -TypeName PSObject
	$errorObject | Add-Member -MemberType NoteProperty -Name code -Value $errorId
    $errorObject | Add-Member -MemberType NoteProperty -Name message -Value "$($exception.Message), HResult: $hresultString"	
	return $errorObject
}


$ErrorActionPreference = "Stop"; #Make all errors terminating
$ServerInfo = New-Object -TypeName PSObject
$errorObj = $null
try {
	# first confirm this is PS4.0+ version 
	if($PSVersionTable.PSVersion.Major -lt 4) {
	    Write-Output "PowerShell version too low!"
		Write-Output '{"appContentZipPath": "","error": {"code": "IISWebServerPowerShellVersionLessThan4","message":"PowerShell version on IIS web server was less than minimum required PowerShell version 4"} }'
		exit
	} else {
		#LoadMWH
		$iisInstallPath = [System.Environment]::ExpandEnvironmentVariables("%windir%\system32\inetsrv\Microsoft.Web.Administration.dll");
		[System.Reflection.Assembly]::LoadFrom($iisInstallPath) | Out-Null; 	

		try {
			GetContentPathsAndZip  				
		}  catch [System.Security.SecurityException] {    
			$errorObj = GetErrorInfoObjFromException -errorId "IISWebServerAccessFailedError" -exception $_.Exception			    
		} catch [System.Management.Automation.MethodInvocationException] {    		
			$errorObj = GetErrorInfoObjFromException -errorId "IISWebAppMigrationError" -exception $_.Exception		
		}
	}
}
catch [System.IO.FileNotFoundException] {    
	$errorObj = GetErrorInfoObjFromException -errorId "IISWebServerIISNotFoundError" -exception $_.Exception	
} catch [System.Security.SecurityException] {    
	$errorObj = GetErrorInfoObjFromException -errorId "IISWebServerAccessFailedError" -exception $_.Exception 	
} catch [System.Management.Automation.MethodInvocationException] {    
	# this can occur due to file access issues, including on apphost or redirection config
	$errorObj = GetErrorInfoObjFromException -errorId "IISWebServerAccessFailedError" -exception $_.Exception	
} catch {	
	$errorObj = GetErrorInfoObjFromException -errorId "IISWebServerPowerShellError" -exception $_.Exception	
}finally{
	if($errorObj){		  
		$ServerInfo | Add-Member -MemberType NoteProperty -Name error -Value $errorObj 
		$ServerInfo | ConvertTo-Json -depth 5 | Write-Output				
	} 

   $ErrorActionPreference = "Continue"; #Reset the error action pref to default
}


# SIG # Begin signature block
# MIIjhAYJKoZIhvcNAQcCoIIjdTCCI3ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCOiXY5RdNhFUIh
# aG7WjUsHP7aX1PNNxHMyzv2Lao0UDqCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWTCCFVUCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgQrWDPzc2
# j+9lEd5uKh8WE1BlBeQ89Rf55gtDuN9vEocwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCB3ab0fqhEwDgZJuwW88a5N/jctDcVXzz3MfOxPhD9
# HOPA3XAViyKakD1hY/4fjgij7jvmpns//pYmhB9dyxpxs9YvdHXbk+zvZj67qt6A
# AMpkwdDixJ35q0mGxlWHKcsqowc1gJ2MSjTGcp9/4Slu388fW4KByj+kg1w/Ks8Z
# cGUqbiCFUrjgEUsKC/l6kHHP4f5hjmRARSCXkOBNyJPcGO2RF7tmlfweiwwT4Bxy
# U5FV1xzKipUbiCyU5Eex77EJdp/Tedp6HldQpg+ZJinVKrhFxMdlVnnWUbN6/6PK
# gdsj8AQWjw9viqbaAVxej0p5xLaK+fS/3DRwmUmgR73EoYIS4zCCEt8GCisGAQQB
# gjcDAwExghLPMIISywYJKoZIhvcNAQcCoIISvDCCErgCAQMxDzANBglghkgBZQME
# AgEFADCCAVAGCyqGSIb3DQEJEAEEoIIBPwSCATswggE3AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIKYzomcP4F6mPnCXp7Xvk+HcH/CFdFsg6oyank0y
# D5MlAgZg+YRQndUYEjIwMjEwNzIyMTcxNjQ2Ljk5WjAEgAIB9KCB0KSBzTCByjEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWlj
# cm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046RUFDRS1FMzE2LUM5MUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2Wggg47MIIE8TCCA9mgAwIBAgITMwAAAUzFTMHQ228/sgAAAAABTDAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MDExMTIxODI2MDBaFw0yMjAyMTExODI2MDBaMIHKMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBP
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpFQUNFLUUzMTYtQzkx
# RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIwDQYJ
# KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMphYFHDrMe576NV7IEKD/jk37xPiaTj
# ee2zK3XP+qUJpBVMY2ICxaRRhy1Cnyf/5vWRpn33Bk9xbGegnpbkoL880bNpSZ6u
# WcpzSgFBOdmNUrTBt96RWXaPY7ktUMBZEWviSf3yCV2IXgWYAQFuZ9ssQ9Ygjpo1
# pvUrtaoUwAjiaM436UCU9fW1D+kcEH05m4hucWbE8JW+O9b3bletiv78n+fC6oKk
# 6aSQRRFL4OJiovS+ib175G6pSf9wDRk9X3kO661OtCcrHZAfwe2MHXDP4eZfGRks
# A/IvvrLFNcajI7It6Tx+onDyR5igRi+kCJoTG0YUGC1UMjCK05WtDrsCAwEAAaOC
# ARswggEXMB0GA1UdDgQWBBQBlh6nBApe5yeVQgGA9BBH3mb6fDAfBgNVHSMEGDAW
# gBTVYzpcijGQ80N7fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8v
# Y3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0Ff
# MjAxMC0wNy0wMS5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBDQV8yMDEw
# LTA3LTAxLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0G
# CSqGSIb3DQEBCwUAA4IBAQBPBOSw99ZDrqiAYq9362Z3HYhBhoSXvMeICG9xw7rl
# p8hAtmiSHPIAcM74xkfYZndBf1ZQ5unU5YmV+/PG/Qu7NX8ZKgkcsNW8UPAnVbTp
# R+vNmf//kXdiDJP3b8U7nMzZ05peRKMV4vUOEYD6+ww8HNSSBEjRVfaESBLZ3opj
# Poxzayaop+WXU5ZWtloml3oLrnum1sicTVqw30mM2jY/wJJH/bK4bTRzzv7t7n18
# gB/+XC/YR/j2+tIuntj0xL0QUFG0XuBAL+6zLSCtJR36q0hP/77Zsk0txL95mNcr
# RfRQJy4xT5lkGIZXbAyEQg51BG5aomVO/1+05vrtz8prMIIGcTCCBFmgAwIBAgIK
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
# j950iEkSoYICzTCCAjYCAQEwgfihgdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9w
# ZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkVBQ0UtRTMxNi1DOTFE
# MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYF
# Kw4DAhoDFQA9mVtOCSgTYnYdGM1jKASXGuD3oKCBgzCBgKR+MHwxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5KQCzzAiGA8yMDIx
# MDcyMjIyNDQzMVoYDzIwMjEwNzIzMjI0NDMxWjB2MDwGCisGAQQBhFkKBAExLjAs
# MAoCBQDkpALPAgEAMAkCAQACAVUCAf8wBwIBAAICER0wCgIFAOSlVE8CAQAwNgYK
# KwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQAC
# AwGGoDANBgkqhkiG9w0BAQUFAAOBgQCgCYm7Ci4Ez06UvAeZVJy/lFN/qGpH/a2i
# vlTE+svpG6+53U+rfTIwXwWWLuiZ0PlTcCY2NHh5ebBoEYAYWkg7suqvP2nOmKWz
# 3ab/9t+ibosNa/Yf0PhBJTEfBOY1YVxdC/A+r1UZ+Kor0OlRwzjUxhkId/G3ln+2
# s6h3Fs8amDGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAy
# MDEwAhMzAAABTMVMwdDbbz+yAAAAAAFMMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkq
# hkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIGMp7a09XNS+
# aMl5VEXsGCKbGmecyLaapX+dq7rqxb+oMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB
# 5DCBvQQg28Klu79QSzLREEwg4fpPCy2GU33T+3PZrxBiZ8SvTiUwgZgwgYCkfjB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAUzFTMHQ228/sgAAAAAB
# TDAiBCCoPxMabqe288BxCGvZmkyGX8dW9kTk2uwMRAnQCGTGDDANBgkqhkiG9w0B
# AQsFAASCAQC3Ioh+tBJ7twQHTFclrUeqGbrE5SI/ld2L1y8PHcod/kazmfDRc4yK
# imyR7hBi+GbLwNZq4LZfYpL+D2SP8qEy1xk0MoUcp0xRXS0NYlOK0NqKSFbok7Pr
# Pqv14Z8+EtzGVtT2yZwZ8R4Fb7cni7f2DfYvi7jX1uSI5wK5ajTMhwZtRLMcNdrI
# miXNZOCzzGSzXTpFx/CqAa1jUqh4+p8Ank96T/tMwVyAkyogYAyB+by4wZfVJaGY
# 9v+TGtBqtuMjuJmYJCi2IOShkQ3TwzRR1LXqfKrnBrAu8I3FC5a+80SLHXLC8pVS
# gkAqnOwe8Yj+QHkpe88okUdH8bOi/Q25
# SIG # End signature block
