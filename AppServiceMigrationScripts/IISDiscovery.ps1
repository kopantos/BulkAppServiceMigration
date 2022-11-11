function GetConfigPaths {
    $sm = New-Object Microsoft.Web.Administration.ServerManager; 
    $Config = $sm.GetApplicationHostConfiguration();
    $configPathsSection = $Config.GetSection("configPaths")   
    $allPaths = @();	
    foreach($configElement in $configPathsSection.GetCollection()) {	
        $pathValue =  $configElement['path'];
		$locationPath = $configElement['locationPath'];
        $configRelativePath = "/";
        $siteName = "";
        $relativeSiteConfigPath = "";
		$heirarchyIndex = 2; # 0 = APPHOST, 1 = APPHOST with site root Location, 2 = site root web.config, 3 = anything lower
        $configError = "";
        if($pathValue.StartsWith("MACHINE/WEBROOT/APPHOST/")) { 
            $configRelativePath = $pathValue.Substring(23);
            $sitePartialPath = $pathValue.Substring(24);
            if($sitePartialPath.Contains("/")) {
				$heirarchyIndex = 3;
                $relativeSiteConfigPath = $sitePartialPath.Substring($sitePartialPath.IndexOf('/'));
                $sitePartialPath = $sitePartialPath.Substring(0, $sitePartialPath.IndexOf('/'));            
            }        
            $siteName = $sitePartialPath;                 
        } elseif ( -not ([string]::IsNullOrEmpty($locationPath))) { 
			$heirarchyIndex = 1;   
			$siteName = $locationPath;
            if($locationPath.Contains("/")) {                
				$heirarchyIndex = 3;
                $siteName = $locationPath.Substring(0, $locationPath.IndexOf('/'));   				
            }                    
		} else {
			$heirarchyIndex = 0;
		}

		$pathConfigObject = $null;
		$sections = @{}

		$configElementCollection = $configElement.GetCollection();
		if ($configElementCollection.Count -lt 1 -and $siteName -ne "") {		

			$configError = "Configuration path contains no sections. This can be due to issues such as invalid configuration or permissions.";
			# no sections in config indicates an issue with reading config - try to get more specific error with GetWebConfiguration                
            try {
               if($siteName -ne "" -and $siteName -ne "/") {
                   $BadConfig = $sm.GetWebConfiguration($siteName, $relativeSiteConfigPath);
                   $root = $BadConfig.RootSectionGroup; #this should throw
               }
            }
            catch
            {
				$configError = GetConfigErrorFromException -exception $_.Exception -configPath $configRelativePath -location $locationPath	
            }
        } else {			
			[array]$sectionsInConfig = $configElementCollection | Select -ExpandProperty RawAttributes | ForEach-Object {$_.name}
			$additionalSectionsToGet = $null;			
			if($pathValue -eq "MACHINE/WEBROOT/APPHOST") {		
				$pathConfigObject = $Config;
				if($heirarchyIndex -eq 0) {
					$additionalSectionsToGet = @("system.applicationHost/sites", "system.webServer/globalModules")
				}
			} else {
				$pathConfigObject = $sm.GetWebConfiguration($siteName, $relativeSiteConfigPath);   
			}
			$sections = GetConfigSections -Config $pathConfigObject -locationPath $locationPath -configPath $configRelativePath -sectionsInConfig $sectionsInConfig -additionalSections $additionalSectionsToGet			
		}				
		
    
        if($pathvalue -ne "") {            
            $newPath = New-Object -TypeName PSObject
            $newPath | Add-Member -MemberType NoteProperty -Name path -Value $pathValue
            $newPath | Add-Member -MemberType NoteProperty -Name locationPath -Value $locationPath
            $newPath | Add-Member -MemberType NoteProperty -Name configPath -Value $configRelativePath
            $newPath | Add-Member -MemberType NoteProperty -Name site -Value $siteName
            $newPath | Add-Member -MemberType NoteProperty -Name relativeSitePath -Value $relativeSiteConfigPath
			$newPath | Add-Member -MemberType NoteProperty -Name config -Value $pathConfigObject
			$newPath | Add-Member -MemberType NoteProperty -Name sections -Value $sections
			$newPath | Add-Member -MemberType NoteProperty -Name heirarchyIndex -Value $heirarchyIndex
            $newPath | Add-Member -MemberType NoteProperty -Name configError -Value $configError
            $allPaths += $newPath  
        }   
    }

$allPaths  
}

function GetConfigSections {
    param( $Config, $locationPath, $configPath, $sectionsInConfig, $additionalSections)
	
	$configSections = @{};
	$sectionNamesOfInterest = @{};
   
	$defaultSections = @("system.webServer/handlers", "system.webServer/isapiFilters", "system.webServer/httpPlatform",
		"system.webServer/security/authentication/basicAuthentication",
		"system.webServer/security/authentication/clientCertificateMappingAuthentication", 
		"system.webServer/security/authentication/iisClientCertificateMappingAuthentication", 
		"system.webServer/security/authentication/digestAuthentication",
		"system.webServer/security/authentication/windowsAuthentication");

	if($additionalSections) {
		$defaultSections += $additionalSections
	}		

	foreach($section in $defaultSections) {
		if($sectionsInConfig -contains $section) {
			$sectionNamesOfInterest.Add($section, "");
		}
	}
    	
	foreach($sectionPath in $sectionNamesOfInterest.Keys) {    	   
        try {
            $configSectionOfInterest = $Config.GetSection($sectionPath, $locationPath);
			$retVal = @{"section"=$configSectionOfInterest;"isValid"=$true}
			$configSections.Add($sectionPath, $retVal);
		} catch {			           
			$configErrorString = GetConfigErrorFromException -exception $_.Exception -configPath $configPath -location $locationPath -configSection $sectionPath
			$configError = @{"isValid"=$false;"configError"=$configErrorString}			
			$configSections.Add($sectionPath, $configError)
		}
	}		
	$configSections;
}

function GetConfigErrorFromException {
	param( $exception, $configPath, $location, $configSection )
	
	$combinedString = "message=$($exception.Message)"
	if($exception.HResult) {
		$hresultString = $exception.HResult.ToString("X");
		$combinedString = "$combinedString;hresult=$hresultString"
	}	
	if($configPath) {
		$combinedString ="$combinedString;path=$configPath"
	}
	if($location) {
		$combinedString ="$combinedString;location=$location"
	}
	if($configSection) {
		$combinedString ="$combinedString;sectionName=$configSection"
	}

	$combinedString
}

function GetConfigErrorInfoObj {
	param($errorId, $exception, $message )

	if(-not $message) {
		if($exception) {
			$message = $exception.Message;
		} else { $message = "" }
	}

	$errorObject = New-Object -TypeName PSObject
	$errorObject | Add-Member -MemberType NoteProperty -Name errorId -Value $errorId
    $errorObject | Add-Member -MemberType NoteProperty -Name detailedMessage -Value $message
	$errorObject | Add-Member -MemberType NoteProperty -Name hResult -Value ""
	$errorObject | Add-Member -MemberType NoteProperty -Name stackTrace -Value ""
	$errorObject | Add-Member -MemberType NoteProperty -Name exceptionType -Value ""
			
	if($exception) {
		if($exception.HResult) {
			$errorObject.hResult = $exception.HResult.ToString("X");
		}	
		$errorObject.stackTrace = $exception.Stacktrace
		$errorObject.exceptionType = $exception.GetType().fullname
	}
	
	return $errorObject
}

function GetApplicationPools {
    $sm = New-Object Microsoft.Web.Administration.ServerManager; 
    $Config = $sm.GetApplicationHostConfiguration();
    $appPoolSection = $Config.GetSection("system.applicationHost/applicationPools")   
    
	$appPools = @{};
    foreach($appPool in $appPoolSection.GetCollection()) {	
		if(-not($appPools.ContainsKey($appPool['name']))) {
			$poolProperties = @{			
				"enable32BitAppOnWin64" = $appPool['enable32BitAppOnWin64'];
				"managedRuntimeVersion" = $appPool['managedRuntimeVersion'];
				"managedPipelineMode" = $appPool['managedPipelineMode'];
				"identityType" = $appPool.GetChildElement('processModel')['identityType']; #is an ENUM value
			}
			$appPools.Add($appPool['name'], $poolProperties);  
		}
    }
	$appPools 
}	

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

function AppendFailCheckDetail {
    param([string] $newDetails, $prevCheckResults)  
    if($newDetails -eq $null) { $newDetails = ""}	
	$prevCheckResults.detailsString += $newDetails;
	$prevCheckResults.result = "Fail";
    return $prevCheckResults
} 

function AppendFailCheckResults {
    param([string] $newDetails, [string] $newLocation, $prevCheckResults)  
    if($newDetails -eq $null) { $newDetails = ""}
	if($newLocation -eq $null) { $newLocation = ""}
	$newDetail = New-Object -TypeName PSObject
    $newDetail | Add-Member -MemberType NoteProperty -Name location -Value $newLocation			  
    $newDetail | Add-Member -MemberType NoteProperty -Name detail -Value $newDetails
	$prevCheckResults.detailsArray += $newDetail;
	$prevCheckResults.result = "Fail";
    return $prevCheckResults
} 

function CondenseDetailsArrayToString {
	param($CheckResults)  
    $detailString = "";
	foreach($d in $CheckResults.detailsArray) {		
		if($d.location -ne $null -and $d.location -ne "") {
			$detailString = "$detailString$($d.detail) ($($d.location)), "
		} else {
			$detailString = "$detailString$($d.detail), ";
		}
	}
	if($detailString.EndsWith(', ')) {
		$detailString = $detailString.Substring(0, $detailString.Length-2)
	}	
	$CheckResults.detailsString += $detailString;	
	$CheckResults.PSObject.Properties.Remove('detailsArray')
    $CheckResults
}
        
function DiscoverAndAssess {
	param($configPaths, $appPoolSettings, $webServerBase)

	$appHostConfigPathObject = $configPaths | Where-Object {$_.path -eq "MACHINE/WEBROOT/APPHOST" -and $_.locationPath -eq ""} | Select-Object -First 1	

    $allSites = @();
    $SitesSection = $appHostConfigPathObject.sections["system.applicationHost/sites"].section; 
	#TODO: check that $appHostConfigPathObject.sections["system.applicationHost/sites"].isValid -eq true or fail here, and non null

	# # PS VERSION CHECK FOR MIGRATION
	# $psVersionCheck = [pscustomobject]@{IssueId="PSVersionCheck";result="Pass";detailsString=""};
	# try {
	# 	$majorVersion = $PSVersionTable.PSVersion.Major
	# 	if($majorVersion -lt 4) {							
	# 		$psVersionCheck = AppendFailCheckDetail -prevCheckResults $psVersionCheck -newDetails "$majorVersion"
	# 	} 		
	# } catch {	
	#     $psVersionCheck = AppendFailCheckDetail -prevCheckResults $psVersionCheck -newDetails "Failed to determine version"
	# }

    foreach($siteSection in $SitesSection.GetCollection()) {          
		$siteName = $siteSection['name'];		
        $newSite = New-Object -TypeName PSObject
        $newSite | Add-Member -MemberType NoteProperty -Name webAppName -Value $siteName
		
		#default pass check objects
		$configErrorCheck = [pscustomobject]@{IssueId="ConfigErrorCheck";result="Pass";detailsString="";detailsArray=@()};
		$httpsBindingCheck = [pscustomobject]@{IssueId="HttpsBindingCheck";result="Pass";detailsString=""};
		$protocolCheck = [pscustomobject]@{IssueId="ProtocolCheck";result="Pass";detailsString=""};
		$tcpPortCheck = [pscustomobject]@{IssueId="TcpPortCheck";result="Pass";detailsString=""};		
		$locationTagCheck = [pscustomobject]@{IssueId="LocationTagCheck";result="Pass";detailsString=""};	
		$appPoolCheck = [pscustomobject]@{IssueId="AppPoolCheck";result="Pass";detailsString=""};
		$appPoolIdentityCheck = [pscustomobject]@{IssueId="AppPoolIdentityCheck";result="Pass";detailsString=""};
		$virtualDirectoryCheck = [pscustomobject]@{IssueId="VirtualDirectoryCheck";result="Pass";detailsString=""};		
		$contentSizeCheck = [pscustomobject]@{IssueId="ContentSizeCheck";result="Pass";detailsString=""};	
		$globalModuleCheck = [pscustomobject]@{IssueId="GlobalModuleCheck";result="Pass";detailsString=""};
	
		#Add binding information (including binding-related check results)
		$bindings = @();						
		$failedProtocols = @{};
		$failedPorts = @{};
		foreach($binding in $siteSection.ChildElements['bindings']) { 
			$bindingInfo = $binding['bindingInformation'];									
			$protocol = $binding['protocol'].ToLower();
			$port = "";
			$ipAddress = "";
			$hostName = "";
			if($protocol -eq "http" -or $protocol -eq "https" -or $protocol -eq "ftp") {				
				$ipAndPort = $bindingInfo.Substring(0,$bindingInfo.LastIndexOf(':'))
				$ipAddress = $ipAndPort.Substring(0,$ipAndPort.LastIndexOf(':'))
				$port = $ipAndPort.SubString($ipAndPort.LastIndexOf(':')+1)
				$hostName = $bindingInfo.Substring($bindingInfo.LastIndexOf(':')+1)
			}
						
            $newBinding = New-Object -TypeName PSObject		
            $newBinding | Add-Member -MemberType NoteProperty -Name protocol -Value $protocol			              
			$newBinding | Add-Member -MemberType NoteProperty -Name ipAddress -Value $ipAddress
            $newBinding | Add-Member -MemberType NoteProperty -Name port -Value $port
            $newBinding | Add-Member -MemberType NoteProperty -Name hostName -Value $hostName            
            $bindings += $newBinding 
			if($protocol -eq 'https') {				
				$httpsBindingCheck.result = "Warn"
			}
			if ($protocol -ne "http" -and $protocol -ne "https") {								
				if (-not $failedProtocols.ContainsKey($protocol)) { $failedProtocols.Add($protocol,0) }				
			}
			if($port -ne "80" -and $port -ne "443" -and $port -ne "") {
				if (-not $failedPorts.ContainsKey($port)) { $failedPorts.Add($port,0) }				
			}
		}
		$newSite | Add-Member -MemberType NoteProperty -Name bindings -Value $bindings	
		if($failedProtocols.Count -gt 0) {
			$protocolCheck = AppendFailCheckDetail -newDetails "$($failedProtocols.Keys -join ', ')" -prevCheckResults $protocolCheck 			
		}
		if($failedPorts.Count -gt 0) {			
			$tcpPortCheck.result = "Warn";
			$tcpPortCheck.detailsString = "$($failedPorts.Keys -join ', ')"
		}

		# Application Pool information including virtual directories and app pool-based check results
		$appPools = @();	
		$virtualApplications=@();
		$appPoolNames = @{};
		$uncPaths = @{};		
		$errorOccurredGettingContentSize = $false;
		$unsupportedIdentityTypes = @{};
		$dirPathsToZip = @{};

		$siteRootVDir = ($siteSection.GetCollection() | Where-Object {$_['path'] -eq '/'}).GetCollection() | Where-Object {$_['path'] -eq '/'}
 		$siteRootPhysicalPath = [System.Environment]::ExpandEnvironmentVariables($siteRootVDir['physicalPath'])

		foreach($appPool in $siteSection.GetCollection()) {	
		
			$appRootVPath = $appPool['path'];
			$appRootZipPath = "";
			$vdirsForAppConfig = @();

			$vDirs = @();			
			foreach($vdir in $appPool.GetCollection()) {							
				$expandedFullPath = [System.Environment]::ExpandEnvironmentVariables($vdir['physicalPath']);
				$vdirInfo = @{"path"=$vdir['path'];"physicalPath"=$expandedFullPath;"sizeInBytes"=0}
				if($vdir['physicalPath'].StartsWith("\\") -and (-not($vdir['physicalPath'].StartsWith("\\?\")) -or $vdir['physicalPath'].StartsWith("\\?\UNC\"))){															
					if(-not($uncPaths.ContainsKey($vdir['path']))) {
						$uncPaths.Add($vdir['path'], "");
					}	
					$errorOccurredGettingContentSize = $true
				} else {
					try {	
						$vdirSize = 0;
						# piping ForEach uses significantly less memory than foreach with index, which will hit max memory limits for large number of files
						Get-ChildItem $expandedFullPath -recurse | ForEach {
							if(-not $_.PSIsContainer) {								
								$vdirSize += $_.Length 																
 							}
						}						
						$vdirInfo.sizeInBytes += $vdirSize;
					} catch {
						$errorOccurredGettingContentSize = $true
					}

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
				$vDirs += $vdirInfo; 
				
				#virtual directory config creation
				$vdirZipPath = GetZipRelativePath -fullPhysicalPath $expandedFullPath -siteHomeDirectory $siteRootPhysicalPath	
				
                if ($vdir['path'] -eq "/")
                {
                     $appRootZipPath = $vdirZipPath;
                }
                else
                {
					$newAppServiceVDir = New-Object -TypeName PSObject
					$newAppServiceVDir | Add-Member NoteProperty -Name virtualPath -Value $vdir['path']
					$newAppServiceVDir | Add-Member NoteProperty -Name physicalPath -Value $vdirZipPath							
                    $vdirsForAppConfig += $newAppServiceVDir                            
                }
			}			
			
			$appPoolName = $appPool['applicationPool'];
			$appPoolInfo = $appPoolSettings[$appPoolName];
			
			$newAppPool = New-Object -TypeName PSObject
			$newAppPool | Add-Member -MemberType NoteProperty -Name path -Value $appPool['path']
			$newAppPool | Add-Member -MemberType NoteProperty -Name applicationPool -Value $appPoolName
			$newAppPool | Add-Member -MemberType NoteProperty -Name enable32BitAppOnWin64 -Value $appPoolInfo.enable32BitAppOnWin64
			$newAppPool | Add-Member -MemberType NoteProperty -Name managedRuntimeVersion -Value $appPoolInfo.managedRuntimeVersion			
			$pipelineModeString = "Integrated";
			if($appPoolInfo.managedPipelineMode -eq 1) { $pipelineModeString = "Classic" }
			$newAppPool | Add-Member -MemberType NoteProperty -Name managedPipelineMode -Value $pipelineModeString			
			$newAppPool | Add-Member -MemberType NoteProperty -Name vdirs -Value $vDirs			
			$appPools += $newAppPool
			if(-not($appPoolNames.ContainsKey($appPoolName))){
				$appPoolNames.Add($appPoolName, "");
			}
			# 0 = LocalSystem; 1=LocalService; 2=NetworkService; 3=SpecificUser; 4=ApplicationPoolIdentity
			if( $appPoolInfo.identityType -ne 4 -and $appPoolInfo.identityType -ne 2 -and $appPoolInfo.identityType -ne 1 ) {
				if(-not($unsupportedIdentityTypes.ContainsKey($appPoolName))) {
					$poolIdentityTypeName = "Unknown Type $($appPoolInfo.identityType)"
					if($appPoolInfo.identityType -eq 3) { $poolIdentityTypeName = "SpecificUser" } 
					if($appPoolInfo.identityType -eq 0) { $poolIdentityTypeName = "LocalSystem" }				
					$unsupportedIdentityTypes.Add($appPoolName, $poolIdentityTypeName);
				}
			}	
			
			$newVirtualApplication = New-Object -TypeName PSObject
			$newVirtualApplication | Add-Member -MemberType NoteProperty -Name virtualPath -Value $appRootVPath
			$newVirtualApplication | Add-Member -MemberType NoteProperty -Name physicalPath -Value $appRootZipPath
			$newVirtualApplication | Add-Member -MemberType NoteProperty -Name virtualDirectories -Value $vdirsForAppConfig			
			$virtualApplications += $newVirtualApplication
		}		
		$newSite  | Add-Member -MemberType NoteProperty -Name applications -Value $appPools	
		$newSite  | Add-Member -MemberType NoteProperty -Name virtualApplications -Value $virtualApplications	
		
		# VIRTUAL DIRECTORIES CHECK 
		if($uncPaths.Count -gt 0) {
			$virtualDirectoryCheck = AppendFailCheckDetail -newDetails "$($uncPaths.Keys -join ', ')" -prevCheckResults $virtualDirectoryCheck 
		}

		# MAX CONTENT SIZE CHECK
		$runningContentSize = 0;
		$maxBytesSize = 2 * 1024 * 1024 * 1024; # 2GB	
        if(-not $errorOccurredGettingContentSize) {
		    foreach($vdir in $dirPathsToZip.Keys) {	
				$vdirMatch = $null;
				foreach($app in $appPools) {
					$vdirMatch = $app.vdirs | Where-Object {$_.physicalPath -eq $vdir}
					if($vdirMatch) { break; }
				}		    	
		    	if($vdirMatch) {
                    $runningContentSize += $vdirMatch.sizeInBytes
                    if($runningContentSize -gt $maxBytesSize) {
		    		    break;
		    	    }
                } else {
                    $errorOccurredGettingContentSize = $true;
                } 			
 		    }
        }

		if( $runningContentSize -gt $maxBytesSize) {
			$contentSizeCheck = AppendFailCheckDetail -newDetails "$runningContentSize" -prevCheckResults $contentSizeCheck
		} elseif ($errorOccurredGettingContentSize) {
			# this occurs in cases like if unable to read directory size and/or UNC shares, probable issue for migration time
			$contentSizeCheck.IssueId = "ContentSizeCheckUnknown"
			$contentSizeCheck.result = "Unknown";
		}
		
		# MULTIPLE APP POOL CHECK
		if($appPoolNames.Count -gt 1) {
			$appPoolCheck = AppendFailCheckDetail -newDetails "$($appPoolNames.Keys -join ', ')" -prevCheckResults $appPoolCheck 			
		}
		# APP POOL IDENTITY CHECK
		if($unsupportedIdentityTypes.Count -gt 0) {			
			$detailString = "";
			foreach($key in $unsupportedIdentityTypes.keys) {
				$detailString = "$detailString$($unsupportedIdentityTypes[$key]) ($key), "								
			}	
			if($detailString.EndsWith(', ')) {
				$detailString = $detailString.Substring(0, $detailString.Length-2)
			}
			$appPoolIdentityCheck = AppendFailCheckDetail -newDetails $detailString -prevCheckResults $appPoolIdentityCheck 						
		}			
				 
		# CONFIG ERRORS		
		[array]$siteConfigPaths = $configPaths | Where-Object {$_.site -eq $siteName}          	
		# in PowerShell 2.0 foreach on a $null object still does a first iteration $null item
		if($siteConfigPaths -ne $null) {
			foreach($configPathObject in $siteConfigPaths) {
				if($configPathObject.configError -ne "") {
					$configErrorCheck = AppendFailCheckResults -newDetails $configPathObject.configError -newLocation $configPathObject.configPath -prevCheckResults $configErrorCheck 
				}
				foreach($sectionkey in $configPathObject.sections.Keys) {			
					if(-not $configPathObject.sections[$sectionKey].isValid) {
						$sectionError =  $configPathObject.sections[$sectionKey].configError
						if(-not $sectionError) {
							$locationPathPart = ""
							if($configPathObject.locationPath -ne "") {
								$locationPathPart = ";location=$($configPathObject.locationPath)"
							}
							$sectionError = "message=Error with config section;path=$($configPathObject.configPath)$locationPathPart;sectionName=$sectionKey"
							
						}
						$configErrorCheck = AppendFailCheckResults -newDetails $sectionError -prevCheckResults $configErrorCheck
					}			
				}
			}
		}
		# TODO: apphost level config errors not getting added to above configErrorCheck
		$siteConfigPaths += $appHostConfigPathObject 

		# LOCATION TAG CHECK
		[array]$locationTags = $siteConfigPaths | Where-Object {$_.locationPath -ne "" -and $_.configPath -eq "/" } | Select -ExpandProperty locationPath			
		if($locationTags.Count -gt 0) {						
			$locationTagCheck = AppendFailCheckDetail -newDetails  "$($locationTags -join ', ')"  -prevCheckResults $locationTagCheck			
		}
		
		# GLOBAL MODULES CHECK
		$unsupportedModules = GetUnsupportedGlobalModules -appHostGlobalModulesSection $appHostConfigPathObject.sections["system.webServer/globalModules"]
		if($unsupportedModules.Count -gt 0) {			
			$globalModuleCheck = AppendFailCheckDetail -newDetails "$($unsupportedModules.Keys -join ', ')" -prevCheckResults $globalModuleCheck
		}
		
		$checksScaffolding = @([pscustomobject]@{IssueId="IsapiFilterCheck";result="Pass";detailsString=""},          
							 [pscustomobject]@{IssueId="AuthCheck";result="Pass";detailsString=""},
							 [pscustomobject]@{IssueId="FrameworkCheck";result="Pass";detailsString=""});
		$appHostLevelChecks = @($configErrorCheck, $httpsBindingCheck, $protocolCheck, $TcpPortCheck, $appPoolCheck, $appPoolIdentityCheck, $locationTagCheck, $globalModuleCheck, $virtualDirectoryCheck, $contentSizeCheck); 
		$checksScaffolding += $appHostLevelChecks;
        		
        $newSite | Add-Member -MemberType NoteProperty -Name configPaths -Value $siteConfigPaths				
        $newSite | Add-Member -MemberType NoteProperty -Name checks -Value $checksScaffolding        

        $allSites += $newSite
    }        

    foreach($site in $allSites) {
		#framework determination	
		# ORDER OF PRECEDENCE if multiple detected: PYTHON > NODE > JAVA > .NET Core > PHP > .NET
		$discoveredFrameworks = @();
		
		#.NET (DEFAULT)
		$dotnetFName = ".NET"
		$rootAppPoolNetFxVersion = ($site.applications | Where-Object {$_.path -eq "/"} | Select-Object -Property managedRuntimeVersion).managedRuntimeVersion		
		$netFx = New-Object -TypeName PSObject
        $netFx | Add-Member -MemberType NoteProperty -Name framework -Value $dotnetFName			  
        $netFx | Add-Member -MemberType NoteProperty -Name version -Value $rootAppPoolNetFxVersion
        $discoveredFrameworks += $netFx 		
		$fx = $dotnetFName;
		$fxVer = $rootAppPoolNetFxVersion;		
		
		[array]$sections = ($site.configPaths | Where-Object {$_.config -ne $null -and $_.configError -eq ""} |  Select-Object -Property sections).sections  		
		#PYTHON		
		$possiblePythonHandlers = GetMatchingHandlersForSite -appHostGlobalModulesSection $appHostConfigPathObject.sections["system.webServer/globalModules"] -siteConfigPaths $site.configPaths -handlerFileNames @("cgi.dll", "iisfcgi.dll");
		$matchingPyProcessors = $possiblePythonHandlers.Values | Where-Object {$_.ToLower().EndsWith("python.exe") -or $_.ToLower().EndsWith(".py")}
		if($matchingPyProcessors.Count -gt 0) {						
			$pyFx = New-Object -TypeName PSObject
            $pyFx | Add-Member -MemberType NoteProperty -Name framework -Value "PYTHON"			  
            $pyFx | Add-Member -MemberType NoteProperty -Name version -Value ""          
            $discoveredFrameworks += $pyFx 
			if($fx -eq $dotnetFName){				
				$fx = $pyFx.framework
				$fxVer = $pyFx.version
			}						
		}			
		#NODE
		$nodeHandlers = GetMatchingHandlersForSite -appHostGlobalModulesSection $appHostConfigPathObject.sections["system.webServer/globalModules"] -siteConfigPaths $site.configPaths -handlerFileNames @("iisnode.dll");
		if($nodeHandlers.Count -gt 0 ) {			
			$nodeFx = New-Object -TypeName PSObject
            $nodeFx | Add-Member -MemberType NoteProperty -Name framework -Value "NODE"			  
            $nodeFx | Add-Member -MemberType NoteProperty -Name version -Value ""           
            $discoveredFrameworks += $nodeFx 
			if($fx -eq $dotnetFName){				
				$fx = $nodeFx.framework
				$fxVer = $nodeFx.version
			} 
		}

		#JAVA
		$hasJava = HasJREHOMEEnvVar -siteSections $sections		
		if($hasJava) {			
			$nodeFx = New-Object -TypeName PSObject
            $nodeFx | Add-Member -MemberType NoteProperty -Name framework -Value "JAVA"			  
            $nodeFx | Add-Member -MemberType NoteProperty -Name version -Value ""           
            $discoveredFrameworks += $nodeFx 
			if($fx -eq $dotnetFName){				
				$fx = $nodeFx.framework
				$fxVer = $nodeFx.version
			} 
		}

		#.NET Core
		$aspnetcoreHandlers = GetMatchingHandlersForSite -appHostGlobalModulesSection $appHostConfigPathObject.sections["system.webServer/globalModules"] -siteConfigPaths $site.configPaths -handlerFileNames @("aspnetcorev2.dll", "aspnetcore.dll");
		if($aspnetcoreHandlers.Count -gt 0 ) {			
			$aspnetcoreFx = New-Object -TypeName PSObject
            $aspnetcoreFx | Add-Member -MemberType NoteProperty -Name framework -Value ".NET Core"			  
            $aspnetcoreFx | Add-Member -MemberType NoteProperty -Name version -Value ""           
            $discoveredFrameworks += $aspnetcoreFx 
			if($fx -eq $dotnetFName){				
				$fx = $aspnetcoreFx.framework
				$fxVer = $aspnetcoreFx.version
			} 
		}

		#PHP
		$possiblePHPHandlers = GetMatchingHandlersForSite -appHostGlobalModulesSection $appHostConfigPathObject.sections["system.webServer/globalModules"] -siteConfigPaths $site.configPaths -handlerFileNames @("cgi.dll", "iisfcgi.dll");
		$matchingPHPProcessors = $possiblePHPHandlers.Values | Where-Object {$_.ToLower().EndsWith("php-cgi.exe") -or $_.ToLower().EndsWith("cgi.exe")}
		if($matchingPHPProcessors.Count -gt 0) {			
			$phpFx = New-Object -TypeName PSObject
            $phpFx | Add-Member -MemberType NoteProperty -Name framework -Value "PHP"			  
            $phpFx | Add-Member -MemberType NoteProperty -Name version -Value ""          
            $discoveredFrameworks += $phpFx 
			if($fx -eq $dotnetFName){				
				$fx = $phpFx.framework
				$fxVer = $phpFx.version
			}						
		}
		
		$site | Add-Member -MemberType NoteProperty -Name framework -Value $fx
		$site | Add-Member -MemberType NoteProperty -Name frameworkVersion -Value $fxVer
		$site | Add-Member -MemberType NoteProperty -Name discoveredFrameworks -Value $discoveredFrameworks
	
		$configCheck = $site.checks | Where-Object { $_.IssueId -eq "ConfigErrorCheck" } | Select-Object -First 1;
		$authCheck = $site.checks | Where-Object { $_.IssueId -eq "AuthCheck" } | Select-Object -First 1;
		$isapiCheck = $site.checks | Where-Object { $_.IssueId -eq "IsapiFilterCheck" } | Select-Object -First 1;
		$frameworkCheck = $site.checks | Where-Object {$_.IssueId -eq "FrameworkCheck" } | Select-Object -First 1;

		#FRAMEWORK CHECK						
		if($netFx.version.StartsWith("v1.")) {
			# want to warn for unsupported v1.X .NET framework usage			
			$netFx.framework = "$($netFx.framework)($($netFx.version))"
		}		
		[array]$warnFrameworks = $discoveredFrameworks | Where-Object {-not $_.framework.StartsWith($dotnetFName) -or $_.version.StartsWith("v1.")}
		if($warnFrameworks.Length -gt 0) {
			$frameworkCheck.result = "Warn";
			$frameworkCheck.detailsString = "$($warnFrameworks.framework -join ', ')"			
		}
		
		#AUTHENTICATION TYPES CHECK 
		$authCheck = GetEnabledAuthSectionsForSite -siteObject $site -authCheck $authCheck -configErrorCheck $configCheck
		#ISAPI FILTER CHECK	
		$isapiCheck = GetUnsupportedIsapiFilters -siteConfigs $site.configPaths -isapiCheck $isapiCheck -configErrorCheck $configCheck
			
		$configCheck = CondenseDetailsArrayToString -CheckResults $configCheck
		
		$migrationReadiness = "Ready";
		$numFails = 0;
		$numWarns = 0;
		$numUnknown = 0;
		foreach($check in $site.checks) {
			if($check.result -eq "Fail") {
				$numFails++;
			} elseif ($check.result -eq "Warn") {
				$numWarns++;
			} elseif ($check.result -eq "Unknown") {
				$numUnknown++;
			}
			# reset single details string to string array		
            if($check.detailsString) {	
			    $check | Add-Member NoteProperty -Name Details -Value @($check.detailsString)
			    $check.PSObject.Properties.Remove('detailsString')
            }
		}
		if($numFails -gt 0) {
			$migrationReadiness = "NotReady";
		} elseif($numUnknown -gt 0) {
			$migrationReadiness = "Unknown"; 		
		} elseif($numWarns -gt 0) {
			$migrationReadiness = "ConditionallyReady"; 
		}
		$site | Add-Member NoteProperty -Name migrationReadiness -Value $migrationReadiness

		# Passed checks are never displayed, only those with non-pass results need to be included
		[array]$site.checks = $site.checks | Where-Object {$_.result -ne "Pass"}
		if($site.checks -eq $null){
			$site.checks = @()
		}
    }
	 
	[array]$discoverySiteData = $allSites | Select-Object -Property webAppName, bindings, applications, virtualApplications, framework, frameworkVersion, discoveredFrameworks
	[array]$readinessSiteData = $allSites | Select-Object -Property webAppName, migrationReadiness, checks
	$discoveryIISSiteDataObject = New-Object -TypeName PSObject
	$discoveryIISSiteDataObject | Add-Member NoteProperty -Name IISSites -Value $discoverySiteData
	$readinessIISSiteDataObject = New-Object -TypeName PSObject
	$readinessIISSiteDataObject | Add-Member NoteProperty -Name IISSites -Value $readinessSiteData 
		 
	# populate on final output object	 
	if($discoverySiteData.Count -lt 1) {
		$errorObj = GetConfigErrorInfoObj -errorId "IISWebServerZeroWebAppsFound" -message "No websites were discovered."	
		$webServerBase | Add-Member -MemberType NoteProperty -Name error -Value $errorObj 		
	} else {
		$webServerBase | Add-Member -MemberType NoteProperty -Name discoveryData -Value $discoveryIISSiteDataObject
		$webServerBase | Add-Member -MemberType NoteProperty -Name readinessData -Value $readinessIISSiteDataObject
	}

	return $webServerBase
}

function GetWebServerBaseObject {
    $appHostConfigPath = [System.Environment]::ExpandEnvironmentVariables("%windir%\System32\inetsrv\config\applicationHost.config");
  	$IISVersion = "";
	try {	
		$sm = New-Object Microsoft.Web.Administration.ServerManager;
		$redirectionConfig = $sm.GetRedirectionConfiguration();
		$cr = $redirectionConfig.GetSection("configurationRedirection");		
		if($cr.Attributes["enabled"].Value) { 
			# redirection is enabled
			$appHostConfigPath = "$($cr.Attributes['path'].Value)applicationHost.config"
		}
	} catch {
		# Do nothing. Checking for shared config is best effort		
		# Write-Output "Failed to determine config location: $($_.Exception)"
	}

	try {
		$IISStpKey = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\InetStp
		$MajorVersion = $IISStpKey.MajorVersion
		$MinorVersion = $IISStpKey.MinorVersion
		if($MajorVersion -ne $null -and $MinorVersion -ne $null) {
			$IISVersion = "$MajorVersion.$MinorVersion"
		} elseif ($MajorVersion -ne $null) {
			$IISVersion = "$MajorVersion"
		}
	} catch {
		# Do nothing. Version discovery is best effort 
		# Write-Output "Failed to determine IIS version: $($_.Exception)"
	}
	 
  $ServerInfo = New-Object -TypeName PSObject
  $ServerInfo | Add-Member -MemberType NoteProperty -Name type -Value "IIS"
  $ServerInfo | Add-Member -MemberType NoteProperty -Name version -Value $IISVersion  
  $ServerInfo | Add-Member -MemberType NoteProperty -Name rootConfigurationLocation -Value $appHostConfigPath 
  return $ServerInfo
}

function GetEnabledAuthSectionsForSite {
    param( $siteObject, $authCheck, $configErrorCheck)
    $failedAuthTypesStringResult = ""; 
	$encounteredError = $false;

	$authTypes = @("basicAuthentication","clientCertificateMappingAuthentication", "iisClientCertificateMappingAuthentication", "digestAuthentication","windowsAuthentication");
	foreach($authType in $authTypes) {		
		$topLevelConfigResults=@{}; #heirarchIndex, Block|Allow
		$failedConfigPaths = @{};
		foreach($p in $siteObject.configPaths) {  
            $configError = "";  	
			# Below looks at effective site config (i.e. ignoring appHost settings if a root web.config exists)
            if($p.configError -eq "") {                           
				#AUTHENTICATION TYPES CHECK       										
			    try {							
					$authSection = $p.sections["system.webServer/security/authentication/$authType"];
					if($authSection) {
						if($authSection.isValid -and $authSection.section['enabled']) { 
							if($p.heirarchyIndex -lt 3) {
								if(-not $topLevelConfigResults.ContainsKey($p.heirarchyIndex)) {
									$topLevelConfigResults.Add($p.heirarchyIndex, "Block");							
								}
							} else {							
								$subpathOfExistingFailPath = $false;
								$removeKeys = @{};
								# check if current path is already represented in failedConfigPaths
								foreach($cp in $failedConfigPaths.Keys) {									
									if($p.configPath.ToLower().StartsWith($cp.ToLower())) {
										$subpathOfExistingFailPath = $true;
										break;
									} elseif ($cp.ToLower().StartsWith($p.configPath.ToLower())) {
										$removeKeys.Add($cp, "");
									}
								}
								#only add unique paths to failure message, not subpaths
								if(-not($failedConfigPaths.ContainsKey($p.configPath)) -and -not($subpathOfExistingFailPath)) {
									$failedConfigPaths.Add($p.configPath, "Block");
								}
								if($removeKeys.Count > 0) {
									foreach($k in $removeKeys.Keys) {
										$failedConfigPaths.Remove($k)
									}
								}
							}
						} elseif ($p.heirarchyIndex -lt 3 -and $authSection.isValid ) {
							if(-not $topLevelConfigResults.ContainsKey($p.heirarchyIndex)) {
								$topLevelConfigResults.Add($p.heirarchyIndex, "Allow");
							}
						} elseif (-not $authSection.isValid) {
							$encounteredError = $true							
						}
					}
			    } catch {
					$encounteredError = $true
					$errorString = GetConfigErrorFromException -exception $_.Exception -configPath $p.configPath -location $p.locationPath -configSection "security/authentication/$authType"	
					$configErrorCheck = AppendFailCheckResults $errorString -newLocation $p.configPath -prevCheckResults $configErrorCheck
			    }
			} else {
				$encounteredError = $true				
				break #bail on this authtype check - we can't tell if can't read a root-level config
			} 	
		} #end foreach config path
	
		$topBlockConfigPath = "";
		if($topLevelConfigResults.Count -gt 0 -and $topLevelConfigResults.Values -contains "Block") {
			$topBlockConfigPath = "/";
			if($topLevelConfigResults.ContainsKey(2)) {
				if($topLevelConfigResults[2] -eq "Block" -and -not($topLevelConfigResults[0] -eq "Block" -or $topLevelConfigResults[1] -eq "Block")) {
					#root web.config blocks without higher block in apphost
					$topBlockConfigPath = "/$($siteObject.webAppName)"; 			
				} elseif($topLevelConfigResults[2] -eq "Allow") {
					#allowed at site level, look at subpaths for Block configs
					$topBlockConfigPath = "";						
				}
			} elseif ($topLevelConfigResults[1] -eq "Allow") {
				#appHost global Block but appHost location tag overrides at root site level
				$topBlockConfigPath = "";
			}
		} 

		if($topBlockConfigPath -ne "") {			
			$failedAuthTypesStringResult = "$failedAuthTypesStringResult$authType ($topBlockConfigPath), "
		} elseif ($failedConfigPaths.Count -gt 0) {                            
			foreach($key in $failedConfigPaths.keys) {
				$failedAuthTypesStringResult = "$failedAuthTypesStringResult$authType ($key), "								
			}
		}
	} #end foreach authtype

	if($failedAuthTypesStringResult.EndsWith(', ')) {						
		$failedAuthTypesStringResult = $failedAuthTypesStringResult.Substring(0, $failedAuthTypesStringResult.Length-2)
	} 

	if($failedAuthTypesStringResult -ne "") {						
		$authCheck = AppendFailCheckDetail -newDetails $failedAuthTypesStringResult -prevCheckResults $authCheck		
	} elseif ($encounteredError) {
		$authCheck.IssueId = "AuthCheckUnknown";
		$authCheck.result = "Unknown"
	}
	$authCheck
}

function GetUnsupportedIsapiFilters {
    param($siteConfigs, $isapiCheck, $configErrorCheck)
    
	$unsupportedIsapiFilters = @{};
	$encounteredError = $false;
    foreach($p in $siteConfigs) {  
		$configError = "";          
		if($p.configError -eq "") {          
			try {					
				foreach($isapiSection in $p.sections["system.webServer/isapiFilters"]) {					
					if($isapiSection.isValid) {
						foreach ($filter in $isapiSection.section.GetCollection()) {
							$filterName = $filter['name'];
							if(-not($filterName.StartsWith("ASP.Net_") -or $unsupportedIsapiFilters.ContainsKey($filterName))) {
								$unsupportedIsapiFilters.Add($filterName, "")	
							}
						}						
					} else {
						$encounteredError = $true
					}
				}
			} catch {
				$encounteredError = $true								 
				$errorString = GetConfigErrorFromException -exception $_.Exception -configPath $p.configPath -location $p.locationPath -configSection "system.webServer/isapiFilters"	
				$configErrorCheck = AppendFailCheckResults $errorString -newLocation $p.configPath -prevCheckResults $configErrorCheck
			}
		} else {
			$encounteredError = $true				
		} 	
	} # end foreach config
          
    if($unsupportedIsapiFilters.Count -gt 0) {						
		$isapiCheck = AppendFailCheckDetail -newDetails "$($unsupportedIsapiFilters.Keys -join ', ')" -prevCheckResults $isapiCheck		
	} elseif ($encounteredError) {
		$isapiCheck.IssueId = "IsapiFilterCheckUnknown"
		$isapiCheck.result = "Unknown"
	}
	$isapiCheck
}

function GetUnsupportedGlobalModules {
	param ( $appHostGlobalModulesSection )
	$unsupportedModules = @{};
	
	$supportedGlobalModules = @{	 
            "HttpLoggingModule"="";
            "UriCacheModule"="";
            "FileCacheModule"="";
            "TokenCacheModule"="";
            "HttpCacheModule"="";
            "DynamicCompressionModule"="";
            "StaticCompressionModule"="";
            "DefaultDocumentModule"="";
            "DirectoryListingModule"="";
            "ProtocolSupportModule"="";
            "HttpRedirectionModule"="";
            "ServerSideIncludeModule"="";
            "StaticFileModule"="";
            "AnonymousAuthenticationModule"="";
            "RequestFilteringModule"="";
            "CustomErrorModule"="";
            "TracingModule"="";
            "FailedRequestsTracingModule"="";
            "RequestMonitorModule"="";
            "IsapiModule"="";
            "IsapiFilterModule"="";
            "CgiModule"="";
            "FastCgiModule"="";
            "ManagedEngineV4.0_32bit"="";
            "ConfigurationValidationModule"="";
            "ManagedEngineV4.0_64bit"="";
            "RewriteModule"="";
            "ManagedEngine64"="";
            "ManagedEngine"="";
            "IpRestrictionModule"="";
            "DynamicIpRestrictionModule"="";
            "ApplicationInitializationModule"="";
            "ModSecurity IIS (32bits)"="";
            "ModSecurity IIS (64bits)"="";
            "iisnode"="";
            "AspNetCoreModuleV2"="";
            "AspNetCoreModule"="";
            "ApplicationRequestRouting"="";
            "httpPlatformHandler"="";
            "PipeStat"="";
            "WebSocketModule"="";

            # The following modules are supported for compatibility with
            # the out-of-box standard IIS modules.  They are not installed
            # on an Antares worker role, so any configuration that
            # references them will need to be handled by a different
            # check
            "UrlAuthorizationModule"="";
            "BasicAuthenticationModule"="";
            "CertificateMappingAuthenticationModule"="";
            "WindowsAuthenticationModule"="";
            "DigestAuthenticationModule"="";
            "IISCertificateMappingAuthenticationModule"="";

            # ToDo: Implement checks for the following:
            "CustomLoggingModule"="";
            "WebDAVModule"=""
        };
	
	if($appHostGlobalModulesSection.isValid) {
		$globalModules = $appHostGlobalModulesSection.section.GetCollection();
		
		foreach ($gModule in $globalModules) {
			$modName = $gModule['name'];
			if(-not($supportedGlobalModules.ContainsKey($modName))) {
				$unsupportedModules.Add($modName, "");
			}		
		}
	} 
	$unsupportedModules
}

function GetMatchingHandlersForSite {
    param( $appHostGlobalModulesSection, $siteConfigPaths, [array]$handlerFileNames)

	$matchingModules = @{};
	$matchingHandlers = @{}; #key=handler, value=scriptProcessor	
	
	if($appHostGlobalModulesSection.isValid) {
		$globalModules = $appHostGlobalModulesSection.section.GetCollection();		
		foreach ($gModule in $globalModules) {
			$modName = $gModule['name'].ToLower();		
			foreach ($fileName in $handlerFileNames) {
				if(-not($matchingModules.ContainsKey($modName))) {
					if($gModule['image'].ToLower().EndsWith($fileName.ToLower())) {
						$matchingModules.Add($modName,"");
					}		
				}
			}
		}
		 	
		$topLevelConfigResults=@{}; #heirarchIndex, list of handlers at apphost or site root level
		$matchingHandlersSubLevels = @{}; #key=handler, value=scriptProcessor #handlers seen at any other level
		foreach($p in $siteConfigPaths) {  						
            if($p.configError -eq "") { 			                       
				#GET HANDLERS
			    try {	
					$handlersSection = $p.sections["system.webServer/handlers"];
					if($handlersSection.isValid) {
						foreach($handler in $handlersSection.section.GetCollection()) {			
							[array]$modNames = $handler['modules'].split(',');
							
							foreach ($module in $matchingModules.keys) {
								foreach($mod in $modNames) {
									if($mod.ToLower() -eq $module) {
										$matchHandlerName = $handler['name'];
										$matchHandlerProcessor =  $handler['scriptProcessor'];

										if($p.heirarchyIndex -lt 3) {
											if(-not $topLevelConfigResults.ContainsKey($p.heirarchyIndex)) {
												$matchModuleHash = @{$matchHandlerName = $matchHandlerProcessor }
												$topLevelConfigResults.Add($p.heirarchyIndex, $matchModuleHash);							
											} else {
												$currentLevelList = $topLevelConfigResults[$p.heirarchyIndex];
												if(-not($currentLevelList.ContainsKey($handler['name']))) {
													$currentLevelList.Add($matchHandlerName, $matchHandlerProcessor)
												}											
											}
										} else {									
											if(-not($matchingHandlersSubLevels.ContainsKey($handler['name']))) {
												$matchingHandlersSubLevels.Add($matchHandlerName, $matchHandlerProcessor)
											}
										}
	
									}
								}
							}
						}
					}
				} catch {
					# don't fail discovery on framework discovery issues
			    }
			} #	else # errors for any section with isValid=false is logged in configErrors check already
		} #end foreach config path
		
		$topBlockConfigPath = "";
		if($topLevelConfigResults.Count -gt 0) {
			# use lowest top level configuration that has handlers defined
			# allows looking at effective site config (i.e. ignoring appHost settings if a root web.config overrides it)
			for($level = 2; $level -ge 0; $level--) {
				if($topLevelConfigResults.ContainsKey($level)) {
					$matchingHandlers = $topLevelConfigResults[$level];		
					break;
				}
			}			
		} 

		if($matchingHandlersSubLevels.Count -gt 0) {
			foreach($subHandler in $matchingHandlersSubLevels.Keys) {
				if(-not($matchingHandlers.ContainsKey($subHandler))) {
					$matchingHandlers.Add($subHandler, $matchingHandlersSubLevels[$subHandler]);
				}
			}
		}							
	} #end if apphost globalmodules section isValid=$true
	
	$matchingHandlers
}

function HasJREHOMEEnvVar {
	param ( $siteSections )

    # Presence of the JRE_HOME environment variable indicates recommended Java configuration using httpPlatformHandler
	try {
		foreach ($sectionsGroup in $siteSections) {		
			if($sectionsGroup["system.webServer/httpPlatform"] -and $sectionsGroup["system.webServer/httpPlatform"].isValid) {
				foreach($varName in $sectionsGroup["system.webServer/httpPlatform"].section.ChildElements['environmentVariables'])				
				{
					if($varName['name'].ToLower() -eq "jre_home") {
						return $true;
					}
				}		
			}
		}
	} catch {
		# do not fail discovery due to Java detection issue
	}
	
	return $false;
}

function ConvertTo-JsonStringWrapper {
	param ($objectToConvert, $depth)

	if(-not $depth) {
		$depth = 10
	}

	try {				
		$majorVersion = $PSVersionTable.PSVersion.Major
		if($majorVersion -lt 3) {
			# ConvertTo-Json is not supported in PS versions lower than 3
			return ConvertObjectToJson -inputObj $objectToConvert		
		} 
	
	} catch {
		Write-Output "ERROR! $($_.Exception)" # Will ultimately result in ResultFileContentJSONParseError
		return
	}

	return ConvertTo-Json $objectToConvert -depth $depth
}

# TODO: implement depth so can't get caught in infinite recursion loop
function ConvertObjectToJson {
	param($inputObj)

	if($inputObj -eq $null) {
		return "null";  
	}

	$objType = $inputObj.GetType().Name;

	switch	($objType) {
		'String' {			
			$escapedStr = $inputObj.Replace('\', '\\').Replace('"', '\"').Replace("`n","\n").Replace("`r","\r").Replace("`t", "\t");
			return "`"$escapedStr`"";		
		}
		'Boolean'{
			return $inputObj.ToString().ToLower();
		}
		'Int32' {
			return $inputObj.ToString();
		}
		'Int64' {
			return $inputObj.ToString();
		}
		'Double' {
			return $inputObj.ToString();
		}
		'Object[]' {
			$arrayContentsJson = "";
			foreach($item in $inputObj) {
				if($arrayContentsJson -ne "") { $arrayContentsJson += ", "}
				$arrayContentsJson += ConvertObjectToJson($item)
			}
			return "[ $arrayContentsJson ]";    
		}
		'Hashtable' { 
			$hashContentsJson = "";
			foreach($key in $inputObj.Keys){
				if($hashContentsJson -ne "") {$hashContentsJson += ", "}
				$hashContentsJson += "`"$key`": $(ConvertObjectToJson($inputObj[$key]))"
			}
		    return "{ $hashContentsJson }"
		}
		default {
			return "{" + 
				(($inputObj | Get-Member -MemberType Properties | % { "`"$($_.Name)`": $(ConvertObjectToJson($inputObj.($_.Name)))" } ) -join ', ') +
				"}";			
		}
	}
}

$ErrorActionPreference = "Stop"; #Make all errors terminating
$errorObj = $null;
try {
	$ServerInfo = GetWebServerBaseObject
    #LoadMWH
	$iisInstallPath = [System.Environment]::ExpandEnvironmentVariables("%windir%\system32\inetsrv\Microsoft.Web.Administration.dll");
	[System.Reflection.Assembly]::LoadFrom($iisInstallPath) | Out-Null; 
	$configPaths = GetConfigPaths;
	$appPoolSettings = GetApplicationPools;

	try {	    
		$ServerInfo = DiscoverAndAssess -configPaths $configPaths -appPoolSettings $appPoolSettings -webServerBase $ServerInfo	
	} catch [System.Security.SecurityException] {    
		$errorObj = GetConfigErrorInfoObj -errorId "IISWebServerAccessFailedError" -exception $_.Exception	    	
	} catch [System.Management.Automation.MethodInvocationException] {    		
		$errorObj = GetConfigErrorInfoObj -errorId "IISWebServerDiscoveryError" -exception $_.Exception	    
	} 
} catch [System.IO.FileNotFoundException] {    
	$errorObj = GetConfigErrorInfoObj -errorId "IISWebServerIISNotFoundError" -exception $_.Exception
} catch [System.Security.SecurityException] {    
	$errorObj = GetConfigErrorInfoObj -errorId "IISWebServerAccessFailedError" -exception $_.Exception 
} catch [System.Management.Automation.MethodInvocationException] {    
	# this can occur due to file access issues, including on apphost or redirection config
	$errorObj = GetConfigErrorInfoObj -errorId "IISWebServerAccessFailedError" -exception $_.Exception
} catch {	
	$errorObj = GetConfigErrorInfoObj -errorId "IISWebServerPowerShellError" -exception $_.Exception
}finally{
	if($errorObj){
		if(-not $ServerInfo.error) {
			$ServerInfo | Add-Member -MemberType NoteProperty -Name error -Value $errorObj			
		} 		 
	} 
	ConvertTo-JsonStringWrapper -objectToConvert $ServerInfo | Write-Output
   $ErrorActionPreference = "Continue"; #Reset the error action pref to default
}


# SIG # Begin signature block
# MIIjhQYJKoZIhvcNAQcCoIIjdjCCI3ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBXpr01F7QeM4se
# bsz80JndHaJiTgfde2Krm+UGkj9o46CCDYEwggX/MIID56ADAgECAhMzAAAB32vw
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
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgc6P4zvlD
# E1Mhsk+3cQdgsPgf6uJGXm4qfBaXI93eUcgwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQCAbubE7+OavroBvnGCutkaggw5c2ZOsY4ojmBUk2n+
# Mk3UGX1bdHWav9NWsx+xqDgQZqGHtjMlSGYWMkDHt0VuDgbD2xLtX3xAwPLNnNve
# STSBxoIsVwmqMarcE0WY9NFJAhml089K8Z0O+JzznfBRcooeUUEMtHUMdJEVl397
# wzEcqnKurZDFI5i9pNuBDLeY9vRWE/9u6k45xWl1fNPgrvHCqKvmA2Q6jz2Li8to
# Bbxd+JeuNzmRzX9l9OkEtNPisB9U/v9ze2hjGO2A+kupDKkulOJMEcjqvO1O4fBj
# Gbk3raG56YbHEfwLC7N6xJeQRHM4RB0tMq3X1/dwqj97oYIS5DCCEuAGCisGAQQB
# gjcDAwExghLQMIISzAYJKoZIhvcNAQcCoIISvTCCErkCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIIcVCTsQpIonRO55RYVn6daY26KjxO7l6u8Eenuc
# 19fwAgZg+YRQnd4YEzIwMjEwNzIyMTcxNjQ3LjE0OVowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkVBQ0UtRTMxNi1DOTFEMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOOzCCBPEwggPZoAMCAQICEzMAAAFMxUzB0NtvP7IAAAAAAUww
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjAxMTEyMTgyNjAwWhcNMjIwMjExMTgyNjAwWjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RUFDRS1FMzE2LUM5
# MUQxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKYWBRw6zHue+jVeyBCg/45N+8T4mk
# 43ntsyt1z/qlCaQVTGNiAsWkUYctQp8n/+b1kaZ99wZPcWxnoJ6W5KC/PNGzaUme
# rlnKc0oBQTnZjVK0wbfekVl2j2O5LVDAWRFr4kn98gldiF4FmAEBbmfbLEPWII6a
# Nab1K7WqFMAI4mjON+lAlPX1tQ/pHBB9OZuIbnFmxPCVvjvW925XrYr+/J/nwuqC
# pOmkkEURS+DiYqL0vom9e+RuqUn/cA0ZPV95DuutTrQnKx2QH8HtjB1wz+HmXxkZ
# LAPyL76yxTXGoyOyLek8fqJw8keYoEYvpAiaExtGFBgtVDIwitOVrQ67AgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUAZYepwQKXucnlUIBgPQQR95m+nwwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEATwTksPfWQ66ogGKvd+tmdx2IQYaEl7zHiAhvccO6
# 5afIQLZokhzyAHDO+MZH2GZ3QX9WUObp1OWJlfvzxv0LuzV/GSoJHLDVvFDwJ1W0
# 6UfrzZn//5F3YgyT92/FO5zM2dOaXkSjFeL1DhGA+vsMPBzUkgRI0VX2hEgS2d6K
# Yz6Mc2smqKfll1OWVrZaJpd6C657ptbInE1asN9JjNo2P8CSR/2yuG00c87+7e59
# fIAf/lwv2Ef49vrSLp7Y9MS9EFBRtF7gQC/usy0grSUd+qtIT/++2bJNLcS/eZjX
# K0X0UCcuMU+ZZBiGV2wMhEIOdQRuWqJlTv9ftOb67c/KazCCBnEwggRZoAMCAQIC
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
# cGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpFQUNFLUUzMTYtQzkx
# RDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUAPZlbTgkoE2J2HRjNYygElxrg96CggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOSkAs8wIhgPMjAy
# MTA3MjIyMjQ0MzFaGA8yMDIxMDcyMzIyNDQzMVowdjA8BgorBgEEAYRZCgQBMS4w
# LDAKAgUA5KQCzwIBADAJAgEAAgFVAgH/MAcCAQACAhEdMAoCBQDkpVRPAgEAMDYG
# CisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEA
# AgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAoAmJuwouBM9OlLwHmVScv5RTf6hqR/2t
# or5UxPrL6Ruvud1Pq30yMF8Fli7omdD5U3AmNjR4eXmwaBGAGFpIO7Lqrz9pzpil
# s92m//bfom6LDWv2H9D4QSUxHwTmNWFcXQvwPq9VGfiqK9DpUcM41MYZCHfxt5Z/
# trOodxbPGpgxggMNMIIDCQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAUzFTMHQ228/sgAAAAABTDANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCB7GErTIBk1
# nas/YR4KiUTAZJhc71D3u/l5WYvn5nFK9TCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EINvCpbu/UEsy0RBMIOH6TwsthlN90/tz2a8QYmfEr04lMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAFMxUzB0NtvP7IAAAAA
# AUwwIgQgqD8TGm6ntvPAcQhr2ZpMhl/HVvZE5NrsDEQJ0AhkxgwwDQYJKoZIhvcN
# AQELBQAEggEAkINpxYBXKqmRTmhjb975awqTqA74C8mIw8Mb0X8SWZXzgqSholcC
# 8k/OHFMhdjzgBbpXbZKS6lE4rmEFVN3XlU/L8qAERwIr5cb5AG2sMK/R/b8jtR9Q
# zeZaZvjEHulC5NTEVvTWRIlip90IG9TFZm/fUdFa8WmvHuS2EeGSCHB9YSRVMula
# XuZrxVRW8ldtAS5Yu7BG4njsLvYC7bGm0BSPiOLeWeqjxTXWWfMeGqzTI3E6flMT
# GVgY/8zs5v5M6AecIL0tkHrduvin13RXXNEYWKxC6TPeAiEIjKaRWZDxkAxLZSQe
# ux1zyjyznywZwdp53TBkB/Z7FpHrLTevUw==
# SIG # End signature block
