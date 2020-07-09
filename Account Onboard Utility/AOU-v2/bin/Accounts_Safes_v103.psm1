# CyberArk REST API for versions 10.3 and above

#region URL definition
# Global URLS
# -----------
$URL_Authentication = $URL_PVWAAPI+"/auth"
$global:URL_Logon = $URL_Authentication+"/$AuthType/Logon"
$global:URL_Logoff = $URL_Authentication+"/Logoff"
#endregion

#region REST Commands
#region Accounts
# URL Methods
# -----------
$global:URL_Accounts = $URL_PVWAAPI+"/Accounts"
$global:URL_AccountsDetails = $URL_Accounts+"/{0}"
$global:URL_Platforms = $URL_PVWAAPI+"/Platforms"
$global:URL_PlatformDetails = $URL_Platforms+"/{0}"

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-Account
# Description....: Returns a list of accounts based on a filter
# Parameters.....: Account name, Account address, Account Safe Name
# Return Values..: List of accounts
# =================================================================================================================================
Function Get-Account
{
<# 
.SYNOPSIS 
	Returns accoutns based on filters
.DESCRIPTION
	Creates a new Account Object
.PARAMETER AccountName
	Account user name
.PARAMETER AccountAddress
	Account address
.PARAMETER SafeName
	The Account Safe Name to search in
#>
	param (
		[Parameter(Mandatory=$true)]
		[String]$accountName, 
		[Parameter(Mandatory=$true)]
		[String]$accountAddress, 
		[Parameter(Mandatory=$true)]
		[String]$safeName
	)
	$_retaccount = $null
	$_accounts = $null
	try{
		$urlSearchAccount = $URL_Accounts+"?filter=safename eq "+$(Encode-URL $safeName)+"&search="+$(Encode-URL "$accountName $accountAddress")
		# Search for created account
		$_accounts = $(Invoke-Rest -Uri $urlSearchAccount -Header $(Get-LogonHeader) -Command "Get")
		if($null -ne $_accounts)
		{
			foreach ($item in $_accounts.value)
			{
				if(($item -ne $null) -and ($item.username -eq $accountName) -and ($item.address -eq $accountAddress))
				{
					$_retaccount = $item
					break;
				}
			}
		}
	} catch {
		Throw $(New-Object System.Exception ("Get-Account: There was an error retreiving the account object.",$_.Exception))
	}
	
	return $_retaccount
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Test-Account
# Description....: Checks if an account exists
# Parameters.....: Account name, Account address, Account Safe Name
# Return Values..: True / False
# =================================================================================================================================
Function Test-Account
{
<# 
.SYNOPSIS 
	Test if an accoutn exists (Search based on filters)
.DESCRIPTION
	Test if an accoutn exists (Search based on filters)
.PARAMETER AccountName
	Account user name
.PARAMETER AccountAddress
	Account address
.PARAMETER SafeName
	The Account Safe Name to search in
#>
	param (
		[Parameter(Mandatory=$true)]
		[String]$accountName, 
		[Parameter(Mandatory=$true)]
		[String]$accountAddress, 
		[Parameter(Mandatory=$true)]
		[String]$safeName
	)
	try {
		$accResult = $(Get-Account -accountName $accountName -accountAddress $accountAddress -safeName $safeName)
		If (($null -eq $accResult) -or ($accResult.count -eq 0))
		{
			# No accounts found
			Write-LogMessage -Type Debug -MSG "Account $accountName does not exist"
			return $false
		}
		else
		{
			# Account Exists
			Write-LogMessage -Type Info -MSG "Account $accountName exist"
			return $true
		}
	} catch {
		# Check the error code returned from the REST call
		$innerExcp = $_.Exception.InnerException
		Write-LogMessage -Type Verbose -Msg "Status Code: $($innerExcp.StatusCode); Status Description: $($innerExcp.StatusDescription); REST Error: $($innerExcp.CyberArkErrorMessage)"
		if($innerExcp.StatusCode -eq "NotFound") {
			return $false
		}
		else{
			Throw $(New-Object System.Exception ("Test-Account: There was an error finding the account object.",$_.Exception))
		}
	}
}
Export-ModuleMember -Function Test-Account

# @FUNCTION@ ======================================================================================================================
# Name...........: New-AccountObject
# Description....: Creates a new Account object
# Parameters.....: Account line read from CSV
# Return Values..: Account Object for onboarding
# =================================================================================================================================
Function New-AccountObject
{
<# 
.SYNOPSIS 
	Creates a new Account Object
.DESCRIPTION
	Creates a new Account Object
.PARAMETER AccountLine
	(Optional) Account Object Name
#>
	param (
		[Parameter(Mandatory=$true)]
		[PSObject]$AccountLine
	)
	try{
		# Convert Account from CSV to Account Object (properties mapping)
		$objAccount = "" | Select "name", "address", "userName", "platformId", "safeName", "secretType", "secret", "platformAccountProperties", "secretManagement", "remoteMachinesAccess"
		$objAccount.platformAccountProperties = $null
		$objAccount.secretManagement = "" | Select "automaticManagementEnabled", "manualManagementReason"
		$objAccount.name = $AccountLine.name
		$objAccount.address = $AccountLine.address
		$objAccount.userName = $AccountLine.userName
		$objAccount.platformId = $AccountLine.platformID
		$objAccount.safeName = $AccountLine.safe
		if ((![string]::IsNullOrEmpty($AccountLine.password)) -and ([string]::IsNullOrEmpty($AccountLine.SSHKey)))
		{ 
			$objAccount.secretType = "password"
			$objAccount.secret = $AccountLine.password
		} elseif(![string]::IsNullOrEmpty($AccountLine.SSHKey)) { 
			$objAccount.secretType = "key" 
			$objAccount.secret = $AccountLine.SSHKey
		}
		else
		{
			# Empty password
			$objAccount.secretType = "password"
			$objAccount.secret = $AccountLine.password
		}
		if(![string]::IsNullOrEmpty($customProps))
		{
			$customProps.count
			# Convert any non-default property in the CSV as a new platform account property
			if($objAccount.platformAccountProperties -eq $null) { $objAccount.platformAccountProperties =  New-Object PSObject }
			For ($i = 0; $i -lt $customProps.count; $i++){
				$prop = $customProps[$i]
				If(![string]::IsNullOrEmpty($prop.Value))
				{
					$objAccount.platformAccountProperties | Add-Member -MemberType NoteProperty -Name $prop.Name -Value $prop.Value 
				}
			}
		}
		$objAccount.secretManagement.automaticManagementEnabled = Convert-ToBool $AccountLine.enableAutoMgmt
		if ($objAccount.secretManagement.automaticManagementEnabled -eq $false)
		{ $objAccount.secretManagement.manualManagementReason = $AccountLine.manualManagementReason }
		$objAccount.remoteMachinesAccess = "" | select "remoteMachines", "accessRestrictedToRemoteMachines"
		$objAccount.remoteMachinesAccess.remoteMachines = $AccountLine.remoteMachineAddresses
		# Convert Restrict Machine Access To List from yes / true to $true
		if ($AccountLine.restrictMachineAccessToList -eq "yes" -or $AccountLine.restrictMachineAccessToList -eq "true") 
		{
			$objAccount.remoteMachinesAccess.accessRestrictedToRemoteMachines =  $true
		} else {
			$objAccount.remoteMachinesAccess.accessRestrictedToRemoteMachines = $false
		}
		
		return $objAccount
	} catch {
		Throw $(New-Object System.Exception ("New-AccountObject: There was an error creating a new account object.",$_.Exception))
	}
}
Export-ModuleMember -Function New-AccountObject

# @FUNCTION@ ======================================================================================================================
# Name...........: New-Account
# Description....: Adds an Account to the PVWA
# Parameters.....: Account object created from New-AccountObject
# Return Values..: True / False
# =================================================================================================================================
Function New-Account
{
<# 
.SYNOPSIS 
	Adds an Account to the PVWA
.DESCRIPTION
	Adds an Account to the PVWA
.PARAMETER AccountObject
	Account Object (created from New-AccountObject function)
#>
	param(
		[Parameter(Mandatory=$true)]
		[PSObject]$AccountObject
	)
	try{			
		$retAddAccount = $false
		# Create the Account
		$restBody = $AccountObject | ConvertTo-Json -Depth 5
		$addAccountResult = $(Invoke-Rest -Uri $URL_Accounts -Header $(Get-LogonHeader) -Body $restBody -Command "Post")
		if($addAccountResult -ne $null)
		{
			Write-LogMessage -Type Debug -MSG (Get-AccountMessageForLog -AccountObject $AccountObject -Type "Success" -Action "Onboarded")
			$retAddAccount = $true
		}
		return $retAddAccount
	}
	catch{
		Throw $(New-Object System.Exception ("New-Account: $(Get-AccountMessageForLog -AccountObject $AccountObject -Type "Fail" -Action "Create")",$_.Exception))
	}
}
Export-ModuleMember -Function New-Account

# @FUNCTION@ ======================================================================================================================
# Name...........: Update-Account
# Description....: Update an existing Account in the PVWA
# Parameters.....: Account object created from New-AccountObject
# Return Values..: True / False
# =================================================================================================================================
Function Update-Account
{
<# 
.SYNOPSIS 
	Update an existing Account in the PVWA
.DESCRIPTION
	Update an existing Account in the PVWA
.PARAMETER AccountObject
	Account Object (created from New-AccountObject function)
#>
	param(
		[Parameter(Mandatory=$true)]
		[PSObject]$AccountObject
	)
	try{			
		$retUpdateAccount = $false
		# Get Existing Account Details
		$s_Account = $(Get-Account -safeName $AccountObject.safeName -accountName $AccountObject.userName -accountAddress $AccountObject.Address)
		$s_ExcludeProperties = @("secret")
		# Check for existing properties needed update
		Foreach($sProp in $s_Account.PSObject.Properties)
		{
			Write-LogMessage -Type Verbose -MSG "Inspecting Account Property $($sProp.Name)"
			$s_ExcludeProperties += $sProp.Name
			If($sProp.TypeNameOfValue -eq "System.Management.Automation.PSCustomObject") 
			{
				# A Nested object
				ForEach($subProp in $s_Account.($sProp.Name).PSObject.Properties) 
				{ 
					Write-LogMessage -Type Verbose -MSG "Inspecting Account Property $($subProp.Name)"
					$s_ExcludeProperties += $subProp.Name
					If(($null -ne $objAccount.$($sProp.Name).$($subProp.Name)) -and ($AccountObject.$($sProp.Name).$($subProp.Name) -ne $subProp.Value))
					{
						Write-LogMessage -Type Verbose -MSG "Updating Account Property $($s_Account.$($sProp.Name)) value from: '$($subProp.Value)' to: '$($AccountObject.$($sProp.Name).$($subProp.Name))'"
						$s_AccountBody += Get-RESTPatchBody -Operation "replace" -Path ($sProp.Name+"/"+$subProp.Name) -Value $AccountObject.$($sProp.Name).$($subProp.Name)
						# Adding a specific case for "/secretManagement/automaticManagementEnabled"
						If("/secretManagement/automaticManagementEnabled" -eq ("/"+$sProp.Name+"/"+$subProp.Name))
						{
							If($AccountObject.secretManagement.automaticManagementEnabled -eq $true)
							{
								# Need to remove the manualManagementReason
								Write-LogMessage -Type Verbose -MSG "Since Account Automatic management is on, removing the Manual management reason"
								$s_AccountBody += Get-RESTPatchBody -Operation "remove" -Path "secretManagement/manualManagementReason" -Value ""
							}
							else
							{
								# Need to add the manualManagementReason
								Write-LogMessage -Type Verbose -MSG "Since Account Automatic management is off, adding the Manual management reason"
								$_value = ""
								if([string]::IsNullOrEmpty($AccountObject.secretManagement.manualManagementReason))
								{
									$_value = "[No Reason]"
								}
								else
								{
									$_value = $AccountObject.secretManagement.manualManagementReason
								}
								$s_AccountBody += Get-RESTPatchBody -Operation "add" -Path "secretManagement/manualManagementReason" -Value $_value
							}
						}
					}
				} 
			} 
			else 
			{ 
				If(($null -ne $AccountObject.$($sProp.Name)) -and ($AccountObject.$($sProp.Name) -ne $sProp.Value))
				{
					Write-LogMessage -Type Verbose -MSG "Updating Account Property $($sProp.Name) value from: '$($sProp.Value)' to: '$($AccountObject.$($sProp.Name))'"
					$s_AccountBody += Get-RESTPatchBody -Operation "replace" -Path $sProp.Name -Value $AccountObject.$($sProp.Name)
				}
			}
		}
		# Check for new Account Properties
		ForEach($sProp in ($AccountObject.PSObject.Properties | where { $_.Name -notin $s_ExcludeProperties }))
		{
			If($sProp.Name -eq "remoteMachinesAccess")
			{
				ForEach($sSubProp in $AccountObject.remoteMachinesAccess.PSObject.Properties)
				{
					Write-LogMessage -Type Verbose -MSG "Updating Account Remote Machine Access Properties $($sSubProp.Name) value to: '$($AccountObject.remoteMachinesAccess.$($sSubProp.Name))'"
					If($sSubProp.Name -in ("remotemachineaddresses","restrictmachineaccesstolist", "remoteMachines", "accessRestrictedToRemoteMachines"))
					{
						# Handle Remote Machine properties
						$_path = ""
						if($sSubProp.Name -in("remotemachineaddresses", "remoteMachines"))
						{
							$_path = "/remoteMachinesAccess/remoteMachines"
						}
						if($sSubProp.Name -in("restrictmachineaccesstolist", "accessRestrictedToRemoteMachines"))
						{
							$_path = "/remoteMachinesAccess/accessRestrictedToRemoteMachines"
						}
						$s_AccountBody += Get-RESTPatchBody -Operation "replace" -Path $_path -Value ($AccountObject.remoteMachinesAccess.$($sSubProp.Name) -join ';')
					}
				}
			}
			ElseIf($sProp.Name -eq "platformAccountProperties")
			{
				ForEach($sSubProp in $AccountObject.remoteMachinesAccess.PSObject.Properties)
				{
					Write-LogMessage -Type Verbose -MSG "Updating Platform Account Properties $($sSubProp.Name) value to: '$($AccountObject.platformAccountProperties.$($sSubProp.Name))'"
					# Handle new Account Platform properties
					$s_AccountBody += Get-RESTPatchBody -Operation "replace" -Path ("platformAccountProperties/"+$sProp.Name) -Value ($AccountObject.platformAccountProperties.$($sProp.Name))
				}
			}
		}
		
		If($s_AccountBody.count -eq 0)
		{
			Write-LogMessage -Type Info -MSG "No Account updates detected"
		}
		else
		{
			# Update the existing account
			$restBody = ConvertTo-Json $s_AccountBody -depth 5
			$urlUpdateAccount = $URL_AccountsDetails -f $s_Account.id
			$UpdateAccountResult = $(Invoke-Rest -Uri $urlUpdateAccount -Header $g_LogonHeader -Body $restBody -Command "PATCH")
			if($UpdateAccountResult -ne $null)
			{
				Write-LogMessage -Type Debug -MSG (Get-AccountMessageForLog -AccountObject $AccountObject -Type "Success" -Action "Updated")
				$retUpdateAccount = $true
			}
		}
		
		# Check if Secret update is needed
		If(![string]::IsNullOrEmpty($AccountObject.secret))
		{
			Update-AccountSecret -AccountObject $AccountObject
			# Verify that the secret type is a Password (Only type that is currently supported to update
			if($AccountObject.secretType -eq "password")
			{
				Write-LogMessage -Type Debug -MSG "Updating Account Secret..."
				# This account has a password and we are going to update item
				$_passBody = "" | select "NewCredentials"
				# $_passBody.ChangeEntireGroup = $false
				$_passBody.NewCredentials = $AccountObject.secret
				# Update secret
				$restBody = ConvertTo-Json $_passBody
				$urlUpdateAccount = $URL_AccountsPassword -f $s_Account.id
				$UpdateAccountResult = $(Invoke-Rest -Uri $urlUpdateAccount -Header $g_LogonHeader -Body $restBody -Command "POST")
				if($UpdateAccountResult -ne $null)
				{
					Write-LogMessage -Type Debug -MSG (Get-AccountMessageForLog -AccountObject $AccountObject -Type "Success" -Action "Secret Updated")
					$retUpdateAccount = $true
				}
			} else {
				Write-LogMessage -Type Warning -MSG "Account Secret Type is not a password, no support for updating the secret - skipping"
			}
		}

		return $retUpdateAccount
	}
	catch{
		Throw $(New-Object System.Exception ("Update-Account: $(Get-AccountMessageForLog -AccountObject $AccountObject -Type "Fail" -Action "Update")",$_.Exception))
	}
}
Export-ModuleMember -Function Update-Account

# @FUNCTION@ ======================================================================================================================
# Name...........: Delete-Account
# Description....: Deletes an Account from the PVWA
# Parameters.....: Account object created from New-AccountObject
# Return Values..: True / False
# =================================================================================================================================
Function Delete-Account
{
<# 
.SYNOPSIS 
	Deletes an Account from the PVWA
.DESCRIPTION
	Deletes an Account from the PVWA
.PARAMETER AccountObject
	Account Object (created from New-AccountObject function)
#>
	param(
		[Parameter(Mandatory=$true)]
		[PSObject]$AccountObject
	)
	try{			
		$retDelAccount = $false
		# Find the account for deletion
		$d_account = $(Get-Account -safeName $AccountObject.safeName -accountName $AccountObject.userName -accountAddress $AccountObject.Address)
		If($null -eq $d_account)
		{
			Write-LogMessage -Type Error -Msg "Account '$(Get-AccountLogName -AccountObject $AccountObject)' does not exists - skipping deletion"
		}
		ElseIf($d_account.Count -gt 1)
		{
			Write-LogMessage -Type Error -Msg "Too many accounts for '$(Get-AccountLogName -AccountObject $AccountObject)' in safe $($objAccount.safeName)"
		}
		Else
		{
			# Single account found for deletion
			$urlDeleteAccount = $URL_AccountsDetails -f $d_account.id
			$DeleteAccountResult = $(Invoke-Rest -Uri $urlDeleteAccount -Header $g_LogonHeader -Command "DELETE")
			if($DeleteAccountResult -ne $null)
			{
				Write-LogMessage -Type Debug -MSG (Get-AccountMessageForLog -AccountObject $AccountObject -Type "Success" -Action "Deleted")
				$retDelAccount = $true
			}
		}
		return $retDelAccount
	}
	catch{
		Throw $(New-Object System.Exception ("Delete-Account: $(Get-AccountMessageForLog -AccountObject $AccountObject -Type "Fail" -Action "Delete")",$_.Exception))
	}
}
Export-ModuleMember -Function Delete-Account

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-PlatformDetails
# Description....: Gets the details of a particular CyberArk Platform specified by the platform name
# Parameters.....: Platform Name
# Return Values..: Platform details
# =================================================================================================================================
Function Get-PlatformDetails {
<#
.SYNOPSIS
Gets the details of a CyberArk platform

.DESCRIPTION
Gets the details of a particular CyberArk Platform specified by the platofrm name

.EXAMPLE
Get-PlatformDetails -platformname "WinDomain"

.PARAMETER platformName
	The name of the platform to get it's details

#>

    [CmdletBinding()]
    [OutputType([String], ParameterSetName="Platform")]
    Param(
        [Parameter(Mandatory=$true,
            HelpMessage="The name of the platform")]
        $platformName           
    )

	try {
		Write-LogMessage -Type Debug -Msg "Getting the details of the platform, $platformName..."
		$platformDetails = (Invoke-Rest -Uri ($URL_PlatformDetails -f $platformName) -Headers $(Get-LogonHeader) -Command GET).details
		return $platformDetails
	}catch{
		Throw $(New-Object System.Exception ("Get-PlatformDetails: There was an error getting the details of the platform, $platformName",$_.Exception))
	}    
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-PlatformDetails
# Description....: Gets the details of a particular CyberArk Platform specified by the platofrm name
# Parameters.....: Platform Name
# Return Values..: Platform details
# =================================================================================================================================
Function Get-Platforms {
<#
.SYNOPSIS
Gets platforms

.DESCRIPTION
Gets the platforms from the vault

#>

    [CmdletBinding()]
    [OutputType()]
    Param(
        [Parameter(Mandatory=$true,
            ParameterSetName="SearchByActive",
            HelpMessage="True or false",
            Position=2)]
        [switch]$SearchByStatus,
        [Parameter(Mandatory=$true,
            ParameterSetName="SearchByPlatformType",
            HelpMessage="The type of platform. Either group or regular",
            Position=2)]
        [switch]$SearchByType,
        [Parameter(Mandatory=$true,
            ParameterSetName="SearchByKeyword",
            HelpMessage="The name of the platform",
            Position=2)]
        [switch]$SearchByKeyword,
        [Parameter(Mandatory=$false,
            ParameterSetName="SearchByActive",
            HelpMessage="True or false",
            Position=3)]
        [ValidateSet("True","False")]
        $active="True",
        [Parameter(Mandatory=$true,
            ParameterSetName="SearchByPlatformType",
            HelpMessage="Group or Regular",
            Position=3)]
        [ValidateSet("Group","Regular")]
        $Type,
        [Parameter(Mandatory=$false,
            ParameterSetName="SearchByKeyword",
            HelpMessage="The name of the platform",
            Position=3)]
        $Keyword="*"
    )
	#Define URI
	if ($searchByStatus){
		$platformsURI = "$URL_Platforms?active=$active"
	} elseif ($searchByType){
		$platformsURI = "$URL_Platforms?platformType=$Type"
	} elseif($SearchByKeyword){
		if ($keyword = "*"){ $keyword="" }
		$platformsURI = "$URL_Platforms?search=$Keyword"
	} else {
		# No filters
		$platformsURI = $URL_Platforms
	}
	
	try {
		Write-LogMessage -Type Debug -Msg "Getting platforms..."
		$platform = (Invoke-Rest -Uri $platformsURI -Headers $(Get-LogonHeader) -Command GET).platforms
		return $platform
	}catch{
		Throw $(New-Object System.Exception ("Get-Platforms: There was an error getting the platforms",$_.Exception))
	}
}
#endregion
#region Helper Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Get-RESTPatchBody
# Description....: Returns an object for REST PATCH command
# Parameters.....: Operation (default:replace), Path, Value
# Return Values..: Object
# =================================================================================================================================
Function Get-RESTPatchBody
{
<# 
.SYNOPSIS 
	Returns an object for REST PATCH command
.DESCRIPTION
	Returns an object for REST PATCH command
.PARAMETER Operation
	Operation for patch (add, replace, remove)
.PARAMETER Path
	The required patch object path
.PARAMETER Value
	The required patch object value
#>
	param(
		[Parameter(Mandatory=$true)]
		[ValidateSet("add","replace","remove")]
		[String]$Operation = "replace",
		[Parameter(Mandatory=$true)]
		[String]$Path,
		[Parameter(Mandatory=$true)]
		[String]$Value
	)
	try{
		$_bodyOp = "" | select "op", "path", "value"
		$_bodyOp.op = $Operation
		$_bodyOp.path = "/$Path"
		$_bodyOp.value = $Value
		
		return $_bodyOp
	}
	catch{
		Throw $(New-Object System.Exception ("Get-RESTPatchBody: Failed to create PATCH command body",$_.Exception))
	}
}
#endregion
#endregion