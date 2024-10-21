function Password_Policies {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"
    $outputFilePath = Join-Path -Path $outputDirectory -ChildPath "PasswordPolicies.json"
    
    # Export the local security policy to a temporary file
    $tempFilePath = "$env:temp\secedit.inf"
    secedit /export /cfg $tempFilePath /quiet
    
    # Read the content of the temporary file
    $policyContent = Get-Content $tempFilePath
    
    # Initialize variables to store the settings
    $enforcePasswordHistory = $null
    $maximumPasswordAge = $null
    $minimumPasswordLength = $null
    $passwordComplexity = $null
    $relaxMinimumPasswordLength = $null
    $storePasswordsReversibleEncryption = $null
    
    # Parse the content to find the password policy settings
    foreach ($line in $policyContent) {
        if ($line -match "^PasswordHistorySize\s*=\s*(\d+)$") {
            $enforcePasswordHistory = $matches[1]
        }
        if ($line -match "^MaximumPasswordAge\s*=\s*(-?\d+)$") {
            $maximumPasswordAge = $matches[1]
        }
        if ($line -match "^MinimumPasswordLength\s*=\s*(\d+)$") {
            $minimumPasswordLength = $matches[1]
        }
        if ($line -match "^PasswordComplexity\s*=\s*(\d+)$") {
            $passwordComplexity = $matches[1]
        }
        if ($line -match "^MACHINE\\System\\CurrentControlSet\\Control\\SAM\\RelaxMinimumPasswordLengthLimits=4,(\d+)$") {
            $relaxMinimumPasswordLength = $matches[1]
        }
        if ($line -match "^ClearTextPassword\s*=\s*(\d+)$") {
            $storePasswordsReversibleEncryption = $matches[1]
        }
    }
    
    # Create a PSObject to store the results
    $data = New-Object PSObject -Property @{
        EnforcePasswordHistory             = $enforcePasswordHistory
        MaximumPasswordAge                 = $maximumPasswordAge
        MinimumPasswordLength              = $minimumPasswordLength
        PasswordComplexity                 = $passwordComplexity
        RelaxMinimumPasswordLength         = $relaxMinimumPasswordLength
        StorePasswordsReversibleEncryption = $storePasswordsReversibleEncryption
    }
    
    # Convert the data to JSON
    $jsonData = $data | ConvertTo-Json -Depth 4
    
    
    
    # Save the JSON data to the output file path
    $jsonData | Out-File -FilePath $outputFilePath -Encoding UTF8
    
    # Read the JSON content back from the output file
    $jsonContent = Get-Content -Path $outputFilePath -Raw | ConvertFrom-Json
    
    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}
    
    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }
    
    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100
    
    # Write the sorted JSON content back to the output file
    $orderedJsonJson | Set-Content -Path $outputFilePath
    
    # Clean up the temporary file
    Remove-Item $tempFilePath
    
    Write-Host "Password policy settings have been saved to $outputFilePath"
    
}

function Account_Lockout_Policy {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "AccountLockoutPolicy.json"
    
    # Export the local security policy to a temporary file
    $tempFilePath = "$env:temp\secedit.inf"
    secedit /export /cfg $tempFilePath /quiet
    
    # Read the content of the temporary file
    $policyContent = Get-Content $tempFilePath
    
    # Initialize variables to store the settings
    $accountLockoutDuration = $null
    $accountLockoutThreshold = $null
    $administratorAccountLockout = $null
    $resetAccountLockoutCounter = $null
    
    # Parse the content to find the password policy settings
    foreach ($line in $policyContent) {
        if ($line -match "^LockoutDuration\s*=\s*(\d+)$") {
            $accountLockoutDuration = $matches[1]
        }
        if ($line -match "^LockoutBadCount\s*=\s*(-?\d+)$") {
            $accountLockoutThreshold = $matches[1]
        }
        if ($line -match "^AllowAdministratorLockout\s*=\s*(\d+)$") {
            $administratorAccountLockout = $matches[1]
        }
        if ($line -match "^ResetLockoutCount\s*=\s*(\d+)$") {
            $resetAccountLockoutCounter = $matches[1]
        }
    }
    
    # Create a PSObject to store the results
    $data = New-Object PSObject -Property @{
        AccountLockoutDuration    = $accountLockoutDuration
        AccountLockoutThreshold   = $accountLockoutThreshold
        AllowAdministratorLockout = $administratorAccountLockout
        ResetLockoutCount         = $resetAccountLockoutCounter
    }
    
    # Convert the data to JSON
    $jsonData = $data | ConvertTo-Json -Depth 4
    
    # Save the JSON data to the output path
    $jsonData | Out-File -FilePath $outputPath -Encoding UTF8
    
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json
    
    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}
    
    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }
    
    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100
    
    # Write the JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath
    
    # Clean up the temporary file
    Remove-Item $tempFilePath
    
    Write-Host "Password policy settings have been saved to $outputPath"
    
    
}

function User_Right_Assignment {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "UserRightAssignment.json"
    
    # Export the local security policy to a temporary file
    $tempFile = "$env:temp\secedit.inf"
    secedit /export /cfg $tempFile /quiet
    
    # Define the rights to retrieve with corresponding secedit privilege names
    $rightsMapping = @{
        "Access Credential Manager as a trusted caller"                  = "SeTrustedCredManAccessPrivilege"
        "Access this computer from the network"                          = "SeNetworkLogonRight"
        "Act as part of the operating system"                            = "SeTcbPrivilege"
        "Adjust memory quotas for a process"                             = "SeIncreaseQuotaPrivilege"
        "Allow log on locally"                                           = "SeInteractiveLogonRight"
        "Allow log in through Remote desktop services"                   = "SeRemoteInteractiveLogonRight"
        "Back up files and directories"                                  = "SeBackupPrivilege"
        "Change the system time"                                         = "SeSystemtimePrivilege"
        "Change the time zone"                                           = "SeTimeZonePrivilege"
        "Create a pagefile"                                              = "SeCreatePagefilePrivilege"
        "Create a token object"                                          = "SeCreateTokenPrivilege"
        "Create global objects"                                          = "SeCreateGlobalPrivilege"
        "Create permanent shared objects"                                = "SeCreatePermanentPrivilege"
        "Create symbolic links"                                          = "SeCreateSymbolicLinkPrivilege"
        "Debug programs"                                                 = "SeDebugPrivilege"
        "Deny access to this computer from the network"                  = "SeDenyNetworkLogonRight"
        "Deny log on as a batch job"                                     = "SeDenyBatchLogonRight"
        "Deny log on as a service"                                       = "SeDenyServiceLogonRight"
        "Deny log on locally"                                            = "SeDenyInteractiveLogonRight"
        "Deny log on through Remote Desktop Services"                    = "SeDenyRemoteInteractiveLogonRight"
        "Enable computer and user accounts to be trusted for delegation" = "SeTrustedForDelegationPrivilege"
        "Force shutdown from a remote system"                            = "SeRemoteShutdownPrivilege"
        "Generate security audits"                                       = "SeAuditPrivilege"
        "Impersonate a client after authentication"                      = "SeImpersonatePrivilege"
        "Increase scheduling priority"                                   = "SeIncreaseBasePriorityPrivilege"
        "Load and unload device drivers"                                 = "SeLoadDriverPrivilege"
        "Lock pages in memory"                                           = "SeLockMemoryPrivilege"
        "Log on as a batch job"                                          = "SeBatchLogonRight"
        "Log on as a service"                                            = "SeServiceLogonRight"
        "Manage auditing and security log"                               = "SeManageVolumePrivilege"
        "Modify an object label"                                         = "SeModifyObjectLabelPrivilege"
        "Modify firmware environment values"                             = "SeSystemEnvironmentPrivilege"
        "Perform volume maintenance tasks"                               = "SeManageVolumePrivilege"
        "Profile single process"                                         = "SeProfileSingleProcessPrivilege"
        "Profile system performance"                                     = "SeSystemProfilePrivilege"
        "Replace a process level token"                                  = "SeAssignPrimaryTokenPrivilege"
        "Restore files and directories"                                  = "SeRestorePrivilege"
        "Shut down the system"                                           = "SeShutdownPrivilege"
        "Take ownership of files or other objects"                       = "SeTakeOwnershipPrivilege"
    }
    
    # Initialize a hashtable to store the results
    $results = @{}
    
    # Read the temporary file and parse the contents
    $content = Get-Content $tempFile
    
    # Loop through the rights mapping and extract their values
    foreach ($entry in $rightsMapping.GetEnumerator()) {
        $displayName = $entry.Key
        $privilegeName = $entry.Value
    
        # Find the line containing the privilege
        $line = $content | Where-Object { $_ -like "*$privilegeName*" }
    
        if ($line) {
            # Extract the SID(s) from the line
            $sids = $line -replace ".*=\s*", "" -split ",\s*"
    
            # Convert SIDs to user-friendly names
            $friendlyNames = foreach ($sid in $sids) {
                try {
                    # Remove the leading asterisk if it exists
                    $sid = $sid.TrimStart('*')
    
                    if ($sid -ne "") {
                        $user = New-Object System.Security.Principal.SecurityIdentifier($sid)
                        $user.Translate([System.Security.Principal.NTAccount]).Value
                    }
                }
                catch {
                    $sid # If conversion fails, return the SID
                }
            }
    
            # Store the friendly names in the results hashtable
            $results[$displayName] = $friendlyNames
        }
        else {
            # If the privilege is not found, record it as not configured
            $results[$displayName] = "Not configured"
        }
    }
    
    # Determine the output file path with incrementing number
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($outputPath)
    $extension = [System.IO.Path]::GetExtension($outputPath)
    $directory = [System.IO.Path]::GetDirectoryName($outputPath)
    $increment = 0
    $newOutputPath = $outputPath
    
    # Loop to find an available filename
    while (Test-Path $newOutputPath) {
        $increment++
        $newOutputPath = Join-Path $directory "$baseName-$increment$extension"
    }
    
    # Check if the JSON file already exists
    if (Test-Path $outputPath) {
        # Read the existing JSON content
        $existingContent = Get-Content $outputPath -Raw | ConvertFrom-Json
        # Convert existing content to a hashtable for easy manipulation
        $existingHashtable = @{}
        foreach ($key in $existingContent.PSObject.Properties.Name) {
            $existingHashtable[$key] = $existingContent.$key
        }
    
        # Append new results to the existing content
        foreach ($key in $results.Keys) {
            if ($existingHashtable.ContainsKey($key)) {
                # If key already exists, update the value
                $existingHashtable[$key] = $results[$key]
            }
            else {
                # If key does not exist, add it
                $existingHashtable[$key] = $results[$key]
            }
        }
    
        # Sort keys alphabetically and prepare the final output
        $finalOutput = @{}
        foreach ($key in $existingHashtable.Keys | Sort-Object) {
            $finalOutput[$key] = $existingHashtable[$key]
        }
    }
    else {
        # Sort keys alphabetically and prepare the final output
        $finalOutput = @{}
        foreach ($key in $results.Keys | Sort-Object) {
            $finalOutput[$key] = $results[$key]
        }
    }
    
    # Convert the final output hashtable to JSON format
    $jsonOutput = $finalOutput | ConvertTo-Json -Depth 3
    
    # Save the output to the specified JSON file
    $jsonOutput | Set-Content $newOutputPath -Force
    
    # Read the JSON file
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json
    
    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}
    
    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }
    
    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100
    
    # Write the JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath
    
    # Remove the temporary file created by secedit
    Remove-Item $tempFile -Force
    
}

function Accounts {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "Accounts.json"
    
    # Export the local security policy to a temporary file
    $tempFile = "$env:temp\secedit.inf"
    secedit /export /cfg $tempFile /quiet
    
    # Define a hashtable to store the settings
    $settings = @{}
    
    # Run secedit to export the security policy to a temporary INF file
    
    # Read the INF file
    $infContent = Get-Content $tempFile
    
    # Function to extract a specific setting from the INF content
    function Get-SettingValue {
        param (
            [string]$settingName
        )
        $escapedSettingName = [regex]::Escape($settingName)
        $value = $infContent | ForEach-Object {
            if ($_ -match "^\s*$escapedSettingName\s*=\s*(.+)\s*$") {
                return $matches[1]
            }
        }
    
        if ($null -eq $value) {
            return "Not Configured"
        }
        else {
            # Process the value to extract the required part
            $processedValue = $value -split ',' | Select-Object -Last 1
            return $processedValue.Trim('"') # Trim quotes if present
        }
    }
    
    # Read and store each required setting
    $settings["Accounts_Block_Microsoft_Accounts"] = Get-SettingValue "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser"
    $settings["Accounts_Guest_Account_Status"] = Get-SettingValue "EnableGuestAccount"
    $settings["Accounts_Limit_Local_Account_Use_Of_Blank_Passwords"] = Get-SettingValue "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse"
    $settings["Accounts_Rename_Administrator_Account"] = Get-SettingValue "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Accounts\AdministratorName"
    $settings["Accounts_Rename_Guest_Account"] = Get-SettingValue "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Accounts\GuestName"
    
    # Convert the hashtable to JSON and save it to the output file
    $settings | ConvertTo-Json | Set-Content $outputPath
    
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json
    
    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}
    
    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }
    
    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100
    
    # Write the JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath
    
    
    # Clean up the temporary INF file
    Remove-Item $tempFile
    
    Write-Output "Settings have been saved to $outputPath"
    
}

function Audit {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "Audit.json"
    
    
    # Function to retrieve the policy setting
    function Get-PolicySetting {
        param (
            [string]$PolicyName
        )
    
        # Execute the secedit command to retrieve the policy
        secedit /export /cfg $env:temp\secedit.inf /quiet
        $policyValue = Select-String -Path "$env:temp\secedit.inf" -Pattern $PolicyName
    
        if ($policyValue) {
            $policyValue = $policyValue -replace ".*=", ""
            $policyValue = $policyValue.Trim()
            # Extract the last value after the comma
            $policyValue = $policyValue.Split(',')[-1].Trim()
        }
        else {
            $policyValue = "Not Configured"
        }
    
        # Remove the temporary file
        Remove-Item "$env:temp\secedit.inf"
    
        return $policyValue
    }
    
    # Retrieve the values for the specified policies
    $policy1 = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\SCENoApplyLegacyAuditPolicy"
    $policy2 = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\CrashOnAuditFail"
    
    # Create a hashtable to store the policies and their values
    $policies = @{
        "Audit: Force audit policy subcategory settings (Windows or later) to override audit policy category settings" = $policy1
        "Audit: Shut down system immediately if unable to log security audits"                                         = $policy2
    }
    
    # Convert the hashtable to JSON and save it to a file
    $policies | ConvertTo-Json | Set-Content -Path $outputPath
    
    Write-Output "Policy settings have been exported to $outputPath"
    
}

function Devices {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "Devices.json"
    
    # Function to retrieve the policy setting
    function Get-PolicySetting {
        param (
            [string]$PolicyName
        )
    
        # Execute the secedit command to retrieve the policy
        secedit /export /cfg $env:temp\secedit.inf /quiet
        $policyValue = Select-String -Path "$env:temp\secedit.inf" -Pattern $PolicyName
    
        if ($policyValue) {
            $policyValue = $policyValue -replace ".*=", ""
            $policyValue = $policyValue.Trim()
            # Extract the last value after the comma
            $policyValue = $policyValue.Split(',')[-1].Trim()
        }
        else {
            $policyValue = "Not Configured"
        }
    
        # Remove the temporary file
        Remove-Item "$env:temp\secedit.inf"
    
        return $policyValue
    }
    
    # Retrieve the value for the specified policy
    $policyValue = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Print\\Providers\\LanMan Print Services\\Servers\\AddPrinterDrivers"
    
    # Create a hashtable to store the policy and its value
    $policies = @{
        "Devices: Prevent users from installing printer drivers" = $policyValue
    }
    
    # Convert the hashtable to JSON and save it to a file
    $policies | ConvertTo-Json | Set-Content -Path $outputPath
    
    Write-Output "Policy setting has been exported to $outputPath"
    
}

function Interactive_Logon {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "InteractiveLogon.json"

    # Function to retrieve the policy setting
    function Get-PolicySetting {
        param (
            [string]$PolicyName
        )

        # Execute the secedit command to retrieve the policy
        secedit /export /cfg $env:temp\secedit.inf /quiet
        $policyValue = Select-String -Path "$env:temp\secedit.inf" -Pattern $PolicyName

        if ($policyValue) {
            $policyValue = $policyValue -replace ".*=", ""
            $policyValue = $policyValue.Trim()
            # Extract the last value after the comma
            $policyValue = $policyValue.Split(',')[-1].Trim()
        }
        else {
            $policyValue = "Not Configured"
        }

        # Remove the temporary file
        Remove-Item "$env:temp\secedit.inf"

        return $policyValue
    }

    # Retrieve the values for the specified policies
    $policies = @{
        "Interactive logon: Do not require CTRL+ALT+DEL"                      = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableCAD"
        "Interactive logon: Don't display last signed-in"                     = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DontDisplayLastUserName"
        "Interactive logon: Machine account lockout threshold"                = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\MaxDevicePasswordFailedAttempts"
        "Interactive logon: Machine inactivity limit"                         = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\InactivityTimeoutSecs"
        "Interactive logon: Message text for users attempting to log on"      = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeText"
        "Interactive logon: Message title for users attempting to log on"     = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\LegalNoticeCaption"
        "Interactive logon: Prompt user to change password before expiration" = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\PasswordExpiryWarning"
        "Interactive logon: Smart card removal behavior"                      = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\ScRemoveOption"
    }

    # Convert the hashtable to JSON and save it to a file
    $policies | ConvertTo-Json | Set-Content -Path $outputPath

    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath


    Write-Output "Policy settings have been exported to $outputPath"

}

function Microsoft_Network_Client {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"
    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "MicrosoftNetworkClient.json"
    
    # Function to retrieve the policy setting
    function Get-PolicySetting {
        param (
            [string]$PolicyName
        )
    
        # Execute the secedit command to retrieve the policy
        secedit /export /cfg $env:temp\secedit.inf /quiet
        $policyValue = Select-String -Path "$env:temp\secedit.inf" -Pattern $PolicyName
    
        if ($policyValue) {
            $policyValue = $policyValue -replace ".*=", ""
            $policyValue = $policyValue.Trim()
            # Extract the last value after the comma
            $policyValue = $policyValue.Split(',')[-1].Trim()
        }
        else {
            $policyValue = "Not Configured"
        }
    
        # Remove the temporary file
        Remove-Item "$env:temp\secedit.inf"
    
        return $policyValue
    }
    
    # Retrieve the values for the specified policies
    $policies = @{
        "Microsoft network client: Digitally sign communications (always)"               = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature"
        "Microsoft network client: Digitally sign communications (if server agrees)"     = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnableSecuritySignature"
        "Microsoft network client: Send unencrypted password to third-party SMB servers" = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\EnablePlainTextPassword"
    }
    
    # Convert the hashtable to JSON and save it to a file
    $policies | ConvertTo-Json -Depth 100 | Set-Content -Path $outputPath
    
    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json
    
    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}
    
    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }
    
    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100
    
    # Write the JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath
    
    Write-Output "Policy settings have been exported and sorted in $outputPath"
    
}

function Microsoft_Network_Server {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "MicrosoftNetworkServer.json"
    
    # Function to retrieve the policy setting
    function Get-PolicySetting {
        param (
            [string]$PolicyName
        )
    
        # Execute the secedit command to retrieve the policy
        secedit /export /cfg $env:temp\secedit.inf /quiet
        $policyValue = Select-String -Path "$env:temp\secedit.inf" -Pattern $PolicyName
    
        if ($policyValue) {
            $policyValue = $policyValue -replace ".*=", ""
            $policyValue = $policyValue.Trim()
            # Extract the last value after the comma
            $policyValue = $policyValue.Split(',')[-1].Trim()
        }
        else {
            $policyValue = "Not Configured"
        }
    
        # Remove the temporary file
        Remove-Item "$env:temp\secedit.inf"
    
        return $policyValue
    }
    
    # Retrieve the values for the specified policies
    $policies = @{
        "Microsoft network server: Amount of idle time required before suspending session" = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\AutoDisconnect"
        "Microsoft network server: Digitally sign communications (always)"                 = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature"
        "Microsoft network server: Digitally sign communications (if client agrees)"       = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\EnableSecuritySignature"
        "Microsoft network server: Disconnect clients when logon hours expire"             = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\EnableForcedLogOff"
        "Microsoft network server: Server SPN target name validation level"                = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SmbServerNameHardeningLevel"
    }
    
    # Convert the hashtable to JSON and save it to a file
    $policies | ConvertTo-Json -Depth 100 | Set-Content -Path $outputPath
    
    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json
    
    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}
    
    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }
    
    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100
    
    # Write the JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath
    
    Write-Output "Policy settings have been exported and sorted in $outputPath"
    
}

function Network_Access {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "NetworkAccess.json"
    
    # Function to retrieve the policy setting
    function Get-PolicySetting {
        param (
            [string]$PolicyName
        )
    
        # Execute the secedit command to retrieve the policy
        secedit /export /cfg $env:temp\secedit.inf /quiet
        $policyValue = Select-String -Path "$env:temp\secedit.inf" -Pattern "^\s*$PolicyName\s*=" -AllMatches
    
        if ($policyValue) {
            $policyValue = $policyValue -replace ".*=", ""
            $policyValue = $policyValue.Trim()
    
            # Special handling for "Remotely accessible registry paths" and "Remotely accessible registry paths and sub-paths"
            if ($PolicyName -match "AllowedExactPaths" -or $PolicyName -match "AllowedPaths") {
                # Remove any prefixes like "Machine=7," and split into an array
                $paths = $policyValue -replace "\d+,", "" -replace "\s+", "" -split ","
                return ($paths -join ",").Trim() # Join the paths with commas and trim any extra spaces
            }
    
            # Extract the last value after the comma for other policies
            $policyValue = $policyValue.Split(',')[-1].Trim()
        }
        else {
            $policyValue = "Not Configured"
        }
    
        # Remove the temporary file
        Remove-Item "$env:temp\secedit.inf"
    
        return $policyValue
    }
    
    # Retrieve the values for the specified policies
    $policies = @{
        "Network access: Allow anonymous SID/Name translation"                                         = Get-PolicySetting "LSAAnonymousNameLookup"
        "Network access: Do not allow anonymous enumeration of SAM accounts"                           = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymousSAM"
        "Network access: Do not allow anonymous enumeration of SAM accounts and shares"                = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous"
        "Network access: Do not allow storage of passwords and credentials for network authentication" = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\DisableDomainCreds"
        "Network access: Let Everyone permissions apply to anonymous users"                            = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\EveryoneIncludesAnonymous"
        "Network access: Named Pipes that can be accessed anonymously"                                 = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\NullSessionPipes"
        "Network access: Remotely accessible registry paths"                                           = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedExactPaths\\Machine"
        "Network access: Remotely accessible registry paths and sub-paths"                             = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\SecurePipeServers\\Winreg\\AllowedPaths\\Machine"
        "Network access: Restrict anonymous access to Named Pipes and Shares"                          = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RestrictNullSessAccess"
        "Network access: Restrict clients allowed to make remote calls to SAM"                         = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\restrictremotesam"
        "Network access: Shares that can be accessed anonymously"                                      = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\NullSessionShares"
        "Network access: Sharing and security model for local accounts"                                = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\ForceGuest"
    }
    
    # Convert the hashtable to JSON and save it to a file
    $policies | ConvertTo-Json -Depth 100 | Set-Content -Path $outputPath
    
    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json
    
    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}
    
    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }
    
    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100
    
    # Write the JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath
    
    Write-Output "Policy settings have been exported and sorted in $outputPath"
    
}

function Network_Security {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "NetworkSecurity.json"

    # Function to retrieve the policy setting
    function Get-PolicySetting {
        param (
            [string]$PolicyName
        )

        # Execute the secedit command to retrieve the policy
        secedit /export /cfg $env:temp\secedit.inf /quiet
        $policyValue = Select-String -Path "$env:temp\secedit.inf" -Pattern "^\s*$PolicyName\s*=" -AllMatches

        if ($policyValue) {
            $policyValue = $policyValue -replace ".*=", ""
            $policyValue = $policyValue.Trim()
        
            # Extract the last value after the comma
            $policyValue = $policyValue.Split(',')[-1].Trim()
        }
        else {
            $policyValue = "Not Configured"
        }

        # Remove the temporary file
        Remove-Item "$env:temp\secedit.inf"

        return $policyValue
    }

    # Retrieve the values for the specified policies
    $policies = @{
        "Network security: Allow Local System to use computer identity for NTLM"                          = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\UseMachineId"
        "Network security: Allow LocalSystem NULL session fallback"                                       = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\allownullsessionfallback"
        "Network Security: Allow PKU2U authentication requests to this computer to use online identities" = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\pku2u\\AllowOnlineID"
        "Network security: Configure encryption types allowed for Kerberos"                               = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\SupportedEncryptionTypes"
        "Network security: Do not store LAN Manager hash value on next password change"                   = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\NoLMHash"
        "Network security: Force logoff when logon hours expire"                                          = Get-PolicySetting "ForceLogoffWhenHourExpire"
        "Network security: LAN Manager authentication level"                                              = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\LmCompatibilityLevel"
        "Network security: LDAP client signing requirements"                                              = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Services\\LDAP\\LDAPClientIntegrity"
        "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients"    = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinClientSec"
        "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers"    = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\NTLMMinServerSec"
        "Network security: Restrict NTLM: Audit Incoming NTLM Traffic"                                    = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\AuditReceivingNTLMTraffic"
        "Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers"                        = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\RestrictSendingNTLMTraffic"
    }

    # Convert the hashtable to JSON and save it to a file
    $policies | ConvertTo-Json -Depth 100 | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Policy settings have been exported and sorted in $outputPath"

}

function System_Cryptography {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "SystemCryptography.json"

    # Function to retrieve the policy setting
    function Get-PolicySetting {
        param (
            [string]$PolicyName
        )

        # Execute the secedit command to retrieve the policy
        secedit /export /cfg $env:temp\secedit.inf /quiet
        $policyValue = Select-String -Path "$env:temp\secedit.inf" -Pattern "^\s*$PolicyName\s*=" -AllMatches

        if ($policyValue) {
            $policyValue = $policyValue -replace ".*=", ""
            $policyValue = $policyValue.Trim()
        
            # Extract the last value after the comma
            $policyValue = $policyValue.Split(',')[-1].Trim()
        }
        else {
            $policyValue = "Not Configured"
        }

        # Remove the temporary file
        Remove-Item "$env:temp\secedit.inf"

        return $policyValue
    }

    # Retrieve the values for the specified policies
    $policies = @{
        "System cryptography: Force strong key protection for user keys stored on the computer" = Get-PolicySetting "MACHINE\\Software\\Policies\\Microsoft\\Cryptography\\ForceKeyProtection"
 
    }

    # Convert the hashtable to JSON and save it to a file
    $policies | ConvertTo-Json -Depth 100 | Set-Content -Path $outputPath



    Write-Output "Policy settings have been exported and sorted in $outputPath"

}

function System_Objects {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "SystemObjects.json"

    # Function to retrieve the policy setting
    function Get-PolicySetting {
        param (
            [string]$PolicyName
        )

        # Execute the secedit command to retrieve the policy
        secedit /export /cfg $env:temp\secedit.inf /quiet
        $policyValue = Select-String -Path "$env:temp\secedit.inf" -Pattern "^\s*$PolicyName\s*=" -AllMatches

        if ($policyValue) {
            $policyValue = $policyValue -replace ".*=", ""
            $policyValue = $policyValue.Trim()
        
            # Extract the last value after the comma
            $policyValue = $policyValue.Split(',')[-1].Trim()
        }
        else {
            $policyValue = "Not Configured"
        }

        # Remove the temporary file
        Remove-Item "$env:temp\secedit.inf"

        return $policyValue
    }

    # Retrieve the values for the specified policies
    $policies = @{
        "System objects: Require case insensitivity for non-Windows subsystems"                           = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\Kernel\\ObCaseInsensitive"
        "System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)" = Get-PolicySetting "MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\ProtectionMode"
    }

    # Convert the hashtable to JSON and save it to a file
    $policies | ConvertTo-Json -Depth 100 | Set-Content -Path $outputPath

    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to the file
    $orderedJsonJson | Set-Content -Path $outputPath


    Write-Output "Policy settings have been exported and sorted in $outputPath"

}

function User_Account_Control {
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "UserAccountControl.json"

    # Function to retrieve the policy setting
    function Get-PolicySetting {
        param (
            [string]$PolicyName
        )

        # Execute the secedit command to retrieve the policy
        secedit /export /cfg $env:temp\secedit.inf /quiet
        $policyValue = Select-String -Path "$env:temp\secedit.inf" -Pattern "^\s*$PolicyName\s*=" -AllMatches

        if ($policyValue) {
            $policyValue = $policyValue -replace ".*=", ""
            $policyValue = $policyValue.Trim()
        
            # Extract the last value after the comma
            $policyValue = $policyValue.Split(',')[-1].Trim()
        }
        else {
            $policyValue = "Not Configured"
        }

        # Remove the temporary file
        Remove-Item "$env:temp\secedit.inf"

        return $policyValue
    }

    # Retrieve the values for the specified policies
    $policies = @{
        "User Account Control: Admin Approval Mode for the Built-in Administrator account"                 = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\FilterAdministratorToken"
        "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" = Get-PolicySetting "MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin"
        "User Account Control: Behavior of the elevation prompt for standard users"                        = Get-PolicySetting "MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser"
        "User Account Control: Detect application installations and prompt for elevation"                  = Get-PolicySetting "MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableInstallerDetection"
        "User Account Control: Only elevate UIAccess applications that are installed in secure locations"  = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableSecureUIAPaths"
        "User Account Control: Run all administrators in Admin Approval Mode"                              = Get-PolicySetting "MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA"
        "User Account Control: Switch to the secure desktop when prompting for elevation"                  = Get-PolicySetting "MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop"
        "User Account Control: Virtualize file and registry write failures to per-user locations"          = Get-PolicySetting "MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableVirtualization"
    }

    # Convert the hashtable to JSON and save it to a file
    $policies | ConvertTo-Json -Depth 100 | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Policy settings have been exported and sorted in $outputPath"

}

function System_Services {
    # Resolve the output directory
    $outputDirectory = Resolve-Path "$PSScriptRoot\Output"

    # Define the output file path
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "SystemServices.json"
    
    # Function to map startup types to their string equivalents
    function Map_StartupType {
        param (
            [string]$startupType
        )
    
        switch ($startupType) {
            "Automatic" { return "Automatic" }
            "Manual" { return "Manual" }
            "Disabled" { return "Disabled" }
            default { return "Not Configured" }
        }
    }
    

    # Function to retrieve the service startup type
    function Get-ServiceStartupType {
        param (
            [string]$ServiceName
        )

        # Get the service object
        $serviceObject = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

        if ($serviceObject) {
            # Get the startup type of the service
            $serviceStartupType = (Get-WmiObject -Class Win32_Service -Filter "Name='$ServiceName'").StartMode
            $serviceStartupType = Map_StartupType $serviceStartupType
        }
        else {
            $serviceStartupType = "Not Configured"
        }

        return $serviceStartupType
    }

    # Retrieve the startup types for the specified services
    $services = @{
        "Bluetooth Audio Gateway Service (BTAGService)"                       = Get-ServiceStartupType "BTAGService"
        "Bluetooth Support Service (bthserv)"                                 = Get-ServiceStartupType "bthserv"
        "Computer Browser (Browser)"                                          = Get-ServiceStartupType "Browser"
        "Downloaded Maps Manager (MapsBroker)"                                = Get-ServiceStartupType "MapsBroker"
        "Geolocation Service (lfsvc)"                                         = Get-ServiceStartupType "lfsvc"
        "IIS Admin Service (IISADMIN)"                                        = Get-ServiceStartupType "IISADMIN"
        "Infrared monitor service (irmon)"                                    = Get-ServiceStartupType "irmon"
        "Link-Layer Topology Discovery Mapper (lltdsvc)"                      = Get-ServiceStartupType "lltdsvc"
        "LxssManager (LxssManager)"                                           = Get-ServiceStartupType "LxssManager"
        "Microsoft FTP Service (FTPSVC)"                                      = Get-ServiceStartupType "FTPSVC"
        "Microsoft iSCSI Initiator Service (MSiSCSI)"                         = Get-ServiceStartupType "MSiSCSI"
        "OpenSSH SSH Server (sshd)"                                           = Get-ServiceStartupType "sshd"
        "Peer Name Resolution Protocol (PNRPsvc)"                             = Get-ServiceStartupType "PNRPsvc"
        "Peer Networking Grouping (p2psvc)"                                   = Get-ServiceStartupType "p2psvc"
        "Peer Networking Identity Manager (p2pimsvc)"                         = Get-ServiceStartupType "p2pimsvc"
        "PNRP Machine Name Publication Service (PNRPAutoReg)"                 = Get-ServiceStartupType "PNRPAutoReg"
        "Print Spooler (Spooler)"                                             = Get-ServiceStartupType "Spooler"
        "Problem Reports and Solutions Control Panel Support (wercplsupport)" = Get-ServiceStartupType "wercplsupport"
        "Remote Access Auto Connection Manager (RasAuto)"                     = Get-ServiceStartupType "RasAuto"
        "Remote Desktop Configuration (SessionEnv)"                           = Get-ServiceStartupType "SessionEnv"
        "Remote Desktop Services (TermService)"                               = Get-ServiceStartupType "TermService"
        "Remote Desktop Services UserMode Port Redirector (UmRdpService)"     = Get-ServiceStartupType "UmRdpService"
        "Remote Procedure Call (RPC) Locator (RpcLocator)"                    = Get-ServiceStartupType "RpcLocator"
        "Remote Registry (RemoteRegistry)"                                    = Get-ServiceStartupType "RemoteRegistry"
        "Routing and Remote Access (RemoteAccess)"                            = Get-ServiceStartupType "RemoteAccess"
        "Server (LanmanServer)"                                               = Get-ServiceStartupType "LanmanServer"
        "Simple TCP/IP Services (simptcp)"                                    = Get-ServiceStartupType "simptcp"
        "SNMP Service (SNMP)"                                                 = Get-ServiceStartupType "SNMP"
        "Special Administration Console Helper (sacsvr)"                      = Get-ServiceStartupType "sacsvr"
        "SSDP Discovery (SSDPSRV)"                                            = Get-ServiceStartupType "SSDPSRV"
        "UPnP Device Host (upnphost)"                                         = Get-ServiceStartupType "upnphost"
        "Web Management Service (WMSvc)"                                      = Get-ServiceStartupType "WMSvc"
        "Windows Error Reporting Service (WerSvc)"                            = Get-ServiceStartupType "WerSvc"
        "Windows Event Collector (Wecsvc)"                                    = Get-ServiceStartupType "Wecsvc"
        "Windows Media Player Network Sharing Service (WMPNetworkSvc)"        = Get-ServiceStartupType "WMPNetworkSvc"
        "Windows Mobile Hotspot Service (icssvc)"                             = Get-ServiceStartupType "icssvc"
        "Windows Push Notifications System Service (WpnService)"              = Get-ServiceStartupType "WpnService"
        "Windows PushToInstall Service (PushToInstall)"                       = Get-ServiceStartupType "PushToInstall"
        "Windows Remote Management (WS-Management) (WinRM)"                   = Get-ServiceStartupType "WinRM"
        "World Wide Web Publishing Service (W3SVC)"                           = Get-ServiceStartupType "W3SVC"
        "Xbox Accessory Management Service (XboxGipSvc)"                      = Get-ServiceStartupType "XboxGipSvc"
        "Xbox Live Auth Manager (XblAuthManager)"                             = Get-ServiceStartupType "XblAuthManager"
        "Xbox Live Game Save (XblGameSave)"                                   = Get-ServiceStartupType "XblGameSave"
        "Xbox Live Networking Service (XboxNetApiSvc)"                        = Get-ServiceStartupType "XboxNetApiSvc"
    }

    # Convert the hashtable to JSON and save it to a file
    $services | ConvertTo-Json -Depth 100 | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Service startup types have been exported and sorted in $outputPath"

}

function Private_Profile {
    # Define the registry paths
    $customPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
    $loggingCustomPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"


    # Output JSON file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "PrivateFirewallSettings.json"

    # Function to retrieve registry value
    function Get-RegistryValue {
        param (
            [string]$Path,
            [string]$Name
        )
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            return $value.$Name
        }
        return $null
    }

    # Firewall settings to retrieve
    $settings = @{
        "FirewallState"            = @{
            "Name" = "EnableFirewall"
            "Path" = $customPath
        }
        "InboundConnections"       = @{
            "Name" = "DefaultInboundAction"
            "Path" = $customPath
        }
        "DisplayNotification"      = @{
            "Name" = "DisableNotifications"
            "Path" = $customPath
        }
        "LogFileName"              = @{
            "Name" = "LogFilePath"
            "Path" = $loggingCustomPath
        }
        "LogFileSize"              = @{
            "Name" = "LogFileSize"
            "Path" = $loggingCustomPath
        }
        "LogDroppedPackets"        = @{
            "Name" = "LogDroppedPackets"
            "Path" = $loggingCustomPath
        }
        "LogSuccessfulConnections" = @{
            "Name" = "LogSuccessfulConnections"
            "Path" = $loggingCustomPath
        }
    }

    # Initialize the results hashtable
    $results = @{}

    # Retrieve values for each setting
    foreach ($setting in $settings.GetEnumerator()) {
        $value = Get-RegistryValue -Path $setting.Value.Path -Name $setting.Value.Name
   
        # Handle null and convert registry return values (0/1) to meaningful descriptions if necessary
        switch ($setting.Key) {
            "FirewallState" { 
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                elseif ($value -eq 1) {
                    $results[$setting.Key] = "Enabled"
                }
                else {
                    $results[$setting.Key] = "Disabled"
                } 
            }
            "InboundConnections" { 
                $defaultInboundAction = Get-RegistryValue -Path $customPath -Name "DefaultInboundAction"
                $doNotAllowExceptions = Get-RegistryValue -Path $customPath -Name "DoNotAllowExceptions"

                if ($defaultInboundAction -eq 1 -and $doNotAllowExceptions -eq 1) {
                    $results[$setting.Key] = "Block all connections"
                }
                elseif ($defaultInboundAction -eq 1) {
                    $results[$setting.Key] = "Block"
                }
                elseif ($defaultInboundAction -eq 0) {
                    $results[$setting.Key] = "Allow"
                }
                else {
                    $results[$setting.Key] = "Not Configured"
                }
            }
            "DisplayNotification" { 
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                elseif ($value -eq 1) {
                    $results[$setting.Key] = "Disabled"
                }
                else {
                    $results[$setting.Key] = "Enabled"
                } 
            }
            "LogDroppedPackets" {
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                elseif ($value -eq 1) {
                    $results[$setting.Key] = "Enabled"
                }
                else {
                    $results[$setting.Key] = "Disabled"
                }
            }

            "LogSuccessfulConnections" {
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                elseif ($value -eq 1) {
                    $results[$setting.Key] = "Enabled"
                }
                else {
                    $results[$setting.Key] = "Disabled"
                }
            }

            "LogFileName" {
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                else {
                    $results[$setting.Key] = $value
                }
            }

            "LogFilesize" {
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                else {
                    $results[$setting.Key] = $value
                }
            }
            default { 
                $results[$setting.Key] = $value 
            }
        }
    }

    # Export the results to JSON
    $results | ConvertTo-Json | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Firewall settings successfully saved to $outputPath"
}

function Public_Profile {
    # Define the registry paths
    $customPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
    $loggingCustomPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"


    # Output JSON file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "PublicFirewallSettings.json"

    # Function to retrieve registry value
    function Get-RegistryValue {
        param (
            [string]$Path,
            [string]$Name
        )
        if (Test-Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
            return $value.$Name
        }
        return $null
    }

    # Firewall settings to retrieve
    $settings = @{
        "FirewallState"                = @{
            "Name" = "EnableFirewall"
            "Path" = $customPath
        }
        "InboundConnections"           = @{
            "Name" = "DefaultInboundAction"
            "Path" = $customPath
        }
        "DisplayNotification"          = @{
            "Name" = "DisableNotifications"
            "Path" = $customPath
        }
        "LocalFirewallRules"           = @{
            "Name" = "AllowLocalPolicyMerge"
            "Path" = $customPath
        }
        "LocalConnectionSecurityRules" = @{
            "Name" = "AllowLocalIPsecPolicyMerge"
            "Path" = $customPath
        }
        "LogFileName"                  = @{
            "Name" = "LogFilePath"
            "Path" = $loggingCustomPath
        }
        "LogFileSize"                  = @{
            "Name" = "LogFileSize"
            "Path" = $loggingCustomPath
        }
        "LogDroppedPackets"            = @{
            "Name" = "LogDroppedPackets"
            "Path" = $loggingCustomPath
        }
        "LogSuccessfulConnections"     = @{
            "Name" = "LogSuccessfulConnections"
            "Path" = $loggingCustomPath
        }
    }

    # Initialize the results hashtable
    $results = @{}

    # Retrieve values for each setting
    foreach ($setting in $settings.GetEnumerator()) {
        $value = Get-RegistryValue -Path $setting.Value.Path -Name $setting.Value.Name
   
        # Handle null and convert registry return values (0/1) to meaningful descriptions if necessary
        switch ($setting.Key) {
            "FirewallState" { 
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                elseif ($value -eq 1) {
                    $results[$setting.Key] = "Enabled"
                }
                else {
                    $results[$setting.Key] = "Disabled"
                } 
            }
            "InboundConnections" { 
                $defaultInboundAction = Get-RegistryValue -Path $customPath -Name "DefaultInboundAction"
                $doNotAllowExceptions = Get-RegistryValue -Path $customPath -Name "DoNotAllowExceptions"

                if ($defaultInboundAction -eq 1 -and $doNotAllowExceptions -eq 1) {
                    $results[$setting.Key] = "Block all connections"
                }
                elseif ($defaultInboundAction -eq 1) {
                    $results[$setting.Key] = "Block"
                }
                elseif ($defaultInboundAction -eq 0) {
                    $results[$setting.Key] = "Allow"
                }
                else {
                    $results[$setting.Key] = "Not Configured"
                }
            }
            "DisplayNotification" { 
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                elseif ($value -eq 1) {
                    $results[$setting.Key] = "Disabled"
                }
                else {
                    $results[$setting.Key] = "Enabled"
                } 
            }

            "LocalFirewallRules" { 
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                elseif ($value -eq 1) {
                    $results[$setting.Key] = "Enabled"
                }
                else {
                    $results[$setting.Key] = "Disabled"
                } 
            }

            "LocalConnectionSecurityRules" {
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                elseif ($value -eq 1) {
                    $results[$setting.Key] = "Enabled"
                }
                else {
                    $results[$setting.Key] = "Disabled"
                } 
            }

            "LogDroppedPackets" {
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                elseif ($value -eq 1) {
                    $results[$setting.Key] = "Enabled"
                }
                else {
                    $results[$setting.Key] = "Disabled"
                }
            }

            "LogSuccessfulConnections" {
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                elseif ($value -eq 1) {
                    $results[$setting.Key] = "Enabled"
                }
                else {
                    $results[$setting.Key] = "Disabled"
                }
            }

            "LogFileName" {
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                else {
                    $results[$setting.Key] = $value
                }
            }

            "LogFilesize" {
                if ($null -eq $value) {
                    $results[$setting.Key] = "Not Configured"
                }
                else {
                    $results[$setting.Key] = $value
                }
            }
            default { 
                $results[$setting.Key] = $value 
            }
        }
    }

    # Export the results to JSON
    $results | ConvertTo-Json | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Firewall settings successfully saved to $outputPath"
}

function Account_Logon {
    # Define the output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "AccountLogon.json"

    # Create the directory if it doesn't exist
    if (-not (Test-Path $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force
    }

    # Run auditpol to get the specific audit policy setting for "Audit Credential Validation"
    $auditResult = auditpol /get /subcategory:"Credential Validation"

    # Parse the audit policy result
    $policyLines = $auditResult -split "`n" | Where-Object { $_ -match "Credential Validation" }

    # Determine Success and Failure settings
    $successEnabled = $policyLines -match "Success"
    $failureEnabled = $policyLines -match "Failure"

    # Create the status string based on the results
    $auditStatus = if ($successEnabled -and $failureEnabled) {
        "Success and Failure"
    }
    elseif ($successEnabled) {
        "Success"
    }
    elseif ($failureEnabled) {
        "Failure"
    }
    else {
        "Not Configured"
    }

    # Create a custom object to store the result in the desired format
    $customObject = [PSCustomObject]@{
        "Audit Credential Validation" = $auditStatus
    }

    # Output the result to a JSON file in the specified path
    $customObject | ConvertTo-Json | Out-File -FilePath $outputPath -Force



}

function Account_Management {
    # Define the output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "AccountManagement.json"

    # Create the directory if it doesn't exist
    if (-not (Test-Path $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force
    }

    # List of subcategories to query
    $subcategories = @(
        "Application Group Management",
        "Security Group Management",
        "User Account Management"
    )

    # Initialize an empty hashtable to store results
    $results = @{}

    # Loop through each subcategory, get its audit policy and add it to the hashtable
    foreach ($subcategory in $subcategories) {
        # Run auditpol to get the specific audit policy setting for the current subcategory
        $auditResult = auditpol /get /subcategory:$subcategory

        # Parse the audit policy result
        $policyLines = $auditResult -split "`n" | Where-Object { $_ -match $subcategory }

        # Determine Success and Failure settings
        $successEnabled = $policyLines -match "Success"
        $failureEnabled = $policyLines -match "Failure"

        # Create the status string based on the results
        $auditStatus = if ($successEnabled -and $failureEnabled) {
            "Success and Failure"
        }
        elseif ($successEnabled) {
            "Success"
        }
        elseif ($failureEnabled) {
            "Failure"
        }
        else {
            "Not Configured"
        }

        # Add the result to the hashtable with the format: "Name": value
        $results["Audit $subcategory"] = $auditStatus
    }

    # Convert the hashtable to JSON and save it to the output path
    $results | ConvertTo-Json | Out-File -FilePath $outputPath -Force

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath


}

function Detailed_Tracking {
    # Define the output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "DetailedTracking.json"

    # Create the directory if it doesn't exist
    if (-not (Test-Path $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force
    }

    # List of subcategories to query
    $subcategories = @(
        "Process Creation",
        "Plug and Play Events"
    )

    # Initialize an empty hashtable to store results
    $results = @{}

    # Loop through each subcategory, get its audit policy and add it to the hashtable
    foreach ($subcategory in $subcategories) {
        # Run auditpol to get the specific audit policy setting for the current subcategory
        $auditResult = auditpol /get /subcategory:$subcategory

        # Parse the audit policy result
        $policyLines = $auditResult -split "`n" | Where-Object { $_ -match $subcategory }

        # Determine Success and Failure settings
        $successEnabled = $policyLines -match "Success"
        $failureEnabled = $policyLines -match "Failure"

        # Create the status string based on the results
        $auditStatus = if ($successEnabled -and $failureEnabled) {
            "Success and Failure"
        }
        elseif ($successEnabled) {
            "Success"
        }
        elseif ($failureEnabled) {
            "Failure"
        }
        else {
            "Not Configured"
        }

        # Add the result to the hashtable with the format: "Name": value
        $results["Audit $subcategory"] = $auditStatus
    }

    # Convert the hashtable to JSON and save it to the output path
    $results | ConvertTo-Json | Out-File -FilePath $outputPath -Force

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath
}

function Logon_Logoff {
    # Define the output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "LogonLogoff.json"

    # Create the directory if it doesn't exist
    if (-not (Test-Path $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force
    }

    # List of subcategories to query
    $subcategories = @(
        "Account Lockout",
        "Group Membership",
        "Logoff",
        "Logon",
        "Other Logon/Logoff Events",
        "Special Logon"
    )

    # Initialize an empty hashtable to store results
    $results = @{}

    # Loop through each subcategory, get its audit policy and add it to the hashtable
    foreach ($subcategory in $subcategories) {
        # Run auditpol to get the specific audit policy setting for the current subcategory
        $auditResult = auditpol /get /subcategory:"$subcategory"

        # If auditpol failed, skip the entry
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error retrieving $subcategory. Skipping..."
            continue
        }

        # Parse the audit policy result
        $policyLines = $auditResult -split "`n" | Where-Object { $_ -match $subcategory }

        # Determine Success and Failure settings
        $successEnabled = $policyLines -match "Success"
        $failureEnabled = $policyLines -match "Failure"

        # Create the status string based on the results
        $auditStatus = if ($successEnabled -and $failureEnabled) {
            "Success and Failure"
        }
        elseif ($successEnabled) {
            "Success"
        }
        elseif ($failureEnabled) {
            "Failure"
        }
        else {
            "None"
        }

        # Add the result to the hashtable with the format: "Name": value
        $results["Audit $subcategory"] = $auditStatus
    }

    # Convert the hashtable to JSON and save it to the output path
    $results | ConvertTo-Json | Out-File -FilePath $outputPath -Force

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

}

function Object_Access {
    # Define the output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "ObjectAccess.json"

    # Create the directory if it doesn't exist
    if (-not (Test-Path $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force
    }

    # List of subcategories to query
    $subcategories = @(
        "Detailed File Share",
        "File Share",
        "Other Object Access Events",
        "Removable Storage"
    )

    # Initialize an empty hashtable to store results
    $results = @{}

    # Loop through each subcategory, get its audit policy and add it to the hashtable
    foreach ($subcategory in $subcategories) {
        # Run auditpol to get the specific audit policy setting for the current subcategory
        $auditResult = auditpol /get /subcategory:"$subcategory"

        # If auditpol failed, skip the entry
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error retrieving $subcategory. Skipping..."
            continue
        }

        # Parse the audit policy result
        $policyLines = $auditResult -split "`n" | Where-Object { $_ -match $subcategory }

        # Determine Success and Failure settings
        $successEnabled = $policyLines -match "Success"
        $failureEnabled = $policyLines -match "Failure"

        # Create the status string based on the results
        $auditStatus = if ($successEnabled -and $failureEnabled) {
            "Success and Failure"
        }
        elseif ($successEnabled) {
            "Success"
        }
        elseif ($failureEnabled) {
            "Failure"
        }
        else {
            "None"
        }

        # Add the result to the hashtable with the format: "Name": value
        $results["Audit $subcategory"] = $auditStatus
    }

    # Convert the hashtable to JSON and save it to the output path
    $results | ConvertTo-Json | Out-File -FilePath $outputPath -Force

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

}

function Policy_Change {
    # Define the output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "PolicyChange.json"

    # Create the directory if it doesn't exist
    if (-not (Test-Path $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force
    }

    # List of subcategories to query
    $subcategories = @(
        "Audit Policy Change",
        "Authentication Policy Change",
        "Authorization Policy Change",
        "MPSSVC Rule-Level Policy Change",
        "Other Policy Change Events"
    )

    # Initialize an empty hashtable to store results
    $results = @{}

    # Loop through each subcategory, get its audit policy and add it to the hashtable
    foreach ($subcategory in $subcategories) {
        # Run auditpol to get the specific audit policy setting for the current subcategory
        $auditResult = auditpol /get /subcategory:"$subcategory"

        # If auditpol failed, skip the entry
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error retrieving $subcategory. Skipping..."
            continue
        }

        # Parse the audit policy result
        $policyLines = $auditResult -split "`n" | Where-Object { $_ -match $subcategory }

        # Determine Success and Failure settings
        $successEnabled = $policyLines -match "Success"
        $failureEnabled = $policyLines -match "Failure"

        # Create the status string based on the results
        $auditStatus = if ($successEnabled -and $failureEnabled) {
            "Success and Failure"
        }
        elseif ($successEnabled) {
            "Success"
        }
        elseif ($failureEnabled) {
            "Failure"
        }
        else {
            "None"
        }

        # Add the result to the hashtable with the format: "Name": value
        $results["Audit $subcategory"] = $auditStatus
    }

    # Convert the hashtable to JSON and save it to the output path
    $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputPath -Force

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

}

function Privilege_Use {
    # Define the output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "PrivilegeUse.json"

    # Create the directory if it doesn't exist
    if (-not (Test-Path $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force
    }

    # Define the subcategory to query
    $subcategory = "Sensitive Privilege Use"

    # Initialize a hashtable to store the result
    $results = @{}

    # Run auditpol to get the specific audit policy setting for the subcategory
    $auditResult = auditpol /get /subcategory:"$subcategory"

    # If auditpol failed, output an error message
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error retrieving $subcategory. Exiting..."
        exit
    }

    # Parse the audit policy result
    $policyLines = $auditResult -split "`n" | Where-Object { $_ -match $subcategory }

    # Determine Success and Failure settings
    $successEnabled = $policyLines -match "Success"
    $failureEnabled = $policyLines -match "Failure"

    # Create the status string based on the results
    $auditStatus = if ($successEnabled -and $failureEnabled) {
        "Success and Failure"
    }
    elseif ($successEnabled) {
        "Success"
    }
    elseif ($failureEnabled) {
        "Failure"
    }
    else {
        "None"
    }

    # Add the result to the hashtable with the format: "Name": value
    $results["Audit $subcategory"] = $auditStatus

    # Convert the hashtable to JSON and save it to the output path
    $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputPath -Force



}

function System {
    # Define the output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "System.json"

    # Create the directory if it doesn't exist
    if (-not (Test-Path $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force
    }

    # List of subcategories to query
    $subcategories = @(
        "IPsec Driver",
        "Other System Events",
        "Security State Change",
        "Security System Extension",
        "System Integrity"
    )

    # Initialize an empty hashtable to store results
    $results = @{}

    # Loop through each subcategory, get its audit policy and add it to the hashtable
    foreach ($subcategory in $subcategories) {
        # Run auditpol to get the specific audit policy setting for the current subcategory
        $auditResult = auditpol /get /subcategory:"$subcategory"

        # If auditpol failed, skip the entry
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Error retrieving $subcategory. Skipping..."
            continue
        }

        # Parse the audit policy result
        $policyLines = $auditResult -split "`n" | Where-Object { $_ -match $subcategory }

        # Determine Success and Failure settings
        $successEnabled = $policyLines -match "Success"
        $failureEnabled = $policyLines -match "Failure"

        # Create the status string based on the results
        $auditStatus = if ($successEnabled -and $failureEnabled) {
            "Success and Failure"
        }
        elseif ($successEnabled) {
            "Success"
        }
        elseif ($failureEnabled) {
            "Failure"
        }
        else {
            "None"
        }

        # Add the result to the hashtable with the format: "Name": value
        $results["Audit $subcategory"] = $auditStatus
    }

    # Convert the hashtable to JSON and save it to the output path
    $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputPath -Force

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath


}

function Personalization {
    # Define output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "Personalization.json"

    # Ensure the output directory exists
    if (-not (Test-Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }

    # Registry path for lock screen settings
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"

    # Initialize hash table to store results
    $settings = @{}

    # Function to check and return value as 'Enabled', 'Disabled', or 'Not Configured'
    function Get-SettingValue {
        param ($regValue)

        if ($null -eq $regValue) {
            return "Disabled"
        }
        elseif ($regValue -eq 1) {
            return "Enabled"
        }
        elseif ($regValue -eq 0) {
            return "Disabled"
        }
    }

    # Get 'Prevent enabling lock screen camera' setting
    $cameraSetting = Get-ItemProperty -Path $registryPath -Name "NoLockScreenCamera" -ErrorAction SilentlyContinue
    $settings["PreventEnablingLockScreenCamera"] = Get-SettingValue($cameraSetting.NoLockScreenCamera)

    # Get 'Prevent enabling lock screen slide show' setting
    $slideshowSetting = Get-ItemProperty -Path $registryPath -Name "NoLockScreenSlideshow" -ErrorAction SilentlyContinue
    $settings["PreventEnablingLockScreenSlideShow"] = Get-SettingValue($slideshowSetting.NoLockScreenSlideshow)

    # Convert hash table to JSON
    $jsonOutput = $settings | ConvertTo-Json

    # Output the JSON to the specified file
    $jsonOutput | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Host "Settings have been written to: $outputPath"

}

function Handwriting_Personalization {
    # Define output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "HandwritingPersonalization.json"

    # Ensure the output directory exists
    if (-not (Test-Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }

    # Function to check and return value as 'Enabled', 'Disabled', or 'Not Configured'
    function Get-SettingValue {
        param ($regValue)

        if ($null -eq $regValue) {
            return "Not Configured"
        }
        elseif ($regValue -eq 1) {
            return "Enabled"
        }
        elseif ($regValue -eq 0) {
            return "Disabled"
        }
    }

    # Initialize hash table to store results
    $settings = @{}

    # Get 'Allow users to enable online speech recognition services' setting
    $speechRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
    $speechSetting = Get-ItemProperty -Path $speechRegPath -Name "AllowInputPersonalization" -ErrorAction SilentlyContinue
    $settings["AllowUsersToEnableOnlineSpeechRecognitionServices"] = Get-SettingValue($speechSetting.AllowInputPersonalization)

    # Get 'Allow Online Tips' setting
    $cloudRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $tipsSetting = Get-ItemProperty -Path $cloudRegPath -Name "AllowOnlineTips" -ErrorAction SilentlyContinue
    $settings["AllowOnlineTips"] = Get-SettingValue($tipsSetting.AllowOnlineTips)

    # Convert hash table to JSON
    $jsonOutput = $settings | ConvertTo-Json

    # Output the JSON to the specified file
    $jsonOutput | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Host "Settings have been written to: $outputPath"

}


function MS_Security_Guide {
    # Define output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "MSSecurityGuide.json"

    # Ensure the output directory exists
    if (-not (Test-Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }

    # Function to check and return value as 'Enabled', 'Disabled', or 'Not Configured'
    function Get-SettingValue {
        param ($regValue)

        if ($null -eq $regValue) {
            return "Not Configured"
        }
        elseif ($regValue -eq 1) {
            return "Enabled"
        }
        elseif ($regValue -eq 0) {
            return "Disabled"
        }
    }

    # Initialize hash table to store results
    $settings = @{}

    # 1. Configure RPC packet level privacy setting for incoming connections
    $rpcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
    $rpcSetting = Get-ItemProperty -Path $rpcRegPath -Name "RpcAuthnLevelPrivacyEnabled" -ErrorAction SilentlyContinue
    $settings["ConfigureRPCPacketLevelPrivacy"] = Get-SettingValue($rpcSetting.RpcAuthnLevelPrivacyEnabled)

    # 2. Configure SMB v1 client driver
    $smbClientRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10"
    $smbClientSetting = Get-ItemProperty -Path $smbClientRegPath -Name "Start" -ErrorAction SilentlyContinue
    $value = $smbClientSetting.Start
    if ($null -eq $value) {
        $valueName = "Not Configured"
    }
    elseif ($value -eq 4) {
        $valueName = "Diable Driver"
    }
    elseif ($value -eq 3) {
        $valueName = "Manual start"
    }
    elseif ($value -eq 2) {
        $valueName = "Automatic start"
    }
    $settings["ConfigureSMBv1Clientdrive"] = $valueName

    # 3. Configure SMB v1 server
    $smbServerRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    $smbServerSetting = Get-ItemProperty -Path $smbServerRegPath -Name "SMB1" -ErrorAction SilentlyContinue
    $settings["ConfigureSMBv1Server"] = Get-SettingValue($smbServerSetting.SMB1)

    # 4. Enable Certificate Padding
    $certPaddingRegPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config"
    $certPaddingSetting = Get-ItemProperty -Path $certPaddingRegPath -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue
    $settings["EnableCertificatePadding"] = Get-SettingValue($certPaddingSetting.EnableCertPaddingCheck)

    # 5. Enable Structured Exception Handling Overwrite Protection (SEHOP)
    $sehRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
    $sehSetting = Get-ItemProperty -Path $sehRegPath -Name "DisableExceptionChainValidation" -ErrorAction SilentlyContinue
    # Invert the value of EnableCertPaddingCheck before passing it
    if ($sehSetting.DisableExceptionChainValidation -eq 1) {
        $invertedValue = 0
        $settings["EnableSEHOP"] = Get-SettingValue($invertedValue)
    }
    elseif ($sehSetting.DisableExceptionChainValidation -eq 0) {
        $invertedValue = 1
        $settings["EnableSEHOP"] = Get-SettingValue($invertedValue)
    }
    else {
        $settings["EnableSEHOP"] = Get-SettingValue($invertedValue)
    }

    # 6. NetBT NodeType configuration
    $netBTRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
    $netBTSetting = Get-ItemProperty -Path $netBTRegPath -Name "NodeType" -ErrorAction SilentlyContinue
    $value = $netBTSetting.NodeType
    if ($null -eq $value) {
        $valueName = "Not Configured"
    }
    elseif ($value -eq 1) {
        $valueName = "B-node"
    }
    elseif ($value -eq 2) {
        $valueName = "P-node"
    }
    elseif ($value -eq 4) {
        $valueName = "M-node"
    }
    elseif ($value -eq 8) {
        $valueName = "H-node"
    }
    $settings["NetBTNodeTypeConfiguration"] = $valueName

    # 7. WDigest Authentication
    $wdigestRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
    $wdigestSetting = Get-ItemProperty -Path $wdigestRegPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    $settings["WDigestAuthentication"] = Get-SettingValue($wdigestSetting.UseLogonCredential)

    # Convert hash table to JSON
    $jsonOutput = $settings | ConvertTo-Json -Depth 100

    # Output the JSON to the specified file
    $jsonOutput | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Host "Settings have been written to: $outputPath"

}

function MSS_Legacy {
    # Define output directory and path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "MSS(Legacy).json"

    # Ensure the output directory exists
    if (-not (Test-Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory | Out-Null
    }

    # Initialize hash table to store results
    $settings = @{}

    # 1. MSS: (AutoAdminLogon) Enable Automatic Logon
    $autoAdminLogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $autoAdminLogonSetting = Get-ItemProperty -Path $autoAdminLogonPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue
    if ($autoAdminLogonSetting.AutoAdminLogon -eq 1) {
        $settings["MSS: (AutoAdminLogon) Enable Automatic Logon"] = "Enabled"
    }
    elseif ($autoAdminLogonSetting.AutoAdminLogon -eq 0) {
        $settings["MSS: (AutoAdminLogon) Enable Automatic Logon"] = "Disabled"
    }
    else {
        $settings["MSS: (AutoAdminLogon) Enable Automatic Logon"] = "Not Configured"
    }

    # 2. MSS: (DisableIPSourceRouting IPv6) IP source routing protection level
    $disableIPSourceRoutingIPv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $disableIPSourceRoutingIPv6Setting = Get-ItemProperty -Path $disableIPSourceRoutingIPv6Path -Name "DisableIPSourceRouting" -ErrorAction SilentlyContinue
    if ($disableIPSourceRoutingIPv6Setting.DisableIPSourceRouting -eq 2) {
        $settings["MSS: (DisableIPSourceRouting IPv6) IP source routing protection level"] = "Highest protection, source routing is completely disabled"
    }
    elseif ($disableIPSourceRoutingIPv6Setting.DisableIPSourceRouting -eq 1) {
        $settings["MSS: (DisableIPSourceRouting IPv6) IP source routing protection level"] = "Medium, source routed packets ignored when forwarding is enabled"
    }
    elseif ($disableIPSourceRoutingIPv6Setting.DisableIPSourceRouting -eq 0) {
        $settings["MSS: (DisableIPSourceRouting IPv6) IP source routing protection level"] = "No additional protection, source routed packets are allowed"
    }
    else {
        $settings["MSS: (DisableIPSourceRouting IPv6) IP source routing protection level"] = "Not Configured"
    }

    # 3. MSS: (DisableIPSourceRouting) IP source routing protection level
    $disableIPSourceRoutingPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $disableIPSourceRoutingSetting = Get-ItemProperty -Path $disableIPSourceRoutingPath -Name "DisableIPSourceRouting" -ErrorAction SilentlyContinue
    if ($disableIPSourceRoutingSetting.DisableIPSourceRouting -eq 2) {
        $settings["MSS: (DisableIPSourceRouting) IP source routing protection level"] = "Highest protection, source routing is completely disabled"
    }
    elseif ($disableIPSourceRoutingSetting.DisableIPSourceRouting -eq 1) {
        $settings["MSS: (DisableIPSourceRouting) IP source routing protection level"] = "Medium, source routed packets ignored when forwarding is enabled"
    }
    elseif ($disableIPSourceRoutingSetting.DisableIPSourceRouting -eq 0) {
        $settings["MSS: (DisableIPSourceRouting) IP source routing protection level"] = "No additional protection, source routed packets are allowed"
    }
    else {
        $settings["MSS: (DisableIPSourceRouting) IP source routing protection level"] = "Not Configured"
    }

    # 4. MSS: (DisableSavePassword) Prevent the dial-up password from being saved
    $disableSavePasswordPath = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"
    $disableSavePasswordSetting = Get-ItemProperty -Path $disableSavePasswordPath -Name "DisableSavePassword" -ErrorAction SilentlyContinue
    if ($disableSavePasswordSetting.DisableSavePassword -eq 1) {
        $settings["MSS: (DisableSavePassword) Prevent the dial-up password from being saved"] = "Enabled"
    }
    elseif ($disableSavePasswordSetting.DisableSavePassword -eq 0) {
        $settings["MSS: (DisableSavePassword) Prevent the dial-up password from being saved"] = "Disabled"
    }
    else {
        $settings["MSS: (DisableSavePassword) Prevent the dial-up password from being saved"] = "Not Configured"
    }

    # 5. MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes
    $enableICMPRedirectPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $enableICMPRedirectSetting = Get-ItemProperty -Path $enableICMPRedirectPath -Name "EnableICMPRedirect" -ErrorAction SilentlyContinue
    if ($enableICMPRedirectSetting.EnableICMPRedirect -eq 1) {
        $settings["MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes"] = "Enabled"
    }
    elseif ($enableICMPRedirectSetting.EnableICMPRedirect -eq 0) {
        $settings["MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes"] = "Disabled"
    }
    else {
        $settings["MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes"] = "Not Configured"
    }

    # 6. MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds
    $keepAliveTimePath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $keepAliveTimeSetting = Get-ItemProperty -Path $keepAliveTimePath -Name "KeepAliveTime" -ErrorAction SilentlyContinue
    if ($null -ne $keepAliveTimeSetting.KeepAliveTime) {
        $keepAliveTimeValue = $keepAliveTimeSetting.KeepAliveTime.ToString()  # Ensure it's a string
        $settings["MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds"] = $keepAliveTimeValue
    }
    else {
        $settings["MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds"] = "Not Configured"
    }

    # 7. MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests
    $noNameReleaseOnDemandPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters"
    $noNameReleaseOnDemandSetting = Get-ItemProperty -Path $noNameReleaseOnDemandPath -Name "NoNameReleaseOnDemand" -ErrorAction SilentlyContinue
    if ($noNameReleaseOnDemandSetting.NoNameReleaseOnDemand -eq 1) {
        $settings["MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests"] = "Enabled"
    }
    elseif ($noNameReleaseOnDemandSetting.NoNameReleaseOnDemand -eq 0) {
        $settings["MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests"] = "Disabled"
    }
    else {
        $settings["MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests"] = "Not Configured"
    }

    # 8. MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses
    $performRouterDiscoveryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $performRouterDiscoverySetting = Get-ItemProperty -Path $performRouterDiscoveryPath -Name "PerformRouterDiscovery" -ErrorAction SilentlyContinue
    if ($performRouterDiscoverySetting.PerformRouterDiscovery -eq 1) {
        $settings["MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses"] = "Enabled"
    }
    elseif ($performRouterDiscoverySetting.PerformRouterDiscovery -eq 0) {
        $settings["MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses"] = "Disabled"
    }
    else {
        $settings["MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses"] = "Not Configured"
    }

    # 9. MSS: (SafeDllSearchMode) Enable Safe DLL search mode
    $safeDllSearchModePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $safeDllSearchModeSetting = Get-ItemProperty -Path $safeDllSearchModePath -Name "SafeDllSearchMode" -ErrorAction SilentlyContinue
    if ($safeDllSearchModeSetting.SafeDllSearchMode -eq 1) {
        $settings["MSS: (SafeDllSearchMode) Enable Safe DLL search mode"] = "Enabled"
    }
    elseif ($safeDllSearchModeSetting.SafeDllSearchMode -eq 0) {
        $settings["MSS: (SafeDllSearchMode) Enable Safe DLL search mode"] = "Disabled"
    }
    else {
        $settings["MSS: (SafeDllSearchMode) Enable Safe DLL search mode"] = "Not Configured"
    }

    # 10. MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires
    $screenSaverGracePeriodPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $screenSaverGracePeriodSetting = Get-ItemProperty -Path $screenSaverGracePeriodPath -Name "ScreenSaverGracePeriod" -ErrorAction SilentlyContinue
    if ($null -ne $screenSaverGracePeriodSetting.ScreenSaverGracePeriod) {
        $settings["MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires"] = $screenSaverGracePeriodSetting.ScreenSaverGracePeriod
    }
    else {
        $settings["MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires"] = "Not Configured"
    }

    # 11. MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted
    $tcpMaxDataRetransmissionsIPv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    $tcpMaxDataRetransmissionsIPv6Setting = Get-ItemProperty -Path $tcpMaxDataRetransmissionsIPv6Path -Name "TcpMaxDataRetransmissions" -ErrorAction SilentlyContinue
    if ($null -ne $tcpMaxDataRetransmissionsIPv6Setting.TcpMaxDataRetransmissions) {
        $settings["MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted"] = $tcpMaxDataRetransmissionsIPv6Setting.TcpMaxDataRetransmissions.ToString()
    }
    else {
        $settings["MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted"] = "Not Configured"
    }

    # 12. MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted
    $tcpMaxDataRetransmissionsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    $tcpMaxDataRetransmissionsSetting = Get-ItemProperty -Path $tcpMaxDataRetransmissionsPath -Name "TcpMaxDataRetransmissions" -ErrorAction SilentlyContinue
    if ($null -ne $tcpMaxDataRetransmissionsSetting.TcpMaxDataRetransmissions) {
        $settings["MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted"] = $tcpMaxDataRetransmissionsSetting.TcpMaxDataRetransmissions.ToString()
    }
    else {
        $settings["MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted"] = "Not Configured"
    }

    # 13. MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning
    $warningLevelPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"
    $warningLevelSetting = Get-ItemProperty -Path $warningLevelPath -Name "WarningLevel" -ErrorAction SilentlyContinue
    if ($null -ne $warningLevelSetting.WarningLevel) {
        $settings["MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning"] = $warningLevelSetting.WarningLevel.ToString()
    }
    else {
        $settings["MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning"] = "Not Configured"
    }



    # Convert hash table to JSON
    $jsonOutput = $settings | ConvertTo-Json -Depth 100

    # Write the JSON to the file
    $jsonOutput | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to a file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Host "Settings have been written to: $outputPath"

}

function Network {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "Network.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }
 
    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define each setting with the associated registry paths, registry name, and conditions
    $registrySettings = @{
        "Configure DNS over HTTPS (DoH) name resolution"                                                                                            = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
            "Name"       = "DoHPolicy";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Prohibit DoH";
                2 = "Allow DoH";
                3 = "Require DoH"
            }
        };
        "Enable Font Providers"                                                                                                                     = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";
            "Name"       = "EnableFontProviders";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled"
            }
        };
        "Enable insecure guest logons"                                                                                                              = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation";
            "Name"       = "AllowInsecureGuestAuth";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled"
            }
        };
        "Prohibit installation and configuration of Network Bridge on your DNS domain network"                                                      = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections";
            "Name"       = "NC_AllowNetBridge_NLA";
            "Conditions" = @{
                0 = "Enabled";
                1 = "Disabled"
            }
        };
        "Prohibit use of Internet Connection Sharing on your DNS domain network"                                                                    = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections";
            "Name"       = "NC_ShowSharedAccessUI";
            "Conditions" = @{
                0 = "Enabled";
                1 = "Disabled"
            }
        };
        "TCPIP6 Parameter DisabledComponents"                                                                                                       = @{
            "Path"       = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";
            "Name"       = "DisabledComponents";
            "Conditions" = @{
                0   = "IPv6 Enabled";
                255 = "IPv6 Disabled"
            }
        };
        "Prohibit access of the Windows Connect Now wizards"                                                                                        = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI";
            "Name"       = "DisableWcnUi";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Minimize the number of simultaneous connections to the Internet or a Windows Domain"                                                       = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy";
            "Name"       = "fMinimizeConnections";
            "Conditions" = @{
                0 = "Allow simultaneous connections";
                1 = "Minimize simultaneous connections"
                2 = "Stay connected to cellular"
                3 = "Prevent Wi-Fi when on Ethernet"
            }
        };
        "Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services" = @{
            "Path"       = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config";
            "Name"       = "AutoConnectAllowedOEM";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled"
            }
        }
    }

    # Iterate through each setting and get the value based on its conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # 5.Define the registry path for LLTDIO settings
    $LLTDIOPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"

    # Get registry values for LLTDIO settings
    $LLTDIO = Get-ItemProperty -Path $LLTDIOPath -Name "EnableLLTDIO" -ErrorAction SilentlyContinue
    $LLTDIODomain = Get-ItemProperty -Path $LLTDIOPath -Name "AllowLLTDIOOnDomain" -ErrorAction SilentlyContinue
    $LLTDIOPublic = Get-ItemProperty -Path $LLTDIOPath -Name "AllowLLTDIOOnPublicNet" -ErrorAction SilentlyContinue
    $LLTDIOPrivate = Get-ItemProperty -Path $LLTDIOPath -Name "ProhibitLLTDIOOnPrivateNet" -ErrorAction SilentlyContinue

    # Initialize the LLTDIO setting
    $LLTDIOStatus = ""

    # Logic to determine LLTDIO status based on registry values
    if ($null -eq $LLTDIO.EnableLLTDIO) {
        $LLTDIOStatus = "Not Configured"
    }
    elseif ($LLTDIO.EnableLLTDIO -eq 0) {
        $LLTDIOStatus = "Disabled"
    }
    else {
        if ($LLTDIODomain.AllowLLTDIOOnDomain -eq 1 ) {
            $LLTDIOStatus += "Allow operation while in domain"
        }
        if ($LLTDIOPublic.AllowLLTDIOOnPublicNet -eq 1) {
            if ($LLTDIOStatus.Length -gt 0) { $LLTDIOStatus += ", " }
            $LLTDIOStatus += "Allow operation while in public network"
        }
        if ($LLTDIOPrivate.ProhibitLLTDIOOnPrivateNet -eq 1) {
            if ($LLTDIOStatus.Length -gt 0) { $LLTDIOStatus += ", " }
            $LLTDIOStatus += "Prohibit operation while in private network"
        }
    }
    # Assign the final LLTDIO setting to the settings hashtable
    $settings["Turn on Mapper I/O (LLTDIO) driver"] = if ($LLTDIOStatus.Length -gt 0) { $LLTDIOStatus } else { "Enabled" }


    # 6. Define the registry path for RSPNDR settings
    $LLTDIOPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD"

    # Get registry values for RSPNDR settings
    $RSPNDR = Get-ItemProperty -Path $LLTDIOPath -Name "EnableRspndr" -ErrorAction SilentlyContinue
    $RSPNDRDomain = Get-ItemProperty -Path $LLTDIOPath -Name "AllowRspndrOnDomain" -ErrorAction SilentlyContinue
    $RSPNDRPublic = Get-ItemProperty -Path $LLTDIOPath -Name "AllowRspndrOnPublicNet" -ErrorAction SilentlyContinue
    $RSPNDRPrivate = Get-ItemProperty -Path $LLTDIOPath -Name "ProhibitRspndrOnPrivateNet" -ErrorAction SilentlyContinue

    # Initialize the RSPNDR setting
    $RSPNDRStatus = ""

    # Logic to determine RSPNDR status based on registry values
    if ($null -eq $RSPNDR.EnableRspndr) {
        $RSPNDRStatus = "Not Configured"
    }
    elseif ($RSPNDR.EnableRspndr -eq 0) {
        $RSPNDRStatus = "Disabled"
    }
    else {
        if ($RSPNDRDomain.AllowRspndrOnDomain -eq 1) {
            $RSPNDRStatus += "Allow operation while in domain"
        }
        if ($RSPNDRPublic.AllowRspndrOnPublicNet -eq 1) {
            if ($RSPNDRStatus.Length -gt 0) { $RSPNDRStatus += ", " }
            $RSPNDRStatus += "Allow operation while in public network"
        }
        if ($RSPNDRPrivate.ProhibitRspndrOnPrivateNet -eq 1) {
            if ($RSPNDRStatus.Length -gt 0) { $RSPNDRStatus += ", " }
            $RSPNDRStatus += "Prohibit operation while in private network"
        }
    }
    # Assign the final RSPNDR setting to the settings hashtable
    $settings["Turn on Responder (RSPNDR) driver"] = if ($RSPNDRStatus.Length -gt 0) { $RSPNDRStatus } else { "Enabled" }


    # 7. Turn off Microsoft Peer-to-Peer Networking Services
    $peerToPeerRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
    $peerToPeerSetting = Get-ItemProperty -Path $peerToPeerRegPath -Name "Disabled" -ErrorAction SilentlyContinue
    $value = $peerToPeerSetting.Disabled

    if ($null -eq $value) {
        $valueName = "Disabled"
    }
    elseif ($value -eq 1) {
        $valueName = "Enabled"
    }
    elseif ($value -eq 0) {
        $valueName = "Disabled"
    }

    # Save the setting in the $settings array
    $settings["TurnOffPeerToPeerNetworkingServices"] = $valueName

    # 9. Hardened UNC Paths
    # Registry paths for NETLOGON and SYSVOL shares
    $netlogonPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
    $sysvolPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"

    #Registry Setting for NETLOGON and SYSVOL shares
    $netlogonSetting = Get-ItemProperty -Path $netlogonPath -Name "\\*\NETLOGON" -ErrorAction SilentlyContinue
    $sysvolSetting = Get-ItemProperty -Path $sysvolPath -Name "\\*\SYSVOL" -ErrorAction SilentlyContinue

    #Registry Values for NETLOGON and SYSVOL shares
    $netlogonValue = $netlogonSetting."\\*\NETLOGON"
    $sysvolValue = $sysvolSetting."\\*\SYSVOL"

    if ($null -eq $netlogonValue -and $null -eq $sysvolValue) {
        $hardenedUNCPathValue = "Disabled" 
    }
    else {
        $hardenedUNCPathValue = $netlogonValue, $sysvolValue
    }
    $settings["Hardened UNC Paths"] = $hardenedUNCPathValue

    # 11. Configuration of wireless settings using Windows Connect Now
    # Define the WCN registry path
    $WCNPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"

    # Get registry values for WCN settings
    $DisableFlashConfigRegistrar = Get-ItemProperty -Path $WCNPath -Name "DisableFlashConfigRegistrar" -ErrorAction SilentlyContinue
    $DisableInBand802DOT11Registrar = Get-ItemProperty -Path $WCNPath -Name "DisableInBand802DOT11Registrar" -ErrorAction SilentlyContinue
    $DisableUPnPRegistrar = Get-ItemProperty -Path $WCNPath -Name "DisableUPnPRegistrar" -ErrorAction SilentlyContinue
    $DisableWPDRegistrar = Get-ItemProperty -Path $WCNPath -Name "DisableWPDRegistrar" -ErrorAction SilentlyContinue
    $EnableRegistrars = Get-ItemProperty -Path $WCNPath -Name "EnableRegistrars" -ErrorAction SilentlyContinue
    $HigherPrecedenceRegistrar = Get-ItemProperty -Path $WCNPath -Name "HigherPrecedenceRegistrar" -ErrorAction SilentlyContinue
    $MaxWCNDeviceNumber = Get-ItemProperty -Path $WCNPath -Name "MaxWCNDeviceNumber" -ErrorAction SilentlyContinue

    # Initialize the WCN settings status array
    $WCNStatusArray = @()

    # Function to determine status
    function Get-WCNSettingStatus {
        param (
            [string]$SettingName,
            $SettingValue
        )

        if ($null -eq $SettingValue) {
            return "$SettingName = Not Configured"
        }
        elseif ($SettingValue -eq 0) {
            return "$SettingName = Disabled"  
        }
        elseif ($SettingValue -eq 1) {
            return "$SettingName = Enabled"
        }
        else {
            return "$SettingName = Unknown Value ($SettingValue)"
        }
    }

    # Check the EnableRegistrars status first
    if ($null -eq $EnableRegistrars) {
        # If EnableRegistrars is not configured
        $WCNoutput = @{
            "Configuration of wireless settings using Windows Connect Now" = "Not Configured"
        }
    }
    elseif ($EnableRegistrars.EnableRegistrars -eq 0) {
        # If EnableRegistrars is disabled
        $WCNoutput = @{
            "Configuration of wireless settings using Windows Connect Now" = "Not Configured"
        }
    }
    elseif ($EnableRegistrars.EnableRegistrars -eq 1) {
        # If EnableRegistrars is enabled
        $WCNStatusArray += Get-WCNSettingStatus "Turn off ability to configure using WCN over Ethernet (UPnP)" $DisableUPnPRegistrar.DisableUPnPRegistrar
        $WCNStatusArray += Get-WCNSettingStatus "Turn off ability to configure using WCN over In-band 802.11 WLAN" $DisableInBand802DOT11Registrar.DisableInBand802DOT11Registrar
        $WCNStatusArray += Get-WCNSettingStatus "Turn off ability to configure using a USB Flash Drive" $DisableFlashConfigRegistrar.DisableFlashConfigRegistrar
        $WCNStatusArray += Get-WCNSettingStatus "Turn off ability to configure Windows Portable device (WPD)" $DisableWPDRegistrar.DisableWPDRegistrar

        # Append maximum number of WCN devices allowed
        $WCNStatusArray += "Maximum number of WCN devices allowed = $(if ($null -eq $MaxWCNDeviceNumber) { 'Not Configured' } else { $MaxWCNDeviceNumber.MaxWCNDeviceNumber })"

        # Custom logic for Higher precedence medium for devices discovered by multiple media
        if ($null -eq $HigherPrecedenceRegistrar) {
            $WCNStatusArray += "Higher precedence medium for devices discovered by multiple media = Not Configured"
        }
        elseif ($HigherPrecedenceRegistrar.HigherPrecedenceRegistrar -eq 1) {  
            $WCNStatusArray += "Higher precedence medium for devices discovered by multiple media = WCN over Ethernet (UPnP)"
        }
        elseif ($HigherPrecedenceRegistrar.HigherPrecedenceRegistrar -eq 2) {  
            $WCNStatusArray += "Higher precedence medium for devices discovered by multiple media = WCN over In-band 802.11 WLAN"
        }
        else {
            $WCNStatusArray += "Higher precedence medium for devices discovered by multiple media = Unknown Value ($($HigherPrecedenceRegistrar.HigherPrecedenceRegistrar))"  
        }

        # Package the settings output
        $WCNoutput = @{
            "Configuration of wireless settings using Windows Connect Now" = $WCNStatusArray
        }
    }
    else {
        $WCNoutput = @{
            "Configuration of wireless settings using Windows Connect Now" = "Unknown Value ($($EnableRegistrars.EnableRegistrars))"
        }
    }

    # Append to settings array
    $settings += $WCNoutput




    # Convert the results to JSON format
    $jsonOutput = $settings | ConvertTo-Json -Depth 100

    # Write the JSON content to the output file
    $jsonOutput | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to the output file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "JSON settings have been sorted and written to $outputPath"

}

function Printers {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "Printers.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define each setting with the associated registry paths, registry name, and conditions
    $registrySettings = @{
        "Allow Print Spooler to accept client connections"                                             = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers";
            "Name"       = "RegisterSpoolerRemoteRpcEndPoint";
            "Conditions" = @{
                1 = "Enabled";
                2 = "Disabled"
            }
        };
        "Configure Redirection Guard"                                                                  = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers";
            "Name"       = "RedirectionguardPolicy";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled";
                2 = "Redirection Guard Audit Only"
            }
        };
        "Configure RPC connection settings: Protocol to use for outgoing RPC connections"              = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC";
            "Name"       = "RpcUseNamedPipeProtocol";
            "Conditions" = @{
                0 = "RPC over TCP";
                1 = "RPC over Named pipes";
            }
        };
        "Configure RPC connection settings: Use authentication for outgoing RPC connections"           = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC";
            "Name"       = "RpcAuthentication";
            "Conditions" = @{
                0 = "Default";
                1 = "Authentication enabled";
                2 = "Authentication disabled"
            }
        };
        "Configure RPC listener settings: Protocols to allow for incoming RPC connections"             = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC";
            "Name"       = "RpcProtocols";
            "Conditions" = @{
                3 = "RPC over named pipes";
                5 = "RPC over TCP";
                7 = "RPC over named pipes and TCP"
            }
        };
        "Configure RPC listener settings: Authentication protocol to use for incoming RPC connections" = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC";
            "Name"       = "ForceKerberosForRpc";
            "Conditions" = @{
                0 = "Negotiate";
                1 = "Kerberos";
                2 = "Both NTLM and Kerberos"
            }
        };
        "Limits print driver installation to Administrators"                                           = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint";
            "Name"       = "RestrictDriverInstallationToAdministrators";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled"
            }
        };
        "Manage processing of Queue-specific files"                                                    = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers";
            "Name"       = "CopyFilesPolicy";
            "Conditions" = @{
                0 = "Do not allow Queue-specific files";
                1 = "Limit Queue-specific files to Color profiles";
                2 = "Allow all Queue-specific files"
            }
        };
        "Point and Print Restrictions: When installing drivers for a new connection"                   = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint";
            "Name"       = "NoWarningNoElevationOnInstall";
            "Conditions" = @{
                1 = "Do Not Show Warning and Elevation Prompt";
                0 = "Show Warning and Elevation Prompt"
            }
        };
        "Point and Print Restrictions: When updating drivers for an existing connection"               = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint";
            "Name"       = "UpdatePromptSettings";
            "Conditions" = @{
                2 = "Do Not Show Warning and Elevation Prompt";
                1 = "Show Warning Only";
                0 = "Show Warning and Elevation Prompt"
            }
        }
    }

    # Iterate through each setting and get the value based on its conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    #Configure RPC over TCP port
    $RPCoverTCPPortPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC"
    $RPCoverTCP = Get-ItemProperty -Path $RPCoverTCPPortPath -Name "RpcTcpPort" -ErrorAction SilentlyContinue
    $settings["Configure RPC over TCP port"] = if ($null -eq $RPCoverTCP.RpcTcpPort) { "Not Configured" } else { "$($RPCoverTCP.RpcTcpPort)" }



    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to the output file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function Notifications {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "Notifications.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory 
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define each setting with the associated registry paths, registry name, and conditions
    $registrySettings = @{
        "Turn off notifications network usage"                                                       = @{
            "Path"       = "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications";
            "Name"       = "NoCloudApplicationNotification";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled"
            }
        };
        "Remove Personalized Website Recommendations from the Recommended section in the Start Menu" = @{
            "Path"       = "HKLM:\Software\Policies\\Microsoft\Windows\Explorer";
            "Name"       = "HideRecommendedPersonalizedSites";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        }
    }

    # Iterate through each setting and get the value based on its conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to the output file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function Audit_Process_Creation {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "AuditProcessCreation.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define each setting with the associated registry paths, registry name, and conditions
    $registrySettings = @{
        "Include command line in process creation events" = @{
            "Path"       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit";
            "Name"       = "ProcessCreationIncludeCmdLine_Enabled";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
    }

    # Iterate through each setting and get the value based on its conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to the output file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function Credentials_Delegation {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "CredentialsDelegation.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define each setting with the associated registry paths, registry name, and conditions
    $registrySettings = @{
        "Encryption Oracle Remediation"                               = @{
            "Path"       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters";
            "Name"       = "AllowEncryptionOracle";
            "Conditions" = @{
                0 = "Force Updated Clients";
                1 = "Mitigated";
                2 = "Vulnerable"
            }
        };
        "Remote host allows delegation of non-exportable credentials" = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation";
            "Name"       = "AllowProtectedCreds";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        }
    }

    # Iterate through each setting and get the value based on its conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to the output file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function Device_Guard {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "DevviceGuard.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define each setting with the associated registry paths, registry name, and conditions
    $registrySettings = @{
        "Turn On Virtualization Based Security"                                                    = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
            "Name"       = "EnableVirtualizationBasedSecurity";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn On Virtualization Based Security: Select Platform Security Level"                    = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
            "Name"       = "RequirePlatformSecurityFeatures";
            "Conditions" = @{
                0 = "Not Configured";
                1 = "Secure Boot";
                3 = "Secure Boot and DMA Protection"
            }
        };
        "Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity" = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
            "Name"       = "HypervisorEnforcedCodeIntegrity";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled with UEFI lock";
                2 = "Enabled without lock";
                3 = "Not Configured"
            }
        };
        "Turn On Virtualization Based Security: Require UEFI Memory Attributes Table"              = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
            "Name"       = "HVCIMATRequired";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn On Virtualization Based Security: Credential Guard Configuration"                    = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
            "Name"       = "LsaCfgFlags";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled with UEFI lock";
                2 = "Enabled without lock";
                3 = "Not Configured"
            }
        };
        "Turn On Virtualization Based Security: Secure Launch Configuration"                       = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
            "Name"       = "ConfigureSystemGuardLaunch";
            "Conditions" = @{
                0 = "Not Configured";
                1 = "Enabled";
                2 = "Disabled"
            }
        };
        "Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection"    = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
            "Name"       = "ConfigureKernelShadowStacksLaunch";
            "Conditions" = @{
                0 = "Not Configured";
                1 = "Enabled in enforcement mode";
                2 = "Enabled in audit mode";
                3 = "Disabled"
            }
        }
    }

    # Iterate through each setting and get the value based on its conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to the output file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function Device_Installation {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "DeviceInstallation.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define each setting with the associated registry paths, registry name, and conditions
    $registrySettings = @{
        "Prevent installation of devices that match any of these device IDs"                                                                                        = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
            "Name"       = "DenyDeviceIDs";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled"
            }
        };
        "Prevent installation of devices that match any of these device IDs: Prevent installation of devices that match any of these device IDs"                    = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs";
            "Name"       = "1";
            "Conditions" = @{}
        };
        "Prevent installation of devices that match any of these device IDs: Also apply to matching devices that are already installed"                             = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
            "Name"       = "DenyDeviceIDsRetroactive";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Prevent installation of devices using drivers that match these device setup classes"                                                                       = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
            "Name"       = "DenyDeviceClasses";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled";
            }
        };
        "Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these device setup" = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses";
            "Name"       = "1";
            "Conditions" = @{}
        };
        "Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed"            = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions";
            "Name"       = "DenyDeviceClassesRetroactive";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Prevent device metadata retrieval from the Internet"                                                                                                       = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata";
            "Name"       = "PreventDeviceMetadataFromNetwork";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
    }

    # Iterate through each setting and get the value based on its conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
    
        # If conditions are empty, output raw value list or flag as Not Configured
        if ($conditions.Count -eq 0) {
            $rawValue = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
            $settings[$setting] = if ($null -eq $rawValue) { "Not Configured" } else { $rawValue }
        }
        else {
            $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
        }
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to the output file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function Early_Launch_Antimalware {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "EarlyLaunchAntimalware.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define each setting with the associated registry paths, registry name, and conditions
    $registrySettings = @{
        "Boot-Start Driver Initialization Policy" = @{
            "Path"       = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch";
            "Name"       = "DriverLoadPolicy";
            "Conditions" = @{
                1 = "Good and Unknown";
                3 = "Good, Unknown, and Bad But Critical";
                7 = "All";
                8 = "Good only"
            }
        };
    }

    # Iterate through each setting and get the value based on its conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
    
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to the output file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function LoggingAndTracing {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "LoggingAndTracing.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define each setting with the associated registry paths, registry name, and conditions
    $registrySettings = @{
        "Continue experiences on this device" = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";
            "Name"       = "EnableCdp";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
    }

    # Iterate through each setting and get the value based on its conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
    
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to the output file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function Internet_Communication_Management {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "InternetCommunicationManagement.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define each setting with the associated registry paths, registry name, and conditions
    $registrySettings = @{
        "Turn off access to the Store"                                                        = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer";
            "Name"       = "NoUseStoreOpenWith";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn off downloading of print drivers over HTTP"                                     = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers";
            "Name"       = "DisableWebPnPDownload";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn off handwriting personalization data sharing"                                   = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC";
            "Name"       = "PreventHandwritingDataSharing";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn off handwriting recognition error reporting"                                    = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports";
            "Name"       = "PreventHandwritingErrorReporting";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com" = @{
            "Path"       = "HKLM:\Software\Policies\Microsoft\Windows\Internet Connection Wizard";
            "Name"       = "ExitOnMSICW";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn off Internet download for Web publishing and online ordering wizards"           = @{
            "Path"       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
            "Name"       = "NoWebServices";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn off printing over HTTP"                                                         = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers";
            "Name"       = "DisableHTTPPrinting";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn off Registration if URL connection is referring to Microsoft.com"               = @{
            "Path"       = "HKLM:\Software\Policies\Microsoft\Windows\Registration Wizard Control";
            "Name"       = "NoRegistration";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn off Search Companion content file updates"                                      = @{
            "Path"       = "HKLM:\Software\Policies\Microsoft\SearchCompanion";
            "Name"       = "DisableContentFileUpdates";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn off the 'Order Prints' picture task"                                            = @{
            "Path"       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
            "Name"       = "NoOnlinePrintsWizard";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn off the 'Publish to Web' task for files and folders"                            = @{
            "Path"       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
            "Name"       = "NoPublishingWizard";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
        "Turn off the Windows Messenger Customer Experience Improvement Program"              = @{
            "Path"       = "HKLM:\Software\Policies\Microsoft\Messenger\Client";
            "Name"       = "CEIP";
            "Conditions" = @{
                1 = "Disabled";
                2 = "Enabled"
            }
        };
        "Turn off Windows Customer Experience Improvement Program"                            = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows";
            "Name"       = "CEIPEnable";
            "Conditions" = @{
                1 = "Disabled";
                0 = "Enabled"
            }
        };
        "Turn off Windows Error Reporting"                                                    = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting";
            "Name"       = "Disabled";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };
    }

    # Iterate through each setting and get the value based on its conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
    
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    # Sort the JSON content alphabetically by keys
    $jsonContent = Get-Content -Path $outputPath -Raw | ConvertFrom-Json

    # Create a new ordered dictionary to hold the sorted JSON content
    $orderedJson = [ordered]@{}

    # Sort the keys alphabetically and add them to the ordered dictionary
    $jsonContent.PSObject.Properties.Name | Sort-Object | ForEach-Object {
        $orderedJson[$_] = $jsonContent.$_
    }

    # Convert the ordered dictionary back to JSON
    $orderedJsonJson = $orderedJson | ConvertTo-Json -Depth 100

    # Write the sorted JSON content to the output file
    $orderedJsonJson | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function Kerberos {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "Kerberos.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define the setting with the associated registry path, registry name, and conditions
    $registrySetting = @{
        "Support device authentication using certificate"                                                    = @{
            "Path"       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters";
            "Name"       = "DevicePKInitEnabled";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled"
            }
        }
        "Support device authentication using certificate: Device authentication behaviour using certificate" = @{
            "Path"       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters";
            "Name"       = "DevicePKInitBehavior";
            "Conditions" = @{
                0 = "Automatic";
                1 = "Force"
            }
        }
    }

    # Get the value based on its conditions
    foreach ($setting in $registrySetting.Keys) {
        $path = $registrySetting[$setting]["Path"]
        $name = $registrySetting[$setting]["Name"]
        $conditions = $registrySetting[$setting]["Conditions"]
    
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function Kernal_DMA_Protection {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "KernelDMAProtection.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define the setting with the associated registry path, registry name, and conditions
    $registrySetting = @{
        "Enumeration policy for external devices incompatible with Kernel DMA Protection" = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection";
            "Name"       = "DeviceEnumerationPolicy";
            "Conditions" = @{
                0 = "Block all";
                1 = "Only while logged in (default)";
                2 = "Allow all"
            }
        }
    }

    # Get the value based on its conditions
    foreach ($setting in $registrySetting.Keys) {
        $path = $registrySetting[$setting]["Path"]
        $name = $registrySetting[$setting]["Name"]
        $conditions = $registrySetting[$setting]["Conditions"]
    
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function Local_Security_Authority {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "LocalSecurityAuthority.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define the registry settings for the two configurations
    $registrySettings = @{
        # 1. Allow Custom SSPs and APs to be loaded into LSASS
        "Allow Custom SSPs and APs to be loaded into LSASS" = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";
            "Name"       = "AllowCustomSSPsAPs";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled"
            }
        };

        # 2. Configures LSASS to run as a protected process
        "Configures LSASS to run as a protected process"    = @{
            "Path"       = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa";
            "Name"       = "RunAsPPL";
            "Conditions" = @{
                0 = "Disabled";
                1 = "Enabled with UEFI Lock";
                2 = "Enabled without UEFI Lock"
            }
        }
    }

    # Retrieve the values for each setting based on the registry path, name, and conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
    
        # Call the Get-RegistryValue function to retrieve and interpret the values
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function Locale_Services {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "Locale_Services.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the result
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define the registry path, value name, and condition mappings for the setting
    $setting = "Disallow copying of user input methods to the system account for sign-in"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"
    $registryValueName = "BlockUserInputMethodsForSignIn"
    $conditions = @{
        1 = "Enabled";
        0 = "Disabled"
    }

    # Retrieve and interpret the value
    $settings[$setting] = Get-RegistryValue -path $registryPath -name $registryValueName -conditions $conditions

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    Write-Output "Setting saved to $outputPath"

}

function Logon {
    # Define the output directory and file path
    $outputDirectory = "$PSScriptRoot\Output"
    $outputPath = Join-Path -Path $outputDirectory -ChildPath "Logon.json"

    # Ensure the output directory exists
    if (-not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory
    }

    # Initialize an empty hashtable to store the results
    $settings = @{}

    # Function to get registry value or return specific interpretations based on value type
    function Get-RegistryValue {
        param (
            [string]$path,
            [string]$name,
            [hashtable]$conditions
        )

        $value = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
        $value = $value.$name

        if ($null -eq $value) {
            return "Not Configured"
        }

        foreach ($condition in $conditions.Keys) {
            if ($value -eq $condition) {
                return $conditions[$condition]
            }
        }

        return "Unknown"
    }

    # Define each setting with associated registry paths, registry name, and conditions
    $registrySettings = @{
        "Block user from showing account details on sign-in" = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";
            "Name"       = "BlockUserFromShowingAccountDetailsOnSignin";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled"
            }
        };
        "Do not display network selection UI"                = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";
            "Name"       = "DontDisplayNetworkSelectionUI";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled"
            }
        };
        "Turn off app notifications on the lock screen"      = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";
            "Name"       = "DisableLockScreenAppNotifications";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled"
            }
        };
        "Turn on convenience PIN sign-in"                    = @{
            "Path"       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";
            "Name"       = "AllowDomainPINLogon";
            "Conditions" = @{
                1 = "Enabled";
                0 = "Disabled"
            }
        }
    }

    # Iterate through each setting and get the value based on its conditions
    foreach ($setting in $registrySettings.Keys) {
        $path = $registrySettings[$setting]["Path"]
        $name = $registrySettings[$setting]["Name"]
        $conditions = $registrySettings[$setting]["Conditions"]
        $settings[$setting] = Get-RegistryValue -path $path -name $name -conditions $conditions
    }

    # Output the results as JSON
    $settings | ConvertTo-Json | Set-Content -Path $outputPath

    Write-Output "Settings saved to $outputPath"

}

function OS_Policies {
    
}



Password_Policies
Account_Lockout_Policy
User_Right_Assignment
Accounts
Audit
Devices
Interactive_Logon
Microsoft_Network_Client
Network_Access
Network_Security
System_Cryptography
System_Objects
User_Account_Control
System_Services
Private_Profile
Public_Profile
Account_Logon
Account_Management
Detailed_Tracking
Logon_Logoff
Object_Access
Policy_Change
Privilege_Use
System
Personalization
Handwriting_Personalization
MS_Security_Guide
MSS_Legacy
Network
Printers
Notifications 
Audit_Process_Creation
Credentials_Delegation
Device_Guard
Device_Installation
Early_Launch_Antimalware
LoggingAndTracing
Internet_Communication_Management
Kerberos
Kernal_DMA_Protection
Local_Security_Authority
Locale_Services
Logon


OS_Policies