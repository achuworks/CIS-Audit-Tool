Import-Module LAPS

$global:results = @()
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$valueName = "RequireSignOrSeal"
$regPath2 = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$valueName2 = "SealSecureChannel"
$regPath3 = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$valueName3 = "SignSecureChannel"
$regPath4 = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$valueName4 = "DisablePasswordChange"
$regPath5 = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$valueName5 = "MaximumPasswordAge"
$regPath6 = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$valueName6 = "RequireStrongKey"
#the below are from 9.1.1 to 9.1.7
<#function CheckFirewall {
    $firewallProfiles = Get-NetFirewallProfile
    foreach ($profile in $firewallProfiles) {
        if ($profile.Enabled -eq $true) {
            Write-Host "$($profile.Name) Firewall ENABLED"
        } else {
            Write-Host "$($profile.Name) Firewall NOT ENABLED"
        }
    }
}#>
$regPath7 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
$valueName7 = "EnableFirewall"
$regPath8 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
$valueName8 = "DefaultInboundAction"
$regPath9 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
$valueName9 = "DisableNotifications"
$regPath10 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
$valueName10 = "LogFilePath"
$regPath11 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
$valueName11="LogFileSize"
$regPath12 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
$valueName12 = "LogDroppedPackets"
$regPath13="HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
$valueName13="LogSuccessfulConnections"
#18.4.1 UAC 
$regPath14="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName14="LocalAccountTokenFilterPolicy"
#18.6.4 DNS Client
#18.6.4.1 DoH
$regPath15="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$valueName15="DoHPolicy"
#18.6.4.2 NetBIOS
$regPath16="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$valueName16="EnableNetbios"
#18.6.4.3 LLMNR
$regPath17="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$valueName17="EnableMulticast"
#18.6.11.4 not allowing users to change the network connection (private,public,domain)
$regPath18="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
$valueName18="NC_StdDomainUserSetLocation"#>
#18.6.21.2 ensure not connection to non-domain network
$regPath19="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
$valueName19="fBlockNonDomain"
#18.9.19.1 no background policy when logged in too 
$regPath20="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$valueName20="NoBackgroundPolicy"

$regPath21="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$valueName21="NoGPOListChanges"
#18.9.19.4 no background policy when computer is running too
$regPath22="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
$valueName22="NoBackgroundPolicy"
#18.9.19.5 no GPO2
$regPath23="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"
$valueName23="NoGPOListChanges"
#18.9.19.7 (6 Already available in Standalone) Updates on Group Policy even if computer is on
$regPath24="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName24="DisableBkGndGroupPolicy"
#18.9.25 goes from here 
#18.9.25.1 LAPS AD
$regPath25="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$valueName25="BackupDirectory"#have to be downloaded from the official Microsoft website !!!! should be done later
#18.9.28 LOGON
$regPath26="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$valueName26="DontEnumerateConnectedUsers"
$regPath27="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$valueName27="EnumerateLocalUsers"
$regPath28="HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$valueName28="BlockDomainPicturePassword"
#18.9.51.1.2 
$regPath29="HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer"
$valueName29="Enabled"
$regPath30="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$valueName30="PwdExpirationProtectionEnabled"
$regPath31="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$valueName31="ADPasswordEncryptionEnabled"
$regPath32="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$valueName32="PasswordComplexity"
$regPath33="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$valueName33="PasswordLength"
$regPath34="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$valueName34="PasswordAgeDays"
$regPath35="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$valueName35="PostAuthenticationResetDelay"
$regPath36="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$valueName36="PostAuthenticationActions"

function Add-Result {
    param (
        [string]$Name,
        [string]$Status,
        [string]$Severity,
        [string]$CurrentValue,
        [string]$ExpectedValue,
        [string]$Message = ''
    )
    $result = [PSCustomObject]@{
        Name          = $Name
        Status        = $Status
        Severity      = $Severity
        CurrentValue  = $CurrentValue
        ExpectedValue = $ExpectedValue
        Message       = $Message
    }
    $result | Export-Csv -Path "temp_output.csv" -NoTypeInformation -Append -Delimiter "|"
}

# Template for exception handling in each function
function Generic-Function-Template {
    param([string]$functionName)
    try {
        # Original function logic here
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result $functionName "ERROR" "HIGH" "N/A" "N/A" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result $functionName "ERROR" "HIGH" "N/A" "N/A" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result $functionName "ERROR" "HIGH" "N/A" "N/A" "Unexpected error: $($_.Exception.Message)"
    }
}

function RequireSignorSeal {
    try {
        $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
        $currentValuee = $currentValue.$valueName
        if ($currentValuee -eq 1) {
            Add-Result "RequireSignOrSeal" "ENABLED" "" $currentValuee 1
        }
        else {
            Add-Result "RequireSignOrSeal" "NOT ENABLED" "MEDIUM" $currentValuee 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "RequireSignOrSeal" "ERROR" "HIGH" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "RequireSignOrSeal" "ERROR" "HIGH" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "RequireSignOrSeal" "ERROR" "HIGH" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

function SealSecureChannel {
    try {
        $currentValue2 = Get-ItemProperty -Path $regPath2 -Name $valueName2 -ErrorAction Stop
        $currentValuee2 = $currentValue2.$valueName2
        if($currentValuee2 -eq 1){
            Add-Result "SealSecureChannel" "ENABLED" "" $currentValuee2 1
        }else{
            Add-Result "SealSecureChannel" "NOT ENABLED" "MEDIUM" $currentValuee2 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "SealSecureChannel" "ERROR" "HIGH" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "SealSecureChannel" "ERROR" "HIGH" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "SealSecureChannel" "ERROR" "HIGH" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

# Continue this pattern for all other functions...
function SignSecureChannel {
    try {
        $currentValue3 = Get-ItemProperty -Path $regPath3 -Name $valueName3 -ErrorAction Stop
        $currentValuee3 = $currentValue3.$valueName3
        if($currentValuee3 -eq 1){
            Add-Result "SignSecureChannel" "ENABLED" "" $currentValuee3 1
        }else{
            Add-Result "SignSecureChannel" "NOT ENABLED" "MEDIUM" $currentValuee3 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "SignSecureChannel" "ERROR" "HIGH" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "SignSecureChannel" "ERROR" "HIGH" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "SignSecureChannel" "ERROR" "HIGH" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

function DisablePasswordChange {
    try {
        $currentValue4 = Get-ItemProperty -Path $regPath4 -Name $valueName4 -ErrorAction Stop
        $currentValuee4 = $currentValue4.$valueName4
        if($currentValuee4 -eq 1){
            Add-Result "DisablePasswordChange" "ENABLED" "" $currentValuee4 1
        }else{
            Add-Result "DisablePasswordChange" "NOT ENABLED" "MEDIUM" $currentValuee4 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "DisablePasswordChange" "ERROR" "HIGH" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "DisablePasswordChange" "ERROR" "HIGH" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "DisablePasswordChange" "ERROR" "HIGH" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

function MaximumPasswordAge {
    try {
        $currentValue5 = Get-ItemProperty -Path $regPath5 -Name $valueName5 -ErrorAction Stop
        $currentValuee5 = $currentValue5.$valueName5
        if($currentValuee5 -eq 30){
            Add-Result "MaximumPasswordAge" "ENABLED" "" $currentValuee5 30
        }else{
            Add-Result "MaximumPasswordAge" "NOT ENABLED" "HIGH" $currentValuee5 30
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "MaximumPasswordAge" "ERROR" "HIGH" "N/A" "30" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "MaximumPasswordAge" "ERROR" "HIGH" "N/A" "30" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "MaximumPasswordAge" "ERROR" "HIGH" "N/A" "30" "Unexpected error: $($_.Exception.Message)"
    }
}

function RequireStrongKey {
    try {
        $currentValue6 = Get-ItemProperty -Path $regPath6 -Name $valueName6 -ErrorAction Stop
        $currentValuee6 = $currentValue6.$valueName6
        if($currentValuee6 -eq 1){
            Add-Result "RequireStrongKey" "ENABLED" "" $currentValuee6 1
        }else{
            Add-Result "RequireStrongKey" "NOT ENABLED" "HIGH" $currentValuee6 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "RequireStrongKey" "ERROR" "HIGH" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "RequireStrongKey" "ERROR" "HIGH" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "RequireStrongKey" "ERROR" "HIGH" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

function EnableFirewall {
    try {
        $currentValue7 = Get-ItemProperty -Path $regPath7 -Name $valueName7 -ErrorAction Stop
        $currentValuee7 = $currentValue7.$valueName7
        if($currentValuee7 -eq 1){
            Add-Result "Firewall state" "ENABLED" "" $currentValuee7 1
        }else{
            Add-Result "Firewall state" "NOT ENABLED" "HIGH" $currentValuee7 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "Firewall state" "ERROR" "HIGH" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "Firewall state" "ERROR" "HIGH" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "Firewall state" "ERROR" "HIGH" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

function DefaultInbound {
    try {
        $currentValue8 = Get-ItemProperty -Path $regPath8 -Name $valueName8 -ErrorAction Stop
        $currentValuee8 = $currentValue8.$valueName8
        if($currentValuee8 -eq 1){
            Add-Result "DefaultInbound" "ENABLED" "" $currentValuee8 1
        }else{
            Add-Result "DefaultInbound" "NOT ENABLED" "MEDIUM" $currentValuee8 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "DefaultInbound" "ERROR" "HIGH" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "DefaultInbound" "ERROR" "HIGH" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "DefaultInbound" "ERROR" "HIGH" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

function DisableNotifications {
    try {
        $currentValue9 = Get-ItemProperty -Path $regPath9 -Name $valueName9 -ErrorAction Stop
        $currentValuee9 = $currentValue9.$valueName9
        if($currentValuee9 -eq 1){
            Add-Result "DisableNotifications" "ENABLED" "" $currentValuee9 1
        }else{
            Add-Result "DisableNotifications" "NOT ENABLED" "MEDIUM" $currentValuee9 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "DisableNotifications" "ERROR" "HIGH" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "DisableNotifications" "ERROR" "HIGH" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "DisableNotifications" "ERROR" "HIGH" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

function LogFilePath {
    try {
        $currentValue10 = Get-ItemProperty -Path $regPath10 -Name $valueName10 -ErrorAction Stop
        $currentValuee10 = $currentValue10.$valueName10
        $expectedLogFilePath = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
        if($currentValuee10 -eq $expectedLogFilePath){
            Add-Result "LogFilePath" "ENABLED" "" $currentValuee10 $expectedLogFilePath
        }else{
            Add-Result "LogFilePath" "NOT ENABLED" "MEDIUM" $currentValuee10 $expectedLogFilePath
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "LogFilePath" "ERROR" "HIGH" "N/A" "$expectedLogFilePath" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "LogFilePath" "ERROR" "HIGH" "N/A" "$expectedLogFilePath" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "LogFilePath" "ERROR" "HIGH" "N/A" "$expectedLogFilePath" "Unexpected error: $($_.Exception.Message)"
    }
}

function LogFileSize {
    try {
        $currentValue11 = Get-ItemProperty -Path $regPath11 -Name $valueName11 -ErrorAction Stop
        $currentValuee11 = $currentValue11.$valueName11
        if($currentValuee11 -eq 16384){
            Add-Result "LogFileSize" "set to 16384" "" $currentValuee11 16384
        }else{
            Add-Result "LogFileSize" "not set to 16384" "MEDIUM" $currentValuee11 16384
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "LogFileSize" "ERROR" "HIGH" "N/A" "16384" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "LogFileSize" "ERROR" "HIGH" "N/A" "16384" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "LogFileSize" "ERROR" "HIGH" "N/A" "16384" "Unexpected error: $($_.Exception.Message)"
    }
}

function LogDroppedPackets {
    try {
        $currentValue12 = Get-ItemProperty -Path $regPath12 -Name $valueName12 -ErrorAction Stop
        $currentValuee12 = $currentValue12.$valueName12
        if($currentValuee12 -eq 1){
            Add-Result "Log Dropped Packets" "ENABLED" "" $currentValuee12 1
        }else{
            Add-Result "Log Dropped Packets" "NOT ENABLED" "HIGH" $currentValuee12 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "Log Dropped Packets" "ERROR" "HIGH" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "Log Dropped Packets" "ERROR" "HIGH" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "Log Dropped Packets" "ERROR" "HIGH" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

function LogSuccessfulConnections {
    try {
        $currentValue13 = Get-ItemProperty -Path $regPath13 -Name $valueName13 -ErrorAction Stop
        $currentValuee13 = $currentValue13.$valueName13
        if($currentValuee13 -eq 1){
            Add-Result "LogSuccessfulConnections" "ENABLED" "" $currentValuee13 1
        }else{
            Add-Result "LogSuccessfulConnections" "NOT ENABLED" "HIGH" $currentValuee13 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "LogSuccessfulConnections" "ERROR" "HIGH" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "LogSuccessfulConnections" "ERROR" "HIGH" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "LogSuccessfulConnections" "ERROR" "HIGH" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

function LocalAccountTokenFilterPolicy {
    try {
        $currentValue14 = Get-ItemProperty -Path $regPath14 -Name $valueName14 -ErrorAction Stop
        $currentValuee14 = $currentValue14.$valueName14
        if($currentValuee14 -eq 0){
            Add-Result "LocalAccountTokenFilterPolicy" "ENABLED" "" $currentValuee14 0
        }else{
            Add-Result "LocalAccountTokenFilterPolicy" "NOT ENABLED" "MEDIUM" $currentValuee14 0
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "LocalAccountTokenFilterPolicy" "ERROR" "MEDIUM" "N/A" "0" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "LocalAccountTokenFilterPolicy" "ERROR" "MEDIUM" "N/A" "0" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "LocalAccountTokenFilterPolicy" "ERROR" "MEDIUM" "N/A" "0" "Unexpected error: $($_.Exception.Message)"
    }
}

function DoHPolicy {
    try {
        $currentValue15 = Get-ItemProperty -Path $regPath15 -Name $valueName15 -ErrorAction Stop
        $currentValuee15 = $currentValue15.$valueName15
        if($currentValuee15 -eq 2 -or $currentValuee15 -eq 3){
            Add-Result "DoHPolicy" "Enabled" "" $currentValuee15 "2 or 3"
        }
        else{
            Add-Result "DoHPolicy" "not ENABLED" "MEDIUM" $currentValuee15 "2 or 3"
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "DoHPolicy" "ERROR" "MEDIUM" "N/A" "2 or 3" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "DoHPolicy" "ERROR" "MEDIUM" "N/A" "2 or 3" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "DoHPolicy" "ERROR" "MEDIUM" "N/A" "2 or 3" "Unexpected error: $($_.Exception.Message)"
    }
}

function EnableNetbios {
    try {
        $currentValue16 = Get-ItemProperty -Path $regPath16 -Name $valueName16 -ErrorAction Stop
        $currentValuee16 = $currentValue16.$valueName16
        if($currentValuee16 -eq 0 -or $currentValuee16 -eq 2){
            Add-Result "NetBIOS" "Enabled" "" $currentValuee16 0
        }
        else{
            Add-Result "NetBIOS" "NOT ENABLED" "LOW" $currentValuee16 0
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "NetBIOS" "ERROR" "LOW" "N/A" "0" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "NetBIOS" "ERROR" "LOW" "N/A" "0" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "NetBIOS" "ERROR" "LOW" "N/A" "0" "Unexpected error: $($_.Exception.Message)"
    }
}

function EnableMulticast {
    try {
        $currentValue17 = Get-ItemProperty -Path $regPath17 -Name $valueName17 -ErrorAction Stop
        $currentValuee17 = $currentValue17.$valueName17
        if($currentValuee17 -eq 0){
            Add-Result "EnableMulticast" "ENABLED" "" $currentValuee17 0
        }else{
            Add-Result "EnableMulticast" "NOT ENABLED" "LOW" $currentValuee17 0
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "EnableMulticast" "ERROR" "LOW" "N/A" "0" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "EnableMulticast" "ERROR" "LOW" "N/A" "0" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "EnableMulticast" "ERROR" "LOW" "N/A" "0" "Unexpected error: $($_.Exception.Message)"
    }
}

function NC_StdDomainUserSetLocation {
    try {
        $currentValue18 = Get-ItemProperty -Path $regPath18 -Name $valueName18 -ErrorAction Stop
        $currentValuee18 = $currentValue18.$valueName18
        if($currentValuee18 -eq 1){
            Add-Result "NC_StdDomainUserSetLocation" "ENABLED" "" $currentValuee18 1
        }else{
            Add-Result "NC_StdDomainUserSetLocation" "NOT ENABLED" "LOW" $currentValuee18 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "NC_StdDomainUserSetLocation" "ERROR" "LOW" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "NC_StdDomainUserSetLocation" "ERROR" "LOW" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "NC_StdDomainUserSetLocation" "ERROR" "LOW" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

function fBlockNonDomain {
    try {
        $currentValue19 = Get-ItemProperty -Path $regPath19 -Name $valueName19 -ErrorAction Stop
        $currentValuee19 = $currentValue19.$valueName19
        if($currentValuee19 -eq 1){
            Add-Result "fBlockNonDomain" "ENABLED" "" $currentValuee19 1
        }else{
            Add-Result "fBlockNonDomain" "NOT ENABLED" "LOW" $currentValuee19 1
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "fBlockNonDomain" "ERROR" "LOW" "N/A" "1" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "fBlockNonDomain" "ERROR" "LOW" "N/A" "1" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "fBlockNonDomain" "ERROR" "LOW" "N/A" "1" "Unexpected error: $($_.Exception.Message)"
    }
}

function NoBackgroundPolicy {
    try {
        $currentValue20 = Get-ItemProperty -Path $regPath20 -Name $valueName20 -ErrorAction Stop
        $currentValuee20 = $currentValue20.$valueName20
        if($currentValuee20 -eq 0){
            Add-Result "NoBackgroundPolicy" "ENABLED" "" $currentValuee20 0
        }else{
            Add-Result "NoBackgroundPolicy" "NOT ENABLED" "LOW" $currentValuee20 0
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "NoBackgroundPolicy" "ERROR" "LOW" "N/A" "0" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "NoBackgroundPolicy" "ERROR" "LOW" "N/A" "0" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "NoBackgroundPolicy" "ERROR" "LOW" "N/A" "0" "Unexpected error: $($_.Exception.Message)"
    }
}

function NoGPOListChanges {
    try {
        $currentValue21 = Get-ItemProperty -Path $regPath21 -Name $valueName21 -ErrorAction Stop
        $currentValuee21 = $currentValue21.$valueName21
        if($currentValuee21 -eq 0){
            Add-Result "NoGPOListChanges" "ENABLED" "" $currentValuee21 0
        }else{
            Add-Result "NoGPOListChanges" "NOT ENABLED" "LOW" $currentValuee21 0
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "NoGPOListChanges" "ERROR" "LOW" "N/A" "0" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "NoGPOListChanges" "ERROR" "LOW" "N/A" "0" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "NoGPOListChanges" "ERROR" "LOW" "N/A" "0" "Unexpected error: $($_.Exception.Message)"
    }
}

function NoBackgroundPolicy2 {
    try {
        $currentValue22 = Get-ItemProperty -Path $regPath22 -Name $valueName22 -ErrorAction Stop
        $currentValuee22 = $currentValue22.$valueName22
        if($currentValuee22 -eq 0){
            Add-Result "NoBackgroundPolicy2" "ENABLED" "" $currentValuee22 0
        }else{
            Add-Result "NoBackgroundPolicy2" "NOT ENABLED" "LOW" $currentValuee22 0
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "NoBackgroundPolicy2" "ERROR" "LOW" "N/A" "0" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "NoBackgroundPolicy2" "ERROR" "LOW" "N/A" "0" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "NoBackgroundPolicy2" "ERROR" "LOW" "N/A" "0" "Unexpected error: $($_.Exception.Message)"
    }
}

function NoGPOListChanges2 {
    try {
        $currentValue23 = Get-ItemProperty -Path $regPath23 -Name $valueName23 -ErrorAction Stop
        $currentValuee23 = $currentValue23.$valueName23
        if($currentValuee23 -eq 0){
            Add-Result "NoGPOListChanges2" "ENABLED" "" $currentValuee23 0
        }else{
            Add-Result "NoGPOListChanges2" "NOT ENABLED" "LOW" $currentValuee23 0
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "NoGPOListChanges2" "ERROR" "LOW" "N/A" "0" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "NoGPOListChanges2" "ERROR" "LOW" "N/A" "0" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "NoGPOListChanges2" "ERROR" "LOW" "N/A" "0" "Unexpected error: $($_.Exception.Message)"
    }
}

function DisableBkGndGroupPolicy {
    try {
        $currentValue24 = Get-ItemProperty -Path $regPath24 -Name $valueName24 -ErrorAction Stop
        $currentValuee24 = $currentValue24.$valueName24
        if($currentValuee24 -eq 0){
            Add-Result "Disable Background Group Policy" "ENABLED" "" $currentValuee24 0
        }else{
            Add-Result "Disable Background Group Policy" "NOT ENABLED" "MEDIUM" $currentValuee24 0
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "Disable Background Group Policy" "ERROR" "MEDIUM" "N/A" "0" "Registry path not found: $($_.Exception.Message)"
    }
    catch [System.Management.Automation.PSArgumentException] {
        Add-Result "Disable Background Group Policy" "ERROR" "MEDIUM" "N/A" "0" "Registry value not found: $($_.Exception.Message)"
    }
    catch {
        Add-Result "Disable Background Group Policy" "ERROR" "MEDIUM" "N/A" "0" "Unexpected error: $($_.Exception.Message)"
    }
}


function BackupDirectory {
    try {
        $currentValue25 = Get-ItemProperty -Path $regPath25 -Name $valueName25 -ErrorAction Stop
        $currentValuee25 = $currentValue25.$valueName25
        if ($currentValuee25 -eq 1 -or $currentValuee25 -eq 2) {
            Add-Result "LAPS BackupDirectory" "ENABLED" "" $currentValuee25 "1 or 2"
        } else {
            Add-Result "LAPS BackupDirectory" "NOT ENABLED" "LOW" $currentValuee25 "1 or 2"
        }
    } catch [System.Management.Automation.ItemNotFoundException] {
        Add-Result "LAPS BackupDirectory" "ERROR" "MEDIUM" "N/A" "0" "Registry path not found: $($_.Exception.Message)"
    } catch [System.Management.Automation.PSArgumentException] {
        Add-Result "LAPS BackupDirectory" "ERROR" "MEDIUM" "N/A" "0" "Registry value not found: $($_.Exception.Message)"
    } catch {
        Add-Result "LAPS BackupDirectory" "ERROR" "MEDIUM" "N/A" "0" "Unexpected error: $($_.Exception.Message)"
    }
}

function DontEnumerateConnectedUsers {
    try {
        $currentValue26 = Get-ItemProperty -Path $regPath26 -Name $valueName26 -ErrorAction Stop
        $currentValuee26 = $currentValue26.$valueName26
        if ($currentValuee26 -eq 1) {
            Add-Result "DontEnumerateConnectedUsers" "ENABLED" "" $currentValuee26 1
        } else {
            Add-Result "DontEnumerateConnectedUsers" "NOT ENABLED" "LOW" $currentValuee26 1
        }
    } catch {
        Add-Result "DontEnumerateConnectedUsers" "ERROR" "MEDIUM" "N/A" "0" "Error retrieving registry value: $($_.Exception.Message)"
    }
}

function EnumerateLocalUsers {
    try {
        $currentValue27 = Get-ItemProperty -Path $regPath27 -Name $valueName27 -ErrorAction Stop
        $currentValuee27 = $currentValue27.$valueName27
        if ($currentValuee27 -eq 0) {
            Add-Result "EnumerateLocalUsers" "ENABLED" "" $currentValuee27 0
        } else {
            Add-Result "EnumerateLocalUsers" "NOT ENABLED" "LOW" $currentValuee27 0
        }
    } catch {
        Add-Result "EnumerateLocalUsers" "ERROR" "MEDIUM" "N/A" "0" "Error retrieving registry value: $($_.Exception.Message)"
    }
}

function BlockDomainPicturePassword {
    try {
        $currentValue28 = Get-ItemProperty -Path $regPath28 -Name $valueName28 -ErrorAction Stop
        $currentValuee28 = $currentValue28.$valueName28
        if ($currentValuee28 -eq 1) {
            Add-Result "BlockDomainPicturePassword" "ENABLED" "" $currentValuee28 1
        } else {
            Add-Result "BlockDomainPicturePassword" "NOT ENABLED" "LOW" $currentValuee28 1
        }
    } catch {
        Add-Result "BlockDomainPicturePassword" "ERROR" "MEDIUM" "N/A" "0" "Error retrieving registry value: $($_.Exception.Message)"
    }
}

function Enabled {
    try {
        $currentValue29 = Get-ItemProperty -Path $regPath29 -Name $valueName29 -ErrorAction Stop
        $currentValuee29 = $currentValue29.$valueName29
        if ($currentValuee29 -eq 0) {
            Add-Result "NTPEnabled" "ENABLED" "" $currentValuee29 0
        } else {
            Add-Result "NTPEnabled" "NOT ENABLED" "LOW" $currentValuee29 0
        }
    } catch {
        Add-Result "NTPEnabled" "ERROR" "MEDIUM" "N/A" "0" "Error retrieving registry value: $($_.Exception.Message)"
    }
}

function PwdExpirationProtectionEnabled {
    try {
        $currentValue30 = Get-ItemProperty -Path $regPath30 -Name $valueName30 -ErrorAction Stop
        $currentValuee30 = $currentValue30.$valueName30
        if ($currentValuee30 -eq 1) {
            Add-Result "PwdExpirationProtection" "ENABLED" "" $currentValuee30 1
        } else {
            Add-Result "PwdExpirationProtection" "NOT ENABLED" "HIGH" $currentValuee30 1
        }
    } catch {
        Add-Result "PwdExpirationProtection" "ERROR" "MEDIUM" "N/A" "0" "Error retrieving registry value: $($_.Exception.Message)"
    }
}

function ADPasswordEncryptionEnabled {
    try {
        $currentValue31 = Get-ItemProperty -Path $regPath31 -Name $valueName31 -ErrorAction Stop
        $currentValuee31 = $currentValue31.$valueName31
        if ($currentValuee31 -eq 1) {
            Add-Result "ADPasswordEncryptionEnabled" "ENABLED" "" $currentValuee31 1
        } else {
            Add-Result "ADPasswordEncryptionEnabled" "NOT ENABLED" "HIGH" $currentValuee31 1
        }
    } catch {
        Add-Result "ADPasswordEncryptionEnabled" "ERROR" "MEDIUM" "N/A" "0" "Error retrieving registry value: $($_.Exception.Message)"
    }
}

function PasswordComplexity {
    try {
        $currentValue32 = Get-ItemProperty -Path $regPath32 -Name $valueName32 -ErrorAction Stop
        $currentValuee32 = $currentValue32.$valueName32
        if ($currentValuee32 -eq 4) {
            Add-Result "PasswordComplexity" "ENABLED" "" $currentValuee32 4
        } else {
            Add-Result "PasswordComplexity" "NOT ENABLED" "HIGH" $currentValuee32 4
        }
    } catch {
        Add-Result "PasswordComplexity" "ERROR" "MEDIUM" "N/A" "0" "Error retrieving registry value: $($_.Exception.Message)"
    }
}

function PasswordLength {
    try {
        $currentValue33 = Get-ItemProperty -Path $regPath33 -Name $valueName33 -ErrorAction Stop
        $currentValuee33 = $currentValue33.$valueName33
        if ($currentValuee33 -eq 15) {
            Add-Result "PasswordLength" "ENABLED" "" $currentValuee33 15
        } else {
            Add-Result "PasswordLength" "NOT ENABLED" "MEDIUM" $currentValuee33 15
        }
    } catch {
        Add-Result "PasswordLength" "ERROR" "MEDIUM" "N/A" "0" "Error retrieving registry value: $($_.Exception.Message)"
    }
}

function PasswordAgeDays {
    try {
        $currentValue34 = Get-ItemProperty -Path $regPath34 -Name $valueName34 -ErrorAction Stop
        $currentValuee34 = $currentValue34.$valueName34
        if ($currentValuee34 -eq 30) {
            Add-Result "PasswordAgeDays" "ENABLED" "" $currentValuee34 30
        } else {
            Add-Result "PasswordAgeDays" "NOT ENABLED" "MEDIUM" $currentValuee34 30
        }
    } catch {
        Add-Result "PasswordAgeDays" "ERROR" "MEDIUM" "N/A" "0" "Error retrieving registry value: $($_.Exception.Message)"
    }
}

function PostAuthenticationResetDelay {
    try {
        $currentValue35 = Get-ItemProperty -Path $regPath35 -Name $valueName35 -ErrorAction Stop
        $currentValuee35 = $currentValue35.$valueName35
        if ($currentValuee35 -le 8 -and $currentValuee35 -ne 0) {
            Add-Result "PostAuthenticationResetDelay" "ENABLED" "" $currentValuee35 "less than 8 not equal to 0"
        } else {
            Add-Result "PostAuthenticationResetDelay" "NOT ENABLED" "MEDIUM" $currentValuee35
        }
    } catch {
        Add-Result "PostAuthenticationResetDelay" "ERROR" "MEDIUM" "N/A" "0" "Error retrieving registry value: $($_.Exception.Message)"
    }
}

function PostAuthenticationActions {
    try {
        $currentValue36 = Get-ItemProperty -Path $regPath36 -Name $valueName36 -ErrorAction Stop
        $currentValuee36 = $currentValue36.$valueName36
        if ($currentValuee36 -eq 3 -or $currentValuee36 -eq 5) {
            Add-Result "PostAuthenticationActions" "ENABLED" "" $currentValuee36 "3 or 5"
        } else {
            Add-Result "PostAuthenticationActions" "NOT ENABLED" "LOW" $currentValuee36
        }
    } catch {
        Add-Result "PostAuthenticationActions" "ERROR" "MEDIUM" "N/A" "0" "Error retrieving registry value: $($_.Exception.Message)"
    }
}

# Initialize temp file
Remove-Item "temp_output.csv" -ErrorAction SilentlyContinue

# Call your functions here
BackupDirectory
DontEnumerateConnectedUsers


function SayHello {
    Write-Output "Hello World"
}

function writeout {
    Write-Host $results
    $results | Export-Csv -Path "output.csv" -NoTypeInformation -Delimiter "|"
}
