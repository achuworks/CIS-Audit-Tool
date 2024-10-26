$global:results = @()
#remediation steps:
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
        [string]$RemediationStatus,
        [string]$Priority

    )
    $global:results += [pscustomobject]@{
        Name = $Name
        RemediationStatus = $RemediationStatus
        Priority=$Priority
       
    }
}
function RequireSignorSeal {
   
    $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
    if ($currentValue.$valueName -ne 1) {
        Set-ItemProperty -Path $regPath -Name $valueName -Value 1
        Add-Result "RequireSignOrSeal" "Remediation applied : ENABLED."
    }
    

}
function SealSecureChannel {
    $currentValue2 = Get-ItemProperty -Path $regPath2 -Name $valueName2 -ErrorAction Stop
    if($currentValue2.$valueName2 -ne 1){
        Set-ItemProperty -Path $regPath2 -Name $valueName2 -Value 1
        Add-Result "SealSecureChannel" "Remediation applied:ENABLED."
    }
}
function SignSecureChannel {
    $currentValue3 = Get-ItemProperty -Path $regPath3 -Name $valueName3 -ErrorAction Stop
    if($currentValue3.$valueName3 -ne 1){
        Set-ItemProperty -Path $regPath3 -Name $valueName3 -Value 1
        Add-Result "SignSecureChannel" "Remediation applied:ENABLED."
    }
}
function DisablePasswordChange {
    $currentValue4 = Get-ItemProperty -Path $regPath4 -Name $valueName4 -ErrorAction Stop
    if($currentValue4.$valueName4 -ne 1){
        Set-ItemProperty -Path $regPath4 -Name $valueName4 -Value 1
        Add-Result "DisablePasswordChange" "Remediation applied:ENABLED."
    }
}
function MaximumPasswordAge{
    $currentValue5 = Get-ItemProperty -Path $regPath5 -Name $valueName5 -ErrorAction Stop
    if($currentValue5.$valueName5 -ne 30){
        Set-ItemProperty -Path $regPath5 -Name $valueName5 -Value 30
        Add-Result  "MaximumPasswordAge" "Remediation applied:ENABLED"
    }
}
function RequireStrongKey{
    $currentValue6 = Get-ItemProperty -Path $regPath6 -Name $valueName6 -ErrorAction Stop
    if($currentValue6.$valueName6 -ne 1){
        Set-ItemProperty -Path $regPath6 -Name $valueName6 -Value 1
        Add-Result  "RequireStrongKey" "Remediation applied:ENABLED"
    }
}
function EnableFirewall {
    $currentValue7 = Get-ItemProperty -Path $regPath7 -Name $valueName7 -ErrorAction Stop
    if($currentValue7.$valueName7 -ne 1){
        Set-ItemProperty -Path $regPath7 -Name $valueName7 -Value 1
        Add-Result  "Firewall state" "Remediation applied:ENABLED"
    } 
}
function DefaultInbound {
    $currentValue8 = Get-ItemProperty -Path $regPath8 -Name $valueName8 -ErrorAction Stop
    if($currentValue8.$valueName8 -ne 1){
        Set-ItemProperty -Path $regPath8 -Name $valueName8 -Value 1
        Add-Result  "DefaultInbound" "Remediation applied:ENABLED"
    }
}
function DisableNotifications {
    $currentValue9 = Get-ItemProperty -Path $regPath9 -Name $valueName9 -ErrorAction Stop
    if($currentValue9.$valueName9 -ne 1){
        Set-ItemProperty -Path $regPath9 -Name $valueName9 -Value 1
        Add-Result  "DisableNotifications" "Remediation applied:ENABLED"
    } 
}
function LogFilePath {
    $currentValue10 = Get-ItemProperty -Path $regPath10 -Name $valueName10 -ErrorAction Stop
    $expectedLogFilePath = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
    if($currentValue10.$valueName10 -ne $expectedLogFilePath){
        Set-ItemProperty -Path $regPath10 -Name $valueName10 -Value $expectedLogFilePath
        Add-Result  "LogFilePath" "Remediation applied:ENABLED"
    } 
}
function LogFileSize
{
    $currentValue11=Get-ItemProperty -Path $regPath11 -Name $valueName11 -ErrorAction Stop 
    if($currentValue11.$valueName11 -ne 16384){
        Set-ItemProperty -Path $regPath11 -Name $valueName11 -Value 16384
        Add-Result "LogFileSize" "Remediation applied:set to 16384"
    }
    
}
function LogDroppedPackets
{
    $currentValue12=Get-ItemProperty -Path $regPath12 -Name $valueName12 -ErrorAction Stop
    if($currentValue12.$valueName12 -eq 1){
        Set-ItemProperty -Path $regPath12 -Name $valueName12 -Value 1
        Add-Result "Log Dropped Packets" "Remediation applied:ENABLED"
    }
    
}
function LogSuccessfulConnections
{
    $currentValue13=Get-ItemProperty -Path $regPath13 -Name $valueName13 -ErrorAction Stop
    if($currentValue13.$valueName13 -ne 1){
        Set-ItemProperty -Path $regPath13 -Name $valueName13 -Value 1
        Add-Result "LogSuccessfulConnections" "Remediation applied:ENABLED"
    }
}
function LocalAccountTokenFilterPolicy
{
    $currentValue14=Get-ItemProperty -Path $regPath14 -Name $valueName14 -ErrorAction Stop
    if($currentValue14.$valueName14 -ne 0){
        Set-ItemProperty -Path $regPath14 -Name $valueName14 -Value 0
        Add-Result "LocalAccountTokenFilterPolicy" "Remediation applied:ENABLED"
    }
    
}

function DoHPolicy {
    $currentValue15=Get-ItemProperty -Path $regPath15 -Name $valueName15 -ErrorAction Stop 
    if($currentValue15.$valueName15 -ne 2 -or $currentValue15.$valueName15 -ne 3){
        Set-ItemProperty -Path $regPath15 -Name $valueName15 -Value 3
        Add-Result "DoHPolicy" "Remediation applied:Enabled"
    }
    
}
    

function EnableNetbios {
    $currentValue16=Get-ItemProperty -Path $regPath16 -Name $valueName16 -ErrorAction Stop
    if($currentValue16.$valueName16 -ne 0 -or $currentValue16.$valueName16 -ne 2){
        Set-ItemProperty -Path $regPath16 -Name $valueName16 -Value 0
        Add-Result "NetBIOS" "Remediation applied:Enabled"
    }
    
}
function EnableMulticast {
    $currentValue17=Get-ItemProperty -Path $regPath17 -Name $valueName17 -ErrorAction Stop
    if($currentValue17.$valueName17 -ne 0){
        Set-ItemProperty -Path $regPath17 -Name $valueName17 -Value 0
        Add-Result "EnableMulticast" "Remediation applied:ENABLED"
    }
}
function NC_StdDomainUserSetLocation {
    $currentValue18=Get-ItemProperty -Path $regPath18 -Name $valueName18 -ErrorAction Stop
    if($currentValue18.$valueName18 -ne 1){
        Set-ItemProperty -Path $regPath18 -Name $valueName18 -Value 1
        Add-Result "NC_StdDomainUserSetLocation" "Remediation applied:ENABLED"
    }
}
function fBlockNonDomain{
    $currentValue19=Get-ItemProperty -Path $regPath19 -Name $valueName19 -ErrorAction Stop
    if($currentValue19.$valueName19 -ne 1){
        Set-ItemProperty -Path $regPath19 -Name $valueName19 -Value 1
        Add-Result "fBlockNonDomain" "Remediation applied:ENABLED"
    }
}
function NoBackgroundPolicy {
    $currentValue20=Get-ItemProperty -Path $regPath20 -Name $valueName20 -ErrorAction Stop
    if($currentValue20.$valueName20 -ne 0){
        Set-ItemProperty -Path $regPath20 -Name $valueName20 -Value 0
        Add-Result "NoBackgroundPolicy" "Remediation applied:ENABLED"
    }
}
function NoGPOListChanges {
    $currentValue21=Get-ItemProperty -Path $regPath21 -Name $valueName21 -ErrorAction Stop
    if($currentValue21.$valueName21 -ne 0){
        Set-ItemProperty -Path $regPath21 -Name $valueName21 -Value 0
        Add-Result "NoGPOListChanges" "Remediation applied:ENABLED"
    }
    
}
function NoBackgroundPolicy2
{
    $currentValue22=Get-ItemProperty -Path $regPath22 -Name $valueName22 -ErrorAction Stop
    if($currentValue22.$valueName22 -ne 0){
        Set-ItemProperty -Path $regPath22 -Name $valueName22 -Value 0
        Add-Result "NoBackgroundPolicy2" "Remediation applied:ENABLED"
    }
    
}
function NoGPOListChanges2 {
    $currentValue23=Get-ItemProperty -Path $regPath23 -Name $valueName23 -ErrorAction Stop
    if($currentValue23.$valueName23 -ne 0){
        Set-ItemProperty -Path $regPath23 -Name $valueName23 -Value 0
        Add-Result "NoGPOListChanges2" "Remediation applied:ENABLED"
    }
}
function DisableBkGndGroupPolicy {
    $currentValue24=Get-ItemProperty -Path $regPath24 -Name $valueName24 -ErrorAction Stop
    if($currentValue24.$valueName24 -ne 0){
        Set-ItemProperty -Path $regPath24 -Name $valueName24 -Value 0
        Add "Disable Background Group Policy" "Remediation applied:ENABLED"
    } 
}
function BackupDirectory {
    $currentValue25=Get-ItemProperty -Path $regPath25 -Name $valueName25 -ErrorAction Stop
    if($currentValue25.$valueName25 -ne 1 -or $currentValue25.$valueName25 -ne 2){
        Set-ItemProperty -Path $regPath25 -Name $valueName25 -Value 1
        Add-Result "LAPS BackupDirectory" "Remediation applied:ENABLED"
    }
}
function DontEnumerateConnectedUsers {
    $currentValue26=Get-ItemProperty -Path $regPath26 -Name $valueName26 -ErrorAction Stop
    if($currentValue26.$valueName26 -ne 1){
        Set-ItemProperty -Path $regPath26 -Name $valueName26 -Value 1
        Add-Result "DontEnumerateConnectedUsers" "Remediation applied:ENABLED"
    }
}
function EnumerateLocalUsers {
    $currentValue27=Get-ItemProperty -Path $regPath27 -Name $valueName27 -ErrorAction Stop
    if($currentValue27.$valueName27 -ne 0){
        Set-ItemProperty -Path $regPath27 -Name $valueName27 -Value 0
        Add-Result "EnumerateLocalUsers" "Remediation applied:ENABLED"
    }
}
function BlockDomainPicturePassword {
    $currentValue28=Get-ItemProperty -Path $regPath28 -Name $valueName28 -ErrorAction Stop
    if($currentValue28.$valueName28 -ne 1){
        Set-ItemProperty -Path $regPath28 -Name $valueName28 -Value 1
        Add-Result "BlockDomainPicturePassword" "Remediation applied:ENABLED"
    }
}
function Enabled {
    $currentValue29=Get-ItemProperty -Path $regPath29 -Name $valueName29 -ErrorAction Stop
    if($currentValue29.$valueName29 -ne 0){
        Set-ItemProperty -Path $regPath29 -Name $valueName29 -Value 0
        Add-Result "NTPEnabled" "Remediation applied:ENABLED"
    }
}
function PwdExpirationProtectionEnabled {
    $currentValue30=Get-ItemProperty -Path $regPath30 -Name $valueName30 -ErrorAction Stop
    if($currentValue30.$valueName30 -ne 1){
        Set-ItemProperty -Path $regPath30 -Name $valueName30 -Value 1
        Add-Result "PwdExpirationProtection" "Remediation applied:ENABLED"
    }
    
}

function ADPasswordEncryptionEnabled {
    $currentValue31=Get-ItemProperty -Path $regPath31 -Name $valueName31 -ErrorAction Stop
    if($currentValue31.$valueName31 -ne 1){
        Set-ItemProperty -Path $regPath 31-Name $valueName31 -Value 1
        Add-Result "ADPasswordEncryptionEnabled" "Remediation applied:ENABLED"
    }
    
}
function PasswordComplexity {
    $currentValue32=Get-ItemProperty -Path $regPath32 -Name $valueName32 -ErrorAction Stop
    if($currentValue32.$valueName32 -ne 4){
        Set-ItemProperty -Path $regPath32 -Name $valueName32 -Value 4
        Add-Result "PasswordComplexity" "Remediation applied:ENABLED"
    }
    
}
function PasswordLength {
    $currentValue33=Get-ItemProperty -Path $regPath33 -Name $valueName33 -ErrorAction Stop
    if($currentValue33.$valueName33 -ne 15){
        Set-ItemProperty -Path $regPath33 -Name $valueName33 -Value 15
        Add-Result "PasswordLength" "Remediation applied:ENABLED"
    }
}
function PasswordAgeDays {
    $currentValue34=Get-ItemProperty -Path $regPath34 -Name $valueName34 -ErrorAction Stop
    if($currentValue34.$valueName34 -ne 30){
        Set-ItemProperty -Path $regPath34 -Name $valueName34 -Value 30
        Add-Result "PasswordAgeDays" "Remediation applied:ENABLED"
    }
}
function PostAuthenticationResetDelay {
    $currentValue35=Get-ItemProperty -Path $regPath35 -Name $valueName35 -ErrorAction Stop
    if($currentValue35.$valueName35  -gt 8 -and $currentValue35.$valueName35 -eq 0){
        Set-ItemProperty -Path $regPath35 -Name $valueName35 -Value 7
        Add-Result "PostAuthenticationResetDelay" "Remediation applied:ENABLED"
    }
}
function PostAuthenticationActions{
    $currentValue36=Get-ItemProperty -Path $regPath36 -Name $valueName36 -ErrorAction Stop
    if($currentValue36.$valueName36 -ne 3 -or $currentValue36.$valueName36 -ne 5){
        Set-ItemProperty -Path $regPath36 -Name $valueName36 -Value 3
        Add-Result "PostAuthenticationActions" "Remediation applied:ENABLED"
    }
}





RequireSignOrSeal
SealSecureChannel
SignSecureChannel
DisablePasswordChange
MaximumPasswordAge
RequireStrongKey
EnableFirewall
DefaultInbound
DisableNotifications
LogFilePath
LogFileSize
LogDroppedPackets
LogSuccessfulConnections
LocalAccountTokenFilterPolicy
DoHPolicy 
EnableNetbios
EnableMulticast
NC_StdDomainUserSetLocation
fBlockNonDomain
NoBackgroundPolicy
NoGPOListChanges
NoBackgroundPolicy2
NoGPOListChanges2
DisableBkGndGroupPolicy 
BackupDirectory
DontEnumerateConnectedUsers
EnumerateLocalUsers
BlockDomainPicturePassword
Enabled
PwdExpirationProtectionEnabled
ADPasswordEncryptionEnabled
PasswordComplexity
PasswordLength
PasswordAgeDays
PostAuthenticationResetDelay
PostAuthenticationActions




Write-Host $results;
$results | Export-Csv -Path "remediationoutput.csv" -NoTypeInformation -Delimiter "|"





