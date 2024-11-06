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
        [string]$StatusToBe,
        [string]$Priority,
        [string]$RegistryValue,
        [string]$ValueToBe
    )
    $global:results += [pscustomobject]@{
        Name = $Name
        Status = $Status
        StatusToBe=$StatusToBe
        Priority = $Priority
        RegistryValue = $RegistryValue
        ValueToBe = $ValueToBe
    }
}
function RequireSignorSeal {
       
        $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
        $currentValuee = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop).$valueName
        if ($currentValue.$valueName -eq 1) {
            Add-Result "RequireSignOrSeal" "ENABLED" "ENABLED" "" $currentValuee 1
        }
        else{
            Add-Result "RequireSignOrSeal" "NOT ENABLED" "ENABLED" "MEDIUM" $currentValuee 1
        }
        
}
function SealSecureChannel {
    $currentValue2 = Get-ItemProperty -Path $regPath2 -Name $valueName2 -ErrorAction Stop
    $currentValuee2 = (Get-ItemProperty -Path $regPath2 -Name $valueName2 -ErrorAction Stop).$valueName2
    if($currentValue2.$valueName2 -eq 1){
        Add-Result "SealSecureChannel" "ENABLED" "ENABLED" "" $currentValuee2 1
    }else{
        Add-Result "SealSecureChannel" "NOT ENABLED" "ENABLED" "MEDIUM" $currentValuee2 1
    }
}
function SignSecureChannel {
    $currentValue3 = Get-ItemProperty -Path $regPath3 -Name $valueName3 -ErrorAction Stop
    $currentValuee3 = (Get-ItemProperty -Path $regPath3 -Name $valueName3 -ErrorAction Stop).$valueName3
    if($currentValue3.$valueName3 -eq 1){
        Add-Result "SignSecureChannel" "ENABLED" "ENABLED" "" $currentValuee3 1
    }else{
        Add-Result "SignSecureChannel" "NOT ENABLED." "ENABLED" "MEDIUM" $currentValuee3 1
    }
}
function DisablePasswordChange {
    $currentValue4 = Get-ItemProperty -Path $regPath4 -Name $valueName4 -ErrorAction Stop
    $currentValuee4 = (Get-ItemProperty -Path $regPath4 -Name $valueName4 -ErrorAction Stop).$valueName4
    if($currentValue4.$valueName4 -eq 1){
        Add-Result "DisablePasswordChange" "ENABLED" "NOT ENABLED" "MEDIUM" $currentValuee4 1
    }else{
        Add-Result "DisablePasswordChange" "NOT ENABLED" "NOT ENABLED" "" $currentValuee4 1
    }
}
function MaximumPasswordAge{
    $currentValue5 = Get-ItemProperty -Path $regPath5 -Name $valueName5 -ErrorAction Stop
    $currentValuee5 = (Get-ItemProperty -Path $regPath5 -Name $valueName5 -ErrorAction Stop).$valueName5
    if($currentValue5.$valueName5 -eq 30){
        Add-Result  "MaximumPasswordAge" "ENABLED" "ENABLED" "" $currentValuee5 30
    }else{
        Add-Result "MaximumPasswordAge" "NOT ENABLED" "ENABLED" "HIGH" $currentValuee5 30
    }
}
function RequireStrongKey{
    $currentValue6 = Get-ItemProperty -Path $regPath6 -Name $valueName6 -ErrorAction Stop
    $currentValuee6 = (Get-ItemProperty -Path $regPath6 -Name $valueName6 -ErrorAction Stop).$valueName6
    if($currentValue6.$valueName6 -eq 1){
        Add-Result  "RequireStrongKey" "ENABLED" "ENABLED" "" $currentValuee6 1
    }else{
        Add-Result "RequireStrongKey" "NOT ENABLED." "ENABLED" "HIGH" $currentValuee6 1
    }
}
function EnableFirewall {
    $currentValue7 = Get-ItemProperty -Path $regPath7 -Name $valueName7 -ErrorAction Stop
    $currentValuee7 = (Get-ItemProperty -Path $regPath7 -Name $valueName7 -ErrorAction Stop).$valueName7
    if($currentValue7.$valueName7 -eq 1){
        Add-Result  "Firewall state" "ENABLED" "ENABLED" "" $currentValuee7 1
    }else{
        Add-Result "Firewall state" "NOT ENABLED." "ENABLED" "HIGH" $currentValuee7 1
    } 
}
function DefaultInbound {
    $currentValue8 = Get-ItemProperty -Path $regPath8 -Name $valueName8 -ErrorAction Stop
    $currentValuee8 = (Get-ItemProperty -Path $regPath8 -Name $valueName8 -ErrorAction Stop).$valueName8
    if($currentValue8.$valueName8 -eq 1){
        Add-Result  "DefaultInbound" "ENABLED" "ENABLED" "" $currentValuee8 1
    }else{
        Add-Result "DefaultInbound" "NOT ENABLED." "ENABLED" "MEDIUM" $currentValuee8 1
    } 
}
function DisableNotifications {
    $currentValue9 = Get-ItemProperty -Path $regPath9 -Name $valueName9 -ErrorAction Stop
    $currentValuee9 = (Get-ItemProperty -Path $regPath9 -Name $valueName9 -ErrorAction Stop).$valueName9
    if($currentValue9.$valueName9 -eq 1){
        Add-Result  "DisableNotifications" "ENABLED" "NOT ENABLED" "MEDIUM" $currentValuee9 1
    }else{
        Add-Result "DisableNotifications" "NOT ENABLED" "NOT ENABLED" "" $currentValuee9 1
    } 
}
function LogFilePath {
    $currentValue10 = Get-ItemProperty -Path $regPath10 -Name $valueName10 -ErrorAction Stop
    $currentValuee10 = (Get-ItemProperty -Path $regPath10 -Name $valueName10 -ErrorAction Stop).$valueName10
    $expectedLogFilePath = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
    if($currentValue10.$valueName10 -eq $expectedLogFilePath){
        Add-Result  "LogFilePath" "ENABLED" "ENABLED" "" $expectedLogFilePath $expectedLogFilePath
    }else{
        Add-Result "LogFilePath" "NOT ENABLED" "ENABLED" "MEDIUM" $currentValuee10 $expectedLogFilePath
    } 
}
function LogFileSize
{
    $currentValue11=Get-ItemProperty -Path $regPath11 -Name $valueName11 -ErrorAction Stop 
    $currentValuee11 = (Get-ItemProperty -Path $regPath11 -Name $valueName11 -ErrorAction Stop).$valueName11
    if($currentValue11.$valueName11 -eq 16384){
        Add-Result "LogFileSize" "SET TO 16384" "SET TO 16384" "" $currentValuee11 16384
    }else{
        Add-Result "LogFileSize" "NOT SET TO 16384" "SET TO 16384" "MEDIUM" $currentValuee11 16384
    }
    
}
function LogDroppedPackets
{
    $currentValue12=Get-ItemProperty -Path $regPath12 -Name $valueName12 -ErrorAction Stop
    $currentValuee12 = (Get-ItemProperty -Path $regPath12 -Name $valueName12 -ErrorAction Stop).$valueName12
    if($currentValue12.$valueName12 -eq 1){
        Add-Result "Log Dropped Packets" "ENABLED" "ENABLED" "" $currentValuee12 1
    }else{
        Add-Result "Log Dropped Packets" "NOT ENABLED" "ENABLED" "HIGH" $currentValuee12 1
    }
    
}
function LogSuccessfulConnections
{
    $currentValue13=Get-ItemProperty -Path $regPath13 -Name $valueName13 -ErrorAction Stop
    $currentValuee13 = (Get-ItemProperty -Path $regPath13 -Name $valueName13 -ErrorAction Stop).$valueName13
    if($currentValue13.$valueName13 -eq 1){
        Add-Result "LogSuccessfulConnections" "ENABLED" "ENABLED" "" $currentValuee13 1
    }else{
        Add-Result "LogSuccessfulConnections" "NOT ENABLED" "ENABLED" "HIGH" $currentValuee13 1
    }
    
}
function LocalAccountTokenFilterPolicy
{
    $currentValue14=Get-ItemProperty -Path $regPath14 -Name $valueName14 -ErrorAction Stop
    $currentValuee14 = (Get-ItemProperty -Path $regPath14 -Name $valueName14 -ErrorAction Stop).$valueName14
    if($currentValue14.$valueName14 -eq 0){
        Add-Result "LocalAccountTokenFilterPolicy" "ENABLED" "ENABLED" "" $currentValuee14 0
    }else{
        Add-Result "LocalAccountTokenFilterPolicy" "NOT ENABLED" "ENABLED" "MEDIUM" $currentValuee14 0
    }
    
}

function DoHPolicy {
    $currentValue15=Get-ItemProperty -Path $regPath15 -Name $valueName15 -ErrorAction Stop 
    $currentValuee15 = (Get-ItemProperty -Path $regPath15 -Name $valueName15 -ErrorAction Stop).$valueName15
    if($currentValue15.$valueName15 -eq 2 -or $currentValue15.$valueName15 -eq 3){
        Add-Result "DoHPolicy" "ENABLED" "ENABLED" "" $currentValuee15 "2 or 3"
    }
    else{
        Add-Result "DoHPolicy" "NOT ENABLED" "ENABLED" "MEDIUM" $currentValuee15 "2 or 3"
    }
    
}
function EnableNetbios {
    $currentValue16=Get-ItemProperty -Path $regPath16 -Name $valueName16 -ErrorAction Stop
    $currentValuee16 = (Get-ItemProperty -Path $regPath16 -Name $valueName16 -ErrorAction Stop).$valueName16
    if($currentValue16.$valueName16 -eq 0 -or $currentValue16.$valueName16 -eq 2){
        Add-Result "NetBIOS" "ENABLED" "ENABLED" "" $currentValuee16 0
    }
    else{
        Add-Result "NetBIOS" "NOT ENABLED" "ENABLED" "LOW" $currentValuee16 0
    }
    
}
function EnableMulticast {
    $currentValue17=Get-ItemProperty -Path $regPath17 -Name $valueName17 -ErrorAction Stop
    $currentValuee17 = (Get-ItemProperty -Path $regPath17 -Name $valueName17 -ErrorAction Stop).$valueName17
    if($currentValue17.$valueName17 -eq 0){
        Add-Result "EnableMulticast" "ENABLED" "ENABLED" "" $currentValuee17 0
    }else{
        Add-Result "EnableMulticast" "NOT ENABLED" "ENABLED" "LOW" $currentValuee17 0
    }
    
}
function NC_StdDomainUserSetLocation {
    $currentValue18=Get-ItemProperty -Path $regPath18 -Name $valueName18 -ErrorAction Stop
    $currentValuee18 = (Get-ItemProperty -Path $regPath18 -Name $valueName18 -ErrorAction Stop).$valueName18
    if($currentValue18.$valueName18 -eq 1){
        Add-Result "NC_StdDomainUserSetLocation" "ENABLED" "ENABLED" "" $currentValuee18 1
    }else{
        Add-Result "NC_StdDomainUserSetLocation" "NOT ENABLED" "ENABLED" "LOW" $currentValuee18 1
    }
    
}
function fBlockNonDomain{
    $currentValue19=Get-ItemProperty -Path $regPath19 -Name $valueName19 -ErrorAction Stop
    $currentValuee19 = (Get-ItemProperty -Path $regPath19 -Name $valueName19 -ErrorAction Stop).$valueName19
    if($currentValue19.$valueName19 -eq 1){
        Add-Result "fBlockNonDomain" "ENABLED" "ENABLED" "" $currentValuee19 1
    }else{
        Add-Result "fBlockNonDomain" "NOT ENABLED" "ENABLED" "LOW" $currentValuee19 1
    }
    
}
function NoBackgroundPolicy {
    $currentValue20=Get-ItemProperty -Path $regPath20 -Name $valueName20 -ErrorAction Stop
    $currentValuee20 = (Get-ItemProperty -Path $regPath20 -Name $valueName20 -ErrorAction Stop).$valueName20
    if($currentValue20.$valueName20 -eq 0){
        Add-Result "NoBackgroundPolicy" "ENABLED" "ENABLED" "" $currentValuee20 0
    }else{
        Add-Result "NoBackgroundPolicy" "NOT ENABLED" "ENABLED" "LOW" $currentValuee20 0
    }
    
}
function NoGPOListChanges {
    $currentValue21=Get-ItemProperty -Path $regPath21 -Name $valueName21 -ErrorAction Stop
    $currentValuee21 = (Get-ItemProperty -Path $regPath21 -Name $valueName21 -ErrorAction Stop).$valueName21
    if($currentValue21.$valueName21 -eq 0){
        Add-Result "NoGPOListChanges" "ENABLED" "ENABLED" "" $currentValuee21 0
    }else{
        Add-Result "NoGPOListChanges" "NOT ENABLED" "ENABLED" "LOW" $currentValuee21 0
    }
    
}
function NoBackgroundPolicy2
{
    $currentValue22=Get-ItemProperty -Path $regPath22 -Name $valueName22 -ErrorAction Stop
    $currentValuee22 = (Get-ItemProperty -Path $regPath22 -Name $valueName22 -ErrorAction Stop).$valueName22
    if($currentValue22.$valueName22 -eq 0){
        Add-Result "NoBackgroundPolicy2" "ENABLED" "ENABLED" "" $currentValuee22 0
    }else{
        Add-Result "NoBackgroundPolicy2" "NOT ENABLED" "ENABLED" "LOW" $currentValuee22 0
    }
    
}
function NoGPOListChanges2 {
    $currentValue23=Get-ItemProperty -Path $regPath23 -Name $valueName23 -ErrorAction Stop
    $currentValuee23 = (Get-ItemProperty -Path $regPath23 -Name $valueName23 -ErrorAction Stop).$valueName23
    if($currentValue23.$valueName23 -eq 0){
        Add-Result "NoGPOListChanges2" "ENABLED" "ENABLED" "" $currentValuee23 0
    }else{
        Add-Result "NoGPOListChanges2" "NOT ENABLED" "ENABLED" "LOW" $currentValuee23 0
    }
    
}
function DisableBkGndGroupPolicy {
    $currentValue24=Get-ItemProperty -Path $regPath24 -Name $valueName24 -ErrorAction Stop
    $currentValuee24 = (Get-ItemProperty -Path $regPath24 -Name $valueName24 -ErrorAction Stop).$valueName24
    if($currentValue24.$valueName24 -eq 0){
        Add-Result "Disable Background Group Policy" "ENABLED" "NOT ENABLED" "MEDIUM" $currentValuee24 0
    }else{
        Add-Result "Disable Background Group Policy" "NOT ENABLED"  "NOT ENABLED" ""  $currentValuee24 0
    }
    
}
function BackupDirectory {
    $currentValue25=Get-ItemProperty -Path $regPath25 -Name $valueName25 -ErrorAction Stop
    $currentValuee25 = (Get-ItemProperty -Path $regPath25 -Name $valueName25 -ErrorAction Stop).$valueName25
    if($currentValue25.$valueName25 -eq 1 -or $currentValue25.$valueName25 -eq 2){
        Add-Result "LAPS BackupDirectory" "ENABLED" "ENABLED" "" $currentValuee25 "1 or 2"
    }else{
        Add-Result "LAPS BackupDirectory" "NOT ENABLED" "ENABLED" "LOW" $currentValuee25 "1 or 2"
    }
}
function DontEnumerateConnectedUsers {
    $currentValue26=Get-ItemProperty -Path $regPath26 -Name $valueName26 -ErrorAction Stop
    $currentValuee26 = (Get-ItemProperty -Path $regPath26 -Name $valueName26 -ErrorAction Stop).$valueName26
    if($currentValue26.$valueName26 -eq 1){
        Add-Result "DontEnumerateConnectedUsers" "ENABLED" "ENABLED" "" $currentValuee26 1
    }else{
        Add-Result "DontEnumerateConnectedUsers" "NOT ENABLED" "ENABLED" "LOW" $currentValuee26 1
    }
    
}
function EnumerateLocalUsers {
    $currentValue27=Get-ItemProperty -Path $regPath27 -Name $valueName27 -ErrorAction Stop
    $currentValuee27 = (Get-ItemProperty -Path $regPath27 -Name $valueName27 -ErrorAction Stop).$valueName27
    if($currentValue27.$valueName27 -eq 0){
        Add-Result "EnumerateLocalUsers" "ENABLED" "NOT ENABLED" "LOW" $currentValuee27 0
    }else{
        Add-Result "EnumerateLocalUsers" "NOT ENABLED" "NOT ENABLED" "" $currentValuee27 0
    }
    
}
function BlockDomainPicturePassword {
    $currentValue28=Get-ItemProperty -Path $regPath28 -Name $valueName28 -ErrorAction Stop
    $currentValuee28 = (Get-ItemProperty -Path $regPath28 -Name $valueName28 -ErrorAction Stop).$valueName28
    if($currentValue28.$valueName28 -eq 1){
        Add-Result "BlockDomainPicturePassword" "ENABLED" "ENABLED" "" $currentValuee28 1
    }else{
        Add-Result "BlockDomainPicturePassword" "NOT ENABLED" "ENABLED" "LOW" $currentValuee28 1
    }
    
}
function Enabled {
    $currentValue29=Get-ItemProperty -Path $regPath29 -Name $valueName29 -ErrorAction Stop
    $currentValuee29 = (Get-ItemProperty -Path $regPath29 -Name $valueName29 -ErrorAction Stop).$valueName29
    if($currentValue29.$valueName29 -eq 0){
        Add-Result "NTPEnabled" "ENABLED" "ENABLED" "" $currentValuee29 0
    }else{
        Add-Result "NTPEnabled" "NOT ENABLED" "ENABLED" "LOW" $currentValuee29 0
    }
    
}
function PwdExpirationProtectionEnabled {
    $currentValue30=Get-ItemProperty -Path $regPath30 -Name $valueName30 -ErrorAction Stop
    $currentValuee30 = (Get-ItemProperty -Path $regPath30 -Name $valueName30 -ErrorAction Stop).$valueName30
    if($currentValue30.$valueName30 -eq 1){
        Add-Result "PwdExpirationProtection" "ENABLED" "ENABLED" "" $currentValuee30 1
    }
    else{
        Add-Result "PwdExpirationProtection" "NOT ENABLED" "ENABLED" "HIGH" $currentValuee30 1
    }
}

function ADPasswordEncryptionEnabled {
    $currentValue31=Get-ItemProperty -Path $regPath31 -Name $valueName31 -ErrorAction Stop
    $currentValuee31 = (Get-ItemProperty -Path $regPath31 -Name $valueName31 -ErrorAction Stop).$valueName31
    if($currentValue31.$valueName31 -eq 1){
        Add-Result "ADPasswordEncryptionEnabled" "ENABLED" "ENABLED" "" $currentValuee31 1
    }else{
        Add-Result "ADPasswordEncryptionEnabled" "NOT ENABLED" "ENABLED" "HIGH" $currentValuee31 1
    }
    
}
function PasswordComplexity {
    $currentValue32=Get-ItemProperty -Path $regPath32 -Name $valueName32 -ErrorAction Stop
    $currentValuee32 = (Get-ItemProperty -Path $regPath32 -Name $valueName32 -ErrorAction Stop).$valueName32
    if($currentValue32.$valueName32 -eq 4){
        Add-Result "PasswordComplexity" "ENABLED" "ENABLED" "" $currentValuee32 4
    }
    else{
        Add-Result "PasswordComplexity" "NOT ENABLED" "ENABLED" "HIGH" $currentValuee32 4
    }
    
}
function PasswordLength {
    $currentValue33=Get-ItemProperty -Path $regPath33 -Name $valueName33 -ErrorAction Stop
    $currentValuee33 = (Get-ItemProperty -Path $regPath33 -Name $valueName33 -ErrorAction Stop).$valueName33
    if($currentValue33.$valueName33 -eq 15){
        Add-Result "PasswordLength" "ENABLED" "ENABLED" "" $currentValuee33 15
    }else{
        Add-Result "PasswordLength" "NOT ENABLED" "ENABLED" "MEDIUM" $currentValuee33 15
    }
    
}
function PasswordAgeDays {
    $currentValue34=Get-ItemProperty -Path $regPath34 -Name $valueName34 -ErrorAction Stop
    $currentValuee34 = (Get-ItemProperty -Path $regPath34 -Name $valueName34 -ErrorAction Stop).$valueName34
    if($currentValue34.$valueName34 -eq 30){
        Add-Result "PasswordAgeDays" "ENABLED" "ENABLED" "" $currentValuee34 30
    }
    else{
        Add-Result "PasswordAgeDays" "NOT ENABLED" "ENABLED" "MEDIUM" $currentValuee34 30
    }
    
}
function PostAuthenticationResetDelay {
    $currentValue35=Get-ItemProperty -Path $regPath35 -Name $valueName35 -ErrorAction Stop
    $currentValuee35 = (Get-ItemProperty -Path $regPath35 -Name $valueName35 -ErrorAction Stop).$valueName35
    if($currentValue35.$valueName35  -le 8 -and $currentValue35.$valueName35 -ne 0){
        Add-Result "PostAuthenticationResetDelay" "ENABLED" "ENABLED" "" $currentValuee35 "less than 8  not equal to 0"
    }else{
        Add-Result "PostAuthenticationResetDelay" "NOT ENABLED" "ENABLED" "MEDIUM" $currentValuee35
    }
    
}
function PostAuthenticationActions{
    $currentValue36=Get-ItemProperty -Path $regPath36 -Name $valueName36 -ErrorAction Stop
    $currentValuee36 = (Get-ItemProperty -Path $regPath36 -Name $valueName36 -ErrorAction Stop).$valueName36
    if($currentValue36.$valueName36 -eq 3 -or $currentValue36.$valueName36 -eq 5){
        Add-Result "PostAuthenticationActions" "ENABLED" "ENABLED" "" $currentValuee36 "3 or 5"
    }else{
        Add-Result "PostAuthenticationActions" "NOT ENABLED" "ENABLED" "LOW" $currentValuee36
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
$results | Export-Csv -Path "output3.csv" -NoTypeInformation -Delimiter "|"