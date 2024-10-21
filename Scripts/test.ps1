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
<#$regPath24="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$valueName24="DisableBkGndGroupPolicy"#>
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
function RequireSignorSeal {
    
        $currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction Stop
        if ($currentValue.$valueName -eq 1) {
            Write-Host "RequireSignOrSeal ENABLED."
        }
        elseif($currentValue.$valueName -eq 0){
            Write-Host "RequireSignOrSeal NOT ENABLED"
        }
}
function SealSecureChannel {
    $currentValue2 = Get-ItemProperty -Path $regPath2 -Name $valueName2 -ErrorAction Stop
    if($currentValue2.$valueName2 -eq 1){
        Write-Host "SealSecureChannel ENABLED."
    }elseif($currentValue2.$valueName2 -eq 0){
        Write-Host "SealSecureChannel NOT ENABLED."
    }
}
function SignSecureChannel {
    $currentValue3 = Get-ItemProperty -Path $regPath3 -Name $valueName3 -ErrorAction Stop
    if($currentValue3.$valueName3 -eq 1){
        Write-Host "SignSecureChannel ENABLED."
    }elseif($currentValue3.$valueName3 -eq 0){
        Write-Host "SignSecureChannel NOT ENABLED."
    }
}
function DisablePasswordChange {
    $currentValue4 = Get-ItemProperty -Path $regPath4 -Name $valueName4 -ErrorAction Stop
    if($currentValue4.$valueName4 -eq 1){
        Write-Host "DisablePasswordChange ENABLED."
    }elseif($currentValue4.$valueName4 -eq 0){
        Write-Host "DisablePasswordChange NOT ENABLED."
    }
}
function MaximumPasswordAge{
    $currentValue5 = Get-ItemProperty -Path $regPath5 -Name $valueName5 -ErrorAction Stop
    if($currentValue5.$valueName5 -eq 30){
        Write-Host  "MaximumPasswordAge ENABLED"
    }elseif($currentValue5.$valueName5 -eq 0){
        Write-Host "MaximumPasswordAge NOT ENABLED."
    }
}
function RequireStrongKey{
    $currentValue6 = Get-ItemProperty -Path $regPath6 -Name $valueName6 -ErrorAction Stop
    if($currentValue6.$valueName6 -eq 1){
        Write-Host  "RequireStrongKey ENABLED"
    }elseif($currentValue6.$valueName6 -eq 0){
        Write-Host "RequireStrongKey NOT ENABLED."
    }
}
function EnableFirewall {
    $currentValue7 = Get-ItemProperty -Path $regPath7 -Name $valueName7 -ErrorAction Stop
    if($currentValue7.$valueName7 -eq 1){
        Write-Host  "Firewall state ENABLED"
    }elseif($currentValue7.$valueName7 -eq 0){
        Write-Host "Firewall state NOT ENABLED."
    } 
}
function DefaultInbound {
    $currentValue8 = Get-ItemProperty -Path $regPath8 -Name $valueName8 -ErrorAction Stop
    if($currentValue8.$valueName8 -eq 1){
        Write-Host  "DefaultInbound ENABLED"
    }elseif($currentValue8.$valueName8 -eq 0){
        Write-Host "DefaultInbound NOT ENABLED."
    } 
}
function DisableNotifications {
    $currentValue9 = Get-ItemProperty -Path $regPath9 -Name $valueName9 -ErrorAction Stop
    if($currentValue9.$valueName9 -eq 1){
        Write-Host  "DisableNotifications ENABLED"
    }elseif($currentValue9.$valueName9 -eq 0){
        Write-Host "DisableNotifications NOT ENABLED."
    } 
}
function LogFilePath {
    $currentValue10 = Get-ItemProperty -Path $regPath10 -Name $valueName10 -ErrorAction Stop
    $expectedLogFilePath = "%SystemRoot%\System32\logfiles\firewall\domainfw.log"
    if($currentValue10.$valueName10 -eq $expectedLogFilePath){
        Write-Host  "LogFilePath ENABLED"
    }else{
        Write-Host "LogFilePath NOT ENABLED."
    } 
}
function LogFileSize
{
    $currentValue11=Get-ItemProperty -Path $regPath11 -Name $valueName11 -ErrorAction Stop 
    if($currentValue11.$valueName11 -eq 16384){
        Write-Host "LogFileSize set to 16384"
    }else{
        Write-Host "LogFileSize not set to 16384"
    }
    
}
function LogDroppedPackets
{
    $currentValue12=Get-ItemProperty -Path $regPath12 -Name $valueName12 -ErrorAction Stop
    if($currentValue12.$valueName12 -eq 1){
        Write-Host "Log Dropped Packets ENABLED"
    }else{
        Write-Host "Log Dropped Packets NOT ENABLED"
    }
    
}
function LogSuccessfulConnections
{
    $currentValue13=Get-ItemProperty -Path $regPath13 -Name $valueName13 -ErrorAction Stop
    if($currentValue13.$valueName13 -eq 1){
        Write-Host "LogSuccessfulConnections ENABLED"
    }else{
        Write-Host "LogSuccessfulConnections NOT ENABLED"
    }
    
}
function LocalAccountTokenFilterPolicy
{
    $currentValue14=Get-ItemProperty -Path $regPath14 -Name $valueName14 -ErrorAction Stop
    if($currentValue14.$valueName14 -eq 0){
        Write-Host "LocalAccountTokenFilterPolicy ENABLED"
    }else{
        Write-Host "LocalAccountTokenFilterPolicy NOT ENABLED"
    }
    
}

function DoHPolicy {
    $currentValue15=Get-ItemProperty -Path $regPath15 -Name $valueName15 -ErrorAction Stop 
    if($currentValue15.$valueName15 -eq 2 -or $currentValue15.$valueName15 -eq 3){
        Write-Host "DoHPolicy Enabled"
    }
    else{
        Write-Host "DoHPolicy not ENABLED"
    }
    
}
function EnableNetbios {
    $currentValue16=Get-ItemProperty -Path $regPath16 -Name $valueName16 -ErrorAction Stop
    if($currentValue16.$valueName16 -eq 0 -or $currentValue16.$valueName16 -eq 2){
        Write-Host "NetBIOS Enabled"
    }
    else{
        Write-Host "NetBIOS NOT ENABLED"
    }
    
}
function EnableMulticast {
    $currentValue17=Get-ItemProperty -Path $regPath17 -Name $valueName17 -ErrorAction Stop
    if($currentValue17.$valueName17 -eq 0){
        Write-Host "EnableMulticast ENABLED"
    }else{
        Write-Host "EnableMulticast NOT ENABLED"
    }
    
}
function NC_StdDomainUserSetLocation {
    $currentValue18=Get-ItemProperty -Path $regPath18 -Name $valueName18 -ErrorAction Stop
    if($currentValue18.$valueName18 -eq 1){
        Write-Host "NC_StdDomainUserSetLocation ENABLED"
    }else{
        Write-Host "NC_StdDomainUserSetLocation NOT ENABLED"
    }
    
}
function fBlockNonDomain{
    $currentValue19=Get-ItemProperty -Path $regPath19 -Name $valueName19 -ErrorAction Stop
    if($currentValue19.$valueName19 -eq 1){
        Write-Host "fBlockNonDomain ENABLED"
    }else{
        Write-Host "fBlockNonDomain NOT ENABLED"
    }
    
}
function NoBackgroundPolicy {
    $currentValue20=Get-ItemProperty -Path $regPath20 -Name $valueName20 -ErrorAction Stop
    if($currentValue20.$valueName20 -eq 0){
        Write-Host "NoBackgroundPolicy ENABLED"
    }else{
        Write-Host "NoBackgroundPolicy NOT ENABLED"
    }
    
}
function NoGPOListChanges {
    $currentValue21=Get-ItemProperty -Path $regPath21 -Name $valueName21 -ErrorAction Stop
    if($currentValue21.$valueName21 -eq 0){
        Write-Host "NoGPOListChanges ENABLED"
    }else{
        Write-Host "NoGPOListChanges NOT ENABLED"
    }
    
}
function NoBackgroundPolicy2
{
    $currentValue22=Get-ItemProperty -Path $regPath22 -Name $valueName22 -ErrorAction Stop
    if($currentValue22.$valueName22 -eq 0){
        Write-Host "NoBackgroundPolicy2 ENABLED"
    }else{
        Write-Host "NoBackgroundPolicy2 NOT ENABLED"
    }
    
}
function NoGPOListChanges2 {
    $currentValue23=Get-ItemProperty -Path $regPath23 -Name $valueName23 -ErrorAction Stop
    if($currentValue23.$valueName23 -eq 0){
        Write-Host "NoGPOListChanges2 ENABLED"
    }else{
        Write-Host "NoGPOListChanges2 NOT ENABLED"
    }
    
}
<#function DisableBkGndGroupPolicy {
    $currentValue24=Get-ItemProperty -Path $regPath24 -Name $valueName24 -ErrorAction Stop
    if($currentValue24.$valueName24 -eq 0){
        Write-Host "Disable Background Group Policy ENABLED"
    }else{
        Write-Host "Disable Background Group Policy NOT ENABLED"
    }
    
}#>
function BackupDirectory {
    $currentValue25=Get-ItemProperty -Path $regPath25 -Name $valueName25 -ErrorAction Stop
    if($currentValue25.$valueName25 -eq 1 -or $currentValue25.$valueName25 -eq 2){
        Write-Host "LAPS BackupDirectory ENABLED"
    }else{
        Write-Host "LAPS :BackupDirectory NOT ENABLED"
    }
}
function DontEnumerateConnectedUsers {
    $currentValue26=Get-ItemProperty -Path $regPath26 -Name $valueName26 -ErrorAction Stop
    if($currentValue26.$valueName26 -eq 1){
        Write-Host "DontEnumerateConnectedUsers ENABLED"
    }else{
        Write-Host "DontEnumerateConnectedUsers NOT ENABLED"
    }
    
}
function EnumerateLocalUsers {
    $currentValue27=Get-ItemProperty -Path $regPath27 -Name $valueName27 -ErrorAction Stop
    if($currentValue27.$valueName27 -eq 0){
        Write-Host "EnumerateLocalUsers ENABLED"
    }else{
        Write-Host "EnumerateLocalUsers NOT ENABLED"
    }
    
}
function BlockDomainPicturePassword {
    $currentValue28=Get-ItemProperty -Path $regPath28 -Name $valueName28 -ErrorAction Stop
    if($currentValue28.$valueName28 -eq 1){
        Write-Host "BlockDomainPicturePassword ENABLED"
    }else{
        Write-Host "BlockDomainPicturePassword NOT ENABLED"
    }
    
}
function Enabled {
    $currentValue29=Get-ItemProperty -Path $regPath29 -Name $valueName29 -ErrorAction Stop
    if($currentValue29.$valueName29 -eq 0){
        Write-Host "NTPEnabled ENABLED"
    }else{
        Write-Host "NTPEnabled NOT ENABLED"
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
#DisableBkGndGroupPolicy 
BackupDirectory
DontEnumerateConnectedUsers
EnumerateLocalUsers
BlockDomainPicturePassword
Enabled




