$global:results = @()

function Add-Result {
    param (
        [string]$Name,
        [string]$RemediationStatus,
        [string]$Priority
    )
    $global:results += [pscustomobject]@{
        Name = $Name
        RemediationStatus = $RemediationStatus
        Priority = $Priority
    }
}

function RequireSignorSeal {
    try {
        $currentValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -ErrorAction Stop
        if ($currentValue.RequireSignOrSeal -ne 1) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1
            Add-Result "RequireSignOrSeal" "Remediation applied: ENABLED" "High"
        }
    } catch {
        Add-Result "RequireSignOrSeal" "Error: $_" "High"
    }
}

function SealSecureChannel {
    try {
        $currentValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -ErrorAction Stop
        if ($currentValue.SealSecureChannel -ne 1) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 1
            Add-Result "SealSecureChannel" "Remediation applied: ENABLED" "High"
        }
    } catch {
        Add-Result "SealSecureChannel" "Error: $_" "High"
    }
}

function SignSecureChannel {
    try {
        $currentValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -ErrorAction Stop
        if ($currentValue.SignSecureChannel -ne 1) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value 1
            Add-Result "SignSecureChannel" "Remediation applied: ENABLED" "High"
        }
    } catch {
        Add-Result "SignSecureChannel" "Error: $_" "High"
    }
}

function DisablePasswordChange {
    try {
        $currentValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -ErrorAction Stop
        if ($currentValue.DisablePasswordChange -ne 1) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value 1
            Add-Result "DisablePasswordChange" "Remediation applied: ENABLED" "High"
        }
    } catch {
        Add-Result "DisablePasswordChange" "Error: $_" "High"
    }
}

function MaximumPasswordAge {
    try {
        $currentValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -ErrorAction Stop
        if ($currentValue.MaximumPasswordAge -ne 30) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -Value 30
            Add-Result "MaximumPasswordAge" "Remediation applied: Set to 30" "High"
        }
    } catch {
        Add-Result "MaximumPasswordAge" "Error: $_" "High"
    }
}

function RequireStrongKey {
    try {
        $currentValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -ErrorAction Stop
        if ($currentValue.RequireStrongKey -ne 1) {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1
            Add-Result "RequireStrongKey" "Remediation applied: ENABLED" "High"
        }
    } catch {
        Add-Result "RequireStrongKey" "Error: $_" "High"
    }
}

function EnableFirewall {
    try {
        $currentValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -ErrorAction Stop
        if ($currentValue.EnableFirewall -ne 1) {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -Value 1
            Add-Result "EnableFirewall" "Remediation applied: ENABLED" "High"
        }
    } catch {
        Add-Result "EnableFirewall" "Error: $_" "High"
    }
}

# Execute remediation functions
RequireSignorSeal
SealSecureChannel
SignSecureChannel
DisablePasswordChange
MaximumPasswordAge
RequireStrongKey
EnableFirewall

# Function to output results to CSV
function writeout {
    Write-Host $global:results
    $global:results | Export-Csv -Path "rem.csv" -NoTypeInformation -Delimiter "|"
}

# Call writeout to save the results to CSV
writeout
