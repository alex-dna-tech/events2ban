<#
.SYNOPSIS
    Synchronizes banned IP counts between local state file and Cloudflare KV.
.DESCRIPTION
    Reads a local JSON state file, merges counts with a remote Cloudflare KV store using max() logic,
    and updates both the local file and the remote store.
.PARAMETER filename
    Path to the banned IPs JSON state file.
.PARAMETER now
    Immediately perform a synchronization.
.PARAMETER install
    Installs a scheduled task to run this script periodically.
.PARAMETER period
    Synchronization interval in minutes (default: 30).
.PARAMETER CFCredPath
    Path to the Cloudflare credential file (default: .\cf_config.xml).
    Generated on first install if not found.
#>
[CmdletBinding()]
param (
    [string]$filename = "bannedIPs.json",
    [switch]$now,
    [string]$UnbanIP,
    [switch]$install,
    [int]$period = 30,
    [string]$CFCredPath = ".\cf_config.xml",
    [string]$LogFile = ""
)
Add-Type -AssemblyName System.Security

if ([string]::IsNullOrWhiteSpace($LogFile)) {
    $LogFile = Join-Path $PSScriptRoot "banSyncKV.log"
}

function _WriteLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $line -Encoding utf8
    switch ($Level) {
        "ERROR" { Write-Host $line -ForegroundColor Red }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        default { Write-Host $line }
    }
}

_WriteLog "=== Script started ==="
_WriteLog "Filename=$filename, CFCredPath=$CFCredPath, LogFile=$LogFile"

function _Sync {
    param(
        [string]$File,
        [string]$CFCredPath
    )

    if ([string]::IsNullOrWhiteSpace($CFCredPath)) {
        $CFCredPath = ".\cf_config.xml"
    }

    if (-not (Test-Path $CFCredPath)) {
        _WriteLog -Level ERROR "Cloudflare credential file not found at '$CFCredPath'."
        exit 1
    }

    try {
        $cred = Import-Clixml -Path $CFCredPath
    } catch {
        _WriteLog -Level ERROR "Failed to load Cloudflare credential file from '$CFCredPath'."
        exit 1
    }

    try {
        $encryptedBytes = [System.Convert]::FromBase64String($cred.ApiToken)
        $bytes = [System.Security.Cryptography.ProtectedData]::Unprotect($encryptedBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $apiToken = [System.Text.Encoding]::UTF8.GetString($bytes)
    } catch {
        _WriteLog -Level ERROR "Failed to decrypt API token from credential file."
        exit 1
    }

    [System.Array]::Clear($bytes, 0, $bytes.Length)

    $accountId = $cred.AccountId
    $namespaceId = $cred.NamespaceId

    $key = "global_banned_ips"
    $encodedKey = [System.Net.WebUtility]::UrlEncode($key)
    $url = "https://api.cloudflare.com/client/v4/accounts/$accountId/storage/kv/namespaces/$namespaceId/values/$encodedKey"
    $headers = @{ "Authorization" = "Bearer $apiToken" }

    try {
        # 1. Load Local State
        $localBans = @{}
        if (Test-Path $File) {
            $content = Get-Content $File -Raw
            if (-not [string]::IsNullOrWhiteSpace($content)) {
                try {
                    $parsedLocal = $content | ConvertFrom-Json
                    foreach($prop in $parsedLocal.psobject.Properties) {
                        $localBans[$prop.Name] = [int]$prop.Value
                    }
                } catch {
                    _WriteLog -Level WARN "Local file '$File' has invalid JSON, treating as empty."
                }
            }
        }

        # 2. Get Remote State (404 = first run, key doesn't exist yet)
        $remoteBans = @{}
        $remoteObj = $null
        try {
            $remoteObj = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction Stop
        } catch {
            if (-not ($_.Exception.Response -and ($_.Exception.Response.StatusCode -eq 404))) { throw }
        }
        if ($remoteObj -is [string]) {
            try {
                $parsedRemote = $remoteObj | ConvertFrom-Json
                foreach($prop in $parsedRemote.psobject.Properties) {
                    $remoteBans[$prop.Name] = [int]$prop.Value
                }
            } catch {
                _WriteLog -Level WARN "Remote KV contains invalid JSON, treating as empty."
            }
        } elseif ($remoteObj -is [PSCustomObject]) {
            foreach($prop in $remoteObj.psobject.Properties) {
                $remoteBans[$prop.Name] = [int]$prop.Value
            }
        }

        # 3. Merge: 0 (tombstone) beats any positive; otherwise max(local, remote)
        $merged = $localBans.Clone()
        foreach($ip in $remoteBans.Keys) {
            if ($merged.ContainsKey($ip)) {
                if ($merged[$ip] -eq 0 -or $remoteBans[$ip] -eq 0) {
                    $merged[$ip] = 0
                } else {
                    $merged[$ip] = [math]::Max($merged[$ip], $remoteBans[$ip])
                }
            } else {
                if ($remoteBans[$ip] -eq 0) {
                    $merged[$ip] = 0
                } else {
                    $merged[$ip] = $remoteBans[$ip]
                }
            }
        }

        # 4. Update Local File
        $merged | ConvertTo-Json -Depth 5 | ForEach-Object { $_ -replace '":\s{2,}', '": ' } | Out-File $File -Encoding utf8 -Force

        # 5. Update Remote KV
        $jsonPut = $merged | ConvertTo-Json -Depth 5
        $jsonPut = $jsonPut -replace '":\s{2,}', '": '
        $putHeaders = $headers.Clone()
        $putHeaders["Content-Type"] = "application/json"
        Invoke-RestMethod -Uri $url -Method Put -Headers $putHeaders -Body $jsonPut -ErrorAction Stop | Out-Null

        _WriteLog "Sync complete. Total IPs: $($merged.Count)"
        exit 0
    }
    catch {
        _WriteLog -Level ERROR "Sync failed: $($_.Exception.Message)"
        exit 1
    }
}

function _UnbanIP {
    param(
        [string]$IP,
        [string]$File
    )

    $ruleName = "events2ban block: $IP"
    try {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop | Out-Null
        Write-Host "Removed firewall rule for $IP"
    } catch {
        if ($_.Exception.Message -match "No MSFT_NetFirewallRule|does not exist") {
            Write-Host "No firewall rule found for $IP"
        } else {
            Write-Warning "Failed to remove firewall rule for ${IP}: $($_.Exception.Message)"
        }
    }

    $localBans = @{}
    if (Test-Path $File) {
        $content = Get-Content $File -Raw -ErrorAction SilentlyContinue
        if (-not [string]::IsNullOrWhiteSpace($content)) {
            try {
                $parsed = $content | ConvertFrom-Json
                foreach($prop in $parsed.psobject.Properties) {
                    $localBans[$prop.Name] = [int]$prop.Value
                }
            } catch {
                Write-Warning "Invalid JSON in $File, starting fresh."
            }
        }
    }

    $localBans[$IP] = 0
    $localBans | ConvertTo-Json -Depth 5 | Out-File $File -Encoding utf8 -Force
    Write-Host "Unbanned $IP. Tombstone (0) set locally. Next sync will propagate to Cloudflare KV."
}

function _GenerateCFCredFile {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = ".\cf_config.xml"
        Write-Host "No path provided, using default: $Path"
    }

    $ApiToken = Read-Host "Enter Cloudflare API Token" -AsSecureString
    $AccountId = Read-Host "Enter Cloudflare Account ID"
    $NamespaceId = Read-Host "Enter Cloudflare KV Namespace ID"

    try {
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiToken)
        try {
            $plainToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($plainToken)
            $encryptedBytes = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
            $encryptedToken = [System.Convert]::ToBase64String($encryptedBytes)
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }

        $credObject = [PSCustomObject]@{
            ApiToken    = $encryptedToken
            AccountId   = $AccountId
            NamespaceId = $NamespaceId
        }
        $credObject | Export-Clixml -Path $Path -Force
        Write-Host "Cloudflare credential file saved to $Path"
        return $true
    } catch {
        Write-Error "Failed to save credential file to '$Path'. Error: $_"
        return $false
    }
}

function _InstallTask {
    param(
        [int]$Interval,
        [string]$CFCredPath
    )

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Installing the scheduled task requires administrative privileges."
        exit 1
    }

    if ([string]::IsNullOrWhiteSpace($CFCredPath)) {
        $CFCredPath = ".\cf_config.xml"
        Write-Host "No credential path provided, using default: $CFCredPath"
    }

    if (-not (Test-Path $CFCredPath)) {
        $choice = Read-Host "Credential file '$CFCredPath' does not exist. Create it now? (y/n)"
        if ($choice -eq 'y') {
            if (-not (_GenerateCFCredFile -Path $CFCredPath)) {
                Write-Error "Could not create credential file. Aborting installation."
                exit 1
            }
        } else {
            Write-Error "Credential file not found. Aborting installation."
            exit 1
        }
    }

    $taskName = "events2ban-sync"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

    $arguments = "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSScriptRoot\banSyncKV.ps1`" -filename `"$filename`" -CFCredPath `"$CFCredPath`" -LogFile `"$PSScriptRoot\banSyncKV.log`" -now"
    $action = New-ScheduledTaskAction -Execute (Get-Command 'powershell.exe').Path -Argument $arguments -WorkingDirectory $PSScriptRoot
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $Interval)
    $principal = New-ScheduledTaskPrincipal -UserID ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -Hidden -StartWhenAvailable -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 3

    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
    Write-Host "Scheduled task '$taskName' installed. Period: $Interval min."
}

if ($UnbanIP) {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Unbanning requires administrative privileges."
        exit 1
    }
    _UnbanIP -IP $UnbanIP -File $filename
}

if ($install) {
    _InstallTask -Interval $period -CFCredPath $CFCredPath
}

if ($now) {
    _Sync -File $filename -CFCredPath $CFCredPath
}
