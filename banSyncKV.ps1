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
#>
[CmdletBinding()]
param (
    [string]$filename = "bannedIPs.json",
    [switch]$now,
    [switch]$install,
    [int]$period = 30
)

# Cloudflare KV Config (Should be moved to a config file or environment variables in production)
$CF_API_TOKEN = ""
$CF_ACCOUNT_ID = ""
$CF_NAMESPACE_ID = ""

function _Sync {
    param([string]$File)

    if ([string]::IsNullOrWhiteSpace($CF_API_TOKEN) -or [string]::IsNullOrWhiteSpace($CF_ACCOUNT_ID) -or [string]::IsNullOrWhiteSpace($CF_NAMESPACE_ID)) {
        Write-Error "Cloudflare KV configuration missing."
        return
    }

    $key = "global_banned_ips"
    $url = "https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/storage/kv/namespaces/$CF_NAMESPACE_ID/values/$key"
    $headers = @{ "Authorization" = "Bearer $CF_API_TOKEN" }

    try {
        # 1. Load Local State
        $localBans = @{}
        if (Test-Path $File) {
            $content = Get-Content $File -Raw
            if (-not [string]::IsNullOrWhiteSpace($content)) {
                $parsedLocal = $content | ConvertFrom-Json
                foreach($prop in $parsedLocal.psobject.Properties) {
                    $localBans[$prop.Name] = [int]$prop.Value
                }
            }
        }

        # 2. Get Remote State
        $remoteJson = Invoke-RestMethod -Uri $url -Method Get -Headers $headers -ErrorAction SilentlyContinue
        $remoteBans = @{}
        if ($remoteJson) {
            $parsedRemote = $remoteJson | ConvertFrom-Json
            foreach($prop in $parsedRemote.psobject.Properties) {
                $remoteBans[$prop.Name] = [int]$prop.Value
            }
        }

        # 3. Merge: max(local, remote)
        $merged = $localBans.Clone()
        foreach($ip in $remoteBans.Keys) {
            if ($merged.ContainsKey($ip)) {
                $merged[$ip] = [math]::Max($merged[$ip], $remoteBans[$ip])
            } else {
                $merged[$ip] = $remoteBans[$ip]
            }
        }

        # 4. Update Local File
        $merged | ConvertTo-Json -Depth 5 | Out-File $File -Encoding utf8 -Force

        # 5. Update Remote KV
        $jsonPut = $merged | ConvertTo-Json -Depth 5
        Invoke-RestMethod -Uri $url -Method Put -Headers $headers -Body $jsonPut -ErrorAction Stop | Out-Null

        Write-Host "Sync complete. Total IPs: $($merged.Count)"
    }
    catch {
        Write-Error "Sync failed: $($_.Exception.Message)"
    }
}

function _InstallTask {
    param([int]$Interval)
    $taskName = "events2ban-sync"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

    $action = New-ScheduledTaskAction -Execute (Get-Command 'powershell.exe').Path -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSScriptRoot\banSyncKV.ps1`" -filename `"$filename`" -now"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $Interval)
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
    Write-Host "Scheduled task '$taskName' installed. Period: $Interval min."
}

if ($install) {
    _InstallTask -Interval $period
}

if ($now) {
    _Sync -File $filename
}
