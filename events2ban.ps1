<#
.SYNOPSIS
    events2ban is a PowerShell script that monitors Windows Event Logs for failed login attempts and bans the offending IP addresses.

.DESCRIPTION
    events2ban is an attempt to recreate the functionality of fail2ban for Windows. It monitors the Windows Event Logs for specific event IDs that indicate a failed login attempt. When a certain number of failed attempts from the same IP address are detected within a specified time window, the script will create a new inbound firewall rule to block that IP address.

    The script can be configured to monitor different event logs and event IDs, and the ban duration is configurable. The script also supports a whitelist of IP addresses that should never be banned.

.PARAMETER ListBans
    Lists all the currently banned IP addresses.

.PARAMETER UnbanIP
    Removes the specified IP address from the ban list.

.PARAMETER ClearAllBans
    Removes all the IP addresses that have been banned by this script.

.PARAMETER Silent
    Runs the script without outputting messages to the console.

.PARAMETER Install
    Installs the scheduled task for the script.

.PARAMETER Uninstall
    Uninstalls the scheduled task for the script.

.PARAMETER CheckWindow
    Specifies the time window in seconds to check for failed login attempts (default is 120).

.PARAMETER CheckCount
    Specifies the number of failed login attempts before banning an IP (default is 5).

.PARAMETER LoopDuration
    Specifies the duration in seconds between checks for new events (default is 5).

.PARAMETER MaxBanDuration
    Specifies the maximum duration in seconds for which an IP can be banned (default is 7776000).

.PARAMETER EventsToTrack
    Specifies the event logs and event IDs to monitor for failed login attempts (default is "Security 4625").

.PARAMETER WhiteList
    Specifies a list of IP addresses that should never be banned.
#>
[CmdletBinding()]
param (
    [switch]$ListBans,
    [string]$UnbanIP,
    [switch]$ClearAllBans,
    [switch]$Silent,
    [switch]$Install,
    [switch]$Uninstall,
    [int]$CheckWindow = 120,
    [int]$CheckCount = 5,
    # TODO: Check `LoopDuration` to be smaller `CheckWindow` and set half of `CheckWindow` if not set by default
    [int]$LoopDuration = 5,
    [int]$MaxBanDuration = 7776000,
    [string]$EventsToTrack = "Security 4625",
    [string]$WhiteList = "" 
)


# Prerequisite Checks
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script requires administrative privileges. Please run it as an administrator."
    exit 1
}


if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Error "This script requires PowerShell version 5.1 or higher."
    exit 1
}

$policy = Get-ExecutionPolicy
if ($policy -eq 'Restricted') {
    Write-Error "The PowerShell execution policy is set to 'Restricted'. Please set it to 'RemoteSigned' or 'Unrestricted' to run this script."
    exit 1
}

################################################################################
#                              __         ___________.                  
#     _______  __ ____   _____/  |_  _____\_____  \_ |__ _____    ____  
#   _/ __ \  \/ // __ \ /    \   __\/  ___//  ____/| __ \\__  \  /    \ 
#   \  ___/\   /\  ___/|   |  \  |  \___ \/       \| \_\ \/ __ \|   |  \
#    \___  >\_/  \___  >___|  /__| /____  >_______ \___  (____  /___|  /
#        \/          \/     \/          \/        \/   \/     \/     \/ 
#
################################################################################


$DebugPreference = if ($Silent) { "SilentlyContinue" } else { "Continue" }


################################################################################
#  Configurable Variables
################################################################################

$BannedIPsStateFile = $PSScriptRoot + "\bannedIPs.json"
$RecordEventLog = "Application"     # Where we store our own event messages
$FirewallRulePrefix = "events2ban block:" # What we name our Rules

################################################################################
#  End of Configurable Variables
################################################################################

New-Variable -Name RegexIP -Force -Value ([regex]'(?<First>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Second>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Third>2[0-4]\d|25[0-5]|[01]?\d\d?)\.(?<Fourth>2[0-4]\d|25[0-5]|[01]?\d\d?)')

$BannedIPs = @{}
$TrackedIPs = @{}

# Define whitelist IPs
$Whitelist = $WhiteList -split '\s+' | Where-Object { $_ -ne "" }

# Split events string into components and validate pair structure
$CheckEventPairs = @()
$eventComponents = $EventsToTrack -split '\s+'
if ($eventComponents.Count % 2 -ne 0) {
    Write-Error "Invalid EventsToTrack format - must contain event pairs in 'LogName1 EventID1 LogName2 EventID2' format"
    exit 1
}

for ($i = 0; $i -lt $eventComponents.Count; $i += 2) {
    $logName = $eventComponents[$i]
    $eventID = [int]$eventComponents[$i + 1]
    if ($logName -in @("Security", "Application", "System")) {
        $CheckEventPairs += @{ LogName = $logName; EventID = $eventID }
    } else {
        Write-Error "Invalid event log type: $logName. Allowed values are Security, Application, System."
        exit 1
    }
}

# We also want to whitelist this machine's NICs.
$SelfList = @() 
$SelfList += (Get-NetIPAddress -AddressFamily IPv4).IPAddress

################################################################################
# Functions
################################################################################

function _LogEventMessage ($text, $task) {
    $e = New-Object System.Diagnostics.EventLog($RecordEventLog)
    $e.Source = "events2ban"
    switch ($task) {
        "BAN" { $logeventID = 1000 }
        "UNBAN" { $logeventID = 2000 }
    }
    $e.WriteEntry($text, [System.Diagnostics.EventLogEntryType]::Information, $logeventID)
}

# Log type functions
function _Error       ($action, $ip, $reason) { _WriteLog "E" $action $ip $reason }
function _Warning     ($action, $ip, $reason) { _WriteLog "W" $action $ip $reason }
function _Debug       ($action, $ip, $reason) { _WriteLog "D" $action $ip $reason }

# Log things to the console
function _WriteLog ($type, $action, $ip, $reason) {
    $timestamp = (Get-Date -format u).replace("Z", "")
    $output = "[$timestamp] ${action}: $ip - $reason"
    switch ($type) {
        "D" { Write-Debug $output }
        "W" { Write-Warning $output }
        "E" { Write-Error $output }
    }
}
	 
# Get the current list of events2ban bans
function _GetJailList {
    return Get-NetFirewallRule -DisplayName "$($FirewallRulePrefix)*" | Select-Object @{Name = 'name'; Expression = { $_.DisplayName } }, @{Name = 'description'; Expression = { $_.Description } }
}

# Confirm if one or more rules exists.
function _RuleExists ($IP) {
    $ruleName = "$FirewallRulePrefix $IP"
    return (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0
}

# Convert subnet Slash (e.g. 26, for /26) to netmask (e.g. 255.255.255.192)
function _Netmask($MaskLength) {
    $IPAddress = [UInt32]([Convert]::ToUInt32($(("1" * $MaskLength).PadRight(32, "0")), 2))
    $DottedIP = $( For ($i = 3; $i -gt -1; $i--) {
            $Remainder = $IPAddress % [Math]::Pow(256, $i)
            ($IPAddress - $Remainder) / [Math]::Pow(256, $i)
            $IPAddress = $Remainder
        } )

    Return [String]::Join('.', $DottedIP)
}
  
# Check if IP is whitelisted
function _Whitelisted($IP) {
    $msg = $null
    foreach ($wl in $Whitelist) {
        if ($IP -eq $wl) { $msg = "Uniquely listed."; break }
        if ($wl.Contains("/")) {
            try {
                $Mask = _Netmask($wl.Split("/")[1])
                $subnet = $wl.Split("/")[0]
                if ((([net.ipaddress]$IP).Address -Band ([net.ipaddress]$Mask).Address ) -eq `
                    (([net.ipaddress]$subnet).Address -Band ([net.ipaddress]$Mask).Address )) {
                    $msg = "Contained in subnet $wl"; break;
                }
            } catch {
                _Warning "WHITELIST" $wl "Invalid CIDR format in whitelist, skipping."
            }
        }
    }
    return $msg
} 

# Read in the saved file of settings. Only called on script start.
function _LoadBannedIPsState {
    if (Test-Path $BannedIPsStateFile) {
        try {
            $content = Get-Content $BannedIPsStateFile -Raw -ErrorAction Stop
            if (-not ([string]::IsNullOrWhiteSpace($content))) {
                $loadedIPs = $content | ConvertFrom-Json -ErrorAction Stop
                if ($loadedIPs) {
                     # $BannedIPs is a hashtable, ConvertFrom-Json returns PSCustomObject. We must convert it.
                     foreach($prop in $loadedIPs.psobject.Properties) {
                         $BannedIPs[$prop.Name] = $prop.Value
                     }
                }
                _Debug "STATE" "events2ban" "$($BannedIPs.Count) ban counts loaded from $BannedIPsStateFile"
            }
        }
        catch {
            $errorMessage = $_.Exception.Message
            _Error "STATE LOAD FAILED" "events2ban" "Could not load or parse $BannedIPsStateFile. Error: `"$errorMessage`""
        }
    }
    else { 
        _Debug "STATE" "events2ban" "No state file found at $BannedIPsStateFile"
    }
}

# Save the current ban counts to the state file
function _SaveBannedIPsState {
    try {
        $BannedIPs | ConvertTo-Json -Depth 5 | Out-File $BannedIPsStateFile -Encoding utf8 -ErrorAction Stop
    }
    catch {
        $errorMessage = $_.Exception.Message
        _Error "STATE SAVE FAILED" "events2ban" "Could not save state to $BannedIPsStateFile. Error: `"$errorMessage`""
    }
}

# Get the ban time for an IP, in seconds
function _GetBanDuration ($IP) {
    if ($BannedIPs.ContainsKey($IP)) {
        [int]$count = $BannedIPs.Get_Item($IP)
    }
    else {
        $count = 0
        $BannedIPs.Add($IP, $count)
    }
    $count += 1
    $BannedIPs.Set_Item($IP, $count)
    $BanDuration = [math]::min([math]::pow(5, $count) * 60, $MaxBanDuration)
    _Debug "IP $IP has the new count of $count, being $BanDuration seconds"
    _SaveBannedIPsState
    return $BanDuration
}

# Ban the IP (with checking)
function _JailLockup ($IP, $ExpireDate = $null, $event = $null) {
    $result = _Whitelisted($IP)
    if ($result) { _Warning "WHITELISTED" $IP "Attempted to ban whitelisted IP" }
    elseif ($SelfList -contains $IP) { _Warning "WHITELISTED" $IP "Attempted to ban self IP" }
    else {
        if (_RuleExists $IP) {
            _Warning "ALREADY BANNED" $IP "Attempted to ban already banned IP"
        }
        else {
            if (!$ExpireDate) {
                $BanDuration = _GetBanDuration($IP)
                $ExpireDate = (Get-Date).AddSeconds($BanDuration)
            }

            _FirewallAdd $IP $ExpireDate

            $jsonLogData = @{
                "IP"                 = $IP
                "BanCount"           = $BannedIPs.Get_Item($IP)
                "BanDurationSeconds" = $BanDuration
                "ExpireDate"         = $ExpireDate.ToString("o")
            }
            if ($event) {
                $jsonLogData['LogName'] = $event.LogName
                $jsonLogData['EventID'] = $event.Id
            }
            $jsonLog = $jsonLogData | ConvertTo-Json -Compress
            _LogEventMessage $jsonLog BAN

        }
    }
}

# Unban the IP (with checking)
function _JailRelease ($IP) {
    if (-not (_RuleExists $IP)) {
        _Debug "NOT BANNED" $IP "Attempted to unban IP that is not banned"
    }
    else {
        _FirewallRemove  $IP
    }
    if ($BannedIPs.ContainsKey($IP)) {
        $BannedIPs.Remove($IP) | Out-Null
        _Debug "UNBAN" $IP "Removed from BannedIPs hashtable."
    }

    if ($TrackedIPs.ContainsKey($IP)) {
        $TrackedIPs.Remove($IP) | Out-Null
        _Debug "UNBAN" $IP "Removed from TrackedIPs hashtable."
    }

    _SaveBannedIPsState
}

# Add the Firewall Rule
function _FirewallAdd ($IP, $ExpireDate) {
    $Expire = (Get-Date $ExpireDate -format u).replace("Z", "")
    $ruleName = "$FirewallRulePrefix $IP"
    $description = "Expire: $Expire"

    if (_RuleExists $IP) {
        _Warning "DUPLICATE RULE" $IP "Firewall rule already exists. Skipping creation."
        return
    }

    try {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol Any -Action Block -RemoteAddress $IP -Description $description -ErrorAction Stop | Out-Null
        _Debug "BAN" $IP "Firewall rule added, expiring on $ExpireDate"
    }
    catch {
        $errorMessage = $_.Exception.Message
        _Error "BAN FAILED" $IP "Could not add firewall rule. Error: `"$errorMessage`""
    }
}

# Remove the Filewall Rule
function _FirewallRemove ($IP) {
    $ruleName = "$FirewallRulePrefix $IP"
    try {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction Stop | Out-Null
        _Debug "UNBAN" $IP "Firewall ban removed"
        _LogEventMessage "UNBAN: $IP - Firewall ban removed" UNBAN
    }
    catch {
        $errorMessage = $_.Exception.Message
        _Error "UNBAN FAILED" $IP "Could not remove firewall rule. Error: `"$errorMessage`""
    }
}

# Remove any expired bans
function _UnbanOldRecords {
    $jail = _GetJailList
    if ($jail) {
        foreach ($inmate in $jail) {
            $IP = $inmate.Name.substring($FirewallRulePrefix.length + 1)
            $ReleaseDate = $inmate.Description.substring("Expire: ".Length)

            if ($([int]([datetime]$ReleaseDate - (Get-Date)).TotalSeconds) -lt 0) {
                _Debug "EXPIRED BAN" $IP "Ban expired at $(Get-Date $ReleaseDate -format G)"
                _FirewallRemove $IP
            }
        }
    }
}

# Tracks failed login attempts from a given IP
function _TrackIP($IP, $event) {
    if ($TrackedIPs.ContainsKey($IP)) {
        $TrackedIPs[$IP].Count += 1
        $TrackedIPs[$IP].Timestamps.Add((Get-Date))
    }
    else {
        $TrackedIPs[$IP] = @{
            Count = 1
            Timestamps = [System.Collections.Generic.List[datetime]]::new()
        }
        $TrackedIPs[$IP].Timestamps.Add((Get-Date))
    }

    # Remove old timestamps
    $TrackedIPs[$IP].Timestamps.RemoveAll({
        $_ -is [datetime] -and $_.AddSeconds($CheckWindow) -lt (Get-Date)
    }) | Out-Null
    $TrackedIPs[$IP].Count = $TrackedIPs[$IP].Timestamps.Count

    if ($TrackedIPs[$IP].Count -ge $CheckCount) {
        _JailLockup $IP $null $event
        $TrackedIPs.Remove($IP)
    }
}


# Install shchedule task
function _InstallScheduledTask {
    $taskName = "events2ban"
    # Unregister existing task if any
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    $action = New-ScheduledTaskAction -Execute (Get-Command 'powershell.exe').Path -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File $($PSScriptRoot)\events2ban.ps1 -Silent"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -Hidden
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
    # Start the task immediately
    Start-ScheduledTask -TaskName $taskName | Out-Null
    Write-Host "Scheduled task 'events2ban' installed and started successfully."
}

function _UninstallScheduledTask {
    $taskName = "events2ban"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Scheduled task 'events2ban' uninstalled successfully."
}

# Handle script argupments
function _HandleCli {
    if ($Install) {
        _InstallScheduledTask
        exit
    }

    if ($Uninstall) {
        _UninstallScheduledTask
        exit
    }

    if ($ListBans) {
        $inmates = _GetJailList
        if ($inmates) {
            "events2ban currently banned listings: `n"
            foreach ($a in $inmates) {
                $IP = $a.name.substring($FirewallRulePrefix.length + 1)
                $Expire = $a.description.substring("Expire: ".length)
                "" + $IP.PadLeft(14) + " expires at $Expire"
            }
            "`nThis is a listing of the current Windows Firewall with Advanced Security rules, starting with `"" + $FirewallRulePrefix + " *`""
        }
        else { "There are no currrently banned IPs" }
        exit
    }

    if ($UnbanIP) {
        _Debug "UNBAN" $UnbanIP "Unban IP invoked from command line"
        _JailRelease $UnbanIP
        exit
    }

    if ($ClearAllBans) {
        _Debug "JAILBREAK" "events2ban" "Jailbreak initiated by console. Removing ALL IPs currently banned"
        $EnrichmentCentre = _GetJailList
        if ($EnrichmentCentre) {
            foreach ($subject in $EnrichmentCentre) {
                $IP = $subject.name.substring($FirewallRulePrefix.length + 1)
                _FirewallRemove $IP
            }
            $BannedIPs.Clear()
            _SaveBannedIPsState
        }
        else { "No current firewall listings to remove." }
        exit
    }
}

function Main {
    _LoadBannedIPsState
    _HandleCli

    _Debug "START" "events2ban" "events2ban invoked"

    _Debug "CONFIG" "events2ban" "Checking for a heap of events: "
    $CheckEventPairs | ForEach-Object { _Debug "CONFIG" "events2ban" " - $($_.LogName) log event code $($_.EventID)" }
    _Debug "CONFIG" "events2ban" "The Whitelist: $Whitelist"
    _Debug "CONFIG" "events2ban" "The Self-list: $Selflist"

    while ($true) {
        $now = Get-Date

        $StartTime = $now.AddSeconds(-$LoopDuration)

        $events = @()
        foreach ($pair in $CheckEventPairs) {
            $filter = @{
                LogName = $pair.LogName
                ID = $pair.EventID
                StartTime = $StartTime
            }
            $events += Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
        }

        if ($events) {
            foreach ($e in $events) {
                $message = $e.Message
                Select-String $RegexIP -input $message -AllMatches | ForEach-Object {
                    foreach ($a in $_.matches) {
                        $IP = $a.Value
                        if ($SelfList -notcontains $IP -and -not (_Whitelisted $IP) -and -not (_RuleExists $IP)) {
                            _TrackIP $IP $e
                        }
                    }
                }
            }
        }

        _UnbanOldRecords
        Start-Sleep -Seconds $LoopDuration
    }
}


Main

