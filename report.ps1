<#
.SYNOPSIS
    Generates an HTML report of events2ban activity and can report IPs to AbuseIPDB service or Email.
.DESCRIPTION
    This script reads the events2ban event logs, creates an HTML report summarizing banned IPs, and can report those IPs to AbuseIPDB.
.PARAMETER ReportDays
    Specifies the number of days to include in the HTML report (default is 7).
.PARAMETER Mail
    If specified, the HTML report will be sent via email.
.PARAMETER SmtpServer
    The address of the SMTP server. Required if -Mail is specified.
.PARAMETER SmtpPort
    The port to use on the SMTP server.
.PARAMETER To
    The recipient's email address(es). Required if -Mail is specified.
.PARAMETER MailCred
    Path to the credential file for SMTP authentication. Required if -Mail is specified.
.PARAMETER GenMailCred
    If specified, prompts for SMTP credentials and saves them to the given path, then exits.
.PARAMETER InstallMailReportTask
    Installs the scheduled task for the HTML report.
.PARAMETER AbuseIPDBReport
    If specified, reports banned IPs from the last 24 hours to AbuseIPDB.
.PARAMETER AbuseIPDBKeyPath
    Path to the AbuseIPDB API key file. Required if -AbuseIPDBReport is specified.
.PARAMETER GenAbuseIPDBKey
    If specified, prompts for an AbuseIPDB API key and saves it to the given path, then exits.
.PARAMETER AbuseIPDBCategories
    Comma-separated list of AbuseIPDB categories to use for reporting. Required if -AbuseIPDBReport is specified.
.PARAMETER InstallAbuseIPDBTask
    Installs the scheduled task for daily AbuseIPDB reporting.
#>
[CmdletBinding()]
param (
    [int]$ReportDays = 7,
    [switch]$Mail,
    [string]$SmtpServer,
    [int]$SmtpPort = 587,
    [string[]]$To,
    [string]$MailCred,
    [string]$GenMailCred,
    [switch]$InstallMailReportTask,
    [switch]$AbuseIPDBReport,
    [string]$AbuseIPDBKeyPath,
    [string]$GenAbuseIPDBKey,
    [string[]]$AbuseIPDBCategories = "18",
    [switch]$InstallAbuseIPDBTask
)

function _GenerateCredentialFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $EmailLogin = Read-Host "Enter SMTP Username"
    $SecurePassword =  Read-Host "Enter SMTP Password" -AsSecureString
    $credential = New-Object System.Management.Automation.PSCredential ($EmailLogin, $SecurePassword)
    try {
        $credential | Export-Clixml -Path $Path -Force
        Write-Host "Credential file saved to $Path"
        return $true
    } catch {
        Write-Error "Failed to save credential file to '$Path'. Error: $_"
        return $false
    }
}

function _GenerateAbuseIPDBKeyFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path
    )

    $ApiKey = Read-Host "Enter AbuseIPDB API Key" -AsSecureString
    try {
        $ApiKey | Export-Clixml -Path $Path -Force
        Write-Host "AbuseIPDB API Key file saved to $Path"
        return $true
    } catch {
        Write-Error "Failed to save API Key file to '$Path'. Error: $_"
        return $false
    }
}

function _InstallMailReportTask {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Installing the scheduled task requires administrative privileges. Please run it as an administrator."
        exit 1
    }

    $taskName = "events2ban-report"

    # Prompt for required parameters
    Write-Host "Configuring scheduled task for events2ban report."
    $CredPath = Read-Host "Enter path to credential file (e.g., .\email.xml or emty)"

    if ([string]::IsNullOrWhiteSpace($CredPath)) {
        $CredPath = ".\email.xml"
        Write-Host "No path provided, using default: $CredPath"
    }

    if (-not (Test-Path $CredPath)) {
        $choice = Read-Host "Credential file '$CredPath' does not exist. Do you want to create it now? (y/n)"
        if ($choice -eq 'y') {
            if (-not (_GenerateCredentialFile -Path $CredPath)) {
                Write-Error "Could not create credential file. Aborting installation."
                exit 1
            }
        } else {
            Write-Error "Credential file not found. Aborting installation."
            exit 1
        }
    }

    $SmtpSrv = Read-Host "Enter SMTP server address (e.g., mail.service.com)"
    $credential = Import-Clixml -Path $CredPath
    $FromAddr = $credential.UserName
    Write-Host "Using '$FromAddr' as sender's email address from credential file."
    $ToAddr = Read-Host "Enter recipient's email address(es), comma-separated (e.g., test@example.com)"

    # Unregister existing task if any
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    
    $arguments = "-ExecutionPolicy Bypass -File `"$($PSScriptRoot)\report.ps1`" -Mail -MailCred `"$CredPath`" -SmtpServer `"$SmtpSrv`" -To `"$ToAddr`""
    $action = New-ScheduledTaskAction -Execute (Get-Command 'powershell.exe').Path -Argument $arguments -WorkingDirectory $PSScriptRoot
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "8am"
    $principal = New-ScheduledTaskPrincipal -UserID ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -Hidden
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
    
    Write-Host "Scheduled task '$taskName' installed successfully. It will run weekly on Monday at 8:00 AM."
}

function _InstallAbuseIPDBTask {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Installing the scheduled task requires administrative privileges. Please run it as an administrator."
        exit 1
    }

    $taskName = "events2ban-abuseipdb-report"

    # Prompt for required parameters
    Write-Host "Configuring scheduled task for events2ban AbuseIPDB reporting."
    $KeyPath = Read-Host "Enter path to AbuseIPDB API key file (e.g., .\abuseipdb.xml or empty)"

    if ([string]::IsNullOrWhiteSpace($KeyPath)) {
        $KeyPath = ".\abuseipdb.xml"
        Write-Host "No path provided, using default: $KeyPath"
    }

    if (-not (Test-Path $KeyPath)) {
        $choice = Read-Host "API key file '$KeyPath' does not exist. Do you want to create it now? (y/n)"
        if ($choice -eq 'y') {
            if (-not (_GenerateAbuseIPDBKeyFile -Path $KeyPath)) {
                Write-Error "Could not create API key file. Aborting installation."
                exit 1
            }
        } else {
            Write-Error "API key file not found. Aborting installation."
            exit 1
        }
    }

    $Categories = Read-Host "Enter AbuseIPDB categories, comma-separated (e.g., 22,18 for SSH and Brute-Force) or empty for default (18) https://www.abuseipdb.com/categories"
    if ([string]::IsNullOrWhiteSpace($Categories)) {
        $Categories = "18"
        Write-Host "No categories provided, using default: $Categories"
    }

    # Unregister existing task if any
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    
    $arguments = "-ExecutionPolicy Bypass -File `"$($PSScriptRoot)\report.ps1`" -AbuseIPDBReport -AbuseIPDBKeyPath `"$KeyPath`" -AbuseIPDBCategories `"$Categories`""
    $action = New-ScheduledTaskAction -Execute (Get-Command 'powershell.exe').Path -Argument $arguments -WorkingDirectory $PSScriptRoot
    $trigger = New-ScheduledTaskTrigger -Daily -At "11:59pm"
    $principal = New-ScheduledTaskPrincipal -UserID ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -Hidden
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force | Out-Null
    
    Write-Host "Scheduled task '$taskName' installed successfully. It will run daily at 11:59 PM."
}

# Handle script argupments
function _HandleCli {
    if ($InstallMailReportTask) {
        _InstallMailReportTask
        exit
    }

    if ($InstallAbuseIPDBTask) {
        _InstallAbuseIPDBTask
        exit
    }

    if ($PSBoundParameters.ContainsKey('GenMailCred')) {
        if (-not $GenMailCred) {
            Write-Error "The -GenMailCred parameter requires a path argument for the credential file."
            exit 1
        }
        _GenerateCredentialFile -Path $GenMailCred
        exit 0
    }

    if ($PSBoundParameters.ContainsKey('GenAbuseIPDBKey')) {
        if (-not $GenAbuseIPDBKey) {
            Write-Error "The -GenAbuseIPDBKey parameter requires a path argument for the API key file."
            exit 1
        }
        _GenerateAbuseIPDBKeyFile -Path $GenAbuseIPDBKey
        exit 0
    }
}

_HandleCli

if ($AbuseIPDBReport) {
    $errorLogPath = Join-Path $PSScriptRoot "report-error.log"

    # Parameter validation
    $missingParams = [System.Collections.Generic.List[string]]@()
    if (-not $AbuseIPDBKeyPath) { $missingParams.Add('AbuseIPDBKeyPath') }
    if (-not $AbuseIPDBCategories) { $missingParams.Add('AbuseIPDBCategories') }

    if ($missingParams.Count -gt 0) {
        foreach ($p in $missingParams) {
            Write-Debug "Required parameter for -AbuseIPDBReport is not set: -$p"
        }
        Write-Error "The following required parameters for -AbuseIPDBReport are missing: $(($missingParams | ForEach-Object { "-$_" }) -join ', ')"
        exit 1
    }

    # Load API key
    try {
        $secureApiKey = Import-Clixml -Path $AbuseIPDBKeyPath
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureApiKey)
        $apiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    } catch {
        $errorMessage = "Failed to import AbuseIPDB API key from '$AbuseIPDBKeyPath'. Error: $_"
        Write-Error $errorMessage
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $errorMessage" | Out-File -FilePath $errorLogPath -Append
        exit 1
    }

    # Get events from last 24 hours
    $events = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'events2ban'
        ID           = 1000
        StartTime = (Get-Date).Date
        EndTime   = (Get-Date).Date.AddDays(1) 
    } -ErrorAction SilentlyContinue

    # Process events for bulk reporting
    $processedIPs = [System.Collections.Generic.HashSet[string]]::new()
    $reportItems = foreach ($event in $events) {
        try {
            $logObject = $event.Message | ConvertFrom-Json
            if ($processedIPs.Add($logObject.ip)) {
                [PSCustomObject]@{
                    IP         = $logObject.ip
                    Categories = $AbuseIPDBCategories -join ','
                    ReportDate = $event.TimeCreated.ToUniversalTime().ToString("o")
                    Comment    = "events2ban report: $(event.Message)"
                }
            }
        } catch {
            $errorMessage = "Failed to process event $($event.Id). Error: $_"
            Write-Warning $errorMessage
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $errorMessage" | Out-File -FilePath $errorLogPath -Append
        }
    }

    if ($reportItems.Count -eq 0) {
        Write-Host "No new events to report to AbuseIPDB."
        exit 0
    }

    try {
        # Manually construct multipart/form-data body for compatibility with PowerShell versions before 6.0
        $boundary = [System.Guid]::NewGuid().ToString()
        $crlf = "`r`n"

        # Generate CSV content in memory, skipping the header as AbuseIPDB expects a header-less CSV.
        $csvContent = ($reportItems | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1) -join $crlf

        $bodyLines = @(
            "--$boundary",
            "Content-Disposition: form-data; name=`"csv`"; filename=`"events2ban-abuseipdb-report.csv`"",
            "Content-Type: text/csv",
            "",
            "IP,Categories,ReportDate,Comment",
            $csvContent,
            "--$boundary--"
        )

        $bodyContent = ($bodyLines -join $crlf) + $crlf
        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($bodyContent)

        $response = Invoke-RestMethod `
            -Uri 'https://api.abuseipdb.com/api/v2/bulk-report' `
            -Method 'POST' `
            -Headers @{ 'Key' = $apiKey; 'Accept' = 'application/json' } `
            -ContentType "multipart/form-data; boundary=$boundary" `
            -Body $bodyBytes
        
        Write-Host "Successfully sent bulk report to AbuseIPDB. Saved reports: $($response.data.savedReports). Unparseable reports: $($response.data.unparseableReports)."
    } catch {
        $errorMessage = "Failed to send bulk report to AbuseIPDB. Error: $_"
        Write-Error $errorMessage
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $errorMessage" | Out-File -FilePath $errorLogPath -Append
        exit 1
    }
    exit 0
}

if ($Mail) {
    $missingParams = [System.Collections.Generic.List[string]]@()
    if (-not $SmtpServer) { $missingParams.Add('SmtpServer') }
    if (-not $To)    { $missingParams.Add('To') }
    if (-not $MailCred)       { $missingParams.Add('MailCred') }

    if ($missingParams.Count -gt 0) {
        foreach ($p in $missingParams) {
            Write-Debug "Required parameter for -Mail is not set: -$p"
        }
        Write-Error "The following required parameters for -Mail are missing: $(($missingParams | ForEach-Object { "-$_" }) -join ', ')"
        exit 1
    }
}

function Get-events2banHTMLReport {
    $startTime = (Get-Date).AddDays(-$ReportDays)
    $events = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'events2ban'
        ID           = 1000
        StartTime    = $startTime
    } -ErrorAction SilentlyContinue

    $jsonLog = @()
    foreach ($e in $events) {
        try {
            $logObject = $e.Message | ConvertFrom-Json
            $logObject | Add-Member -NotePropertyName TimeCreated -NotePropertyValue $e.TimeCreated
            $jsonLog += $logObject
        } catch {
            Write-Warning "Failed to parse message for event $($e.Id)"
        }
    }

    $ipStats = $jsonLog | Group-Object -Property ip | 
               Select-Object @{Name='IP'; Expression={$_.Name}}, 
                             @{Name='Count'; Expression={($_.Group | Measure-Object BanCount -Maximum).Maximum}},
                             @{Name='TotalBanDuration'; Expression={
                                 $totalSeconds = ($_.Group | Measure-Object BanDurationSeconds -Sum).Sum
                                 $days = [math]::Floor($totalSeconds / 86400)
                                 $hours = [math]::Floor(($totalSeconds % 86400) / 3600)
                                 $minutes = [math]::Floor(($totalSeconds % 3600) / 60)
                                 "$days d $hours h $minutes m"
                             }} |
               Sort-Object Count -Descending

    $totalEvents = $jsonLog.Count
    $uniqueIPs = $ipStats.Count

    $dateRange = "$($startTime.ToString('yy-MM-dd')) - $((Get-Date).ToString('yy-MM-dd'))"
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>events2ban Report</title>
    <style>
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>
    <h1>events2ban Report $dateRange (Last $ReportDays Days)</h1>
    
    <h2>IP Statistics</h2>
    <table>
        <tr><th>IP Address</th><th>Count</th><th>Total Ban Duration</th><th>Details</th></tr>
        $(if ($ipStats) {
            ($ipStats | ForEach-Object {
                "<tr><td>$($_.IP)</td><td>$($_.Count)</td><td>$($_.TotalBanDuration)</td>" +
                "<td><a href='https://www.abuseipdb.com/check/$($_.IP)' target='_blank'>View Details</a></td></tr>"
            }) -join "`n"
        } else {
            "<tr><td colspan='4'>No events found</td></tr>"
        })
    </table>
    
    <h2>Total Statistics</h2>
    <table>
        <tr><th>Total Events</th><td>$totalEvents</td></tr>
        <tr><th>Unique IPs</th><td>$uniqueIPs</td></tr>
    </table>
</body>
</html>
"@

    return [pscustomobject]@{
        Html      = $html
        DateRange = $dateRange
    }
}


if ($Mail) {
    $errorLogPath = Join-Path $PSScriptRoot "report-error.log"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    try {
        $credential = Import-Clixml -Path $MailCred
    } catch {
        $errorMessage = "Failed to import credential file from '$MailCred'. Error: $_"
        Write-Error $errorMessage
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $errorMessage" | Out-File -FilePath $errorLogPath -Append
        exit 1
    }

    $reportData = Get-events2banHTMLReport
	
	# Create SMTP client
	$smtp = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort)
	$smtp.EnableSsl = $true
	$NetCred = $credential.GetNetworkCredential()
	$smtp.Credentials = New-Object System.Net.NetworkCredential($NetCred.UserName, $NetCred.Password);

	# Create MailMessage
	$msg = New-Object System.Net.Mail.MailMessage
	$msg.From = $credential.UserName
	$msg.To.Add($To)
	$msg.Subject = "events2ban Report $($reportData.DateRange)"
	$msg.Body = $reportData.Html
	$msg.IsBodyHtml = $true

	# Send
	try {
	    $smtp.Send($msg)
	} catch {
        $errorMessage = "Failed to send email report. Error: $_"
        Write-Error $errorMessage
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $errorMessage" | Out-File -FilePath $errorLogPath -Append
        exit 1
	}
    exit 0
}

$reportData = Get-events2banHTMLReport
$reportPath = Join-Path $PSScriptRoot "report.html"
$reportData.Html | Out-File $reportPath -Force
Write-Host "Report generated at $reportPath"


