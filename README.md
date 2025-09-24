# events2ban
[![Stand With Ukraine](https://raw.githubusercontent.com/vshymanskyy/StandWithUkraine/main/banner-direct-single.svg)](https://stand-with-ukraine.pp.ua)

[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](./LICENSE)

> A maintained and extended fork of the original [wail2ban](https://github.com/glasnt/wail2ban) project by Katie McLaughlin.  
> This project continues development, adds modern support, and ensures ongoing compatibility.

## Overview

events2ban monitors Windows Event Logs for failed login attempts from specified event IDs. When multiple failed attempts originate from the same IP within a configurable time window, it automatically creates temporary Windows Firewall rules to block further access from those IPs.

## Installation
To install events2ban:

1. Download or copy the `events2ban.ps1` script to any folder.
2. Run it with the `-install` parameter.

## Prerequisites

The script checks for and requires:

- Administrative privileges (must be run as administrator)
- PowerShell version 5.1 or higher
- PowerShell execution policy set to 'RemoteSigned' or less restrictive

## Security Considerations

#### Avoid Storing Plain-Text Passwords and API Keys

When using features in `report.ps1`, it is strongly recommended to use encrypted files for credentials and API keys instead of passing them in plain text.

**For Email Reporting:**
You can create an encrypted credential file using the `-GenMailCred` parameter.
You can then use `C:\secure\mail_creds.xml` with the `-MailCred` parameter.

**For AbuseIPDB Reporting:**
You can create an encrypted API key file using the `-GenAbuseIPDBKey` parameter.
You can then use `C:\secure\abuseipdb.xml` with the `-AbuseIPDBKeyPath` parameter.

## Usage

### events2ban.ps1

- To list current banned IPs:
  ```powershell
  .\events2ban.ps1 -ListBans
  ```

- To unban a specific IP:
  ```powershell
  .\events2ban.ps1 -UnbanIP "X.X.X.X"
  ```

- To unban all IPs:
  ```powershell
  .\events2ban.ps1 -ClearAllBans
  ```

- To run the script silently (no console messages):
  ```powershell
  .\events2ban.ps1 -Silent
  ```

- To install the scheduled task to run at startup:
  ```powershell
  .\events2ban.ps1 -install
  ```

- To uninstall the scheduled task:
  ```powershell
  .\events2ban.ps1 -uninstall
  ```

### report.ps1

- To generate an HTML report of recent activity:
  ```powershell
  .\report.ps1
  ```

- To create an encrypted credential file for sending emails:
  ```powershell
  .\report.ps1 -GenMailCred "C:\secure\events2ban_creds.xml"
  ```

- To generate and email a report using a credential file:
  ```powershell
  .\report.ps1 -Mail -SmtpServer "smtp.example.com" -To "recipient@example.com" -MailCred "C:\secure\events2ban_creds.xml"
  ```

- To create an encrypted AbuseIPDB API key file:
  ```powershell
  .\report.ps1 -GenAbuseIPDBKey "C:\secure\abuseipdb.xml"
  ```

- To report recently banned IPs to AbuseIPDB:
  ```powershell
  .\report.ps1 -AbuseIPDBReport -AbuseIPDBKeyPath "C:\secure\abuseipdb.xml" -AbuseIPDBCategories "18,22"
  ```

### Parameters Overview

#### `events2ban.ps1` Parameters
- `-ListBans`: Lists all the currently banned IP addresses.
- `-UnbanIP <IP>`: Removes the specified IP address from the ban list.
- `-ClearAllBans`: Removes all the IP addresses that have been banned by this script.
- `-Silent`: Runs the script without outputting messages to the console.
- `-install`: Installs the scheduled task for the script to run at startup.
- `-uninstall`: Uninstalls the scheduled task for the script.
- `-CheckWindow <int>`: Specifies the time window in seconds to check for failed login attempts (default is 120).
- `-CheckCount <int>`: Specifies the number of failed login attempts before banning an IP (default is 5).
- `-LoopDuration <int>`: Specifies the duration in seconds between checks for new events (default is 5).
- `-MaxBanDuration <int>`: Specifies the maximum duration in seconds for which an IP can be banned (default is 7776000).
- `-EventsToTrack <string>`: Specifies the event logs and event IDs to monitor for failed login attempts. Format must be space-separated pairs of Log Name (Application, Security, System) and EventID (integer) (e.g., "Security 4625 Application 1000"). Default is "Security 4625".
- `-WhiteList <string>`: Specifies IP addresses that should never be banned. Format must be space-separated IPv4 addresses or CIDR notations (e.g., "192.168.0.1 192.168.1.0/24").

#### `report.ps1` Parameters
- `-ReportDays <int>`: Specifies the number of days to include in the HTML report (default is 7).
- `-Mail`: If specified, the HTML report will be sent via email.
- `-SmtpServer <string>`: The address of the SMTP server. Required if `-Mail` is specified.
- `-SmtpPort <int>`: The port to use on the SMTP server (default is 587).
- `-To <string[]>`: The recipient's email address(es). Required if `-Mail` is specified.
- `-MailCred <string>`: Path to the credential file for SMTP authentication. Required if `-Mail` is specified.
- `-GenMailCred <string>`: If specified, prompts for SMTP credentials and saves them to the given path, then exits.
- `-InstallMailReportTask`: Installs the scheduled task for the HTML report.
- `-AbuseIPDBReport`: If specified, reports banned IPs from the last 24 hours to AbuseIPDB.
- `-AbuseIPDBKeyPath <string>`: Path to the AbuseIPDB API key file. Required if `-AbuseIPDBReport` is specified.
- `-GenAbuseIPDBKey <string>`: If specified, prompts for an AbuseIPDB API key and saves it to the given path, then exits.
- `-AbuseIPDBCategories <string[]>`: Comma-separated list of AbuseIPDB categories to use for reporting. Required if `-AbuseIPDBReport` is specified.
- `-InstallAbuseIPDBTask`: Installs the scheduled task for daily AbuseIPDB reporting.

## Functional Overview

- Monitors specified event logs for certain Event IDs related to failed login attempts.
- Tracks attempts from each IP address within a configurable time window (`$CheckWindow` seconds).
- If an IP exceeds the attempt threshold (`$CheckCount`) within the window, it is banned:
  - Adds a firewall rule with a name prefixed by `$FirewallRulePrefix`.
  - The ban duration scales exponentially based on previous bans, with a maximum cap (`$MaxBanDuration` seconds).
- Bans are automatically revoked after their expiry time, and rules are removed.
- Supports whitelists for IPs that should never be banned.
- Keeps the state of bans in a JSON file to allow persistence across runs.
- Provides CLI commands to list, unban, or clear bans.
- Generates HTML reports summarizing the bans and IP statistics.

## Limitations & Notes

- This script is intended for use on Windows systems where PowerShell 5.1+ and Windows Firewall are available.
- The system needs to be run with administrator privileges.
- The script relies on specific event IDs and log types; adjust the `$EventsToTrack` hashtable for your environment.
- Ban durations are exponential but capped to avoid excessively long bans.
- It does not run as a persistent service but can be scheduled to run at startup or on an interval.

## Additional

You can extend or customize the script by tweaking:

- `$EventsToTrack`: To monitor different logs or event IDs.
- `$Whitelist`: To prevent banning certain IPs.
- `$CheckWindow` and `$CheckCount`: To customize detection sensitivity.
- The firewall rule naming conventions in `$FirewallRulePrefix`.

> [!NOTE] 
> The script logs significant actions and errors, which can be retrieved by examining Windows Event Logs under the "Application" log with source "events2ban".

---

For further customization or integration, review and modify the `events2ban.ps1` script as needed.
