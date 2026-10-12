#Requires -Version 5.1
<#
.SYNOPSIS
    Local privilege escalation audit -- WinPEAS equivalent in pure PowerShell.
    No admin required. No external tools. No internet access needed.

.DESCRIPTION
    Checks for common local privilege escalation paths:
      - System info / patch level
      - Current user token and privileges
      - AV / EDR products running
      - Unquoted service paths
      - Weak service binary permissions
      - AlwaysInstallElevated
      - Scheduled tasks with writable paths
      - Registry AutoRun entries
      - Stored credentials and password files
      - UAC configuration
      - Network recon (ports, shares, ARP)
      - PowerShell history and logging gaps

.PARAMETER OutFile
    Optional path to save output as a text file.
    Example: .\Invoke-PrivEscAudit.ps1 -OutFile C:\Temp\privesc.txt

.EXAMPLE
    .\Invoke-PrivEscAudit.ps1
    .\Invoke-PrivEscAudit.ps1 -OutFile C:\Temp\audit.txt
#>
[CmdletBinding()]
param(
    [string]$OutFile
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
$script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:Transcript = [System.Text.StringBuilder]::new()

function Write-Section {
    param([string]$Title)
    $line = '=' * 70
    $msg  = "`n$line`n  $Title`n$line"
    Write-Host $msg -ForegroundColor Cyan
    [void]$script:Transcript.AppendLine($msg)
}

function Write-Find {
    param([string]$Sev, [string]$Text, [string]$Detail = '')
    $color = switch ($Sev) {
        'HIGH'   { 'Red' }
        'MEDIUM' { 'Yellow' }
        'INFO'   { 'Gray' }
        default  { 'White' }
    }
    $prefix = "[$Sev]"
    $msg = "$prefix $Text"
    Write-Host $msg -ForegroundColor $color
    if ($Detail) { Write-Host "       $Detail" -ForegroundColor DarkGray }
    [void]$script:Transcript.AppendLine($msg)
    if ($Detail) { [void]$script:Transcript.AppendLine("       $Detail") }
    $script:Findings.Add([PSCustomObject]@{ Severity=$Sev; Finding=$Text; Detail=$Detail })
}

function Write-Info {
    param([string]$Text)
    Write-Host "  $Text" -ForegroundColor White
    [void]$script:Transcript.AppendLine("  $Text")
}

# ---------------------------------------------------------------------------
# Section 1 -- System Info
# ---------------------------------------------------------------------------
Write-Section "SYSTEM INFORMATION"

try {
    $os  = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
    $cs  = Get-WmiObject Win32_ComputerSystem  -ErrorAction Stop
    Write-Info "Hostname      : $($cs.Name)"
    Write-Info "Domain        : $($cs.Domain)"
    Write-Info "OS            : $($os.Caption) Build $($os.BuildNumber)"
    Write-Info "Architecture  : $($os.OSArchitecture)"
    Write-Info "Last Boot     : $($os.ConvertToDateTime($os.LastBootUpTime))"
    Write-Info "Logged Users  : $($cs.UserName)"
    Write-Info "System Dir    : $($os.SystemDirectory)"

    # Flag old OS
    if ($os.BuildNumber -lt 17763) {
        Write-Find 'HIGH' "Old OS build $($os.BuildNumber) -- may lack security patches" `
            'Consider patching or upgrading'
    }
} catch { Write-Find 'INFO' "Could not read OS info: $_" }

# Hotfixes / patch gap
try {
    $patches = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending
    if ($patches) {
        $latest = $patches[0].InstalledOn
        Write-Info "Last Hotfix   : $($patches[0].HotFixID) on $latest"
        $daysSince = ([DateTime]::Now - [DateTime]$latest).Days
        if ($daysSince -gt 60) {
            Write-Find 'MEDIUM' "Last patch was $daysSince days ago -- unpatched vulnerabilities likely" `
                "Last patch: $($patches[0].HotFixID)"
        }
    } else {
        Write-Find 'MEDIUM' "No hotfixes found -- patching history unavailable"
    }
} catch {}

# PowerShell version
Write-Info "PS Version    : $($PSVersionTable.PSVersion)"
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Find 'MEDIUM' "PowerShell $($PSVersionTable.PSVersion) -- downgrade attack possible to avoid logging"
}

# ---------------------------------------------------------------------------
# Section 2 -- Current User & Privileges
# ---------------------------------------------------------------------------
Write-Section "CURRENT USER & TOKEN"

Write-Info "User          : $env:USERDOMAIN\$env:USERNAME"
Write-Info "Domain        : $env:USERDOMAIN"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Info "Local Admin   : $isAdmin"
if ($isAdmin) { Write-Find 'HIGH' "Running as LOCAL ADMIN -- all local privesc paths open" }

# Token privileges
try {
    $privs = whoami /priv 2>$null
    $dangerPrivs = @(
        'SeDebugPrivilege',
        'SeImpersonatePrivilege',
        'SeAssignPrimaryTokenPrivilege',
        'SeTakeOwnershipPrivilege',
        'SeLoadDriverPrivilege',
        'SeRestorePrivilege',
        'SeBackupPrivilege',
        'SeTcbPrivilege',
        'SeCreateTokenPrivilege'
    )
    foreach ($priv in $dangerPrivs) {
        $match = $privs | Select-String $priv
        if ($match) {
            $enabled = $match -match 'Enabled'
            if ($enabled) {
                Write-Find 'HIGH' "Dangerous privilege ENABLED: $priv" `
                    'Can be abused for privilege escalation'
            } else {
                Write-Find 'MEDIUM' "Dangerous privilege present (disabled): $priv"
            }
        }
    }
} catch {}

# Local group memberships
try {
    $groups = whoami /groups 2>$null
    $intGroups = @('Administrators','Remote Desktop Users','Backup Operators',
                   'Server Operators','Account Operators','Print Operators','DnsAdmins')
    foreach ($g in $intGroups) {
        if ($groups | Select-String $g) {
            $sev = if ($g -eq 'Administrators') { 'HIGH' } else { 'MEDIUM' }
            Write-Find $sev "Member of: $g"
        }
    }
} catch {}

# Cached domain logon count
try {
    $cached = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' `
        -ErrorAction SilentlyContinue).CachedLogonsCount
    if ($null -ne $cached) {
        Write-Info "Cached Logons : $cached domain credential hashes stored locally"
        if ([int]$cached -gt 2) {
            Write-Find 'MEDIUM' "CachedLogonsCount=$cached -- DCC2 hashes extractable with SYSTEM access" `
                'Reduce to 1 via GPO: Interactive logon: Number of previous logons to cache'
        }
    }
} catch {}

# ---------------------------------------------------------------------------
# Section 3 -- AV / EDR Detection
# ---------------------------------------------------------------------------
Write-Section "AV / EDR PRODUCTS"

try {
    $avProds = Get-WmiObject -Namespace 'root\SecurityCenter2' -Class AntiVirusProduct `
        -ErrorAction SilentlyContinue
    if ($avProds) {
        foreach ($av in $avProds) {
            Write-Info "AV Product    : $($av.displayName)  State: $($av.productState)"
        }
    } else {
        Write-Find 'HIGH' "No AV product registered in SecurityCenter2"
    }
} catch {}

$edrs = @{
    'CylanceSvc'      = 'Cylance'
    'CSFalconService' = 'CrowdStrike Falcon'
    'SentinelAgent'   = 'SentinelOne'
    'CarbonBlack'     = 'Carbon Black'
    'cyserver'        = 'Cortex XDR'
    'trapsagent'      = 'Cortex XDR (Traps)'
    'TaniumClient'    = 'Tanium'
    'MsMpEng'         = 'Windows Defender'
    'mbamservice'     = 'Malwarebytes'
    'bdservicehost'   = 'Bitdefender'
}
foreach ($svc in $edrs.Keys) {
    $proc = Get-Process -Name $svc -ErrorAction SilentlyContinue
    if ($proc) { Write-Info "EDR Running   : $($edrs[$svc]) (PID $($proc.Id))" }
}

# Defender real-time protection
try {
    $defStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($defStatus) {
        Write-Info "Defender RTP  : $($defStatus.RealTimeProtectionEnabled)"
        Write-Info "Defender AMSI : $($defStatus.AmsIEnabled)"
        if (-not $defStatus.RealTimeProtectionEnabled) {
            Write-Find 'HIGH' "Windows Defender Real-Time Protection is DISABLED"
        }
    }
} catch {}

# ---------------------------------------------------------------------------
# Section 4 -- Services (Unquoted Paths & Weak Permissions)
# ---------------------------------------------------------------------------
Write-Section "SERVICES -- UNQUOTED PATHS & WEAK PERMISSIONS"

# Unquoted service paths
try {
    $svcs = Get-WmiObject Win32_Service -ErrorAction Stop
    foreach ($svc in $svcs) {
        $path = $svc.PathName
        if (-not $path) { continue }
        # Strip args after .exe
        $binPath = $path -replace '".*?"','' -replace '\s+-.*$',''
        if ($binPath -notmatch '"' -and $binPath -match ' ' -and $binPath -notmatch 'System32|SysWOW64|MicrosoftEdge') {
            Write-Find 'HIGH' "Unquoted service path: $($svc.Name)" `
                "Path: $binPath  |  RunAs: $($svc.StartName)"
        }
    }
} catch { Write-Find 'INFO' "Could not enumerate services: $_" }

# Services running as domain accounts (not SYSTEM/Local/Network)
try {
    Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {
            $_.StartName -and
            $_.StartName -notmatch 'LocalSystem|LocalService|NetworkService|NT AUTHORITY|NT SERVICE'
        } | ForEach-Object {
            Write-Find 'MEDIUM' "Service runs as domain account: $($_.Name)" `
                "Account: $($_.StartName)  |  Path: $($_.PathName)"
        }
} catch {}

# Writable service binary paths
try {
    $svcs = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue
    foreach ($svc in $svcs) {
        if (-not $svc.PathName) { continue }
        $exePath = ($svc.PathName -replace '"','').Split(' ')[0]
        if (-not (Test-Path $exePath -ErrorAction SilentlyContinue)) { continue }
        try {
            $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
            foreach ($ace in $acl.Access) {
                if ($ace.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users') {
                    if ($ace.FileSystemRights -match 'Write|Modify|FullControl|GenericWrite|GenericAll') {
                        Write-Find 'HIGH' "Writable service binary: $($svc.Name)" `
                            "Path: $exePath  |  Principal: $($ace.IdentityReference)  |  Rights: $($ace.FileSystemRights)"
                    }
                }
            }
        } catch {}
    }
} catch {}

# ---------------------------------------------------------------------------
# Section 5 -- Scheduled Tasks
# ---------------------------------------------------------------------------
Write-Section "SCHEDULED TASKS"

try {
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.Principal.UserId -match 'SYSTEM|Administrator' }
    foreach ($task in $tasks) {
        $action = $task.Actions | Where-Object { $_.Execute } | Select-Object -First 1
        if (-not $action) { continue }
        $exePath = ($action.Execute -replace '"','').Trim()
        if (-not $exePath) { continue }

        # Check if the task binary or script is writable
        if (Test-Path $exePath -ErrorAction SilentlyContinue) {
            try {
                $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                foreach ($ace in $acl.Access) {
                    if ($ace.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users') {
                        if ($ace.FileSystemRights -match 'Write|Modify|FullControl') {
                            Write-Find 'HIGH' "SYSTEM task with writable binary: $($task.TaskName)" `
                                "Path: $exePath  |  Rights: $($ace.FileSystemRights)"
                        }
                    }
                }
            } catch {}
        }

        # Scripts (.ps1 / .bat / .vbs) referenced in task args
        $args = $action.Arguments
        if ($args) {
            $scriptMatch = [regex]::Match($args, '[A-Za-z]:\\[^\s"]+\.(ps1|bat|vbs|cmd)')
            if ($scriptMatch.Success) {
                $scriptPath = $scriptMatch.Value
                if (Test-Path $scriptPath -ErrorAction SilentlyContinue) {
                    try {
                        $sacl = Get-Acl $scriptPath -ErrorAction SilentlyContinue
                        foreach ($ace in $sacl.Access) {
                            if ($ace.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users') {
                                if ($ace.FileSystemRights -match 'Write|Modify|FullControl') {
                                    Write-Find 'HIGH' "SYSTEM task with writable script: $($task.TaskName)" `
                                        "Script: $scriptPath"
                                }
                            }
                        }
                    } catch {}
                } else {
                    # Script path in task does not exist -- can create it
                    $dir = Split-Path $scriptPath -Parent
                    if (Test-Path $dir -ErrorAction SilentlyContinue) {
                        Write-Find 'HIGH' "SYSTEM task references non-existent script (can create): $($task.TaskName)" `
                            "Missing: $scriptPath"
                    }
                }
            }
        }
    }
} catch { Write-Find 'INFO' "Could not enumerate scheduled tasks: $_" }

# ---------------------------------------------------------------------------
# Section 6 -- Registry Checks
# ---------------------------------------------------------------------------
Write-Section "REGISTRY -- MISCONFIGURATIONS"

# AlwaysInstallElevated
try {
    $aieHKCU = (Get-ItemProperty 'HKCU:\Software\Policies\Microsoft\Windows\Installer' `
        -ErrorAction SilentlyContinue).AlwaysInstallElevated
    $aieHKLM = (Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\Installer' `
        -ErrorAction SilentlyContinue).AlwaysInstallElevated
    if ($aieHKCU -eq 1 -and $aieHKLM -eq 1) {
        Write-Find 'HIGH' "AlwaysInstallElevated is ENABLED" `
            'Any user can install MSI packages as SYSTEM. Create malicious MSI for instant SYSTEM.'
    } elseif ($aieHKCU -eq 1 -or $aieHKLM -eq 1) {
        Write-Find 'MEDIUM' "AlwaysInstallElevated partially set (only one hive)" `
            "HKCU=$aieHKCU  HKLM=$aieHKLM  -- both must be 1 to exploit"
    } else {
        Write-Info "AlwaysInstallElevated : Not set (secure)"
    }
} catch {}

# UAC level
try {
    $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -ErrorAction SilentlyContinue)
    $uacLevel = $uac.ConsentPromptBehaviorAdmin
    $luaEnabled = $uac.EnableLUA
    Write-Info "UAC Enabled   : $luaEnabled  |  ConsentPromptBehaviorAdmin: $uacLevel"
    if ($luaEnabled -eq 0) {
        Write-Find 'HIGH' "UAC is DISABLED (EnableLUA=0)" `
            'All processes run with full admin token. No elevation prompt.'
    } elseif ($uacLevel -eq 0) {
        Write-Find 'HIGH' "UAC set to never notify (ConsentPromptBehaviorAdmin=0)" `
            'Elevation silently granted -- UAC bypass not needed.'
    } elseif ($uacLevel -le 2) {
        Write-Find 'MEDIUM' "UAC set to low notification level ($uacLevel)" `
            'May be bypassable without prompt via UACME/fodhelper/eventvwr techniques'
    }
} catch {}

# AutoRun entries
try {
    $autoRunKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($key in $autoRunKeys) {
        $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch 'PS' } | ForEach-Object {
                $val = $_.Value
                $exePath = ($val -replace '"','').Split(' ')[0]
                $writable = $false
                if (Test-Path $exePath -ErrorAction SilentlyContinue) {
                    try {
                        $acl = Get-Acl $exePath -ErrorAction SilentlyContinue
                        $writable = $acl.Access | Where-Object {
                            $_.IdentityReference -match 'Everyone|Users|Authenticated' -and
                            $_.FileSystemRights -match 'Write|Modify|FullControl'
                        }
                    } catch {}
                }
                if ($writable) {
                    Write-Find 'HIGH' "Writable AutoRun binary: $($_.Name)" `
                        "Key: $key  |  Path: $exePath"
                } else {
                    Write-Find 'INFO' "AutoRun entry: $($_.Name) -> $val"
                }
            }
        }
    }
} catch {}

# PowerShell Logging
try {
    $psLog = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
        -ErrorAction SilentlyContinue
    $modLog = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
        -ErrorAction SilentlyContinue
    $transcription = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' `
        -ErrorAction SilentlyContinue

    if (-not $psLog -or $psLog.EnableScriptBlockLogging -ne 1) {
        Write-Find 'MEDIUM' "PowerShell Script Block Logging is DISABLED" `
            'Malicious PS commands will not be recorded in event log 4104'
    } else {
        Write-Info "PS Script Block Logging : Enabled"
    }
    if (-not $modLog -or $modLog.EnableModuleLogging -ne 1) {
        Write-Find 'MEDIUM' "PowerShell Module Logging is DISABLED"
    }
    if (-not $transcription -or $transcription.EnableTranscripting -ne 1) {
        Write-Find 'INFO' "PowerShell Transcription is DISABLED"
    }
} catch {}

# LAPS deployed?
try {
    $laps = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' `
        -ErrorAction SilentlyContinue
    if ($laps -and $laps.AdmPwdEnabled -eq 1) {
        Write-Info "LAPS          : Enabled"
    } else {
        Write-Find 'MEDIUM' "LAPS does not appear to be deployed on this machine" `
            'Local Administrator password may be same across all machines'
    }
} catch {}

# Credential Guard
try {
    $cg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' `
        -ErrorAction SilentlyContinue).EnableVirtualizationBasedSecurity
    Write-Info "Credential Guard VBS : $(if($cg -eq 1){'Enabled'}else{'Disabled/Not configured'})"
    if ($cg -ne 1) {
        Write-Find 'MEDIUM' "Credential Guard not enabled -- LSASS credential dump possible with SYSTEM"
    }
} catch {}

# ---------------------------------------------------------------------------
# Section 7 -- Stored Credentials & Password Files
# ---------------------------------------------------------------------------
Write-Section "STORED CREDENTIALS & PASSWORD FILES"

# cmdkey
try {
    $ck = cmdkey /list 2>$null
    $ck | Select-String 'Target:' | ForEach-Object {
        Write-Find 'MEDIUM' "Credential Manager entry: $($_ -replace 'Target:\s*','')"
    }
} catch {}

# PowerShell history
try {
    $histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $histPath) {
        $histLines = Get-Content $histPath -ErrorAction SilentlyContinue
        Write-Info "PS History    : $($histLines.Count) commands at $histPath"
        # Look for passwords in history
        $sensWords = @('password','passwd','secret','cred','key','token','-pass','ConvertTo-SecureString')
        foreach ($word in $sensWords) {
            $matches = $histLines | Select-String $word -CaseSensitive:$false
            if ($matches) {
                Write-Find 'HIGH' "Sensitive keyword '$word' found in PS history" `
                    "$($matches[0].Line)"
            }
        }
    }
} catch {}

# Unattend / Sysprep password files
$passFiles = @(
    "$env:SystemRoot\Panther\Unattend.xml",
    "$env:SystemRoot\Panther\Unattend\Unattend.xml",
    "$env:SystemRoot\System32\sysprep\sysprep.xml",
    "$env:SystemRoot\System32\sysprep.inf",
    'C:\unattend.xml',
    'C:\unattend.txt'
)
foreach ($pf in $passFiles) {
    if (Test-Path $pf -ErrorAction SilentlyContinue) {
        Write-Find 'HIGH' "Password file exists: $pf"
        $hit = Select-String -Path $pf -Pattern 'password|cpassword|AdminPassword' `
            -CaseSensitive:$false -ErrorAction SilentlyContinue
        if ($hit) { Write-Find 'HIGH' "  Contains password strings!" "  $($hit[0].Line.Trim())" }
    }
}

# web.config / app.config with connection strings
try {
    $webConfigs = Get-ChildItem 'C:\inetpub' -Recurse -Filter 'web.config' -ErrorAction SilentlyContinue
    foreach ($wc in $webConfigs) {
        $hit = Select-String -Path $wc.FullName -Pattern 'password=|pwd=' -CaseSensitive:$false `
            -ErrorAction SilentlyContinue
        if ($hit) {
            Write-Find 'HIGH' "web.config contains password: $($wc.FullName)" `
                "$($hit[0].Line.Trim())"
        }
    }
} catch {}

# WiFi passwords
try {
    $profiles = (netsh wlan show profiles 2>$null) | Select-String 'All User Profile' |
        ForEach-Object { ($_ -split ':')[1].Trim() }
    foreach ($p in $profiles) {
        $keyLine = (netsh wlan show profile name=$p key=clear 2>$null) | Select-String 'Key Content'
        if ($keyLine) {
            Write-Find 'MEDIUM' "WiFi password recovered: $p" `
                "$keyLine"
        }
    }
} catch {}

# SAM backup files
$samFiles = @('C:\Windows\repair\SAM','C:\Windows\repair\SYSTEM','C:\Windows\System32\config\RegBack\SAM')
foreach ($sf in $samFiles) {
    if (Test-Path $sf -ErrorAction SilentlyContinue) {
        Write-Find 'HIGH' "SAM backup file accessible: $sf" `
            'Can be used to extract local account hashes offline'
    }
}

# ---------------------------------------------------------------------------
# Section 8 -- PATH Hijacking
# ---------------------------------------------------------------------------
Write-Section "PATH HIJACKING"

$env:PATH.Split(';') | Where-Object { $_ } | ForEach-Object {
    $dir = $_.Trim()
    if (-not (Test-Path $dir -ErrorAction SilentlyContinue)) {
        Write-Find 'MEDIUM' "PATH entry does not exist (can create): $dir"
        return
    }
    try {
        $acl = Get-Acl $dir -ErrorAction SilentlyContinue
        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -match 'Everyone|Users|Authenticated Users|BUILTIN\\Users') {
                if ($ace.FileSystemRights -match 'Write|Modify|FullControl') {
                    Write-Find 'HIGH' "Writable PATH directory: $dir" `
                        "Principal: $($ace.IdentityReference)  Rights: $($ace.FileSystemRights)"
                }
            }
        }
    } catch {}
}

# ---------------------------------------------------------------------------
# Section 9 -- Network Recon
# ---------------------------------------------------------------------------
Write-Section "NETWORK RECON"

# IP config
try {
    $nics = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue
    foreach ($nic in $nics) {
        Write-Info "Interface     : $($nic.Description)"
        Write-Info "  IP          : $($nic.IPAddress -join ', ')"
        Write-Info "  Gateway     : $($nic.DefaultIPGateway -join ', ')"
        Write-Info "  DNS         : $($nic.DNSServerSearchOrder -join ', ')"
    }
} catch {}

# Open ports (listening)
try {
    Write-Info "`nListening Ports:"
    $listeners = netstat -ano 2>$null | Select-String 'LISTENING'
    $listeners | ForEach-Object { Write-Info "  $_" }
} catch {}

# ARP table -- all reachable hosts
try {
    Write-Info "`nARP Table (reachable hosts):"
    arp -a 2>$null | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' -and $_ -notmatch '255|Broadcast' } |
        ForEach-Object { Write-Info "  $_" }
} catch {}

# Network shares visible
try {
    Write-Info "`nVisible Network Shares:"
    $shares = net view 2>$null
    if ($shares) { $shares | ForEach-Object { Write-Info "  $_" } }
} catch {}

# ---------------------------------------------------------------------------
# Section 10 -- Interesting Files & Recent Activity
# ---------------------------------------------------------------------------
Write-Section "INTERESTING FILES"

# Recent files
try {
    $recent = Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 15
    Write-Info "Recent Files:"
    $recent | ForEach-Object { Write-Info "  $($_.LastWriteTime.ToString('yyyy-MM-dd'))  $($_.Name)" }
} catch {}

# Desktop / Documents -- interesting extensions
try {
    $searchPaths = @($env:USERPROFILE, "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents")
    $sensitiveExt = @('*.kdbx','*.key','*.pfx','*.p12','*.pem','*.ppk','*.rdp','*.cred','*pass*.txt','*cred*.txt')
    foreach ($sp in $searchPaths) {
        foreach ($ext in $sensitiveExt) {
            Get-ChildItem $sp -Filter $ext -ErrorAction SilentlyContinue | ForEach-Object {
                Write-Find 'HIGH' "Sensitive file found: $($_.FullName)"
            }
        }
    }
} catch {}

# RDP saved connections
try {
    $rdpSessions = Get-ChildItem 'HKCU:\Software\Microsoft\Terminal Server Client\Servers' `
        -ErrorAction SilentlyContinue
    if ($rdpSessions) {
        Write-Info "`nSaved RDP Connections:"
        $rdpSessions | ForEach-Object {
            $user = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).UsernameHint
            Write-Find 'MEDIUM' "Saved RDP: $($_.PSChildName)  User: $user"
        }
    }
} catch {}

# ---------------------------------------------------------------------------
# Section 11 -- Processes of Interest
# ---------------------------------------------------------------------------
Write-Section "RUNNING PROCESSES"

try {
    # Processes running as SYSTEM from non-standard locations
    $sysProcs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -and $_.ExecutablePath -notmatch 'System32|SysWOW64|Program Files|Windows' }
    foreach ($p in $sysProcs) {
        $owner = $null
        try { $owner = $p.GetOwner().User } catch {}
        if ($owner -match 'SYSTEM|Administrator') {
            Write-Find 'MEDIUM' "SYSTEM process from non-standard path: $($p.Name)" `
                "Path: $($p.ExecutablePath)"
        }
    }

    # Interesting processes for situational awareness
    $intProcs = @('keepass','bitwarden','1password','lastpass','putty','winscp','filezilla',
                  'mstsc','mobaxterm','securecrt','kitty')
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
        $pn = $_.Name.ToLower()
        foreach ($ip in $intProcs) {
            if ($pn -match $ip) {
                Write-Find 'MEDIUM' "Interesting process running: $($_.Name) (PID $($_.Id))" `
                    'May contain cleartext credentials in memory or config files'
            }
        }
    }
} catch {}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
Write-Section "SUMMARY"

$high   = @($script:Findings | Where-Object { $_.Severity -eq 'HIGH' })
$medium = @($script:Findings | Where-Object { $_.Severity -eq 'MEDIUM' })
$info   = @($script:Findings | Where-Object { $_.Severity -eq 'INFO' })

Write-Host "`n  HIGH   : $($high.Count)" -ForegroundColor Red
Write-Host "  MEDIUM : $($medium.Count)" -ForegroundColor Yellow
Write-Host "  INFO   : $($info.Count)" -ForegroundColor Gray

if ($high.Count -gt 0) {
    Write-Host "`n  HIGH findings:" -ForegroundColor Red
    $high | ForEach-Object { Write-Host "    - $($_.Finding)" -ForegroundColor Red }
}

if ($medium.Count -gt 0) {
    Write-Host "`n  MEDIUM findings:" -ForegroundColor Yellow
    $medium | ForEach-Object { Write-Host "    - $($_.Finding)" -ForegroundColor Yellow }
}

# Save output
if ($OutFile) {
    try {
        $script:Transcript.ToString() | Out-File -FilePath $OutFile -Encoding UTF8 -Force
        Write-Host "`n[+] Output saved to: $OutFile" -ForegroundColor Cyan
    } catch {
        Write-Warning "Could not save output: $_"
    }
}

Write-Host "`n[*] Audit complete.`n" -ForegroundColor Cyan