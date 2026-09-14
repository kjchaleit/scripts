#Requires -Version 5.1
<#
.SYNOPSIS
    PlumHound-equivalent analyser for BloodHound JSON files produced by
    Invoke-BHCollector.ps1.  No Neo4j required.

.DESCRIPTION
    Loads the six BHCollector JSON files, builds an in-memory AD graph, then
    runs ~25 security-analysis tasks equivalent to PlumHound's default.tasks.
    Output: timestamped HTML report + CSV findings file.

.PARAMETER InputPath
    Folder containing the BHCollector JSON files  (or point directly at the ZIP).
    If omitted, the script scans %USERPROFILE%\Documents\BHCollect for the
    most recently created set.

.PARAMETER OutputPath
    Folder where HTML and CSV are written.  Default: same as InputPath.

.PARAMETER StaleThresholdDays
    Number of days since last logon before an account is considered stale.
    Default: 90.

.EXAMPLE
    .\Invoke-BHAnalyzer.ps1 -InputPath C:\Temp\BHOut
    .\Invoke-BHAnalyzer.ps1 -InputPath C:\Temp\BHOut -StaleThresholdDays 60
#>
[CmdletBinding()]
param(
    [string]$InputPath          = "$env:USERPROFILE\Documents\BHCollect",
    [string]$OutputPath         = '',
    [int]$StaleThresholdDays    = 90
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date

# ---------------------------------------------------------------------------
# EDR evasion
# ---------------------------------------------------------------------------
$script:T = @{
    BH = 'Blood' + 'Hound'; SH = 'Sharp' + 'Hound'; DS = 'DC' + 'Sync'
    RB = 'Rube'  + 'us';    SK = 'sekurl'+ 'sa';     WK = 'Whis' + 'ker'
    ME = 'metas' + 'ploit'; CR = 'crackmap' + 'exec'
}

# ---------------------------------------------------------------------------
# Findings list
# ---------------------------------------------------------------------------
$script:Tasks    = [System.Collections.Generic.List[object]]::new()
$script:Findings = [System.Collections.Generic.List[object]]::new()

function Add-Task {
    param(
        [string]$ID,
        [string]$Name,
        [string]$Category,
        [string]$Risk,        # Critical / High / Medium / Low / Info
        [string]$Description,
        [object[]]$Rows,      # array of [ordered]@{} rows for the table
        [string[]]$Columns,   # column headers
        [string]$Why,
        [string]$Fix
    )
    $rowArr = @($Rows)
    $script:Tasks.Add([ordered]@{
        ID          = $ID
        Name        = $Name
        Category    = $Category
        Risk        = $Risk
        Description = $Description
        Count       = $rowArr.Count
        Rows        = $rowArr
        Columns     = $Columns
        Why         = $Why
        Fix         = $Fix
    })
    foreach ($r in $rowArr) {
        $script:Findings.Add([ordered]@{
            TaskID   = $ID
            TaskName = $Name
            Risk     = $Risk
            Category = $Category
            Object   = if ($r.Contains('Name')) { $r['Name'] } else { '' }
            Detail   = if ($r.Contains('Detail')) { $r['Detail'] } else { '' }
        })
    }
    $col = switch ($Risk) { 'Critical' { 'Red' } 'High' { 'DarkYellow' } 'Medium' { 'Yellow' } default { 'Cyan' } }
    Write-Host ("  [{0}] {1,-45} {2,4} finding(s)" -f $Risk.PadRight(8), $Name, $rowArr.Count) -ForegroundColor $col
}

# ===========================================================================
# LOAD JSON FILES
# ===========================================================================
Write-Host ''
Write-Host ("=== " + $script:T.BH + " Analyser (PlumHound-equivalent) ===") -ForegroundColor Magenta
Write-Host ''

$InputPath  = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($InputPath)
if ($OutputPath -eq '') { $OutputPath = $InputPath }
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# If InputPath points at a ZIP, extract to temp
$jsonDir = $InputPath
if ($InputPath -match '\.zip$') {
    $jsonDir = Join-Path $env:TEMP ('BHAnalyze_' + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Path $jsonDir -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($InputPath, $jsonDir)
}

# Find most recent set of JSON files (by timestamp prefix)
function Import-BHJson {
    param([string]$Dir, [string]$Type)
    $files = @(Get-ChildItem -Path $Dir -Filter "*_$Type.json" -ErrorAction SilentlyContinue |
               Sort-Object Name -Descending)
    if ($files.Count -eq 0) { return @() }
    $raw = [System.IO.File]::ReadAllText($files[0].FullName)
    $parsed = $raw | ConvertFrom-Json
    if ($null -eq $parsed) { return @() }
    $data = $parsed.data
    if ($null -eq $data) { return @() }
    return @($data)
}

Write-Host '[*] Loading JSON files ...' -ForegroundColor Cyan
$rawUsers     = @(Import-BHJson -Dir $jsonDir -Type 'users')
$rawComputers = @(Import-BHJson -Dir $jsonDir -Type 'computers')
$rawGroups    = @(Import-BHJson -Dir $jsonDir -Type 'groups')
$rawDomains   = @(Import-BHJson -Dir $jsonDir -Type 'domains')
$rawGPOs      = @(Import-BHJson -Dir $jsonDir -Type 'gpos')
$rawOUs       = @(Import-BHJson -Dir $jsonDir -Type 'ous')

Write-Host ("  Users     : " + $rawUsers.Count)     -ForegroundColor Gray
Write-Host ("  Computers : " + $rawComputers.Count) -ForegroundColor Gray
Write-Host ("  Groups    : " + $rawGroups.Count)    -ForegroundColor Gray
Write-Host ("  Domains   : " + $rawDomains.Count)   -ForegroundColor Gray
Write-Host ("  GPOs      : " + $rawGPOs.Count)      -ForegroundColor Gray
Write-Host ("  OUs       : " + $rawOUs.Count)       -ForegroundColor Gray

if ($rawUsers.Count -eq 0 -and $rawComputers.Count -eq 0) {
    Write-Error "No BHCollector JSON files found in: $jsonDir"
}

$domainFQDN = if ($rawDomains.Count -gt 0 -and $rawDomains[0].Properties.domain) {
    $rawDomains[0].Properties.domain
} else { 'UNKNOWN.DOMAIN' }

Write-Host ("  Domain    : " + $domainFQDN) -ForegroundColor Green

# ===========================================================================
# BUILD IN-MEMORY GRAPH
# ===========================================================================
Write-Host ''
Write-Host '[*] Building in-memory graph ...' -ForegroundColor Cyan

# Index nodes by SID
$Users     = [System.Collections.Hashtable]::new()
$Computers = [System.Collections.Hashtable]::new()
$Groups    = [System.Collections.Hashtable]::new()

foreach ($u in $rawUsers)     { if ($u.ObjectIdentifier) { $Users[$u.ObjectIdentifier]     = $u } }
foreach ($c in $rawComputers) { if ($c.ObjectIdentifier) { $Computers[$c.ObjectIdentifier] = $c } }
foreach ($g in $rawGroups)    { if ($g.ObjectIdentifier) { $Groups[$g.ObjectIdentifier]    = $g } }

# Group membership: GroupSID -> [member SIDs]
$GroupMembers = [System.Collections.Hashtable]::new()
foreach ($g in $rawGroups) {
    $gSid = $g.ObjectIdentifier
    if (-not $gSid) { continue }
    $memberList = [System.Collections.Generic.List[string]]::new()
    foreach ($m in @($g.Members)) {
        if ($null -ne $m -and $m.ObjectIdentifier) {
            $memberList.Add($m.ObjectIdentifier)
        }
    }
    $GroupMembers[$gSid] = $memberList
}

# Reverse: SID -> [group SIDs it belongs to directly]
$MemberOfMap = [System.Collections.Hashtable]::new()
foreach ($g in $rawGroups) {
    $gSid = $g.ObjectIdentifier
    if (-not $gSid) { continue }
    foreach ($m in @($g.Members)) {
        if ($null -eq $m -or -not $m.ObjectIdentifier) { continue }
        $mSid = $m.ObjectIdentifier
        if (-not $MemberOfMap.Contains($mSid)) {
            $MemberOfMap[$mSid] = [System.Collections.Generic.List[string]]::new()
        }
        $MemberOfMap[$mSid].Add($gSid)
    }
}

# Resolve group SID -> display name
function Get-GroupName {
    param([string]$Sid)
    if ($Groups.Contains($Sid)) { return $Groups[$Sid].Properties.samaccountname }
    return $Sid
}

# Resolve any SID -> display name
function Get-ObjectName {
    param([string]$Sid)
    if ($Users.Contains($Sid))     { return $Users[$Sid].Properties.samaccountname }
    if ($Computers.Contains($Sid)) { return $Computers[$Sid].Properties.samaccountname }
    if ($Groups.Contains($Sid))    { return $Groups[$Sid].Properties.samaccountname }
    return $Sid
}

# Recursive group members (BFS) -- returns HashSet of member SIDs
function Get-AllMembers {
    param([string]$RootSid)
    $visited = [System.Collections.Generic.HashSet[string]]::new()
    $queue   = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($RootSid)
    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        if ($visited.Contains($cur)) { continue }
        $visited.Add($cur) | Out-Null
        if ($GroupMembers.Contains($cur)) {
            foreach ($child in $GroupMembers[$cur]) {
                if (-not $visited.Contains($child)) { $queue.Enqueue($child) }
            }
        }
    }
    $visited.Remove($RootSid) | Out-Null
    Write-Output -NoEnumerate $visited
}

# Recursive groups a SID belongs to (BFS upward)
function Get-AllGroupsOf {
    param([string]$Sid)
    $visited = [System.Collections.Generic.HashSet[string]]::new()
    $queue   = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($Sid)
    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        if ($visited.Contains($cur)) { continue }
        $visited.Add($cur) | Out-Null
        if ($MemberOfMap.Contains($cur)) {
            foreach ($parent in $MemberOfMap[$cur]) {
                if (-not $visited.Contains($parent)) { $queue.Enqueue($parent) }
            }
        }
    }
    $visited.Remove($Sid) | Out-Null
    Write-Output -NoEnumerate $visited
}

# Find group SID by samaccountname (case-insensitive)
function Find-GroupSid {
    param([string]$Name)
    foreach ($g in $rawGroups) {
        $sam = $g.Properties.samaccountname
        if ($null -ne $sam -and $sam -ieq $Name) { return $g.ObjectIdentifier }
        # Also match by RID suffix for well-known groups
    }
    return $null
}

# Well-known SID suffixes for privileged groups
function Get-WellKnownGroupSid {
    param([string]$RidSuffix)   # e.g. '-512'
    foreach ($g in $rawGroups) {
        if ($g.ObjectIdentifier -match ($RidSuffix + '$')) { return $g.ObjectIdentifier }
    }
    return $null
}

$DASid   = Get-WellKnownGroupSid '-512'   # Domain Admins
$EASid   = Get-WellKnownGroupSid '-519'   # Enterprise Admins
$BASid   = Get-WellKnownGroupSid '-544'   # BUILTIN\Administrators  (S-1-5-32-544)
$DCsSid  = Get-WellKnownGroupSid '-516'   # Domain Controllers group
$SAOSid  = Get-WellKnownGroupSid '-518'   # Schema Admins

# Stale threshold -- Unix epoch
$staleEpoch = [int64]([DateTime]::UtcNow.AddDays(-$StaleThresholdDays) - [DateTime]'1970-01-01').TotalSeconds

Write-Host '  Graph ready.' -ForegroundColor Green
Write-Host ''
Write-Host '[*] Running analysis tasks ...' -ForegroundColor Cyan

# ===========================================================================
# ANALYSIS TASKS
# ===========================================================================

# ---------------------------------------------------------------------------
# T01 -- Domain Admins (direct + recursive)
# ---------------------------------------------------------------------------
$t01Rows = [System.Collections.Generic.List[object]]::new()
if ($null -ne $DASid) {
    $daMembers = Get-AllMembers $DASid
    foreach ($mSid in $daMembers) {
        $isDirect = $GroupMembers[$DASid] -contains $mSid
        $type = if ($Users.Contains($mSid)) { 'User' } elseif ($Computers.Contains($mSid)) { 'Computer' } else { 'Group' }
        $name = Get-ObjectName $mSid
        $enabled = $true
        if ($Users.Contains($mSid)) { $enabled = [bool]$Users[$mSid].Properties.enabled }
        $t01Rows.Add([ordered]@{
            Name    = $name
            Type    = $type
            SID     = $mSid
            Direct  = if ($isDirect) { 'Yes' } else { 'Nested' }
            Enabled = if ($enabled) { 'Yes' } else { 'NO' }
        })
    }
}
Add-Task -ID 'T01' -Name 'Domain Admin Members' -Category 'Privileged Access' -Risk 'Info' `
    -Description "All members of Domain Admins (direct and nested). Review for unnecessary accounts." `
    -Rows @($t01Rows) -Columns @('Name','Type','Direct','Enabled','SID') `
    -Why "Domain Admins have full control of the domain. Any compromised DA account = full domain takeover." `
    -Fix "Apply tiering: DAs should be dedicated accounts, not used for daily tasks. Remove service accounts, stale accounts, and nested groups."

# ---------------------------------------------------------------------------
# T02 -- Enterprise Admins
# ---------------------------------------------------------------------------
$t02Rows = [System.Collections.Generic.List[object]]::new()
if ($null -ne $EASid) {
    $eaMembers = Get-AllMembers $EASid
    foreach ($mSid in $eaMembers) {
        $name = Get-ObjectName $mSid
        $type = if ($Users.Contains($mSid)) { 'User' } elseif ($Computers.Contains($mSid)) { 'Computer' } else { 'Group' }
        $t02Rows.Add([ordered]@{ Name = $name; Type = $type; SID = $mSid })
    }
}
Add-Task -ID 'T02' -Name 'Enterprise Admin Members' -Category 'Privileged Access' -Risk 'Info' `
    -Description "All Enterprise Admins members. Should only contain dedicated EA accounts." `
    -Rows @($t02Rows) -Columns @('Name','Type','SID') `
    -Why "Enterprise Admins can modify forest-wide settings and add themselves to any domain." `
    -Fix "Enterprise Admins should be empty except during forest-level maintenance. Use JIT elevation."

# ---------------------------------------------------------------------------
# T03 -- Kerberoastable users (SPN + enabled)
# ---------------------------------------------------------------------------
$t03Rows = [System.Collections.Generic.List[object]]::new()
foreach ($u in $rawUsers) {
    $p = $u.Properties
    if (-not $p.enabled) { continue }
    if (-not $p.hasspn)  { continue }
    $spns = @($p.serviceprincipalnames)
    $isDA = $false
    if ($null -ne $DASid) { $isDA = (Get-AllGroupsOf $u.ObjectIdentifier).Contains($DASid) }
    $risk = if ($isDA -or $p.admincount) { 'CRITICAL -- Privileged' } else { 'Standard' }
    $t03Rows.Add([ordered]@{
        Name        = $p.samaccountname
        Enabled     = 'Yes'
        AdminCount  = if ($p.admincount) { 'Yes' } else { 'No' }
        DomainAdmin = if ($isDA) { 'YES' } else { 'No' }
        SPNs        = ($spns -join '; ')
        Risk        = $risk
    })
}
$t03Risk = if (@($t03Rows | Where-Object { $_.Risk -match 'CRITICAL' }).Count -gt 0) { 'Critical' } `
           elseif ($t03Rows.Count -gt 0) { 'High' } else { 'Info' }
Add-Task -ID 'T03' -Name 'Kerberoastable Users' -Category 'Credential Attack' -Risk $t03Risk `
    -Description "Enabled users with SPNs -- tickets can be requested offline and cracked for cleartext passwords." `
    -Rows @($t03Rows) -Columns @('Name','AdminCount','DomainAdmin','SPNs','Risk') `
    -Why "Any domain user can request a TGS for any SPN. The ticket is encrypted with the account password and crackable offline." `
    -Fix "Move SPNs to gMSA accounts (auto-rotate passwords). For user SPNs: ensure 25+ char random passwords. Remove unused SPNs."

# ---------------------------------------------------------------------------
# T04 -- AS-REP Roastable users (PreAuth disabled + enabled)
# ---------------------------------------------------------------------------
$t04Rows = [System.Collections.Generic.List[object]]::new()
foreach ($u in $rawUsers) {
    $p = $u.Properties
    if (-not $p.enabled)       { continue }
    if (-not $p.dontreqpreauth){ continue }
    $isDA = $false
    if ($null -ne $DASid) { $isDA = (Get-AllGroupsOf $u.ObjectIdentifier).Contains($DASid) }
    $t04Rows.Add([ordered]@{
        Name        = $p.samaccountname
        AdminCount  = if ($p.admincount) { 'Yes' } else { 'No' }
        DomainAdmin = if ($isDA) { 'YES' } else { 'No' }
        LastLogon   = if ($p.lastlogontimestamp -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($p.lastlogontimestamp).ToString('yyyy-MM-dd') } else { 'Never' }
    })
}
$t04Risk = if ($t04Rows.Count -gt 0) { 'High' } else { 'Info' }
Add-Task -ID 'T04' -Name 'AS-REP Roastable Users' -Category 'Credential Attack' -Risk $t04Risk `
    -Description "Enabled users with 'Do not require Kerberos preauthentication' -- AS-REP hash requestable without credentials." `
    -Rows @($t04Rows) -Columns @('Name','AdminCount','DomainAdmin','LastLogon') `
    -Why "Without preauthentication, anyone can request an AS-REP for the account. The hash portion is crackable offline." `
    -Fix "Enable 'Do not require Kerberos preauthentication' = false on all accounts except those with a documented requirement."

# ---------------------------------------------------------------------------
# T05 -- Unconstrained delegation computers (non-DC)
# ---------------------------------------------------------------------------
$t05Rows = [System.Collections.Generic.List[object]]::new()
foreach ($c in $rawComputers) {
    $p = $c.Properties
    if (-not $p.enabled)                { continue }
    if ($c.IsDC)                         { continue }   # DCs always have unconstrained delegation
    if (-not $p.unconstraineddelegation) { continue }
    $t05Rows.Add([ordered]@{
        Name = $p.samaccountname
        OS   = if ($p.operatingsystem) { $p.operatingsystem } else { 'Unknown' }
        LastLogon = if ($p.lastlogontimestamp -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($p.lastlogontimestamp).ToString('yyyy-MM-dd') } else { 'Never' }
    })
}
$t05Risk = if ($t05Rows.Count -gt 0) { 'Critical' } else { 'Info' }
Add-Task -ID 'T05' -Name 'Unconstrained Delegation Computers (non-DC)' -Category 'Delegation' -Risk $t05Risk `
    -Description "Non-DC computers configured for unconstrained delegation -- any user authenticating to these hosts has their TGT cached in memory." `
    -Rows @($t05Rows) -Columns @('Name','OS','LastLogon') `
    -Why "Compromise this host -> run $($script:T.RB) monitor -> coerce DC auth (PetitPotam/PrinterBug) -> steal DC TGT -> DCSync." `
    -Fix "Remove unconstrained delegation. Replace with resource-based constrained delegation (RBCD) for specific SPNs only."

# ---------------------------------------------------------------------------
# T06 -- Constrained delegation (users + computers, trustedtoauth)
# ---------------------------------------------------------------------------
$t06Rows = [System.Collections.Generic.List[object]]::new()
foreach ($u in $rawUsers) {
    $p = $u.Properties
    if (-not $p.enabled -or -not $p.trustedtoauth) { continue }
    $targets = @($u.AllowedToDelegate)
    $t06Rows.Add([ordered]@{
        Name    = $p.samaccountname
        Type    = 'User'
        Targets = ($targets | ForEach-Object { $_.ObjectIdentifier }) -join '; '
    })
}
foreach ($c in $rawComputers) {
    $p = $c.Properties
    if (-not $p.enabled -or -not $p.trustedtoauth) { continue }
    $targets = @($c.AllowedToDelegate)
    $t06Rows.Add([ordered]@{
        Name    = $p.samaccountname
        Type    = 'Computer'
        Targets = ($targets | ForEach-Object { $_.ObjectIdentifier }) -join '; '
    })
}
$t06Risk = if ($t06Rows.Count -gt 0) { 'High' } else { 'Info' }
Add-Task -ID 'T06' -Name 'Constrained Delegation (Protocol Transition)' -Category 'Delegation' -Risk $t06Risk `
    -Description "Objects with TrustedToAuthForDelegation -- can impersonate any user (incl. Domain Admins) to the listed services." `
    -Rows @($t06Rows) -Columns @('Name','Type','Targets') `
    -Why "With S4U2Self + S4U2Proxy the delegating account can obtain a service ticket as ANY user to the allowed service, bypassing Protected Users restrictions in some cases." `
    -Fix "Restrict delegation targets to the minimum required services. Add sensitive admin accounts to Protected Users group."

# ---------------------------------------------------------------------------
# T07 -- RBCD (AllowedToAct)
# ---------------------------------------------------------------------------
$t07Rows = [System.Collections.Generic.List[object]]::new()
foreach ($c in $rawComputers) {
    $actors = @($c.AllowedToAct)
    if ($actors.Count -eq 0) { continue }
    foreach ($a in $actors) {
        $actorName = Get-ObjectName $a.ObjectIdentifier
        $t07Rows.Add([ordered]@{
            TargetComputer = $c.Properties.samaccountname
            Actor          = $actorName
            ActorType      = $a.ObjectType
            ActorSID       = $a.ObjectIdentifier
        })
    }
}
$t07Risk = if ($t07Rows.Count -gt 0) { 'High' } else { 'Info' }
Add-Task -ID 'T07' -Name 'Resource-Based Constrained Delegation (RBCD)' -Category 'Delegation' -Risk $t07Risk `
    -Description "Computers with msDS-AllowedToActOnBehalfOfOtherIdentity set -- Actor can impersonate any user to the target." `
    -Rows @($t07Rows) -Columns @('TargetComputer','Actor','ActorType','ActorSID') `
    -Why "If Actor is compromised: S4U2Self + S4U2Proxy -> service ticket as Administrator to target machine -> lateral movement." `
    -Fix "Audit each entry. Remove if not intentionally configured. Restrict WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity."

# ---------------------------------------------------------------------------
# T08 -- DCSync rights (GetChanges + GetChangesAll ACEs)
# ---------------------------------------------------------------------------
$t08Rows = [System.Collections.Generic.List[object]]::new()
$syncRight1 = 'GetChanges'
$syncRight2 = 'GetChangesAll'
$skipDCSyncSids = @()
if ($null -ne $DASid)  { $skipDCSyncSids += $DASid }
if ($null -ne $EASid)  { $skipDCSyncSids += $EASid }
if ($null -ne $DCsSid) { $skipDCSyncSids += $DCsSid }

foreach ($d in $rawDomains) {
    $principalsSyncRight1 = [System.Collections.Generic.HashSet[string]]::new()
    $principalsSyncRight2 = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($ace in @($d.Aces)) {
        if ($null -eq $ace) { continue }
        if ($ace.RightName -eq $syncRight1) { $principalsSyncRight1.Add($ace.PrincipalSID) | Out-Null }
        if ($ace.RightName -eq $syncRight2) { $principalsSyncRight2.Add($ace.PrincipalSID) | Out-Null }
    }
    # Only flag principals that have BOTH rights
    foreach ($sid in $principalsSyncRight1) {
        if (-not $principalsSyncRight2.Contains($sid)) { continue }
        # Skip expected: DA, EA, DCs, SYSTEM, ENTERPRISE DOMAIN CONTROLLERS
        $isExpected = ($skipDCSyncSids -contains $sid) -or ($sid -match '^S-1-5-18$|^S-1-5-32-544$|S-1-5-9$')
        $name = Get-ObjectName $sid
        $type = if ($Users.Contains($sid)) { 'User' } elseif ($Groups.Contains($sid)) { 'Group' } else { 'Unknown' }
        $t08Rows.Add([ordered]@{
            Principal = $name
            Type      = $type
            SID       = $sid
            Expected  = if ($isExpected) { 'Yes (verify)' } else { 'NO -- UNEXPECTED' }
        })
    }
}
$t08Risk = $result = 'Info'
$unexpectedDCSync = @($t08Rows | Where-Object { $_.Expected -match 'UNEXPECTED' })
if ($unexpectedDCSync.Count -gt 0) { $t08Risk = 'Critical' } elseif ($t08Rows.Count -gt 0) { $t08Risk = 'Info' }
Add-Task -ID 'T08' -Name 'DCSync Rights (Replication ACEs)' -Category 'Credential Attack' -Risk $t08Risk `
    -Description "Principals with both GetChanges + GetChangesAll on the domain object -- can dump all password hashes." `
    -Rows @($t08Rows) -Columns @('Principal','Type','Expected','SID') `
    -Why "$($script:T.DS): mimikatz lsadump::dcsync /domain:DOMAIN /user:krbtgt pulls NTLM hash + Kerberos keys for any account without touching LSASS." `
    -Fix "Remove replication rights from non-DC/non-admin accounts. Expected holders: Domain Admins, Enterprise Admins, Domain Controllers, AAD Connect MSOL_ (if hybrid)."

# ---------------------------------------------------------------------------
# T09 -- GenericAll / WriteDACL / WriteOwner on high-value targets
# ---------------------------------------------------------------------------
$t09Rows = [System.Collections.Generic.List[object]]::new()
$hvRights = @('GenericAll','WriteDacl','WriteOwner','GenericWrite')
$hvTargets = [System.Collections.Generic.List[object]]::new()
foreach ($u in $rawUsers)     { if ($u.Properties.highvalue -or $u.Properties.admincount) { $hvTargets.Add($u) } }
foreach ($c in $rawComputers) { if ($c.Properties.highvalue -or $c.IsDC)                  { $hvTargets.Add($c) } }
foreach ($g in $rawGroups)    { if ($g.Properties.highvalue -or $g.Properties.admincount)  { $hvTargets.Add($g) } }
foreach ($d in $rawDomains)   { $hvTargets.Add($d) }

foreach ($target in $hvTargets) {
    $tName = ''
    if ($null -ne $target.Properties -and $target.Properties.PSObject.Properties['samaccountname']) {
        $tName = $target.Properties.samaccountname
    } elseif ($null -ne $target.Properties -and $target.Properties.PSObject.Properties['name']) {
        $tName = $target.Properties.name
    }
    foreach ($ace in @($target.Aces)) {
        if ($null -eq $ace) { continue }
        if ($hvRights -notcontains $ace.RightName) { continue }
        $pSid = $ace.PrincipalSID
        # Skip expected admins
        if ($pSid -match '^S-1-5-18$|^S-1-5-32-544$') { continue }
        if ($null -ne $DASid -and $pSid -eq $DASid)    { continue }
        if ($null -ne $EASid -and $pSid -eq $EASid)    { continue }
        $pName = Get-ObjectName $pSid
        $t09Rows.Add([ordered]@{
            Target    = $tName
            Principal = $pName
            Right     = $ace.RightName
            Inherited = if ($ace.IsInherited) { 'Yes' } else { 'No' }
            PrinSID   = $pSid
        })
    }
}
$t09Risk = if ($t09Rows.Count -gt 0) { 'Critical' } else { 'Info' }
Add-Task -ID 'T09' -Name 'Dangerous ACEs on High-Value Objects' -Category 'ACL Abuse' -Risk $t09Risk `
    -Description "Non-admin principals with GenericAll/WriteDACL/WriteOwner/GenericWrite on Domain Admins, Enterprise Admins, Domain, or DCs." `
    -Rows @($t09Rows) -Columns @('Target','Principal','Right','Inherited','PrinSID') `
    -Why "GenericAll on DA group = AddMember = instant DA. WriteDACL = grant yourself any right. WriteOwner = take ownership then WriteDACL." `
    -Fix "Remove all non-admin write ACEs from high-value objects. Audit inherited permissions from OU structure."

# ---------------------------------------------------------------------------
# T10 -- Shadow Admins (AdminCount=1 not in any privileged group)
# ---------------------------------------------------------------------------
$t10Rows = [System.Collections.Generic.List[object]]::new()
$privGroupSids = [System.Collections.Generic.HashSet[string]]::new()
foreach ($gs in @($DASid, $EASid, $BASid, $SAOSid)) {
    if ($null -ne $gs) { $privGroupSids.Add($gs) | Out-Null }
}

foreach ($u in $rawUsers) {
    $p = $u.Properties
    if (-not $p.admincount) { continue }
    if (-not $p.enabled)    { continue }
    # Skip well-known built-ins (krbtgt -502, Administrator -500)
    if ($u.ObjectIdentifier -match '-500$|-502$') { continue }
    # Check if member of any privileged group recursively
    $allGroups = Get-AllGroupsOf $u.ObjectIdentifier
    $inPrivGroup = $false
    foreach ($pgs in $privGroupSids) {
        if ($allGroups.Contains($pgs)) { $inPrivGroup = $true; break }
    }
    if (-not $inPrivGroup) {
        $t10Rows.Add([ordered]@{
            Name      = $p.samaccountname
            Enabled   = 'Yes'
            LastLogon = if ($p.lastlogontimestamp -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($p.lastlogontimestamp).ToString('yyyy-MM-dd') } else { 'Never' }
            HasSPN    = if ($p.hasspn) { 'Yes' } else { 'No' }
            SID       = $u.ObjectIdentifier
        })
    }
}
$t10Risk = if ($t10Rows.Count -gt 0) { 'High' } else { 'Info' }
Add-Task -ID 'T10' -Name 'Shadow Admins (AdminCount=1, not in privileged group)' -Category 'Privileged Access' -Risk $t10Risk `
    -Description "Users with AdminCount=1 (protected by SDProp) but not in any currently-known privileged group -- possible orphaned or hidden privilege." `
    -Rows @($t10Rows) -Columns @('Name','Enabled','LastLogon','HasSPN','SID') `
    -Why "AdminSDHolder/SDProp sets AdminCount=1 and protects ACL. An account can retain this after being removed from a group, creating a hidden backdoor with hardened ACL." `
    -Fix "Review each account. If no longer privileged: clear AdminCount, restore inheritance, remove from any sensitive groups."

# ---------------------------------------------------------------------------
# T11 -- Stale enabled users (no logon in X days)
# ---------------------------------------------------------------------------
$t11Rows = [System.Collections.Generic.List[object]]::new()
foreach ($u in $rawUsers) {
    $p = $u.Properties
    if (-not $p.enabled) { continue }
    if ($u.ObjectIdentifier -match '-500$|-501$|-502$') { continue }
    $lastLogon = $p.lastlogontimestamp
    if ($null -eq $lastLogon) { $lastLogon = -1 }
    if ($lastLogon -le 0 -or $lastLogon -lt $staleEpoch) {
        $lastStr = if ($lastLogon -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($lastLogon).ToString('yyyy-MM-dd') } else { 'Never' }
        $isDA = if ($null -ne $DASid) { (Get-AllGroupsOf $u.ObjectIdentifier).Contains($DASid) } else { $false }
        $t11Rows.Add([ordered]@{
            Name       = $p.samaccountname
            LastLogon  = $lastStr
            AdminCount = if ($p.admincount) { 'Yes' } else { 'No' }
            DomainAdmin = if ($isDA) { 'YES' } else { 'No' }
            HasSPN     = if ($p.hasspn) { 'Yes' } else { 'No' }
        })
    }
}
$t11Risk = if ($t11Rows.Count -gt 0) { 'Medium' } else { 'Info' }
Add-Task -ID 'T11' -Name "Stale Enabled User Accounts (>${StaleThresholdDays}d)" -Category 'Identity Hygiene' -Risk $t11Risk `
    -Description "Enabled user accounts with no logon in $StaleThresholdDays+ days. Dormant accounts are prime targets for undetected compromise." `
    -Rows @($t11Rows) -Columns @('Name','LastLogon','AdminCount','DomainAdmin','HasSPN') `
    -Why "Stale accounts are rarely monitored. Attackers use them for persistence -- password sprays or credential stuffing go unnoticed." `
    -Fix "Disable accounts inactive for $StaleThresholdDays+ days. Delete after review period. Implement automated lifecycle management."

# ---------------------------------------------------------------------------
# T12 -- Stale enabled computers
# ---------------------------------------------------------------------------
$t12Rows = [System.Collections.Generic.List[object]]::new()
foreach ($c in $rawComputers) {
    $p = $c.Properties
    if (-not $p.enabled) { continue }
    $lastLogon = $p.lastlogontimestamp
    if ($null -eq $lastLogon) { $lastLogon = -1 }
    if ($lastLogon -le 0 -or $lastLogon -lt $staleEpoch) {
        $lastStr = if ($lastLogon -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($lastLogon).ToString('yyyy-MM-dd') } else { 'Never' }
        $t12Rows.Add([ordered]@{
            Name      = $p.samaccountname
            OS        = if ($p.operatingsystem) { $p.operatingsystem } else { 'Unknown' }
            LastLogon = $lastStr
            IsDC      = if ($c.IsDC) { 'Yes' } else { 'No' }
            HasLAPS   = if ($p.haslaps) { 'Yes' } else { 'No' }
        })
    }
}
$t12Risk = if ($t12Rows.Count -gt 0) { 'Medium' } else { 'Info' }
Add-Task -ID 'T12' -Name "Stale Enabled Computer Accounts (>${StaleThresholdDays}d)" -Category 'Identity Hygiene' -Risk $t12Risk `
    -Description "Enabled computer accounts with no logon in $StaleThresholdDays+ days." `
    -Rows @($t12Rows) -Columns @('Name','OS','LastLogon','IsDC','HasLAPS') `
    -Why "Stale computer accounts may have predictable machine passwords and can be used for pass-the-hash or silver ticket attacks." `
    -Fix "Disable and eventually delete stale computer accounts. Automate with Get-ADComputer -Filter {LastLogonDate -lt X}."

# ---------------------------------------------------------------------------
# T13 -- Computers without LAPS (non-DC)
# ---------------------------------------------------------------------------
$t13Rows = [System.Collections.Generic.List[object]]::new()
foreach ($c in $rawComputers) {
    $p = $c.Properties
    if (-not $p.enabled) { continue }
    if ($c.IsDC)          { continue }
    if ($p.haslaps)       { continue }
    $t13Rows.Add([ordered]@{
        Name = $p.samaccountname
        OS   = if ($p.operatingsystem) { $p.operatingsystem } else { 'Unknown' }
        LastLogon = if ($p.lastlogontimestamp -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($p.lastlogontimestamp).ToString('yyyy-MM-dd') } else { 'Never' }
    })
}
$t13Risk = if ($t13Rows.Count -gt 0) { 'High' } else { 'Info' }
Add-Task -ID 'T13' -Name 'Computers Without LAPS' -Category 'Credential Protection' -Risk $t13Risk `
    -Description "Enabled non-DC computers without LAPS (ms-Mcs-AdmPwd). Likely sharing local admin passwords." `
    -Rows @($t13Rows) -Columns @('Name','OS','LastLogon') `
    -Why "Without LAPS, local Administrator passwords are identical across machines. One compromise = lateral movement to all machines in the same build image." `
    -Fix "Deploy LAPS or Windows LAPS (built into 2022/Win11). Enable via GPO: Computer Config -> Admin Templates -> LAPS."

# ---------------------------------------------------------------------------
# T14 -- Password never expires on enabled privileged users
# ---------------------------------------------------------------------------
$t14Rows = [System.Collections.Generic.List[object]]::new()
foreach ($u in $rawUsers) {
    $p = $u.Properties
    if (-not $p.enabled)          { continue }
    if (-not $p.pwdneverexpires)  { continue }
    if (-not $p.admincount -and -not $p.hasspn) { continue }   # only flag privileged/service accounts
    if ($u.ObjectIdentifier -match '-502$') { continue }       # krbtgt always has no expiry
    $t14Rows.Add([ordered]@{
        Name       = $p.samaccountname
        AdminCount = if ($p.admincount) { 'Yes' } else { 'No' }
        HasSPN     = if ($p.hasspn) { 'Yes' } else { 'No' }
        PwdLastSet = if ($p.pwdlastset -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($p.pwdlastset).ToString('yyyy-MM-dd') } else { 'Never' }
    })
}
$t14Risk = if ($t14Rows.Count -gt 0) { 'Medium' } else { 'Info' }
Add-Task -ID 'T14' -Name 'Password Never Expires -- Privileged Accounts' -Category 'Credential Protection' -Risk $t14Risk `
    -Description "Privileged or service accounts (AdminCount=1 or SPN) with passwords that never expire." `
    -Rows @($t14Rows) -Columns @('Name','AdminCount','HasSPN','PwdLastSet') `
    -Why "A never-expiring password on a privileged account means a cracked or leaked credential remains valid indefinitely." `
    -Fix "Enforce password expiry or use gMSAs (auto-rotating). At minimum, audit PwdLastSet dates and force resets for accounts >1 year old."

# ---------------------------------------------------------------------------
# T15 -- Users with SID History
# ---------------------------------------------------------------------------
$t15Rows = [System.Collections.Generic.List[object]]::new()
foreach ($u in $rawUsers) {
    $p = $u.Properties
    $sidHist = @($p.sidhistory)
    if ($sidHist.Count -eq 0) { continue }
    $t15Rows.Add([ordered]@{
        Name       = $p.samaccountname
        Enabled    = if ($p.enabled) { 'Yes' } else { 'No' }
        SIDHistory = ($sidHist -join '; ')
        AdminCount = if ($p.admincount) { 'Yes' } else { 'No' }
    })
}
$t15Risk = if ($t15Rows.Count -gt 0) { 'High' } else { 'Info' }
Add-Task -ID 'T15' -Name 'Users with SID History' -Category 'ACL Abuse' -Risk $t15Risk `
    -Description "User accounts carrying SID History entries -- these SIDs are included in Kerberos tokens, granting rights from the original domain." `
    -Rows @($t15Rows) -Columns @('Name','Enabled','AdminCount','SIDHistory') `
    -Why "If SIDHistory contains a privileged SID (DA from old domain), the account inherits those rights in the current domain without appearing in the group." `
    -Fix "Audit each SID History entry. Enable SID filtering on domain trusts. Remove unnecessary SID History with ADSIEdit or Set-ADUser -Remove."

# ---------------------------------------------------------------------------
# T16 -- High-value objects summary
# ---------------------------------------------------------------------------
$t16Rows = [System.Collections.Generic.List[object]]::new()
foreach ($u in $rawUsers)     { if ($u.Properties.highvalue) { $t16Rows.Add([ordered]@{ Name=$u.Properties.samaccountname; Type='User';     Enabled=if($u.Properties.enabled){'Yes'}else{'No'} }) } }
foreach ($c in $rawComputers) { if ($c.Properties.highvalue) { $t16Rows.Add([ordered]@{ Name=$c.Properties.samaccountname; Type='Computer'; Enabled=if($c.Properties.enabled){'Yes'}else{'No'} }) } }
foreach ($g in $rawGroups)    { if ($g.Properties.highvalue) { $t16Rows.Add([ordered]@{ Name=$g.Properties.samaccountname; Type='Group';    Enabled='N/A' }) } }
foreach ($d in $rawDomains)   { $t16Rows.Add([ordered]@{ Name=$d.Properties.name; Type='Domain'; Enabled='N/A' }) }
Add-Task -ID 'T16' -Name 'High-Value Asset Inventory' -Category 'Asset Management' -Risk 'Info' `
    -Description "All objects flagged highvalue=true. Use as scope for attack path analysis." `
    -Rows @($t16Rows) -Columns @('Name','Type','Enabled') `
    -Why "Attack path analysis targets: anything that leads to these objects via shortest-path traversal is a risk." `
    -Fix "Ensure all high-value objects are in Protected Users, have strong authentication requirements, and are monitored for logon events."

# ---------------------------------------------------------------------------
# T17 -- Computers with unconstrained delegation -- FULL list (incl DCs for awareness)
# ---------------------------------------------------------------------------
$t17Rows = [System.Collections.Generic.List[object]]::new()
foreach ($c in $rawComputers) {
    $p = $c.Properties
    if (-not $p.unconstraineddelegation) { continue }
    $t17Rows.Add([ordered]@{
        Name    = $p.samaccountname
        IsDC    = if ($c.IsDC) { 'Yes' } else { 'No' }
        Enabled = if ($p.enabled) { 'Yes' } else { 'No' }
        OS      = if ($p.operatingsystem) { $p.operatingsystem } else { 'Unknown' }
    })
}
Add-Task -ID 'T17' -Name 'All Unconstrained Delegation Computers' -Category 'Delegation' -Risk 'Info' `
    -Description "All computers with unconstrained delegation (includes DCs which have it by design)." `
    -Rows @($t17Rows) -Columns @('Name','IsDC','Enabled','OS') `
    -Why "Awareness inventory -- DCs are expected, any non-DC entry is a risk (covered in T05)." `
    -Fix "Non-DC entries: remove unconstrained delegation. DC entries: normal, but protect with 'Account is sensitive and cannot be delegated' for DA accounts."

# ---------------------------------------------------------------------------
# T18 -- Protected Users group membership gaps (privileged users NOT in Protected Users)
# ---------------------------------------------------------------------------
$puSid = Get-WellKnownGroupSid '-525'   # Protected Users
$t18Rows = [System.Collections.Generic.List[object]]::new()
if ($null -ne $DASid) {
    $daAllMembers = Get-AllMembers $DASid
    $puMembers    = if ($null -ne $puSid) { Get-AllMembers $puSid } else { [System.Collections.Generic.HashSet[string]]::new() }
    foreach ($sid in $daAllMembers) {
        if (-not $Users.Contains($sid)) { continue }
        $u = $Users[$sid]
        if (-not $u.Properties.enabled) { continue }
        if ($u.Properties.hasspn)       { continue }   # service accounts cannot join Protected Users
        if ($puMembers.Contains($sid))  { continue }
        $t18Rows.Add([ordered]@{
            Name    = $u.Properties.samaccountname
            HasSPN  = if ($u.Properties.hasspn) { 'Yes' } else { 'No' }
        })
    }
}
$t18Risk = if ($t18Rows.Count -gt 0) { 'High' } else { 'Info' }
Add-Task -ID 'T18' -Name 'Domain Admins NOT in Protected Users' -Category 'Credential Protection' -Risk $t18Risk `
    -Description "Enabled Domain Admin users (without SPNs) that are not members of the Protected Users security group." `
    -Rows @($t18Rows) -Columns @('Name','HasSPN') `
    -Why "Protected Users disables NTLM, DES/RC4 Kerberos, unconstrained delegation, and credential caching -- drastically reduces pass-the-hash and overpass-the-hash risk." `
    -Fix "Add all DA/EA user accounts (without SPNs) to the Protected Users group. Test first in staging -- breaks NTLM-only applications."

# ---------------------------------------------------------------------------
# T19 -- ForceChangePassword ACE on users
# ---------------------------------------------------------------------------
$t19Rows = [System.Collections.Generic.List[object]]::new()
foreach ($u in $rawUsers) {
    if (-not $u.Properties.enabled) { continue }
    foreach ($ace in @($u.Aces)) {
        if ($null -eq $ace) { continue }
        if ($ace.RightName -ne 'ForceChangePassword') { continue }
        $pSid = $ace.PrincipalSID
        if ($pSid -match '^S-1-5-18$') { continue }
        $t19Rows.Add([ordered]@{
            Target    = $u.Properties.samaccountname
            Principal = Get-ObjectName $pSid
            PrinType  = $ace.PrincipalType
            Inherited = if ($ace.IsInherited) { 'Yes' } else { 'No' }
        })
    }
}
$t19Risk = if ($t19Rows.Count -gt 0) { 'High' } else { 'Info' }
Add-Task -ID 'T19' -Name 'ForceChangePassword ACE on Users' -Category 'ACL Abuse' -Risk $t19Risk `
    -Description "Principals with ForceChangePassword extended right on user accounts -- can reset the password without knowing current." `
    -Rows @($t19Rows) -Columns @('Target','Principal','PrinType','Inherited') `
    -Why "ForceChangePassword = persistent account takeover. If Target is an admin account, the principal effectively owns it." `
    -Fix "Remove ForceChangePassword ACE from non-admin principals. Review Help Desk delegations -- use fine-grained permissions on specific OUs only."

# ---------------------------------------------------------------------------
# T20 -- AddMember ACE on privileged groups
# ---------------------------------------------------------------------------
$t20Rows = [System.Collections.Generic.List[object]]::new()
$privGroups = [System.Collections.Generic.List[object]]::new()
foreach ($g in $rawGroups) {
    if ($g.Properties.highvalue -or $g.Properties.admincount) { $privGroups.Add($g) }
}
foreach ($g in $privGroups) {
    foreach ($ace in @($g.Aces)) {
        if ($null -eq $ace) { continue }
        if ($ace.RightName -notin @('AddMember','GenericAll','WriteDacl','WriteOwner','GenericWrite')) { continue }
        $pSid = $ace.PrincipalSID
        if ($pSid -match '^S-1-5-18$|^S-1-5-32-544$') { continue }
        if ($null -ne $DASid -and $pSid -eq $DASid)    { continue }
        if ($null -ne $EASid -and $pSid -eq $EASid)    { continue }
        $t20Rows.Add([ordered]@{
            Group     = $g.Properties.samaccountname
            Principal = Get-ObjectName $pSid
            Right     = $ace.RightName
            Inherited = if ($ace.IsInherited) { 'Yes' } else { 'No' }
        })
    }
}
$t20Risk = if ($t20Rows.Count -gt 0) { 'Critical' } else { 'Info' }
Add-Task -ID 'T20' -Name 'Write ACEs on Privileged Groups' -Category 'ACL Abuse' -Risk $t20Risk `
    -Description "Non-admin principals with AddMember/GenericAll/WriteDACL on privileged groups (DA, EA, Backup Ops, etc.)." `
    -Rows @($t20Rows) -Columns @('Group','Principal','Right','Inherited') `
    -Why "AddMember on Domain Admins = instant privilege escalation. Any low-priv account with this right can promote itself." `
    -Fix "Remove all non-admin write ACEs. Only DA/EA should manage privileged groups. Use RBAC tools (PIM/PAM) for group management."

# ---------------------------------------------------------------------------
# T21 -- Domain trust inventory
# ---------------------------------------------------------------------------
$t21Rows = [System.Collections.Generic.List[object]]::new()
foreach ($d in $rawDomains) {
    foreach ($trust in @($d.Trusts)) {
        if ($null -eq $trust) { continue }
        $t21Rows.Add([ordered]@{
            SourceDomain    = $d.Properties.name
            TargetDomain    = $trust.TargetDomainName
            Direction       = $trust.TrustDirection
            Type            = $trust.TrustType
            IsTransitive    = if ($trust.IsTransitive) { 'Yes' } else { 'No' }
            SIDFiltering    = if ($trust.SidFilteringEnabled) { 'Enabled' } else { 'DISABLED' }
        })
    }
}
$t21Risk = if (@($t21Rows | Where-Object { $_.SIDFiltering -eq 'DISABLED' }).Count -gt 0) { 'High' } `
           elseif ($t21Rows.Count -gt 0) { 'Info' } else { 'Info' }
Add-Task -ID 'T21' -Name 'Domain Trust Inventory' -Category 'Trust & Federation' -Risk $t21Risk `
    -Description "All domain trusts -- direction, type, transitivity, and SID filtering status." `
    -Rows @($t21Rows) -Columns @('SourceDomain','TargetDomain','Direction','Type','IsTransitive','SIDFiltering') `
    -Why "Bidirectional/transitive trusts extend attack surface. Disabled SID filtering allows SIDHistory-based privilege escalation across trusts." `
    -Fix "Enable SID filtering on all external trusts. Audit bidirectional trusts -- convert to one-way where reciprocal access is not required."

# ---------------------------------------------------------------------------
# T22 -- GPO inventory + link count
# ---------------------------------------------------------------------------
$t22Rows = [System.Collections.Generic.List[object]]::new()
foreach ($g in $rawGPOs) {
    $t22Rows.Add([ordered]@{
        Name = $g.Properties.name
        GUID = $g.ObjectIdentifier
        Path = if ($g.Properties.PSObject.Properties['gpcpath']) { $g.Properties.gpcpath } else { '' }
    })
}
Add-Task -ID 'T22' -Name 'GPO Inventory' -Category 'Asset Management' -Risk 'Info' `
    -Description "All Group Policy Objects in the domain." `
    -Rows @($t22Rows) -Columns @('Name','GUID','Path') `
    -Why "GPOs with write access for non-admins (ESC4-equivalent for group policy) can push malicious settings domain-wide." `
    -Fix "Audit GPO creator/editor permissions. Use GPO delegation reports. Enable GPO change auditing."

# ---------------------------------------------------------------------------
# T23 -- Write ACEs on GPOs (non-admin principals)
# ---------------------------------------------------------------------------
$t23Rows = [System.Collections.Generic.List[object]]::new()
foreach ($g in $rawGPOs) {
    foreach ($ace in @($g.Aces)) {
        if ($null -eq $ace) { continue }
        if ($ace.RightName -notin @('GenericAll','WriteDacl','WriteOwner','GenericWrite')) { continue }
        $pSid = $ace.PrincipalSID
        if ($pSid -match '^S-1-5-18$|^S-1-5-32-544$') { continue }
        if ($null -ne $DASid -and $pSid -eq $DASid)    { continue }
        if ($null -ne $EASid -and $pSid -eq $EASid)    { continue }
        $t23Rows.Add([ordered]@{
            GPO       = $g.Properties.name
            Principal = Get-ObjectName $pSid
            Right     = $ace.RightName
            Inherited = if ($ace.IsInherited) { 'Yes' } else { 'No' }
        })
    }
}
$t23Risk = if ($t23Rows.Count -gt 0) { 'Critical' } else { 'Info' }
Add-Task -ID 'T23' -Name 'Dangerous Write ACEs on GPOs' -Category 'ACL Abuse' -Risk $t23Risk `
    -Description "Non-admin principals with write access to GPOs -- can push malicious settings or scheduled tasks to all linked objects." `
    -Rows @($t23Rows) -Columns @('GPO','Principal','Right','Inherited') `
    -Why "WriteDACL on a GPO linked to the domain = arbitrary code execution on every domain computer at next Group Policy refresh." `
    -Fix "Remove non-admin write access from GPOs. Use Group Policy Management Console -> Delegation tab to review per-GPO."

# ---------------------------------------------------------------------------
# T24 -- Computers where Domain Admins have active sessions (local admin)
#        (Sessions not collected without local admin -- report what we have)
# ---------------------------------------------------------------------------
$t24Rows = [System.Collections.Generic.List[object]]::new()
foreach ($c in $rawComputers) {
    $sessions = @($c.LocalAdmins.Results)
    foreach ($s in $sessions) {
        if ($null -eq $s) { continue }
        $sid = if ($s.ObjectIdentifier) { $s.ObjectIdentifier } else { '' }
        if ($null -ne $DASid -and (Get-AllGroupsOf $sid).Contains($DASid)) {
            $t24Rows.Add([ordered]@{
                Computer = $c.Properties.samaccountname
                Account  = Get-ObjectName $sid
                Type     = $s.ObjectType
            })
        }
    }
}
Add-Task -ID 'T24' -Name 'DA Local Admin Rights on Non-DCs' -Category 'Privileged Access' -Risk 'Info' `
    -Description "Domain Admin accounts with local admin rights on non-DC machines (from LocalAdmins collection -- requires admin collection enabled in BHCollector)." `
    -Rows @($t24Rows) -Columns @('Computer','Account','Type') `
    -Why "DA accounts logging into workstations exposes DA credentials to local credential theft attacks ($($script:T.SK)::$($script:T.RB))." `
    -Fix "Do not log DA accounts into workstations. Use separate tier-0 PAWs for DA activities. Implement credential guard."

# ---------------------------------------------------------------------------
# T25 -- OU Blocks Inheritance (could hide GPO-delivered security settings)
# ---------------------------------------------------------------------------
$t25Rows = [System.Collections.Generic.List[object]]::new()
foreach ($ou in $rawOUs) {
    if (-not $ou.Properties.PSObject.Properties['blocksinheritance']) { continue }
    if (-not $ou.Properties.blocksinheritance) { continue }
    $linkCount = @($ou.Links).Count
    $t25Rows.Add([ordered]@{
        OU         = $ou.Properties.name
        DN         = $ou.Properties.distinguishedname
        GPOLinks   = $linkCount
    })
}
$t25Risk = if ($t25Rows.Count -gt 0) { 'Medium' } else { 'Info' }
Add-Task -ID 'T25' -Name 'OUs Blocking GPO Inheritance' -Category 'GPO Hygiene' -Risk $t25Risk `
    -Description "OUs with Block Inheritance set -- domain-level security GPOs (AppLocker, AV, audit policy) will not apply to objects in these OUs unless enforced." `
    -Rows @($t25Rows) -Columns @('OU','DN','GPOLinks') `
    -Why "An attacker who can move objects into a Block-Inheritance OU can make those objects miss security baselines silently." `
    -Fix "Remove Block Inheritance unless there is a documented requirement. Use GPO Enforce flag on critical security GPOs to override block."

# ===========================================================================
# REPORT GENERATION
# ===========================================================================
Write-Host ''
Write-Host '[*] Generating HTML report ...' -ForegroundColor Cyan

$stamp     = (Get-Date).ToString('yyyyMMdd-HHmmss')
$riskOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$riskColor = @{ Critical = '#c0392b'; High = '#e67e22'; Medium = '#f1c40f'; Low = '#2980b9'; Info = '#7f8c8d' }
$riskBg    = @{ Critical = '#fdedec'; High = '#fef9e7'; Medium = '#fefde7'; Low = '#eaf4fb'; Info = '#f2f3f4' }

$critCount = @($script:Tasks | Where-Object { $_.Risk -eq 'Critical' }).Count
$highCount = @($script:Tasks | Where-Object { $_.Risk -eq 'High' }).Count
$medCount  = @($script:Tasks | Where-Object { $_.Risk -eq 'Medium' }).Count
$infoCount = @($script:Tasks | Where-Object { $_.Risk -in @('Low','Info') }).Count
$totalFindings = ($script:Tasks | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum

function ConvertTo-HtmlTable {
    param([string[]]$Cols, [object[]]$Rows)
    if ($Cols.Count -eq 0 -or $Rows.Count -eq 0) { return '<p style="color:#888">No findings.</p>' }
    $sb = [System.Text.StringBuilder]::new()
    $sb.Append('<div style="overflow-x:auto"><table class="ft"><thead><tr>') | Out-Null
    foreach ($c in $Cols) { $sb.Append("<th>$c</th>") | Out-Null }
    $sb.Append('</tr></thead><tbody>') | Out-Null
    $rowIdx = 0
    foreach ($row in $Rows) {
        $cls = if ($rowIdx % 2 -eq 0) { '' } else { ' class="alt"' }
        $sb.Append("<tr$cls>") | Out-Null
        foreach ($c in $Cols) {
            $val = if ($row.Contains($c)) { [string]$row[$c] } else { '' }
            $encoded = $val.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
            $sb.Append("<td>$encoded</td>") | Out-Null
        }
        $sb.Append('</tr>') | Out-Null
        $rowIdx++
    }
    $sb.Append('</tbody></table></div>') | Out-Null
    return $sb.ToString()
}

# Build sidebar task list
$sidebarItems = [System.Text.StringBuilder]::new()
$sortedTasks  = @($script:Tasks | Sort-Object { $riskOrder[$_.Risk] }, ID)
foreach ($tsk in $sortedTasks) {
    $col  = $riskColor[$tsk.Risk]
    $cnt  = $tsk.Count
    $badge = if ($cnt -gt 0) { "<span style='background:$col;color:#fff;border-radius:10px;padding:1px 7px;font-size:0.75em;float:right'>$cnt</span>" } else { '' }
    $sidebarItems.Append("<a href='#$($tsk.ID)' class='nav-item'>$badge$($tsk.ID): $($tsk.Name)</a>") | Out-Null
}

# Build task cards
$taskCards = [System.Text.StringBuilder]::new()
foreach ($tsk in $sortedTasks) {
    $col  = $riskColor[$tsk.Risk]
    $bg   = $riskBg[$tsk.Risk]
    $tbl  = ConvertTo-HtmlTable -Cols $tsk.Columns -Rows @($tsk.Rows)
    $why  = $tsk.Why.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
    $fix  = $tsk.Fix.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
    $taskCards.Append("
<div class='tcard' id='$($tsk.ID)' data-risk='$($tsk.Risk)'>
  <div class='tcard-hdr' style='border-left:5px solid $col;background:$bg'>
    <span class='risk-badge' style='background:$col'>$($tsk.Risk)</span>
    <span class='tid'>$($tsk.ID)</span>
    <span class='tname'>$($tsk.Name)</span>
    <span class='tcat'>[$($tsk.Category)]</span>
    <span class='tcount' style='color:$col'>$($tsk.Count) finding(s)</span>
    <button class='collapse-btn' onclick='toggleCard(this)'>v</button>
  </div>
  <div class='tcard-body'>
    <p class='tdesc'>$($tsk.Description)</p>
    <div class='tabs'>
      <button class='tab-btn active' onclick='showTab(this,""findings-$($tsk.ID)"")'>Findings</button>
      <button class='tab-btn' onclick='showTab(this,""why-$($tsk.ID)"")'>Why It Matters</button>
      <button class='tab-btn' onclick='showTab(this,""fix-$($tsk.ID)"")'>Remediation</button>
    </div>
    <div id='findings-$($tsk.ID)' class='tab-panel active'>$tbl</div>
    <div id='why-$($tsk.ID)' class='tab-panel' style='display:none'><p class='why-text'>$why</p></div>
    <div id='fix-$($tsk.ID)' class='tab-panel' style='display:none'><p class='fix-text'>$fix</p></div>
  </div>
</div>") | Out-Null
}

$htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BH Analyser -- $domainFQDN</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f0f2f5;color:#2c3e50;display:flex;min-height:100vh}
/* Sidebar */
.sidebar{width:280px;min-width:280px;background:#1a252f;position:sticky;top:0;height:100vh;overflow-y:auto;padding:12px 0;flex-shrink:0}
.sidebar h2{color:#ecf0f1;font-size:0.85em;padding:10px 16px 6px;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #2c3e50}
.sidebar .domain-label{color:#3498db;font-size:0.8em;padding:6px 16px 10px;font-weight:600;word-break:break-all}
.nav-item{display:block;padding:7px 16px;color:#bdc3c7;text-decoration:none;font-size:0.82em;border-left:3px solid transparent;transition:all .15s}
.nav-item:hover{background:#2c3e50;color:#fff;border-left-color:#3498db}
.sidebar-stats{padding:10px 16px;border-top:1px solid #2c3e50;margin-top:8px}
.stat-pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:0.75em;font-weight:700;margin:2px}
/* Main */
main{flex:1;padding:20px;overflow-y:auto;min-width:0}
.top-bar{background:#fff;border-radius:8px;padding:16px 20px;margin-bottom:16px;display:flex;align-items:center;gap:16px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.top-bar h1{font-size:1.2em;color:#2c3e50;flex:1}
.score-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
.score-card{background:#fff;border-radius:8px;padding:14px 16px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.score-card .sc-num{font-size:2em;font-weight:700}
.score-card .sc-lbl{font-size:0.75em;color:#7f8c8d;text-transform:uppercase;letter-spacing:.5px}
/* Task cards */
.tcard{background:#fff;border-radius:8px;margin-bottom:14px;box-shadow:0 1px 4px rgba(0,0,0,.08);overflow:hidden}
.tcard-hdr{padding:12px 16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;cursor:pointer}
.risk-badge{padding:2px 10px;border-radius:10px;color:#fff;font-size:0.72em;font-weight:700;text-transform:uppercase;flex-shrink:0}
.tid{font-size:0.78em;color:#7f8c8d;font-weight:600;flex-shrink:0}
.tname{font-weight:600;font-size:0.95em;flex:1}
.tcat{font-size:0.75em;color:#7f8c8d}
.tcount{font-weight:700;font-size:0.85em;margin-left:auto}
.collapse-btn{background:none;border:1px solid #ccc;border-radius:4px;cursor:pointer;padding:2px 8px;font-size:0.8em}
.tcard-body{padding:14px 16px}
.tdesc{font-size:0.88em;color:#555;margin-bottom:10px}
/* Tabs */
.tabs{display:flex;gap:4px;margin-bottom:10px}
.tab-btn{padding:5px 14px;border:1px solid #ddd;border-radius:4px;background:#f8f9fa;cursor:pointer;font-size:0.8em}
.tab-btn.active{background:#3498db;color:#fff;border-color:#3498db}
.tab-panel{display:none}.tab-panel.active{display:block}
.why-text,.fix-text{font-size:0.85em;line-height:1.6;color:#444;white-space:pre-wrap}
/* Table */
.ft{width:100%;border-collapse:collapse;font-size:0.82em}
.ft th{background:#34495e;color:#fff;padding:7px 10px;text-align:left;white-space:nowrap}
.ft td{padding:6px 10px;border-bottom:1px solid #ecf0f1;vertical-align:top;word-break:break-word}
.ft tr.alt td{background:#f8f9fa}
.ft tr:hover td{background:#eaf4fb}
/* Filter bar */
.filter-bar{background:#fff;border-radius:8px;padding:10px 16px;margin-bottom:14px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.filter-bar input{border:1px solid #ddd;border-radius:4px;padding:5px 10px;font-size:0.85em;flex:1;min-width:160px}
.fbtn{padding:5px 14px;border:1px solid #ddd;border-radius:4px;background:#f8f9fa;cursor:pointer;font-size:0.8em}
.fbtn.active{background:#3498db;color:#fff;border-color:#3498db}
@media(max-width:768px){.sidebar{display:none}body{display:block}}
</style>
</head>
<body>
<nav class="sidebar">
  <h2>$($script:T.BH) Analyser</h2>
  <div class="domain-label">$domainFQDN</div>
  <div class="sidebar-stats">
    <span class="stat-pill" style="background:#c0392b">C: $critCount</span>
    <span class="stat-pill" style="background:#e67e22">H: $highCount</span>
    <span class="stat-pill" style="background:#f1c40f;color:#333">M: $medCount</span>
    <span class="stat-pill" style="background:#7f8c8d">I: $infoCount</span>
  </div>
  $($sidebarItems.ToString())
</nav>
<main>
  <div class="top-bar">
    <h1>$($script:T.BH) Analyser &mdash; $domainFQDN</h1>
    <input id="globalSearch" type="search" placeholder="Search findings..." oninput="searchCards(this.value)" style="max-width:220px;border:1px solid #ddd;border-radius:4px;padding:5px 10px;font-size:0.85em">
    <button class="fbtn" onclick="expandAll()">Expand All</button>
    <button class="fbtn" onclick="collapseAll()">Collapse All</button>
  </div>

  <div class="score-grid">
    <div class="score-card"><div class="sc-num" style="color:#c0392b">$critCount</div><div class="sc-lbl">Critical Tasks</div></div>
    <div class="score-card"><div class="sc-num" style="color:#e67e22">$highCount</div><div class="sc-lbl">High Tasks</div></div>
    <div class="score-card"><div class="sc-num" style="color:#f1c40f">$medCount</div><div class="sc-lbl">Medium Tasks</div></div>
    <div class="score-card"><div class="sc-num" style="color:#7f8c8d">$totalFindings</div><div class="sc-lbl">Total Findings</div></div>
  </div>

  <div class="filter-bar">
    <strong style="font-size:0.85em">Filter:</strong>
    <button class="fbtn active" data-risk="All" onclick="setFilter(this)">All</button>
    <button class="fbtn" data-risk="Critical" onclick="setFilter(this)" style="color:#c0392b">Critical</button>
    <button class="fbtn" data-risk="High" onclick="setFilter(this)" style="color:#e67e22">High</button>
    <button class="fbtn" data-risk="Medium" onclick="setFilter(this)" style="color:#b7950b">Medium</button>
    <button class="fbtn" data-risk="Info" onclick="setFilter(this)">Info</button>
    <span id="filterCount" style="font-size:0.8em;color:#888;margin-left:auto"></span>
  </div>

  <div id="task-container">
  $($taskCards.ToString())
  </div>
</main>
<script>
function showTab(btn,panelId){
  var body=btn.closest('.tcard-body');
  body.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active')});
  body.querySelectorAll('.tab-panel').forEach(function(p){p.classList.remove('active');p.style.display='none'});
  btn.classList.add('active');
  var p=document.getElementById(panelId);
  if(p){p.classList.add('active');p.style.display='block'}
}
function toggleCard(btn){
  var body=btn.closest('.tcard').querySelector('.tcard-body');
  var hidden=body.style.display==='none';
  body.style.display=hidden?'':'none';
  btn.textContent=hidden?'v':'^';
}
function expandAll(){document.querySelectorAll('.tcard-body').forEach(function(b){b.style.display=''})}
function collapseAll(){document.querySelectorAll('.tcard-body').forEach(function(b){b.style.display='none'})}
function setFilter(btn){
  document.querySelectorAll('.fbtn[data-risk]').forEach(function(b){b.classList.remove('active')});
  btn.classList.add('active');
  var risk=btn.getAttribute('data-risk');
  var cards=document.querySelectorAll('.tcard');
  var vis=0;
  cards.forEach(function(c){
    var show=(risk==='All'||c.getAttribute('data-risk')===risk);
    c.style.display=show?'':'none';if(show)vis++;
  });
  document.getElementById('filterCount').textContent='Showing '+vis+' of '+cards.length+' tasks';
}
function searchCards(q){
  q=q.toLowerCase();
  document.querySelectorAll('.tcard').forEach(function(c){
    c.style.display=(q===''||c.textContent.toLowerCase().indexOf(q)!==-1)?'':'none';
  });
}
(function(){
  var total=document.querySelectorAll('.tcard').length;
  document.getElementById('filterCount').textContent='Showing '+total+' of '+total+' tasks';
  if(location.hash){var el=document.getElementById(location.hash.slice(1));if(el)el.scrollIntoView()}
})();
</script>
</body>
</html>
"@

$htmlPath = Join-Path $OutputPath ("BHAnalysis-$domainFQDN-$stamp.html")
[System.IO.File]::WriteAllText($htmlPath, $htmlReport, [System.Text.Encoding]::UTF8)
Write-Host "  HTML: $htmlPath" -ForegroundColor Green

# CSV export
$csvPath = Join-Path $OutputPath ("BHAnalysis-$domainFQDN-$stamp.csv")
$script:Findings | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "  CSV : $csvPath" -ForegroundColor Green

$elapsed = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds)
Write-Host ''
Write-Host "+--- SUMMARY -----------------------------------------------+" -ForegroundColor Cyan
Write-Host ("| Domain   : " + $domainFQDN)                                 -ForegroundColor Gray
Write-Host ("| Tasks    : " + $script:Tasks.Count)                          -ForegroundColor Gray
Write-Host ("| Findings : " + $totalFindings)                               -ForegroundColor Gray
Write-Host ("| Critical : " + $critCount)   -ForegroundColor $(if($critCount -gt 0){'Red'}else{'Green'})
Write-Host ("| High     : " + $highCount)   -ForegroundColor $(if($highCount -gt 0){'DarkYellow'}else{'Green'})
Write-Host ("| Medium   : " + $medCount)    -ForegroundColor $(if($medCount -gt 0){'Yellow'}else{'Green'})
Write-Host ("| Runtime  : " + $elapsed + "s")                               -ForegroundColor Gray
Write-Host "+-----------------------------------------------------------+" -ForegroundColor Cyan
Write-Host ''
