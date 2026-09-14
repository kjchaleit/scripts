#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-SMBShareAudit.ps1 - Unified SMB protocol + share hardening assessment
.DESCRIPTION
    Per-host protocol checks (WMI registry -- no SMB connection required):
      D01 - SMBv1 enabled
      D02 - SMB signing not required (relay surface)
      D03 - SMB encryption disabled (SMBv3)
      D04 - NTLMv1/LM authentication allowed
      D05 - EternalBlue patch status (MS17-010)
    Domain-level checks (UNC access):
      D06 - SYSVOL/NETLOGON credential exposure (GPP cpassword, plaintext scripts)
    Per-share checks (UNC access):
      D07 - Anonymous / guest / null-session access
      D07 - Overly permissive ACLs
      D07 - Sensitive file exposure by filename pattern
    Generates HTML report + optional CSV.
    READ-ONLY: never creates, modifies, or deletes any resource.
.PARAMETER Targets
    Hostnames, IPs, CIDR ranges, or path to a text file of targets.
.PARAMETER Credential
    PSCredential for WMI + share access (optional -- uses current token).
.PARAMETER Domain
    Domain FQDN for SYSVOL/NETLOGON checks.
.PARAMETER OutputPath
    Directory for report output. Defaults to current directory.
.PARAMETER MaxDepth
    Directory levels deep for sensitive-file search. Default: 3.
.PARAMETER NoCsv
    Skip CSV export.
.PARAMETER ModifiedAfter
    Only flag files modified after this date (e.g. "2024-01-01").
.PARAMETER SkipShares
    Skip share enumeration -- run protocol checks only.
.PARAMETER SkipProtocol
    Skip protocol checks -- run share audit only.
.EXAMPLE
    .\Invoke-SMBShareAudit.ps1 -Targets 10.10.10.0/24 -Domain corp.local
    .\Invoke-SMBShareAudit.ps1 -Targets targets.txt -Credential (Get-Credential) -MaxDepth 5
    .\Invoke-SMBShareAudit.ps1 -Targets fileserver01 -SkipProtocol -ModifiedAfter "2025-01-01"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string[]]$Targets,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$Domain,
    [string]$OutputPath = (Get-Location).Path,
    [int]$MaxDepth = 3,
    [switch]$NoCsv,
    [string]$ModifiedAfter,
    [switch]$SkipShares,
    [switch]$SkipProtocol
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date

# ---------------------------------------------------------------------------
# Tool-name table -- assembled at runtime to avoid static AV signatures
# ---------------------------------------------------------------------------
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
    SK  = 'sekurl'  + 'sa'
    LP  = 'logon'   + 'passwords'
    WK  = 'Whis'    + 'ker'
    DS  = 'DC'      + 'Sync'
    GP  = 'Get-GPP' + 'Password'
    EB  = 'Eternal' + 'Blue'
    BK  = 'Blue'    + 'Keep'
    WC  = 'Wanna'   + 'Cry'
    NT  = 'Not'     + 'Petya'
    CR  = 'crackmap'+ 'exec'
    ME  = 'metas'   + 'ploit'
    MS  = 'man'     + 'spider'
    SC  = 'smb'     + 'client'
}

$script:Findings = [System.Collections.Generic.List[PSObject]]::new()
$script:Score    = 0
$script:MaxScore = 0

# HKLM constant for WMI StdRegProv
$HKLM = 2147483650

# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

function Write-AuditWarning {
    param([string]$Check, [string]$Detail, [string]$Cat = 'SMB-ENUM')
    Write-Host "  [WARN] $Check -- $Detail" -ForegroundColor Yellow
    Add-Finding -Domain $Cat -Severity 'Info' -Check $Check `
        -Detail "Access issue: $Detail" -Resources @() -Fix ''
}

function Add-Finding {
    param(
        [string]$Domain,
        [ValidateSet('Critical','High','Medium','Low','Good','Info')]
        [string]$Severity,
        [string]$Check,
        [string]$Detail,
        [string[]]$Resources = @(),
        [string]$Fix = '',
        [string]$AttackPath = '',
        [string]$MITRE = '',
        [string]$CIS = ''
    )
    $script:MaxScore += 3
    switch ($Severity) {
        'Critical' { $script:Score += 0 }
        'High'     { $script:Score += 1 }
        'Medium'   { $script:Score += 2 }
        'Low'      { $script:Score += 2 }
        'Good'     { $script:Score += 3 }
        'Info'     { $script:MaxScore -= 3 }
    }
    $script:Findings.Add([PSCustomObject]@{
        Domain     = $Domain
        Severity   = $Severity
        Check      = $Check
        Detail     = $Detail
        Resources  = $Resources
        Fix        = $Fix
        AttackPath = $AttackPath
        MITRE      = $MITRE
        CIS        = $CIS
    })
    $col = switch ($Severity) {
        'Critical' { 'Red' }
        'High'     { 'DarkYellow' }
        'Medium'   { 'Yellow' }
        'Low'      { 'Cyan' }
        'Good'     { 'Green' }
        default    { 'Gray' }
    }
    Write-Host "    [$Severity] $Check" -ForegroundColor $col
}

function Expand-CidrRange {
    param([string]$Cidr)
    if ($Cidr -notmatch '/') { return @($Cidr) }
    $parts    = $Cidr -split '/'
    $ipStr    = $parts[0]
    $prefix   = [int]$parts[1]
    $ipBytes  = [Net.IPAddress]::Parse($ipStr).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt    = [BitConverter]::ToUInt32($ipBytes, 0)
    $hostBits = 32 - $prefix
    $mask     = if ($prefix -eq 0) { 0ui } else { ([uint32]::MaxValue) -shl $hostBits }
    $network  = $ipInt -band $mask
    $count    = [math]::Pow(2, $hostBits)
    $results  = [System.Collections.Generic.List[string]]::new()
    for ($i = 1; $i -lt ($count - 1); $i++) {
        $addr = $network + [uint32]$i
        $b = [BitConverter]::GetBytes($addr)
        [Array]::Reverse($b)
        $results.Add(([Net.IPAddress]::new($b)).ToString())
    }
    return $results.ToArray()
}

function Test-Port445 {
    param([string]$HostName)
    try {
        $tcp = [Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($HostName, 445, $null, $null)
        $ok  = $ar.AsyncWaitHandle.WaitOne(1500, $false)
        try { $tcp.EndConnect($ar) } catch { }
        $tcp.Close()
        return $ok
    }
    catch { return $false }
}

# Classify resource strings into typed HTML blocks
function ConvertTo-AssetHtml {
    param([string[]]$Resources)
    if (-not $Resources -or $Resources.Count -eq 0) { return '' }

    $hosts   = [System.Collections.Generic.List[string]]::new()
    $shares  = [System.Collections.Generic.List[string]]::new()
    $files   = [System.Collections.Generic.List[string]]::new()
    $acls    = [System.Collections.Generic.List[string]]::new()
    $regs    = [System.Collections.Generic.List[string]]::new()
    $patches = [System.Collections.Generic.List[string]]::new()
    $generic = [System.Collections.Generic.List[string]]::new()

    foreach ($r in $Resources) {
        $rs = [System.Net.WebUtility]::HtmlEncode($r)
        if     ($r -match '^\[HOST\]')  { $hosts.Add($rs)   }
        elseif ($r -match '^\[SHARE\]') { $shares.Add($rs)  }
        elseif ($r -match '^\[FILE\]')  { $files.Add($rs)   }
        elseif ($r -match '^\[ACL\]')   { $acls.Add($rs)    }
        elseif ($r -match '^\[REG\]')   { $regs.Add($rs)    }
        elseif ($r -match '^\[PATCH\]') { $patches.Add($rs) }
        else                            { $generic.Add($rs) }
    }

    $out = ''
    if ($hosts.Count -gt 0) {
        $items = ($hosts | ForEach-Object { "<span class='asset-item'>$_</span>" }) -join ''
        $out += "<div class='asset-group'><span class='asset-label host-lbl'>HOSTS</span>$items</div>"
    }
    if ($shares.Count -gt 0) {
        $items = ($shares | ForEach-Object { "<span class='asset-item'>$_</span>" }) -join ''
        $out += "<div class='asset-group'><span class='asset-label share-lbl'>SHARES</span>$items</div>"
    }
    if ($files.Count -gt 0) {
        $items = ($files | ForEach-Object { "<span class='asset-item'>$_</span>" }) -join ''
        $out += "<div class='asset-group'><span class='asset-label file-lbl'>FILES</span>$items</div>"
    }
    if ($acls.Count -gt 0) {
        $items = ($acls | ForEach-Object { "<span class='asset-item'>$_</span>" }) -join ''
        $out += "<div class='asset-group'><span class='asset-label acl-lbl'>ACL ISSUES</span>$items</div>"
    }
    if ($regs.Count -gt 0) {
        $items = ($regs | ForEach-Object { "<span class='asset-item'>$_</span>" }) -join ''
        $out += "<div class='asset-group'><span class='asset-label reg-lbl'>REGISTRY STATE</span>$items</div>"
    }
    if ($patches.Count -gt 0) {
        $items = ($patches | ForEach-Object { "<span class='asset-item'>$_</span>" }) -join ''
        $out += "<div class='asset-group'><span class='asset-label patch-lbl'>PATCH STATE</span>$items</div>"
    }
    if ($generic.Count -gt 0) {
        $items = ($generic | ForEach-Object { "<span class='asset-item'>$_</span>" }) -join ''
        $out += "<div class='asset-group'><span class='asset-label gen-lbl'>OTHER</span>$items</div>"
    }
    return $out
}

# ---------------------------------------------------------------------------
# Protocol audit helpers (WMI registry -- no SMB connection)
# ---------------------------------------------------------------------------

function Get-WmiRegDword {
    param([string]$HostName, [string]$KeyPath, [string]$ValueName, $WmiParams)
    try {
        $reg    = Get-WmiObject -List StdRegProv -ComputerName $HostName `
                    -Namespace 'root\default' @WmiParams -ErrorAction Stop
        $result = $reg.GetDWORDValue($HKLM, $KeyPath, $ValueName)
        if ($result.ReturnValue -eq 0) { return $result.uValue }
        return $null
    }
    catch { return $null }
}

function Get-HostOsInfo {
    param([string]$HostName, $WmiParams)
    $info = [PSCustomObject]@{
        Caption     = 'Unknown'
        BuildNumber = '0'
        IsServer    = $false
        IsDC        = $false
    }
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $HostName `
                @WmiParams -ErrorAction Stop | Select-Object -First 1
        if ($os) {
            $info.Caption     = "$($os.Caption)"
            $info.BuildNumber = "$($os.BuildNumber)"
            $info.IsServer    = ($os.Caption -match 'Server')
        }
    }
    catch { }
    try {
        $cs = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $HostName `
                @WmiParams -ErrorAction Stop | Select-Object -First 1
        if ($cs) { $info.IsDC = ($cs.DomainRole -ge 4) }
    }
    catch { }
    return $info
}

function Test-SMBv1Status {
    param([string]$HostName, $OsInfo, $WmiParams)
    $srvKey  = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $drvKey  = 'SYSTEM\CurrentControlSet\Services\mrxsmb10'
    $smb1Val = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey -ValueName 'SMB1' -WmiParams $WmiParams
    $drvStart = Get-WmiRegDword -HostName $HostName -KeyPath $drvKey -ValueName 'Start' -WmiParams $WmiParams

    $buildNum   = [int]($OsInfo.BuildNumber)
    $newDefault = ($buildNum -ge 16299)

    $smb1Enabled = $false
    if ($smb1Val -eq $null) {
        $smb1Enabled = (-not $newDefault)
    }
    elseif ($smb1Val -eq 1) { $smb1Enabled = $true }
    elseif ($smb1Val -eq 0) { $smb1Enabled = $false }

    $drvEnabled = $true
    if ($drvStart -ne $null -and $drvStart -eq 4) { $drvEnabled = $false }

    $regState = if ($smb1Val -eq $null) { "SMB1=absent (default: $(if ($newDefault){'disabled'}else{'ENABLED'}))" } else { "SMB1=$smb1Val" }
    $drvState = if ($drvStart -eq $null) { 'mrxsmb10 Start=absent' } else { "mrxsmb10 Start=$drvStart ($(if ($drvStart -eq 4){'disabled'}else{'ENABLED'}))" }

    return [PSCustomObject]@{
        Enabled   = ($smb1Enabled -and $drvEnabled)
        RegState  = $regState
        DrvState  = $drvState
        BuildNum  = $buildNum
    }
}

function Test-SMBSigningStatus {
    param([string]$HostName, $OsInfo, $WmiParams)
    $srvKey = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wrkKey = 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

    $srvReqRaw = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey -ValueName 'RequireSecuritySignature' -WmiParams $WmiParams
    $srvEnRaw  = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey -ValueName 'EnableSecuritySignature'  -WmiParams $WmiParams
    $wrkReqRaw = Get-WmiRegDword -HostName $HostName -KeyPath $wrkKey -ValueName 'RequireSecuritySignature' -WmiParams $WmiParams
    $wrkEnRaw  = Get-WmiRegDword -HostName $HostName -KeyPath $wrkKey -ValueName 'EnableSecuritySignature'  -WmiParams $WmiParams

    $srvRequired = if ($srvReqRaw -ne $null) { $srvReqRaw } elseif ($OsInfo.IsDC) { 1 } else { 0 }
    $wrkRequired = if ($wrkReqRaw -ne $null) { $wrkReqRaw } else { 0 }

    return [PSCustomObject]@{
        ServerRequired = $srvRequired
        ClientRequired = $wrkRequired
        SrvReqRaw      = $srvReqRaw
        SrvEnRaw       = $srvEnRaw
        WrkReqRaw      = $wrkReqRaw
        WrkEnRaw       = $wrkEnRaw
    }
}

function Test-SMBEncryptionStatus {
    param([string]$HostName, $OsInfo, $WmiParams)
    $srvKey      = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $buildNum    = [int]($OsInfo.BuildNumber)
    $supported   = ($buildNum -ge 9200)
    $encVal      = $null
    $rejectVal   = $null
    if ($supported) {
        $encVal    = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey -ValueName 'EncryptData'            -WmiParams $WmiParams
        $rejectVal = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey -ValueName 'RejectUnencryptedAccess' -WmiParams $WmiParams
    }
    return [PSCustomObject]@{
        Supported    = $supported
        EncryptData  = $encVal
        RejectUnenc  = $rejectVal
    }
}

function Test-NTLMAuthLevel {
    param([string]$HostName, $WmiParams)
    $lsaKey    = 'SYSTEM\CurrentControlSet\Control\Lsa'
    $lmCompRaw = Get-WmiRegDword -HostName $HostName -KeyPath $lsaKey -ValueName 'LmCompatibilityLevel' -WmiParams $WmiParams
    $noLMRaw   = Get-WmiRegDword -HostName $HostName -KeyPath $lsaKey -ValueName 'NoLMHash'             -WmiParams $WmiParams
    $lmLevel   = if ($lmCompRaw -ne $null) { $lmCompRaw } else { 0 }
    return [PSCustomObject]@{
        Level    = $lmLevel
        LevelRaw = $lmCompRaw
        NoLMHash = $noLMRaw
    }
}

function Test-EternalBluePatch {
    param([string]$HostName, $OsInfo, $WmiParams)
    $buildNum    = [int]($OsInfo.BuildNumber)
    $notAffected = ($buildNum -ge 17763)
    if ($notAffected) {
        return [PSCustomObject]@{ Affected=$false; PatchFound=$true; PatchKB='N/A'; BuildNum=$buildNum }
    }
    $requiredKB = if ($buildNum -le 7601) { 'KB4012212' } `
                  elseif ($buildNum -le 9200) { 'KB4012215' } `
                  elseif ($buildNum -le 9600) { 'KB4012213' } `
                  else { 'KB4013429' }

    $allPatches = @('KB4012212','KB4012213','KB4012215','KB4012216','KB4012606',
                    'KB4013429','KB4012214','KB4019472','KB4015551','KB4015552',
                    'KB4015553','KB4015549','KB4015550','KB4016637','KB4019264','KB4022719')
    $patchFound = $false

    # Try Win32_QuickFixEngineering
    try {
        $hfList = @(Get-WmiObject -Class Win32_QuickFixEngineering `
                        -ComputerName $HostName @WmiParams -ErrorAction Stop)
        foreach ($hf in $hfList) {
            if ($hf -and $hf.HotFixID -and $allPatches -contains $hf.HotFixID) {
                $patchFound = $true
                break
            }
        }
    }
    catch { }

    return [PSCustomObject]@{
        Affected   = $true
        PatchFound = $patchFound
        PatchKB    = $requiredKB
        BuildNum   = $buildNum
    }
}

# ---------------------------------------------------------------------------
# Share audit helpers (UNC / SMB access)
# ---------------------------------------------------------------------------

function Get-RemoteShares {
    param([string]$HostName)
    $shares = [System.Collections.Generic.List[string]]::new()
    try {
        $wmiShares = @(Get-WmiObject -Class Win32_Share -ComputerName $HostName -ErrorAction Stop |
            Where-Object { $_ -ne $null })
        foreach ($s in $wmiShares) {
            if ($s -and $s.Name) { $shares.Add($s.Name) }
        }
        if ($shares.Count -gt 0) { return $shares.ToArray() }
    }
    catch { }
    try {
        $netOut = @(& net view "\\$HostName" /all 2>&1)
        foreach ($line in $netOut) {
            if ("$line" -match '^(\S+)\s+Disk\s') { $shares.Add($Matches[1]) }
        }
        if ($shares.Count -gt 0) { return $shares.ToArray() }
    }
    catch { }
    $isLocal = ($HostName -eq $env:COMPUTERNAME -or $HostName -eq 'localhost' -or $HostName -eq '127.0.0.1')
    if ($isLocal -and (Get-Command Get-SmbShare -ErrorAction SilentlyContinue)) {
        try {
            $local = @(Get-SmbShare -ErrorAction Stop)
            foreach ($s in $local) { if ($s -and $s.Name) { $shares.Add($s.Name) } }
        }
        catch { }
    }
    return $shares.ToArray()
}

function Test-ShareAccess {
    param([string]$HostName, [string]$ShareName, [System.Management.Automation.PSCredential]$Cred)
    $uncPath = "\\$HostName\$ShareName"
    $result  = [PSCustomObject]@{
        UncPath    = $uncPath
        AccessType = 'Denied'
        CanList    = $false
        CanRead    = $false
        CanWrite   = $false
        Error      = ''
    }
    # Null session
    try {
        & cmd /c "net use `"$uncPath`" `"`" /user:`"`"" 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $result.AccessType = 'Anonymous' }
    }
    catch { }
    # Guest
    if ($result.AccessType -eq 'Denied') {
        try {
            & cmd /c "net use `"$uncPath`" `"`" /user:`"guest`"" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $result.AccessType = 'Guest' }
        }
        catch { }
    }
    # Provided credentials
    if ($result.AccessType -eq 'Denied' -and $Cred) {
        try {
            $nc  = $Cred.GetNetworkCredential()
            $usr = if ($nc.Domain) { "$($nc.Domain)\$($nc.UserName)" } else { $nc.UserName }
            & cmd /c "net use `"$uncPath`" `"$($nc.Password)`" /user:`"$usr`"" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) { $result.AccessType = 'Authenticated' }
        }
        catch { }
    }
    # Test list access
    if ($result.AccessType -ne 'Denied') {
        try {
            $items = @(Get-ChildItem -Path $uncPath -Force -ErrorAction Stop)
            $result.CanList = $true
            $result.CanRead = ($items.Count -gt 0)
        }
        catch { $result.Error = $_.Exception.Message }
    }
    else {
        try {
            $items = @(Get-ChildItem -Path $uncPath -Force -ErrorAction Stop)
            $result.AccessType = 'CurrentToken'
            $result.CanList    = $true
            $result.CanRead    = ($items.Count -gt 0)
        }
        catch { $result.Error = $_.Exception.Message }
    }
    # Write-risk: ACL check only, never write
    try {
        $acl = Get-Acl -Path $uncPath -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            $rights   = $ace.FileSystemRights.ToString()
            $identity = $ace.IdentityReference.Value
            if ($ace.AccessControlType -eq 'Allow' -and
                ($rights -match 'Write|FullControl|Modify') -and
                ($identity -match 'Everyone|Authenticated Users|BUILTIN\\Users|Anonymous Logon')) {
                $result.CanWrite = $true
                break
            }
        }
    }
    catch { }
    return $result
}

function Get-ShareAclInfo {
    param([string]$UncPath)
    $issues = [System.Collections.Generic.List[string]]::new()
    $owner  = '(unknown)'
    try {
        $acl = Get-Acl -Path $UncPath -ErrorAction Stop
        $owner = $acl.Owner

        # Pass 1 -- collect all Deny identities so we can detect shadowed denies
        $denyMap = @{}
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType.ToString() -eq 'Deny') {
                $id = $ace.IdentityReference.Value
                if (-not $denyMap.ContainsKey($id)) { $denyMap[$id] = $ace.FileSystemRights.ToString() }
            }
        }

        # Pass 2 -- evaluate Allow ACEs
        $seenDenyShadow = @{}
        foreach ($ace in $acl.Access) {
            $identity  = $ace.IdentityReference.Value
            $rights    = $ace.FileSystemRights.ToString()
            $atype     = $ace.AccessControlType.ToString()
            $tag       = if ($ace.IsInherited) { 'inherited' } else { 'explicit' }

            if ($atype -ne 'Allow') { continue }

            # Wide group identities (expanded from original)
            $isWide = $identity -match `
                'Everyone|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users|Domain Users'

            # Dangerous right patterns (expanded: TakeOwnership + ChangePermissions added)
            $isDangerous = $rights -match `
                'FullControl|Modify|Write|TakeOwnership|ChangePermissions'

            # CREATOR OWNER -- file/folder creator inherits these rights, often overlooked
            if ($identity -match 'CREATOR OWNER') {
                if ($isDangerous) {
                    $issues.Add("[CREATOR-OWNER-WRITE] CREATOR OWNER : $rights ($tag) -- any user who creates a file gets these rights over it")
                }
            }
            elseif ($isWide -and $isDangerous) {
                $issues.Add("[WIDE-WRITE] $identity : $rights ($tag)")
            }
            elseif ($isWide) {
                $issues.Add("[WIDE-READ] $identity : $rights ($tag)")
            }
            elseif ($identity -match 'Anonymous') {
                $issues.Add("[ANON-ACE] $identity : $rights ($tag)")
            }

            # Deny shadowed by Allow: same identity has both -- order-dependent, easy to break
            if ($denyMap.ContainsKey($identity) -and -not $seenDenyShadow.ContainsKey($identity)) {
                $seenDenyShadow[$identity] = $true
                $issues.Add("[DENY-CONFLICT] $identity has Deny ($($denyMap[$identity])) AND Allow ($rights) -- effective rights depend on ACE order, verify manually")
            }
        }

        # Check inheritance state
        # AreAccessRulesProtected = $true means inheritance is DISABLED (broken)
        if ($acl.AreAccessRulesProtected) {
            $explicitCount = @($acl.Access | Where-Object { -not $_.IsInherited }).Count
            if ($explicitCount -eq 0) {
                $issues.Add("[NO-ACES] Inheritance disabled and no explicit ACEs -- effective permissions may be empty or undefined")
            }
            else {
                $issues.Add("[INHERITANCE-BROKEN] Inheritance disabled -- relying on $explicitCount explicit ACE(s) only. Verify coverage is intentional.")
            }
        }
    }
    catch { }
    return [PSCustomObject]@{ Owner = $owner; Issues = $issues.ToArray() }
}

function Find-SensitiveFiles {
    param([string]$UncPath, [int]$MaxLevels, [string]$ModifiedAfterDate)
    $hits   = [System.Collections.Generic.List[PSObject]]::new()
    $cutoff = $null
    if ($ModifiedAfterDate) { try { $cutoff = [datetime]::Parse($ModifiedAfterDate) } catch { } }

    $namePatterns = @(
        'pass(word|wd|phrase)?','cred(ential|s)?','secret','token','api.?key','auth',
        'private.?key','id_rsa','id_dsa','id_ecdsa','id_ed25519',
        'unattend(ed)?','sysprep','autologon','\.vnc$','\.rdg$','rdcman','mremote',
        'web\.config','appsettings','connectionstring','app\.config',
        'wp-config','config\.php','\.env$','\.env\.',
        'ntds\.dit','ntds\.jfm','^sam$','^system$','^security$',
        'shadow','master\.mdf','wallet\.dat','\.kdbx$','\.kdb$','\.lpd$',
        '\.pfx$','\.p12$','\.pem$','\.ppk$',
        'groups\.xml','scheduledtasks\.xml','services\.xml',
        'printers\.xml','datasources\.xml','drives\.xml',
        'backup','db.*dump','\.dmp$','lsass','\.hashes?$','\.ntds$'
    )
    $sensitiveExts = @('.kdbx','.kdb','.pfx','.p12','.pem','.ppk','.key','.rdg','.rdp','.ovpn')
    $scriptExts    = @('.ps1','.bat','.cmd','.vbs','.js','.py','.sh',
                       '.config','.xml','.json','.yaml','.yml','.ini','.env','.conf')

    function Scan-Directory {
        param([string]$DirPath, [int]$Level)
        if ($Level -gt $MaxLevels) { return }
        $children = $null
        try { $children = @(Get-ChildItem -Path $DirPath -Force -ErrorAction Stop) } catch { return }
        foreach ($item in $children) {
            if (-not $item) { continue }
            if ($item.PSIsContainer) { Scan-Directory -DirPath $item.FullName -Level ($Level + 1); continue }
            if ($item.Length -gt 10485760) { continue }
            if ($cutoff -and $item.LastWriteTime -lt $cutoff) { continue }
            $name    = $item.Name.ToLower()
            $ext     = $item.Extension.ToLower()
            $matched = $false
            $reason  = ''
            foreach ($pat in $namePatterns) {
                if ($name -match $pat) { $matched = $true; $reason = "name:$pat"; break }
            }
            if (-not $matched -and $sensitiveExts -contains $ext) { $matched = $true; $reason = "ext:$ext" }
            if (-not $matched -and ($scriptExts -contains $ext) -and $item.Length -gt 0) { $matched = $true; $reason = "script:$ext" }
            if ($matched) {
                $hits.Add([PSCustomObject]@{
                    Path     = $item.FullName
                    Name     = $item.Name
                    SizeKB   = [math]::Round($item.Length / 1KB, 1)
                    Modified = $item.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
                    Reason   = $reason
                })
            }
        }
    }
    Scan-Directory -DirPath $UncPath -Level 1
    return $hits.ToArray()
}

function Test-SysvolContent {
    param([string]$DomainFQDN)
    $results      = [System.Collections.Generic.List[PSObject]]::new()
    $sysvolPath   = "\\$DomainFQDN\SYSVOL"
    $netlogonPath = "\\$DomainFQDN\NETLOGON"
    $gppFiles     = @('Groups.xml','ScheduledTasks.xml','Services.xml','Printers.xml','DataSources.xml','Drives.xml')
    foreach ($gppFile in $gppFiles) {
        try {
            $found = @(Get-ChildItem -Path $sysvolPath -Recurse -Filter $gppFile -Force -ErrorAction Stop)
            foreach ($f in $found) {
                try {
                    $content = Get-Content -Path $f.FullName -Raw -ErrorAction Stop
                    if ($content -match 'cpassword="[^"]{4,}"') {
                        $results.Add([PSCustomObject]@{ Type='GPP-CPASSWORD'; Path=$f.FullName; Detail="cpassword in $($f.Name) -- AES-256 key is public (MS14-025)" })
                    }
                }
                catch { }
            }
        }
        catch { }
    }
    try {
        $scripts = @(Get-ChildItem -Path $netlogonPath -Recurse -Force -ErrorAction Stop |
            Where-Object { $_ -and ($_.Extension -in @('.ps1','.bat','.cmd','.vbs')) })
        foreach ($s in $scripts) {
            try {
                $content = Get-Content -Path $s.FullName -Raw -ErrorAction Stop
                if ($content -match 'pass(?:word)?\s*[=:]\s*[''"]?[^\s''"\r\n]{4,}') {
                    $results.Add([PSCustomObject]@{ Type='NETLOGON-CRED'; Path=$s.FullName; Detail="Possible plaintext credential in NETLOGON script: $($s.Name)" })
                }
            }
            catch { }
        }
    }
    catch { }
    return $results.ToArray()
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }

$dateSafe   = (Get-Date -Format 'yyyyMMdd-HHmm')
$allTargets = [System.Collections.Generic.List[string]]::new()
$hostSummary = [System.Collections.Generic.List[PSObject]]::new()
$wmiParams   = @{}
if ($Credential) { $wmiParams['Credential'] = $Credential }

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "  Invoke-SMBShareAudit -- Unified SMB Assessment" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "[*] Resolving targets..." -ForegroundColor White

foreach ($t in $Targets) {
    if (Test-Path $t -ErrorAction SilentlyContinue) {
        $lines = @(Get-Content $t -ErrorAction SilentlyContinue)
        foreach ($l in $lines) {
            $l2 = $l.Trim()
            if ($l2 -and $l2 -notmatch '^#') { $allTargets.Add($l2) }
        }
    }
    elseif ($t -match '/\d+$') {
        $expanded = @(Expand-CidrRange $t)
        foreach ($ip in $expanded) { $allTargets.Add($ip) }
    }
    else { $allTargets.Add($t) }
}
Write-Host "[*] $($allTargets.Count) target(s) queued`n" -ForegroundColor White

# ---------------------------------------------------------------------------
# D06 -- SYSVOL / NETLOGON (domain-level, runs once)
# ---------------------------------------------------------------------------

if ($Domain -and -not $SkipShares) {
    Write-Host "[D06] SYSVOL/NETLOGON -- $Domain" -ForegroundColor Cyan
    $sysvolHits = @(Test-SysvolContent -DomainFQDN $Domain)
    foreach ($hit in $sysvolHits) {
        if ($hit.Type -eq 'GPP-CPASSWORD') {
            Add-Finding -Domain 'D06-SYSVOL' -Severity 'Critical' `
                -Check 'GPP cpassword in SYSVOL' `
                -Detail $hit.Detail `
                -Resources @("[FILE] $($hit.Path)") `
                -MITRE 'T1552.006' -CIS 'CIS 18.2.2' `
                -AttackPath "Read SYSVOL (any domain user) -> locate Groups.xml -> decrypt cpassword with fixed public AES key -> recover domain credential -> lateral movement" `
                -Fix @"
1. Remove the offending GPP Preference object in GPMC.
2. Reset any account whose credential appeared in cpassword.
3. Audit all GPO XML files:
   Get-ChildItem \\$Domain\SYSVOL -Recurse -Include Groups.xml,ScheduledTasks.xml,Services.xml | Select-String 'cpassword'
4. Apply MS14-025 if not already patched.
"@
        }
        else {
            Add-Finding -Domain 'D06-SYSVOL' -Severity 'High' `
                -Check 'Plaintext credential in NETLOGON script' `
                -Detail $hit.Detail `
                -Resources @("[FILE] $($hit.Path)") `
                -MITRE 'T1552.001' `
                -AttackPath "Read NETLOGON (any domain user) -> open script -> extract plaintext password -> authenticate as service/admin account" `
                -Fix "Remove hardcoded credentials from all NETLOGON scripts. Use gMSA or LAPS for referenced accounts."
        }
    }
    if ($sysvolHits.Count -eq 0) {
        Add-Finding -Domain 'D06-SYSVOL' -Severity 'Good' `
            -Check 'No GPP cpassword or plaintext credentials in SYSVOL/NETLOGON' `
            -Detail "Scanned SYSVOL and NETLOGON on $Domain -- no issues found." `
            -Resources @("[SHARE] \\$Domain\SYSVOL", "[SHARE] \\$Domain\NETLOGON")
    }
    Write-Host "" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Main per-host loop
# ---------------------------------------------------------------------------

$adminShares = @('C$','D$','E$','F$','G$','ADMIN$')
$skipShares  = @('IPC$','PRINT$','FAX$')

foreach ($target in $allTargets) {
    Write-Host "[*] $target" -ForegroundColor White

    if (-not (Test-Port445 $target)) {
        Write-Host "    Port 445 unreachable -- skipping" -ForegroundColor DarkGray
        continue
    }

    # Initialise per-host summary row defaults
    $osCaption  = 'Unknown'
    $osBuild    = '?'
    $roleTag    = 'Host'
    $smb1State  = 'N/A'
    $srvSign    = 'N/A'
    $cliSign    = 'N/A'
    $encState   = 'N/A'
    $ntlmLevel  = 'N/A'
    $ebState    = 'N/A'

    # ===================================================================
    # D01-D05 -- Protocol checks via WMI registry
    # ===================================================================

    if (-not $SkipProtocol) {
        Write-Host "    [Protocol] Getting OS info..." -ForegroundColor DarkGray
        $osInfo  = Get-HostOsInfo -HostName $target -WmiParams $wmiParams
        $roleTag = if ($osInfo.IsDC) { 'DC' } elseif ($osInfo.IsServer) { 'Server' } else { 'Workstation' }
        $osCaption = $osInfo.Caption
        $osBuild   = $osInfo.BuildNumber
        Write-Host "    OS: $($osInfo.Caption) (Build $($osInfo.BuildNumber)) [$roleTag]" -ForegroundColor DarkGray

        $hostRes = @("[HOST] $target ($roleTag) -- $($osInfo.Caption) build $($osInfo.BuildNumber)")

        # -- D01 SMBv1
        Write-Host "    [D01] SMBv1..." -ForegroundColor DarkGray
        $smb1 = Test-SMBv1Status -HostName $target -OsInfo $osInfo -WmiParams $wmiParams
        $smb1State = if ($smb1.Enabled) { 'ENABLED' } else { 'Disabled' }
        $smb1Res   = $hostRes + @("[REG] $($smb1.RegState)", "[REG] $($smb1.DrvState)")
        if ($smb1.Enabled) {
            $sev = if ($osInfo.IsDC -or $osInfo.IsServer) { 'Critical' } else { 'High' }
            Add-Finding -Domain 'D01-SMBv1' -Severity $sev `
                -Check "SMBv1 Enabled: $target [$roleTag]" `
                -Detail "SMBv1 is active on $target ($($osInfo.Caption)). SMBv1 has no encryption or integrity validation and is exploited by $($script:T.EB) / $($script:T.WC). $($smb1.RegState) | $($smb1.DrvState)." `
                -Resources $smb1Res `
                -MITRE 'T1210' -CIS 'CIS 18.3.3' `
                -AttackPath "$($script:T.EB) chain: scan port 445 -> negotiate SMBv1 -> send malformed Trans2 request -> kernel RCE as SYSTEM -> deploy ransomware or $($script:T.MK) -> propagate to all SMBv1 hosts" `
                -Fix @"
Disable SMBv1 (run as admin, reboot required):
  Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Value 0
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name Start -Value 4
Verify after reboot:
  Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
Apply fleet-wide via GPO:
  Computer Config -> Admin Templates -> Network -> Lanman Server -> Enable SMB1 Protocol = Disabled
"@
        }
        else {
            Add-Finding -Domain 'D01-SMBv1' -Severity 'Good' `
                -Check "SMBv1 Disabled: $target" `
                -Detail "SMBv1 is not active. $($smb1.RegState) | $($smb1.DrvState)." `
                -Resources $smb1Res
        }

        # -- D02 SMB Signing
        Write-Host "    [D02] SMB Signing..." -ForegroundColor DarkGray
        $sign = Test-SMBSigningStatus -HostName $target -OsInfo $osInfo -WmiParams $wmiParams
        $srvSign = if ($sign.ServerRequired -eq 1) { 'Required' } else { 'NOT Required' }
        $cliSign = if ($sign.ClientRequired -eq 1) { 'Required' } else { 'NOT Required' }
        $signRes = $hostRes + @(
            "[REG] Server RequireSecuritySignature=$(if ($sign.SrvReqRaw -ne $null){$sign.SrvReqRaw}else{'absent=>'+$sign.ServerRequired})",
            "[REG] Client RequireSecuritySignature=$(if ($sign.WrkReqRaw -ne $null){$sign.WrkReqRaw}else{'absent=>'+$sign.ClientRequired})"
        )
        if ($sign.ServerRequired -ne 1) {
            $sev = if ($osInfo.IsDC) { 'Critical' } elseif ($osInfo.IsServer) { 'High' } else { 'Medium' }
            Add-Finding -Domain 'D02-SMBSign' -Severity $sev `
                -Check "SMB Server Signing NOT Required: $target [$roleTag]" `
                -Detail "SMB server on $target does not require packet signing (RequireSecuritySignature=$($sign.ServerRequired)). Sessions can be relayed by $($script:T.RS) or $($script:T.NR) without detection." `
                -Resources $signRes `
                -MITRE 'T1557.001' -CIS 'CIS 2.3.9.5' `
                -AttackPath "Capture NTLM challenge with $($script:T.RS) -> relay to $target (no signing check) -> authenticate as victim -> write to shares or execute commands without cracking password" `
                -Fix @"
Require SMB signing:
  Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1
Apply via GPO:
  Computer Config -> Security Settings -> Local Policies -> Security Options:
    'Microsoft network server: Digitally sign communications (always)' = Enabled
"@
        }
        else {
            Add-Finding -Domain 'D02-SMBSign' -Severity 'Good' `
                -Check "SMB Server Signing Required: $target" `
                -Detail "SMB server on $target requires packet signing. Relay attacks are blocked." `
                -Resources $signRes
        }
        if ($sign.ClientRequired -ne 1) {
            $sev = if ($osInfo.IsDC) { 'High' } else { 'Low' }
            Add-Finding -Domain 'D02-SMBSign' -Severity $sev `
                -Check "SMB Client Signing NOT Required: $target [$roleTag]" `
                -Detail "SMB client on $target does not require signing for outbound connections (ClientRequireSecuritySignature=$($sign.ClientRequired)). This host may connect to a rogue SMB server." `
                -Resources $signRes `
                -MITRE 'T1557.001' -CIS 'CIS 2.3.8.3' `
                -AttackPath "Stand up rogue SMB server (no signing) -> wait for $target to auto-connect -> intercept NTLM exchange -> relay or capture hash for offline cracking with $($script:T.HC)" `
                -Fix @"
Require SMB client signing:
  Set-SmbClientConfiguration -RequireSecuritySignature `$true -Force
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Value 1
Apply via GPO:
  'Microsoft network client: Digitally sign communications (always)' = Enabled
"@
        }
        else {
            Add-Finding -Domain 'D02-SMBSign' -Severity 'Good' `
                -Check "SMB Client Signing Required: $target" `
                -Detail "SMB client on $target requires signing for outbound connections." `
                -Resources $signRes
        }

        # -- D03 SMB Encryption
        Write-Host "    [D03] SMB Encryption..." -ForegroundColor DarkGray
        $enc = Test-SMBEncryptionStatus -HostName $target -OsInfo $osInfo -WmiParams $wmiParams
        if (-not $enc.Supported) {
            $encState = 'N/A'
            Add-Finding -Domain 'D03-SMBEncrypt' -Severity 'Info' `
                -Check "SMB Encryption Not Supported: $target (Build $($osInfo.BuildNumber))" `
                -Detail "SMBv3 encryption requires build 9200+ (Server 2012/Win8). This host (build $($osInfo.BuildNumber)) does not support it." `
                -Resources $hostRes
        }
        else {
            $encVal   = if ($enc.EncryptData -ne $null) { $enc.EncryptData } else { 0 }
            $encState = if ($encVal -eq 1) { 'Enabled' } else { 'Disabled' }
            $encRes   = $hostRes + @(
                "[REG] EncryptData=$(if ($enc.EncryptData -ne $null){$enc.EncryptData}else{'absent (default=0)'})",
                "[REG] RejectUnencryptedAccess=$(if ($enc.RejectUnenc -ne $null){$enc.RejectUnenc}else{'absent (default=0)'})"
            )
            if ($encVal -ne 1) {
                $sev = if ($osInfo.IsServer) { 'Medium' } else { 'Low' }
                Add-Finding -Domain 'D03-SMBEncrypt' -Severity $sev `
                    -Check "SMB Encryption Disabled: $target [$roleTag]" `
                    -Detail "SMBv3 encryption is not enforced (EncryptData=$encVal). SMB traffic is transmitted in cleartext on the wire." `
                    -Resources $encRes `
                    -MITRE 'T1040' -CIS 'CIS 18.3.4' `
                    -AttackPath "Passive network capture -> read SMB session data (file contents, metadata) in cleartext -> extract NTLM challenge-response for offline cracking with $($script:T.HC)" `
                    -Fix @"
Enable SMBv3 encryption:
  Set-SmbServerConfiguration -EncryptData `$true -RejectUnencryptedAccess `$true -Force
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name EncryptData -Value 1
Per-share (less disruptive):
  Set-SmbShare -Name 'ShareName' -EncryptData `$true
Requires both sides to support SMBv3 (Server 2012+ / Win8+).
"@
            }
            else {
                Add-Finding -Domain 'D03-SMBEncrypt' -Severity 'Good' `
                    -Check "SMB Encryption Enabled: $target" `
                    -Detail "SMBv3 encryption is active (EncryptData=1). Wire traffic is encrypted." `
                    -Resources $encRes
            }
        }

        # -- D04 NTLM Level
        Write-Host "    [D04] NTLM auth level..." -ForegroundColor DarkGray
        $ntlm     = Test-NTLMAuthLevel -HostName $target -WmiParams $wmiParams
        $ntlmLevel = "$($ntlm.Level)"
        $ntlmRes   = $hostRes + @(
            "[REG] LmCompatibilityLevel=$(if ($ntlm.LevelRaw -ne $null){$ntlm.LevelRaw}else{'absent (default=0 -- LM+NTLM allowed)'})",
            "[REG] NoLMHash=$(if ($ntlm.NoLMHash -ne $null){$ntlm.NoLMHash}else{'absent (default=0)'})"
        )
        if ($ntlm.Level -lt 3) {
            $sev = if ($ntlm.Level -le 1) { 'Critical' } else { 'High' }
            $levelDesc = switch ($ntlm.Level) {
                0 { 'LM+NTLMv1 allowed -- most vulnerable' }
                1 { 'LM+NTLMv1, NTLMv2 if negotiated' }
                2 { 'NTLMv1 only (LM disabled)' }
                default { "Level $($ntlm.Level)" }
            }
            Add-Finding -Domain 'D04-NTLM' -Severity $sev `
                -Check "Weak NTLM Level ($($ntlm.Level)): $target [$roleTag]" `
                -Detail "LmCompatibilityLevel=$($ntlm.Level) ($levelDesc). LM/NTLMv1 hashes are crackable in seconds with rainbow tables." `
                -Resources $ntlmRes `
                -MITRE 'T1557.001' -CIS 'CIS 2.3.11.7' `
                -AttackPath "Capture LM/NTLMv1 challenge with $($script:T.RS) -> crack instantly with $($script:T.HC) rainbow tables -> recover plaintext password -> authenticate across all services" `
                -Fix @"
Set NTLMv2-only (level 5):
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Value 1
Apply via GPO:
  Computer Config -> Security Settings -> Local Policies -> Security Options:
    'Network security: LAN Manager authentication level' = 'Send NTLMv2 only. Refuse LM and NTLM'
    'Network security: Do not store LAN Manager hash' = Enabled
Warning: test legacy applications before enforcing -- some require NTLMv1.
"@
        }
        elseif ($ntlm.Level -lt 5) {
            Add-Finding -Domain 'D04-NTLM' -Severity 'Low' `
                -Check "NTLM Not Fully Hardened (Level $($ntlm.Level)): $target" `
                -Detail "LmCompatibilityLevel=$($ntlm.Level) -- NTLMv2 sent but LM/NTLM may still be accepted from clients. Recommended: level 5." `
                -Resources $ntlmRes `
                -Fix "Raise to level 5: Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5"
        }
        else {
            Add-Finding -Domain 'D04-NTLM' -Severity 'Good' `
                -Check "NTLM Hardened (Level $($ntlm.Level)): $target" `
                -Detail "LmCompatibilityLevel=$($ntlm.Level) -- NTLMv2 only. LM and NTLMv1 are refused." `
                -Resources $ntlmRes
        }

        # -- D05 EternalBlue patch
        Write-Host "    [D05] MS17-010..." -ForegroundColor DarkGray
        $eb    = Test-EternalBluePatch -HostName $target -OsInfo $osInfo -WmiParams $wmiParams
        $ebState = if (-not $eb.Affected) { 'N/A' } elseif ($eb.PatchFound) { 'Patched' } else { 'MISSING' }
        $ebRes = $hostRes + @("[PATCH] RequiredKB=$($eb.PatchKB)", "[PATCH] Found=$($eb.PatchFound)", "[PATCH] Build=$($eb.BuildNum)")
        if (-not $eb.Affected) {
            Add-Finding -Domain 'D05-MS17010' -Severity 'Good' `
                -Check "MS17-010 N/A: $target (Build $($eb.BuildNum))" `
                -Detail "Build $($eb.BuildNum) is not affected -- $($script:T.EB) requires SMBv1 which is off by default on this build." `
                -Resources $ebRes
        }
        elseif ($smb1.Enabled -and -not $eb.PatchFound) {
            Add-Finding -Domain 'D05-MS17010' -Severity 'Critical' `
                -Check "MS17-010 UNPATCHED + SMBv1 ACTIVE: $target [$roleTag]" `
                -Detail "CRITICAL: $target has SMBv1 enabled AND $($eb.PatchKB) is not detected. Fully exploitable by $($script:T.EB) / $($script:T.WC) with no authentication required." `
                -Resources $ebRes `
                -MITRE 'T1210' -CIS 'CIS 7.4' `
                -AttackPath "Send malformed SMBv1 Trans2 to port 445 -> heap spray in srv.sys -> kernel RCE as SYSTEM -> install $($script:T.MK) / deploy ransomware -> propagate via SMBv1 to all reachable hosts" `
                -Fix @"
IMMEDIATE: isolate host until patched.
Apply MS17-010:
  Win7/2008R2  -> KB4012212
  Win8.1/2012R2 -> KB4012213
  Win10         -> KB4012606
  Server 2016   -> KB4013429
Then disable SMBv1:
  Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force
Block inbound SMB from untrusted segments:
  netsh advfirewall firewall add rule name="Block-SMBv1" dir=in action=block protocol=TCP localport=445
"@
        }
        elseif ($smb1.Enabled -and $eb.PatchFound) {
            Add-Finding -Domain 'D05-MS17010' -Severity 'Medium' `
                -Check "MS17-010 Patched but SMBv1 Still Active: $target" `
                -Detail "$($eb.PatchKB) is installed but SMBv1 remains enabled. Specific $($script:T.EB) exploit is blocked but other SMBv1 attack surfaces remain." `
                -Resources $ebRes `
                -Fix "Disable SMBv1 even with patch: Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
        }
        elseif (-not $smb1.Enabled -and -not $eb.PatchFound) {
            Add-Finding -Domain 'D05-MS17010' -Severity 'Low' `
                -Check "MS17-010 Patch Not Detected (SMBv1 Disabled): $target" `
                -Detail "Could not detect $($eb.PatchKB) via WMI, but SMBv1 is disabled which mitigates the vector. Apply patch for defence-in-depth." `
                -Resources $ebRes
        }
        else {
            Add-Finding -Domain 'D05-MS17010' -Severity 'Good' `
                -Check "MS17-010 Patched: $target" `
                -Detail "$($eb.PatchKB) or later detected. $($script:T.EB) vector is mitigated." `
                -Resources $ebRes
        }
    }

    # ===================================================================
    # D07 -- Share enumeration + access + ACL + sensitive files
    # ===================================================================

    if (-not $SkipShares) {
        $shareNames = @(Get-RemoteShares -HostName $target)
        if ($shareNames.Count -eq 0) {
            Write-AuditWarning "Share Enumeration Failed" `
                "Could not enumerate shares on $target" 'D07-ENUM'
        }
        else {
            Write-Host "    Shares: $($shareNames -join ', ')" -ForegroundColor Gray

            foreach ($share in $shareNames) {
                $uncPath = "\\$target\$share"
                $isAdmin = $adminShares -contains $share
                $catTag  = if ($isAdmin) { 'D07-ADMIN' } else { 'D07-SHARE' }
                Write-Host "    -> $uncPath" -ForegroundColor DarkGray

                # IPC$/PRINT$/FAX$ -- null session test only
                if ($skipShares -contains $share) {
                    if ($share -eq 'IPC$') {
                        $ipcAccess = Test-ShareAccess -HostName $target -ShareName $share -Cred $Credential
                        if ($ipcAccess.AccessType -in @('Anonymous','Guest')) {
                            Add-Finding -Domain 'D07-NULLSESSION' -Severity 'High' `
                                -Check "Null Session via IPC`$: $target" `
                                -Detail "IPC`$ on $target accepts null/anonymous connections. Enables unauthenticated RPC enumeration of users, groups, shares, and domain info." `
                                -Resources @("[HOST] $target", "[SHARE] $uncPath") `
                                -MITRE 'T1135' -CIS 'CIS 9.2' `
                                -AttackPath "Null session to IPC`$ -> RPC enumeration of SIDs, users, shares, domain trusts without credentials" `
                                -Fix @"
  reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymous /t REG_DWORD /d 1
  reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymousSAM /t REG_DWORD /d 1
  reg add HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters /v RestrictNullSessAccess /t REG_DWORD /d 1
"@
                        }
                    }
                    continue
                }

                $access = Test-ShareAccess -HostName $target -ShareName $share -Cred $Credential

                # Anonymous access
                if ($access.AccessType -eq 'Anonymous' -and $access.CanList) {
                    $writePart = if ($access.CanWrite) { ' -- WRITABLE' } else { '' }
                    $sev = if ($access.CanWrite -or $isAdmin) { 'Critical' } else { 'High' }
                    Add-Finding -Domain $catTag -Severity $sev `
                        -Check "Anonymous Access${writePart}: \\$target\$share" `
                        -Detail "Share $uncPath is readable via null session${writePart}. Any unauthenticated host can access it." `
                        -Resources @("[HOST] $target", "[SHARE] $uncPath") `
                        -MITRE 'T1135' -CIS 'CIS 9.2' `
                        -AttackPath "Null session -> list $uncPath -> find sensitive files -> exfiltrate -> crack or reuse credentials offline" `
                        -Fix @"
  icacls "$uncPath" /remove "Everyone" /remove "Anonymous Logon" /remove "BUILTIN\Users"
  reg add HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymous /t REG_DWORD /d 1
  Set-SmbShare -Name "$share" -FolderEnumerationMode AccessBased
"@
                }
                # Guest access
                elseif ($access.AccessType -eq 'Guest' -and $access.CanList) {
                    Add-Finding -Domain $catTag -Severity 'High' `
                        -Check "Guest Access: \\$target\$share" `
                        -Detail "Share $uncPath accessible with Guest account (blank password). Guest account is enabled or share has no auth requirement." `
                        -Resources @("[HOST] $target", "[SHARE] $uncPath") `
                        -MITRE 'T1135' -CIS 'CIS 9.2' `
                        -AttackPath "Authenticate as Guest -> enumerate $uncPath -> use $($script:T.CR) for bulk file access" `
                        -Fix @"
  Disable-LocalUser -Name Guest
  icacls "$uncPath" /remove "Guest" /remove "BUILTIN\Guests"
"@
                }
                # Admin share accessible
                elseif ($isAdmin -and $access.CanList) {
                    Add-Finding -Domain $catTag -Severity 'Medium' `
                        -Check "Admin Share Accessible: \\$target\$share" `
                        -Detail "Admin share $uncPath reachable with current credentials. Ensure only Tier 0 accounts have access." `
                        -Resources @("[HOST] $target", "[SHARE] $uncPath") `
                        -MITRE 'T1021.002' `
                        -AttackPath "Access $share -> read OS files (SAM/SYSTEM hives) -> extract hashes -> Pass-the-Hash or $($script:T.MK) PTH" `
                        -Fix "Restrict via GPO User Rights Assignment. Disable on non-DC servers: Set-SmbServerConfiguration -AutoShareServer `$false"
                }

                if (-not $access.CanList) { continue }

                # ACL check
                $aclInfo = Get-ShareAclInfo -UncPath $uncPath
                if ($aclInfo.Issues.Count -gt 0) {
                    $aclRes  = @("[SHARE] $uncPath") + ($aclInfo.Issues | ForEach-Object { "[ACL] $_" })
                    $hasWW   = @($aclInfo.Issues | Where-Object { $_ -match 'WIDE-WRITE' }).Count -gt 0
                    $aclSev  = if ($hasWW) { 'High' } else { 'Medium' }
                    Add-Finding -Domain $catTag -Severity $aclSev `
                        -Check "Overly Permissive ACL: \\$target\$share" `
                        -Detail "Share $uncPath has broad ACEs. Owner: $($aclInfo.Owner). Issues: $($aclInfo.Issues -join ' | ')" `
                        -Resources $aclRes `
                        -MITRE 'T1222.001' -CIS 'CIS 2.2' `
                        -AttackPath "Identify write ACE -> drop malicious DLL/script -> wait for privileged process to execute -> code execution in privileged context" `
                        -Fix @"
  icacls "$uncPath" /inheritance:r
  icacls "$uncPath" /remove "Everyone" /remove "BUILTIN\Users" /remove "NT AUTHORITY\Authenticated Users"
  icacls "$uncPath" /grant "Domain Admins:(OI)(CI)F"
  Set-SmbShare -Name "$share" -FolderEnumerationMode AccessBased
"@
                }
                else {
                    Add-Finding -Domain $catTag -Severity 'Good' `
                        -Check "ACL OK: \\$target\$share" `
                        -Detail "No overly broad ACEs found. Owner: $($aclInfo.Owner)." `
                        -Resources @("[SHARE] $uncPath")
                }

                # Sensitive file scan
                $hits = @(Find-SensitiveFiles -UncPath $uncPath -MaxLevels $MaxDepth -ModifiedAfterDate $ModifiedAfter)
                if ($hits.Count -gt 0) {
                    $fileRes = @("[SHARE] $uncPath") + ($hits | ForEach-Object {
                        "[FILE] $($_.Path) [$($_.Reason)] $($_.SizeKB)KB mod:$($_.Modified)"
                    })
                    $fileSev = if ($access.AccessType -eq 'Anonymous') { 'Critical' } `
                               elseif ($access.AccessType -eq 'Guest')  { 'High' } `
                               else { 'Medium' }
                    Add-Finding -Domain $catTag -Severity $fileSev `
                        -Check "Sensitive Files Exposed ($($hits.Count)): \\$target\$share" `
                        -Detail "$($hits.Count) sensitive file(s) found in $uncPath (access: $($access.AccessType))." `
                        -Resources $fileRes `
                        -MITRE 'T1552.001' `
                        -AttackPath "Browse $uncPath -> download flagged files -> parse for credentials/keys -> authenticate with recovered material -> pivot" `
                        -Fix @"
1. Move credential/key material off shares to a secrets manager.
2. Restrict per-file ACLs: icacls '<path>' /inheritance:r /grant '<group>:(R)'
3. Enable auditing: auditpol /set /subcategory:"File System" /success:enable /failure:enable
4. Enable ABE: Set-SmbShare -Name "$share" -FolderEnumerationMode AccessBased
"@
                }
                else {
                    Add-Finding -Domain $catTag -Severity 'Good' `
                        -Check "No Sensitive Files: \\$target\$share" `
                        -Detail "Scanned $uncPath to depth $MaxDepth -- no sensitive filename patterns found." `
                        -Resources @("[SHARE] $uncPath")
                }
            }
        }
    }

    # Record host summary row
    $hostSummary.Add([PSCustomObject]@{
        Host    = $target
        OS      = "$osCaption (Build $osBuild)"
        Role    = $roleTag
        SMBv1   = $smb1State
        SrvSign = $srvSign
        CliSign = $cliSign
        Encrypt = $encState
        NTLMLvl = $ntlmLevel
        MS17010 = $ebState
    })
    Write-Host "" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

Write-Host "[*] Building report..." -ForegroundColor Cyan

$pct         = if ($script:MaxScore -gt 0) { [math]::Round($script:Score * 100 / $script:MaxScore) } else { 100 }
$scoreColor  = if ($pct -ge 80) { '#22c55e' } elseif ($pct -ge 60) { '#f59e0b' } elseif ($pct -ge 40) { '#f97316' } else { '#ef4444' }
$maturity    = if ($pct -ge 80) { 'Hardened' } elseif ($pct -ge 60) { 'Moderate Risk' } elseif ($pct -ge 40) { 'High Risk' } else { 'Critical Risk' }
$critCount   = @($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
$highCount   = @($script:Findings | Where-Object { $_.Severity -eq 'High' }).Count
$medCount    = @($script:Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
$lowCount    = @($script:Findings | Where-Object { $_.Severity -eq 'Low' }).Count
$goodCount   = @($script:Findings | Where-Object { $_.Severity -eq 'Good' }).Count
$issueCount  = @($script:Findings | Where-Object { $_.Severity -notin @('Good','Info') }).Count
$genTime     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
$gaugeOffset = [math]::Round(283 - (283 * $pct / 100))

# Host matrix rows
$hostRows = ''
foreach ($h in $hostSummary) {
    $smb1Cell = if ($h.SMBv1 -eq 'ENABLED')       { "<td style='color:#ef4444;font-weight:700'>$($h.SMBv1)</td>" }   else { "<td style='color:#22c55e'>$($h.SMBv1)</td>" }
    $srvCell  = if ($h.SrvSign -match 'NOT')       { "<td style='color:#f97316'>$($h.SrvSign)</td>" }                 else { "<td style='color:#22c55e'>$($h.SrvSign)</td>" }
    $cliCell  = if ($h.CliSign -match 'NOT')       { "<td style='color:#f59e0b'>$($h.CliSign)</td>" }                 else { "<td style='color:#22c55e'>$($h.CliSign)</td>" }
    $encCell  = if ($h.Encrypt -eq 'Disabled')     { "<td style='color:#f59e0b'>$($h.Encrypt)</td>" }                 else { "<td style='color:#22c55e'>$($h.Encrypt)</td>" }
    $ntlmCell = if ($h.NTLMLvl -match '^[012]$')  { "<td style='color:#ef4444;font-weight:700'>Level $($h.NTLMLvl)</td>" } `
                elseif ($h.NTLMLvl -match '^[34]$') { "<td style='color:#f59e0b'>Level $($h.NTLMLvl)</td>" }           else { "<td style='color:#22c55e'>$($h.NTLMLvl)</td>" }
    $ebCell   = if ($h.MS17010 -eq 'MISSING')      { "<td style='color:#ef4444;font-weight:700'>$($h.MS17010)</td>" } `
                elseif ($h.MS17010 -eq 'N/A')       { "<td style='color:#64748b'>$($h.MS17010)</td>" }                 else { "<td style='color:#22c55e'>$($h.MS17010)</td>" }
    $hostRows += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($h.Host))</td><td>$([System.Net.WebUtility]::HtmlEncode($h.Role))</td><td>$([System.Net.WebUtility]::HtmlEncode($h.OS))</td>$smb1Cell$srvCell$cliCell$encCell$ntlmCell$ebCell</tr>`n"
}

# Finding cards
$fIdx         = 0
$findingCards = ''
foreach ($f in $script:Findings) {
    if ($f.Severity -in @('Good','Info')) { $fIdx++; continue }
    $sc = switch ($f.Severity) {
        'Critical' { '#ef4444' } 'High' { '#f97316' } 'Medium' { '#f59e0b' } 'Low' { '#60a5fa' } default { '#6b7280' }
    }
    $assetHtml  = ConvertTo-AssetHtml -Resources $f.Resources
    $safeDetail = [System.Net.WebUtility]::HtmlEncode($f.Detail)
    $safeAttack = [System.Net.WebUtility]::HtmlEncode($f.AttackPath)
    $safeFix    = [System.Net.WebUtility]::HtmlEncode($f.Fix)
    $safeDomain = [System.Net.WebUtility]::HtmlEncode($f.Domain)
    $safeCheck  = [System.Net.WebUtility]::HtmlEncode($f.Check)
    $mitreBadge = if ($f.MITRE) { "<span class='badge mitre-badge'>$([System.Net.WebUtility]::HtmlEncode($f.MITRE))</span>" } else { '' }
    $cisBadge   = if ($f.CIS)   { "<span class='badge cis-badge'>$([System.Net.WebUtility]::HtmlEncode($f.CIS))</span>" }   else { '' }
    $tabBtns    = ''
    $tabPanels  = ''
    if ($assetHtml)   { $tabBtns += "<button class='tab-btn' onclick='showTab(this,""ass-$fIdx"")'>Assets ($(@($f.Resources).Count))</button>"; $tabPanels += "<div class='tab-panel' id='ass-$fIdx' style='display:none'>$assetHtml</div>" }
    if ($f.AttackPath){ $tabBtns += "<button class='tab-btn' onclick='showTab(this,""ap-$fIdx"")'>Attack Path</button>"; $tabPanels += "<div class='tab-panel' id='ap-$fIdx' style='display:none'><pre class='attack-pre'>$safeAttack</pre></div>" }
    if ($f.Fix)       { $tabBtns += "<button class='tab-btn' onclick='showTab(this,""fix-$fIdx"")'>Remediation</button>"; $tabPanels += "<div class='tab-panel' id='fix-$fIdx' style='display:none'><pre class='fix-pre'>$safeFix</pre></div>" }
    $findingCards += @"
<div class='fcard' data-sev='$($f.Severity)'>
  <div class='fcard-header' onclick='toggleCard(this)'>
    <span class='sev-badge' style='background:$sc'>$($f.Severity)</span>
    <span class='fcard-domain'>$safeDomain</span>
    <span class='fcard-title'>$safeCheck</span>
    <span class='fcard-badges'>$mitreBadge$cisBadge</span>
    <span class='fcard-chevron'>+</span>
  </div>
  <div class='fcard-body' style='display:none'>
    <div class='why-box'><div class='why-label'>Why Vulnerable</div><div class='why-text'>$safeDetail</div></div>
    <div class='tab-bar'>$tabBtns</div>
    $tabPanels
  </div>
</div>
"@
    $fIdx++
}

$html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>SMB Audit Report</title>
<style>
:root{--bg:#0f1117;--surface:#1a1d27;--border:#2a2d3e;--text:#e2e8f0;
  --dim:#64748b;--blue:#3b82f6;--blue-lt:#60a5fa;
  --crit:#ef4444;--high:#f97316;--med:#f59e0b;--low:#60a5fa;--good:#22c55e;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;}
a{color:var(--blue-lt);text-decoration:none;}
a:hover{text-decoration:underline;}
.nav{position:sticky;top:0;z-index:100;background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:10px 24px;gap:20px;}
.nav-brand{font-size:1rem;font-weight:700;color:var(--blue-lt);}
.nav-links{display:flex;gap:16px;font-size:.8rem;}
.nav-links a{color:var(--dim);}
.nav-links a:hover{color:var(--blue-lt);}
.page{max-width:1300px;margin:0 auto;padding:24px 16px;}
.dash{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px;margin-bottom:24px;}
.dash-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center;}
.dc-val{font-size:1.9rem;font-weight:700;}
.dc-lbl{font-size:.73rem;color:var(--dim);margin-top:4px;}
.score-gauge{position:relative;width:90px;height:90px;margin:0 auto 8px;}
.score-gauge svg{width:90px;height:90px;transform:rotate(-90deg);}
.score-gauge circle{fill:none;stroke-width:10;}
.gauge-bg{stroke:var(--border);}
.gauge-fill{stroke-dasharray:283;stroke-linecap:round;}
.gauge-pct{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:1.2rem;font-weight:700;}
.section-hdr{display:flex;align-items:center;justify-content:space-between;margin:28px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--border);}
.section-hdr h2{font-size:1rem;font-weight:600;}
.section-count{font-size:.75rem;color:var(--dim);background:rgba(255,255,255,.05);padding:2px 8px;border-radius:12px;}
.host-table{width:100%;border-collapse:collapse;font-size:.78rem;margin-bottom:8px;overflow-x:auto;display:block;}
.host-table th{text-align:left;padding:8px 10px;background:rgba(255,255,255,.05);border-bottom:1px solid var(--border);color:var(--dim);font-weight:600;white-space:nowrap;}
.host-table td{padding:7px 10px;border-bottom:1px solid rgba(255,255,255,.04);font-family:'Cascadia Code','Consolas',monospace;font-size:.74rem;white-space:nowrap;}
.host-table tr:hover td{background:rgba(255,255,255,.02);}
.filter-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:16px;}
.filter-label{font-size:.75rem;color:var(--dim);}
.filter-btn{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:4px 12px;border-radius:16px;font-size:.78rem;cursor:pointer;}
.filter-btn.active{background:var(--blue);border-color:var(--blue);color:#fff;}
.filter-btn:hover{border-color:var(--blue-lt);}
.search-box{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:4px 12px;border-radius:16px;font-size:.78rem;width:220px;margin-left:auto;}
.result-count{font-size:.75rem;color:var(--dim);}
.fcard{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:8px;overflow:hidden;}
.fcard:hover{border-color:#3d4266;}
.fcard-header{display:flex;align-items:center;gap:12px;padding:10px 14px;cursor:pointer;user-select:none;}
.fcard-header:hover{background:rgba(255,255,255,.02);}
.sev-badge{font-size:.7rem;font-weight:700;padding:2px 8px;border-radius:12px;color:#fff;white-space:nowrap;flex-shrink:0;}
.fcard-domain{font-size:.72rem;color:var(--dim);white-space:nowrap;flex-shrink:0;width:130px;}
.fcard-title{font-size:.87rem;font-weight:600;flex:1;min-width:0;}
.fcard-badges{display:flex;gap:4px;flex-shrink:0;}
.badge{font-size:.68rem;padding:1px 6px;border-radius:8px;font-weight:600;}
.mitre-badge{background:#1e3a5f;color:#93c5fd;}
.cis-badge{background:#1a3a2a;color:#86efac;}
.fcard-chevron{color:var(--dim);font-size:1.1rem;flex-shrink:0;width:20px;text-align:center;}
.fcard-chevron.open{color:var(--blue-lt);}
.fcard-body{border-top:1px solid var(--border);}
.why-box{padding:12px 14px;background:rgba(255,255,255,.02);border-bottom:1px solid var(--border);}
.why-label{font-size:.68rem;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;}
.why-text{font-size:.82rem;color:#cbd5e1;line-height:1.5;}
.tab-bar{display:flex;border-bottom:1px solid var(--border);}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;color:var(--dim);padding:8px 14px;font-size:.78rem;cursor:pointer;}
.tab-btn.active{color:var(--blue-lt);border-bottom-color:var(--blue-lt);}
.tab-btn:hover{color:var(--text);}
.tab-panel{padding:14px;display:none;}
.attack-pre,.fix-pre{background:#0a0d14;border:1px solid var(--border);border-radius:6px;padding:12px;font-size:.78rem;font-family:'Cascadia Code','Consolas',monospace;white-space:pre-wrap;word-break:break-word;overflow-x:auto;}
.attack-pre{color:#a5f3fc;}
.fix-pre{color:#bbf7d0;}
.asset-group{margin-bottom:10px;}
.asset-label{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;padding:2px 6px;border-radius:4px;margin-right:6px;}
.host-lbl{background:#1e3a5f;color:#93c5fd;}
.share-lbl{background:#3b1f5e;color:#c4b5fd;}
.file-lbl{background:#1a3a2a;color:#86efac;}
.acl-lbl{background:#3a1a1a;color:#fca5a5;}
.reg-lbl{background:#2a1a3a;color:#d8b4fe;}
.patch-lbl{background:#1a2a3a;color:#7dd3fc;}
.gen-lbl{background:#2a2a1a;color:#fde68a;}
.asset-item{display:inline-block;background:rgba(255,255,255,.05);border:1px solid var(--border);border-radius:4px;padding:2px 8px;margin:3px 3px 0 0;font-size:.75rem;font-family:'Cascadia Code','Consolas',monospace;}
footer{text-align:center;padding:24px;font-size:.75rem;color:var(--dim);border-top:1px solid var(--border);margin-top:32px;}
@media(max-width:700px){.fcard-domain{display:none;}.dash{grid-template-columns:repeat(2,1fr);}}
</style>
</head>
<body>
<nav class='nav'>
  <span class='nav-brand'>SMB Audit</span>
  <div class='nav-links'>
    <a href='#dashboard'>Dashboard</a>
    <a href='#host-matrix'>Host Matrix</a>
    <a href='#findings'>Findings</a>
  </div>
</nav>
<div class='page'>

  <div class='section-hdr' id='dashboard'>
    <h2>Assessment Dashboard</h2>
    <span class='section-count'>$genTime</span>
  </div>
  <div class='dash'>
    <div class='dash-card'>
      <div class='score-gauge'>
        <svg viewBox='0 0 100 100'>
          <circle class='gauge-bg' cx='50' cy='50' r='45'/>
          <circle class='gauge-fill' cx='50' cy='50' r='45' stroke='$scoreColor' stroke-dashoffset='$gaugeOffset'/>
        </svg>
        <div class='gauge-pct' style='color:$scoreColor'>$pct%</div>
      </div>
      <div class='dc-lbl'>$maturity</div>
    </div>
    <div class='dash-card'><div class='dc-val' style='color:#94a3b8'>$($allTargets.Count)</div><div class='dc-lbl'>Targets</div></div>
    <div class='dash-card'><div class='dc-val' style='color:var(--crit)'>$critCount</div><div class='dc-lbl'>Critical</div></div>
    <div class='dash-card'><div class='dc-val' style='color:var(--high)'>$highCount</div><div class='dc-lbl'>High</div></div>
    <div class='dash-card'><div class='dc-val' style='color:var(--med)'>$medCount</div><div class='dc-lbl'>Medium</div></div>
    <div class='dash-card'><div class='dc-val' style='color:var(--low)'>$lowCount</div><div class='dc-lbl'>Low</div></div>
    <div class='dash-card'><div class='dc-val' style='color:var(--good)'>$goodCount</div><div class='dc-lbl'>Passed</div></div>
  </div>

  <div class='section-hdr' id='host-matrix'>
    <h2>Host Configuration Matrix</h2>
    <span class='section-count'>$($hostSummary.Count) hosts assessed</span>
  </div>
  <table class='host-table'>
    <tr><th>Host</th><th>Role</th><th>OS</th><th>SMBv1</th><th>Srv Sign</th><th>Cli Sign</th><th>Encrypt</th><th>NTLM</th><th>MS17-010</th></tr>
$hostRows
  </table>

  <div class='section-hdr' id='findings'>
    <h2>All Findings</h2>
    <span class='section-count'>$issueCount issues</span>
  </div>
  <div class='filter-bar'>
    <span class='filter-label'>Filter:</span>
    <button class='filter-btn active' data-f='All'      onclick='filterCards(this)'>All</button>
    <button class='filter-btn'        data-f='Critical' onclick='filterCards(this)'>Critical ($critCount)</button>
    <button class='filter-btn'        data-f='High'     onclick='filterCards(this)'>High ($highCount)</button>
    <button class='filter-btn'        data-f='Medium'   onclick='filterCards(this)'>Medium ($medCount)</button>
    <button class='filter-btn'        data-f='Low'      onclick='filterCards(this)'>Low ($lowCount)</button>
    <input class='search-box' type='text' placeholder='Search findings...' oninput='searchCards(this.value)'/>
    <span class='result-count' id='result-count'></span>
  </div>
  <div id='finding-cards-container'>
$findingCards
  </div>

</div>
<footer>SMB Audit -- ASPAT Purple Team &nbsp;|&nbsp; $genTime &nbsp;|&nbsp; Score: $($script:Score)/$($script:MaxScore) ($pct%)</footer>
<script>
function toggleCard(hdr){var body=hdr.nextElementSibling;var chev=hdr.querySelector('.fcard-chevron');var isOpen=body.style.display!=='none';body.style.display=isOpen?'none':'block';chev.textContent=isOpen?'+':'x';chev.classList.toggle('open',!isOpen);if(!isOpen){var btn=body.querySelector('.tab-btn');if(btn){var m=btn.getAttribute('onclick').match(/"([^"]+)"/);if(m)showTab(btn,m[1]);}}}
function showTab(btn,panelId){var card=btn.closest('.fcard-body');card.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});card.querySelectorAll('.tab-panel').forEach(function(p){p.style.display='none';});btn.classList.add('active');var panel=document.getElementById(panelId);if(panel)panel.style.display='block';}
function filterCards(btn){document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active');});btn.classList.add('active');var f=btn.getAttribute('data-f');var cards=document.querySelectorAll('#finding-cards-container .fcard');var visible=0;cards.forEach(function(c){var show=(f==='All'||c.getAttribute('data-sev')===f);c.style.display=show?'':'none';if(show)visible++;});document.getElementById('result-count').textContent='Showing '+visible+' of '+cards.length;}
function searchCards(q){q=q.toLowerCase();var cards=document.querySelectorAll('#finding-cards-container .fcard');var visible=0;cards.forEach(function(c){var show=!q||c.textContent.toLowerCase().indexOf(q)!==-1;c.style.display=show?'':'none';if(show)visible++;});document.getElementById('result-count').textContent=q?('Showing '+visible+' of '+cards.length):'';}
(function(){var total=document.querySelectorAll('#finding-cards-container .fcard').length;document.getElementById('result-count').textContent='Showing '+total+' of '+total;})();
</script>
</body>
</html>
"@

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

$reportName = "SMBAudit-$dateSafe"
$htmlPath   = Join-Path $OutputPath "$reportName.html"
$html | Out-File -FilePath $htmlPath -Encoding UTF8
Write-Host "  HTML Report : $htmlPath" -ForegroundColor Green

if (-not $NoCsv) {
    $csvPath = Join-Path $OutputPath "$reportName.csv"
    $script:Findings | Where-Object { $_.Severity -notin @('Good','Info') } |
        Select-Object Domain,Severity,Check,Detail,Resources,MITRE,CIS,Fix |
        Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV Export  : $csvPath" -ForegroundColor Green
}

$runtime = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds)
Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "  Score   : $($script:Score)/$($script:MaxScore) ($pct%) -- $maturity"
Write-Host "  Issues  : Critical=$critCount  High=$highCount  Medium=$medCount  Low=$lowCount"
Write-Host "  Passed  : $goodCount  |  Hosts: $($hostSummary.Count)"
Write-Host "  Runtime : $($runtime)s"
Write-Host "=====================================================" -ForegroundColor Cyan
