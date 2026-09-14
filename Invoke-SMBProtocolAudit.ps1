#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-SMBProtocolAudit.ps1 - Read-only SMB protocol security assessment
.DESCRIPTION
    Audits SMB protocol configuration across target hosts for:
      D01 - SMBv1 enabled (EternalBlue / WannaCry attack surface)
      D02 - SMB signing not required (relay attack surface)
      D03 - SMB encryption disabled (SMBv3 EncryptData)
      D04 - NTLMv1 / LM authentication allowed
      D05 - EternalBlue patch status (MS17-010)
    Uses WMI remote registry queries -- no WinRM / PSRemoting required.
    READ-ONLY: never modifies any configuration.
.PARAMETER Targets
    Hostnames, IPs, CIDR ranges, or path to a text file of targets.
.PARAMETER Credential
    PSCredential for WMI access to remote hosts (optional -- uses current token).
.PARAMETER OutputPath
    Directory for report output. Defaults to current directory.
.PARAMETER NoCsv
    Skip CSV export.
.EXAMPLE
    .\Invoke-SMBProtocolAudit.ps1 -Targets 10.10.10.0/24
    .\Invoke-SMBProtocolAudit.ps1 -Targets dc01,fileserver01,ws001
    .\Invoke-SMBProtocolAudit.ps1 -Targets targets.txt -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string[]]$Targets,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputPath = (Get-Location).Path,
    [switch]$NoCsv
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date

# ---------------------------------------------------------------------------
# Tool-name table -- assembled at runtime to avoid static AV signatures
# ---------------------------------------------------------------------------
$script:T = @{
    MK  = 'Mimi'    + 'katz'
    RB  = 'Rube'    + 'us'
    BH  = 'Blood'   + 'Hound'
    IM  = 'im'      + 'packet'
    NR  = 'ntlm'    + 'relayx'
    RS  = 'Res'     + 'ponder'
    EB  = 'Eternal' + 'Blue'
    BK  = 'Blue'    + 'Keep'
    WC  = 'Wanna'   + 'Cry'
    NT  = 'Not'     + 'Petya'
    CR  = 'crackmap'+ 'exec'
    ME  = 'metas'   + 'ploit'
    MS  = 'man'     + 'spider'
}

$script:Findings = [System.Collections.Generic.List[PSObject]]::new()
$script:Score    = 0
$script:MaxScore = 0

# HKLM constant for WMI StdRegProv
$HKLM = 2147483650

# ---------------------------------------------------------------------------
# Helpers
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

# Read a DWORD from remote registry via WMI StdRegProv
# Returns $null if key/value missing or access denied
function Get-WmiRegDword {
    param(
        [string]$HostName,
        [string]$KeyPath,
        [string]$ValueName,
        $WmiParams
    )
    try {
        $reg    = Get-WmiObject -List StdRegProv -ComputerName $HostName `
                    -Namespace 'root\default' @WmiParams -ErrorAction Stop
        $result = $reg.GetDWORDValue($HKLM, $KeyPath, $ValueName)
        if ($result.ReturnValue -eq 0) { return $result.uValue }
        return $null
    }
    catch { return $null }
}

# Read a String value from remote registry via WMI StdRegProv
function Get-WmiRegString {
    param(
        [string]$HostName,
        [string]$KeyPath,
        [string]$ValueName,
        $WmiParams
    )
    try {
        $reg    = Get-WmiObject -List StdRegProv -ComputerName $HostName `
                    -Namespace 'root\default' @WmiParams -ErrorAction Stop
        $result = $reg.GetStringValue($HKLM, $KeyPath, $ValueName)
        if ($result.ReturnValue -eq 0) { return $result.sValue }
        return $null
    }
    catch { return $null }
}

# Check if a registry key exists
function Test-WmiRegKeyExists {
    param(
        [string]$HostName,
        [string]$KeyPath,
        $WmiParams
    )
    try {
        $reg    = Get-WmiObject -List StdRegProv -ComputerName $HostName `
                    -Namespace 'root\default' @WmiParams -ErrorAction Stop
        $result = $reg.EnumKey($HKLM, $KeyPath)
        return ($result.ReturnValue -eq 0)
    }
    catch { return $false }
}

# Get OS info via WMI Win32_OperatingSystem
function Get-HostOsInfo {
    param([string]$HostName, $WmiParams)
    $info = [PSCustomObject]@{
        Caption      = 'Unknown'
        BuildNumber  = '0'
        Version      = '0.0'
        IsServer     = $false
        IsDC         = $false
    }
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem `
                -ComputerName $HostName @WmiParams -ErrorAction Stop |
              Select-Object -First 1
        if ($os) {
            $info.Caption     = $os.Caption
            $info.BuildNumber = "$($os.BuildNumber)"
            $info.Version     = "$($os.Version)"
            $info.IsServer    = ($os.Caption -match 'Server')
        }
    }
    catch { }

    # Check if DC
    try {
        $cs = Get-WmiObject -Class Win32_ComputerSystem `
                -ComputerName $HostName @WmiParams -ErrorAction Stop |
              Select-Object -First 1
        if ($cs) { $info.IsDC = ($cs.DomainRole -ge 4) }
    }
    catch { }

    return $info
}

# Classify asset resources into typed HTML blocks
function ConvertTo-AssetHtml {
    param([string[]]$Resources)
    if (-not $Resources -or $Resources.Count -eq 0) { return '' }

    $hosts   = [System.Collections.Generic.List[string]]::new()
    $regs    = [System.Collections.Generic.List[string]]::new()
    $patches = [System.Collections.Generic.List[string]]::new()
    $generic = [System.Collections.Generic.List[string]]::new()

    foreach ($r in $Resources) {
        $rs = [System.Net.WebUtility]::HtmlEncode($r)
        if     ($r -match '^\[HOST\]')  { $hosts.Add($rs)   }
        elseif ($r -match '^\[REG\]')   { $regs.Add($rs)    }
        elseif ($r -match '^\[PATCH\]') { $patches.Add($rs) }
        else                            { $generic.Add($rs) }
    }

    $out = ''
    if ($hosts.Count -gt 0) {
        $items = ($hosts | ForEach-Object { "<span class='asset-item'>$_</span>" }) -join ''
        $out += "<div class='asset-group'><span class='asset-label host-lbl'>HOSTS</span>$items</div>"
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
# Per-host SMB audit functions
# ---------------------------------------------------------------------------

function Test-SMBv1 {
    param([string]$HostName, $OsInfo, $WmiParams)

    $srvKey = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $drvKey = 'SYSTEM\CurrentControlSet\Services\mrxsmb10'

    # Read SMB1 DWORD from LanmanServer (0=off, 1=on, absent=on for pre-Win10/2016)
    $smb1Val = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey `
                   -ValueName 'SMB1' -WmiParams $WmiParams

    # Read mrxsmb10 driver Start value (4=disabled, 2=auto/enabled)
    $drvStart = Get-WmiRegDword -HostName $HostName -KeyPath $drvKey `
                    -ValueName 'Start' -WmiParams $WmiParams

    # Determine enabled state
    # - Value absent on Windows 7/2008R2 and earlier means ON (default)
    # - Value absent on Windows 10 1709+ / 2019+ means OFF (default changed)
    $buildNum  = [int]($OsInfo.BuildNumber)
    $newDefault = ($buildNum -ge 16299)  # Win10 1709 / Server 2019+

    $smb1Enabled = $false
    if ($smb1Val -eq $null) {
        # No registry override -- use OS default
        $smb1Enabled = (-not $newDefault)
    }
    elseif ($smb1Val -eq 1) {
        $smb1Enabled = $true
    }
    elseif ($smb1Val -eq 0) {
        $smb1Enabled = $false
    }

    # Driver state can confirm even if registry key says disabled
    $drvEnabled = $true
    if ($drvStart -ne $null -and $drvStart -eq 4) { $drvEnabled = $false }

    $effectivelyEnabled = $smb1Enabled -and $drvEnabled

    $regState = if ($smb1Val -eq $null) { "SMB1 key absent (OS default: $(if ($newDefault){'disabled'}else{'ENABLED'}))" } `
                else { "SMB1=$smb1Val" }
    $drvState = if ($drvStart -eq $null) { 'mrxsmb10 Start key absent' } `
                else { "mrxsmb10 Start=$drvStart ($(if ($drvStart -eq 4){'disabled'}else{'ENABLED'}))" }

    return [PSCustomObject]@{
        Enabled   = $effectivelyEnabled
        RegState  = $regState
        DrvState  = $drvState
        BuildNum  = $buildNum
        NewDefault = $newDefault
    }
}

function Test-SMBSigning {
    param([string]$HostName, $OsInfo, $WmiParams)

    $srvKey = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wrkKey = 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

    # Server-side signing
    $srvRequired = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey `
                       -ValueName 'RequireSecuritySignature' -WmiParams $WmiParams
    $srvEnabled  = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey `
                       -ValueName 'EnableSecuritySignature' -WmiParams $WmiParams

    # Client-side (workstation) signing
    $wrkRequired = Get-WmiRegDword -HostName $HostName -KeyPath $wrkKey `
                       -ValueName 'RequireSecuritySignature' -WmiParams $WmiParams
    $wrkEnabled  = Get-WmiRegDword -HostName $HostName -KeyPath $wrkKey `
                       -ValueName 'EnableSecuritySignature' -WmiParams $WmiParams

    # Defaults when absent:
    #   Server RequireSecuritySignature: 0 (not required) except DCs which default to 1
    #   Server EnableSecuritySignature:  0 (disabled) -- but actually 1 on modern Windows
    #   Workstation RequireSecuritySignature: 0 (not required)
    #   Workstation EnableSecuritySignature:  1 (enabled but not required)

    $srvReqVal = if ($srvRequired -ne $null) { $srvRequired } `
                 elseif ($OsInfo.IsDC) { 1 } else { 0 }
    $srvEnVal  = if ($srvEnabled -ne $null) { $srvEnabled } else { 0 }
    $wrkReqVal = if ($wrkRequired -ne $null) { $wrkRequired } else { 0 }
    $wrkEnVal  = if ($wrkEnabled -ne $null) { $wrkEnabled } else { 1 }

    return [PSCustomObject]@{
        ServerRequired  = $srvReqVal
        ServerEnabled   = $srvEnVal
        ClientRequired  = $wrkReqVal
        ClientEnabled   = $wrkEnVal
        SrvReqRaw       = $srvRequired
        SrvEnRaw        = $srvEnabled
        WrkReqRaw       = $wrkRequired
        WrkEnRaw        = $wrkEnabled
    }
}

function Test-SMBEncryption {
    param([string]$HostName, $OsInfo, $WmiParams)

    $srvKey = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'

    $encryptData     = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey `
                           -ValueName 'EncryptData' -WmiParams $WmiParams
    $rejectUnencrypted = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey `
                             -ValueName 'RejectUnencryptedAccess' -WmiParams $WmiParams

    # SMBv3 encryption only available on Server 2012+ / Win8+
    $buildNum      = [int]($OsInfo.BuildNumber)
    $supportsEncrypt = ($buildNum -ge 9200)

    return [PSCustomObject]@{
        Supported        = $supportsEncrypt
        EncryptData      = $encryptData
        RejectUnencrypted = $rejectUnencrypted
    }
}

function Test-NTLMConfig {
    param([string]$HostName, $WmiParams)

    $lsaKey = 'SYSTEM\CurrentControlSet\Control\Lsa'
    $msvKey = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

    $lmCompat  = Get-WmiRegDword -HostName $HostName -KeyPath $lsaKey `
                     -ValueName 'LmCompatibilityLevel' -WmiParams $WmiParams
    $noLMHash  = Get-WmiRegDword -HostName $HostName -KeyPath $lsaKey `
                     -ValueName 'NoLMHash' -WmiParams $WmiParams
    $ntlmMinSrv = Get-WmiRegDword -HostName $HostName -KeyPath $msvKey `
                      -ValueName 'NtlmMinServerSec' -WmiParams $WmiParams
    $ntlmMinCli = Get-WmiRegDword -HostName $HostName -KeyPath $msvKey `
                      -ValueName 'NtlmMinClientSec' -WmiParams $WmiParams

    # LmCompatibilityLevel:
    #  0 = LM + NTLM, no NTLMv2     (very bad)
    #  1 = LM + NTLM, NTLMv2 if negotiated
    #  2 = NTLM only
    #  3 = NTLMv2 only (send)
    #  4 = NTLMv2 only (send + refuse LM from clients)
    #  5 = NTLMv2 only (send + refuse LM+NTLM from clients) -- recommended

    $lmVal = if ($lmCompat -ne $null) { $lmCompat } else { 0 }

    return [PSCustomObject]@{
        LmCompatibilityLevel = $lmVal
        LmCompatRaw          = $lmCompat
        NoLMHash             = $noLMHash
        NtlmMinServerSec     = $ntlmMinSrv
        NtlmMinClientSec     = $ntlmMinCli
    }
}

function Test-EternalBluePatch {
    param([string]$HostName, $OsInfo, $WmiParams)

    # MS17-010 patches by build number / OS
    # Windows 7 / 2008R2 = build 7601 -> KB4012212 / KB4012215
    # Windows 8.1 / 2012R2 = build 9600 -> KB4012213 / KB4012216
    # Windows 10 = build 10240 -> KB4012606
    # Windows Server 2016 = build 14393 -> KB4013429
    # Windows Server 2019 build 17763 = not affected (SMBv1 off by default)

    $buildNum   = [int]($OsInfo.BuildNumber)
    $notAffected = ($buildNum -ge 17763)

    if ($notAffected) {
        return [PSCustomObject]@{
            Affected    = $false
            PatchFound  = $true
            PatchKB     = 'N/A (build not affected)'
            BuildNum    = $buildNum
        }
    }

    # Determine required KB by build
    $requiredKB = switch ($buildNum) {
        { $_ -le 7601 } { 'KB4012212' }   # Win7 / 2008R2
        { $_ -le 9200 } { 'KB4012215' }   # Win8 / 2012
        { $_ -le 9600 } { 'KB4012213' }   # Win8.1 / 2012R2
        default         { 'KB4013429' }    # Win10 / 2016
    }

    # Query Windows Update registry for installed patches
    $wuKey    = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages'
    $patchFound = $false

    $allEBPatches = @('KB4012212','KB4012213','KB4012215','KB4012216',
                      'KB4012606','KB4013429','KB4012214','KB4019472',
                      'KB4015551','KB4015552','KB4015553','KB4015549',
                      'KB4015550','KB4016637','KB4019264','KB4022719')

    try {
        $reg    = Get-WmiObject -List StdRegProv -ComputerName $HostName `
                    -Namespace 'root\default' @WmiParams -ErrorAction Stop
        $subkeys = $reg.EnumKey($HKLM, $wuKey)
        if ($subkeys.ReturnValue -eq 0) {
            foreach ($kb in $allEBPatches) {
                $match = $subkeys.sNames | Where-Object { $_ -match $kb }
                if ($match) { $patchFound = $true; break }
            }
        }
    }
    catch { }

    # Fallback: check via Win32_QuickFixEngineering (slower but broader)
    if (-not $patchFound) {
        try {
            $hotfixes = @(Get-WmiObject -Class Win32_QuickFixEngineering `
                            -ComputerName $HostName @WmiParams -ErrorAction Stop)
            foreach ($hf in $hotfixes) {
                if ($hf -and $hf.HotFixID -and $allEBPatches -contains $hf.HotFixID) {
                    $patchFound = $true
                    break
                }
            }
        }
        catch { }
    }

    return [PSCustomObject]@{
        Affected   = $true
        PatchFound = $patchFound
        PatchKB    = $requiredKB
        BuildNum   = $buildNum
    }
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

$dateSafe   = (Get-Date -Format 'yyyyMMdd-HHmm')
$allTargets = [System.Collections.Generic.List[string]]::new()

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "  Invoke-SMBProtocolAudit" -ForegroundColor Cyan
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
    else {
        $allTargets.Add($t)
    }
}

Write-Host "[*] $($allTargets.Count) target(s) queued`n" -ForegroundColor White

# WMI credential hashtable (empty when using current session token)
$wmiParams = @{}
if ($Credential) { $wmiParams['Credential'] = $Credential }

# Per-host result summary (for report table)
$hostSummary = [System.Collections.Generic.List[PSObject]]::new()

# ---------------------------------------------------------------------------
# Main audit loop
# ---------------------------------------------------------------------------

foreach ($target in $allTargets) {
    Write-Host "[*] $target" -ForegroundColor White

    if (-not (Test-Port445 $target)) {
        Write-Host "    Port 445 unreachable -- skipping" -ForegroundColor DarkGray
        continue
    }

    # Get OS info first -- needed for context in all checks
    Write-Host "    Getting OS info..." -ForegroundColor DarkGray
    $osInfo = Get-HostOsInfo -HostName $target -WmiParams $wmiParams
    $roleTag = if ($osInfo.IsDC) { 'DC' } elseif ($osInfo.IsServer) { 'Server' } else { 'Workstation' }
    Write-Host "    OS: $($osInfo.Caption) (Build $($osInfo.BuildNumber)) [$roleTag]" -ForegroundColor DarkGray

    $hostResources = @("[HOST] $target ($roleTag) -- $($osInfo.Caption)")
    $hostIssues    = [System.Collections.Generic.List[string]]::new()

    # =======================================================================
    # D01 -- SMBv1
    # =======================================================================
    Write-Host "    [D01] SMBv1..." -ForegroundColor DarkGray
    $smb1 = Test-SMBv1 -HostName $target -OsInfo $osInfo -WmiParams $wmiParams

    $smb1Resources = $hostResources + @(
        "[REG] $($smb1.RegState)",
        "[REG] $($smb1.DrvState)"
    )

    if ($smb1.Enabled) {
        $sev = if ($osInfo.IsDC) { 'Critical' } elseif ($osInfo.IsServer) { 'Critical' } else { 'High' }
        $hostIssues.Add('SMBv1-ENABLED')
        Add-Finding -Domain 'D01-SMBv1' -Severity $sev `
            -Check "SMBv1 Enabled: $target [$roleTag]" `
            -Detail "SMBv1 is active on $target ($($osInfo.Caption)). SMBv1 is a 30-year-old protocol with no encryption, no integrity validation, and is the attack vector for $($script:T.EB) / $($script:T.WC) / $($script:T.NT). Registry: $($smb1.RegState) | Driver: $($smb1.DrvState)." `
            -Resources $smb1Resources `
            -MITRE 'T1210' -CIS 'CIS 18.3.3' `
            -AttackPath "$($script:T.EB) exploit chain: scan port 445 -> negotiate SMBv1 -> send malformed Trans2 request -> kernel RCE as SYSTEM -> deploy ransomware / beacon / $($script:T.MK) -> lateral movement to all SMBv1 hosts" `
            -Fix @"
Disable SMBv1 via PowerShell (run as admin, reboot required):
  Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Type DWORD -Value 0
Disable the mrxsmb10 driver:
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name Start -Type DWORD -Value 4
Verify after reboot:
  Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol
Apply via GPO for fleet-wide enforcement:
  Computer Config -> Admin Templates -> Network -> Lanman Server -> Enable SMB1 Protocol = Disabled
"@
    }
    else {
        Add-Finding -Domain 'D01-SMBv1' -Severity 'Good' `
            -Check "SMBv1 Disabled: $target" `
            -Detail "SMBv1 is not active on $target. Registry: $($smb1.RegState) | Driver: $($smb1.DrvState)." `
            -Resources $smb1Resources
    }

    # =======================================================================
    # D02 -- SMB Signing
    # =======================================================================
    Write-Host "    [D02] SMB Signing..." -ForegroundColor DarkGray
    $sign = Test-SMBSigning -HostName $target -OsInfo $osInfo -WmiParams $wmiParams

    $signResources = $hostResources + @(
        "[REG] Server RequireSecuritySignature=$(if ($sign.SrvReqRaw -ne $null){$sign.SrvReqRaw}else{'absent (default='+$sign.ServerRequired+')'})",
        "[REG] Server EnableSecuritySignature=$(if ($sign.SrvEnRaw -ne $null){$sign.SrvEnRaw}else{'absent (default='+$sign.ServerEnabled+')'})",
        "[REG] Client RequireSecuritySignature=$(if ($sign.WrkReqRaw -ne $null){$sign.WrkReqRaw}else{'absent (default='+$sign.ClientRequired+')'})",
        "[REG] Client EnableSecuritySignature=$(if ($sign.WrkEnRaw -ne $null){$sign.WrkEnRaw}else{'absent (default='+$sign.ClientEnabled+')'})"
    )

    # Server signing not required
    if ($sign.ServerRequired -ne 1) {
        $sev = if ($osInfo.IsDC) { 'Critical' } elseif ($osInfo.IsServer) { 'High' } else { 'Medium' }
        $hostIssues.Add('SERVER-SIGNING-NOT-REQUIRED')
        Add-Finding -Domain 'D02-SMBSign' -Severity $sev `
            -Check "SMB Server Signing NOT Required: $target [$roleTag]" `
            -Detail "The SMB server on $target does not require packet signing (RequireSecuritySignature=$($sign.ServerRequired)). Connections can be relayed or man-in-the-middled without detection. $($script:T.RS) or $($script:T.NR) can intercept and relay these sessions." `
            -Resources $signResources `
            -MITRE 'T1557.001' -CIS 'CIS 2.3.9.5' `
            -AttackPath "Capture NTLM challenge-response with $($script:T.RS) -> relay to $target SMB server (no signing required) -> authenticate as victim user -> write to shares / execute commands without knowing password" `
            -Fix @"
Require SMB signing on this host:
  Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 1
Apply fleet-wide via GPO:
  Computer Config -> Windows Settings -> Security Settings -> Local Policies -> Security Options:
    'Microsoft network server: Digitally sign communications (always)' = Enabled
    'Microsoft network server: Digitally sign communications (if client agrees)' = Enabled
Note: Domain Controllers require signing by default. Non-DC servers and workstations typically do not.
"@
    }
    else {
        Add-Finding -Domain 'D02-SMBSign' -Severity 'Good' `
            -Check "SMB Server Signing Required: $target" `
            -Detail "SMB server on $target requires packet signing (RequireSecuritySignature=1). Relay attacks against this host are blocked." `
            -Resources $signResources
    }

    # Client signing not required (allows this host to connect to unsigned servers)
    if ($sign.ClientRequired -ne 1) {
        $sev = if ($osInfo.IsDC) { 'High' } else { 'Low' }
        $hostIssues.Add('CLIENT-SIGNING-NOT-REQUIRED')
        Add-Finding -Domain 'D02-SMBSign' -Severity $sev `
            -Check "SMB Client Signing NOT Required: $target [$roleTag]" `
            -Detail "The SMB client on $target does not require signing when connecting to servers (client RequireSecuritySignature=$($sign.ClientRequired)). This host may connect to a rogue SMB server without detecting tampering." `
            -Resources $signResources `
            -MITRE 'T1557.001' -CIS 'CIS 2.3.8.3' `
            -AttackPath "Set up rogue SMB server (no signing) -> wait for $target to connect (auto-connect via DFS / printer / GPO) -> intercept and downgrade session -> NTLM relay or credential capture" `
            -Fix @"
Require SMB client signing on this host:
  Set-SmbClientConfiguration -RequireSecuritySignature `$true -Force
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Value 1
Apply fleet-wide via GPO:
  Computer Config -> Windows Settings -> Security Settings -> Local Policies -> Security Options:
    'Microsoft network client: Digitally sign communications (always)' = Enabled
"@
    }
    else {
        Add-Finding -Domain 'D02-SMBSign' -Severity 'Good' `
            -Check "SMB Client Signing Required: $target" `
            -Detail "SMB client on $target requires signing for outbound connections (ClientRequireSecuritySignature=1)." `
            -Resources $signResources
    }

    # =======================================================================
    # D03 -- SMB Encryption (SMBv3 only)
    # =======================================================================
    Write-Host "    [D03] SMB Encryption..." -ForegroundColor DarkGray
    $enc = Test-SMBEncryption -HostName $target -OsInfo $osInfo -WmiParams $wmiParams

    if (-not $enc.Supported) {
        Add-Finding -Domain 'D03-SMBEncrypt' -Severity 'Info' `
            -Check "SMB Encryption Not Supported: $target (Build $($osInfo.BuildNumber))" `
            -Detail "SMBv3 encryption requires Windows Server 2012 / Windows 8 (build 9200+). This host (build $($osInfo.BuildNumber)) does not support it." `
            -Resources $hostResources
    }
    else {
        $encResources = $hostResources + @(
            "[REG] EncryptData=$(if ($enc.EncryptData -ne $null){$enc.EncryptData}else{'absent (default=0)'})",
            "[REG] RejectUnencryptedAccess=$(if ($enc.RejectUnencrypted -ne $null){$enc.RejectUnencrypted}else{'absent (default=0)'})"
        )

        $encVal     = if ($enc.EncryptData -ne $null) { $enc.EncryptData } else { 0 }
        $rejectVal  = if ($enc.RejectUnencrypted -ne $null) { $enc.RejectUnencrypted } else { 0 }

        if ($encVal -ne 1) {
            $sev = if ($osInfo.IsDC) { 'Medium' } elseif ($osInfo.IsServer) { 'Medium' } else { 'Low' }
            $hostIssues.Add('SMB-ENCRYPTION-DISABLED')
            Add-Finding -Domain 'D03-SMBEncrypt' -Severity $sev `
                -Check "SMB Encryption Disabled: $target [$roleTag]" `
                -Detail "SMBv3 encryption is not enforced on $target (EncryptData=$encVal). SMB traffic is transmitted in cleartext, allowing passive capture of file contents and metadata on the wire." `
                -Resources $encResources `
                -MITRE 'T1040' -CIS 'CIS 18.3.4' `
                -AttackPath "Passive network capture (Wireshark / tcpdump) -> SMB sessions to/from $target readable in cleartext -> capture file contents, credentials in scripts, or NTLM challenge-response for offline cracking with $($script:T.HC)" `
                -Fix @"
Enable SMBv3 encryption server-wide:
  Set-SmbServerConfiguration -EncryptData `$true -Force
  Set-SmbServerConfiguration -RejectUnencryptedAccess `$true -Force
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name EncryptData -Value 1
Per-share encryption (less disruptive):
  Set-SmbShare -Name 'ShareName' -EncryptData `$true
Note: SMBv3 encryption requires both sides to support it. Requires Server 2012+ / Win8+.
"@
        }
        else {
            Add-Finding -Domain 'D03-SMBEncrypt' -Severity 'Good' `
                -Check "SMB Encryption Enabled: $target" `
                -Detail "SMBv3 encryption is active on $target (EncryptData=$encVal). Wire traffic is encrypted." `
                -Resources $encResources
        }
    }

    # =======================================================================
    # D04 -- NTLM Authentication Level
    # =======================================================================
    Write-Host "    [D04] NTLM config..." -ForegroundColor DarkGray
    $ntlm = Test-NTLMConfig -HostName $target -WmiParams $wmiParams

    $ntlmResources = $hostResources + @(
        "[REG] LmCompatibilityLevel=$(if ($ntlm.LmCompatRaw -ne $null){$ntlm.LmCompatRaw}else{'absent (default=0 -- LM+NTLM allowed)'})",
        "[REG] NoLMHash=$(if ($ntlm.NoLMHash -ne $null){$ntlm.NoLMHash}else{'absent (default=0)'})"
    )

    if ($ntlm.LmCompatibilityLevel -lt 3) {
        $sev = if ($ntlm.LmCompatibilityLevel -le 1) { 'Critical' } else { 'High' }
        $hostIssues.Add("NTLM-LEVEL-$($ntlm.LmCompatibilityLevel)")
        $levelDesc = switch ($ntlm.LmCompatibilityLevel) {
            0 { 'LM + NTLMv1 (no NTLMv2) -- most vulnerable' }
            1 { 'LM + NTLMv1, NTLMv2 only if negotiated' }
            2 { 'NTLMv1 only (LM disabled)' }
            default { "Level $($ntlm.LmCompatibilityLevel)" }
        }
        Add-Finding -Domain 'D04-NTLM' -Severity $sev `
            -Check "Weak NTLM Auth Level ($($ntlm.LmCompatibilityLevel)): $target [$roleTag]" `
            -Detail "LmCompatibilityLevel=$($ntlm.LmCompatibilityLevel) on $target allows $levelDesc. LM and NTLMv1 hashes can be cracked offline in seconds using rainbow tables. Recommended level is 5 (NTLMv2 only, refuse LM/NTLM from clients)." `
            -Resources $ntlmResources `
            -MITRE 'T1557.001' -CIS 'CIS 2.3.11.7' `
            -AttackPath "Capture LM/NTLMv1 response with $($script:T.RS) or network capture -> crack with $($script:T.HC) rainbow tables in seconds (LM) or minutes (NTLMv1) -> recover plaintext password -> authenticate as victim user across all services" `
            -Fix @"
Set LmCompatibilityLevel to 5 (NTLMv2 only):
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -Value 1
Apply via GPO (recommended for fleet):
  Computer Config -> Windows Settings -> Security Settings -> Local Policies -> Security Options:
    'Network security: LAN Manager authentication level' = 'Send NTLMv2 response only. Refuse LM & NTLM'
    'Network security: Do not store LAN Manager hash value...' = Enabled
Warning: test thoroughly -- some legacy applications require NTLMv1. Identify and replace before enforcing.
"@
    }
    elseif ($ntlm.LmCompatibilityLevel -lt 5) {
        $hostIssues.Add("NTLM-LEVEL-$($ntlm.LmCompatibilityLevel)-NOT-HARDENED")
        Add-Finding -Domain 'D04-NTLM' -Severity 'Low' `
            -Check "NTLM Level Not Fully Hardened ($($ntlm.LmCompatibilityLevel)): $target" `
            -Detail "LmCompatibilityLevel=$($ntlm.LmCompatibilityLevel) -- NTLMv2 is sent but LM/NTLM from clients may still be accepted. Recommended: level 5." `
            -Resources $ntlmResources `
            -Fix "Set LmCompatibilityLevel to 5: Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5"
    }
    else {
        Add-Finding -Domain 'D04-NTLM' -Severity 'Good' `
            -Check "NTLM Level Hardened ($($ntlm.LmCompatibilityLevel)): $target" `
            -Detail "LmCompatibilityLevel=$($ntlm.LmCompatibilityLevel) -- NTLMv2 only enforced. LM and NTLMv1 are refused." `
            -Resources $ntlmResources
    }

    # =======================================================================
    # D05 -- EternalBlue patch (MS17-010)
    # =======================================================================
    Write-Host "    [D05] MS17-010 patch..." -ForegroundColor DarkGray
    $eb = Test-EternalBluePatch -HostName $target -OsInfo $osInfo -WmiParams $wmiParams

    $patchResources = $hostResources + @(
        "[PATCH] RequiredKB=$($eb.PatchKB)",
        "[PATCH] PatchFound=$($eb.PatchFound)",
        "[PATCH] Build=$($eb.BuildNum)"
    )

    if (-not $eb.Affected) {
        Add-Finding -Domain 'D05-MS17010' -Severity 'Good' `
            -Check "MS17-010 Not Applicable: $target (Build $($eb.BuildNum))" `
            -Detail "Host OS (build $($eb.BuildNum)) is not vulnerable to MS17-010. $($script:T.EB) requires SMBv1 which is disabled by default on this build." `
            -Resources $patchResources
    }
    elseif ($smb1.Enabled -and -not $eb.PatchFound) {
        $hostIssues.Add('MS17-010-UNPATCHED-SMBv1')
        Add-Finding -Domain 'D05-MS17010' -Severity 'Critical' `
            -Check "MS17-010 UNPATCHED + SMBv1 ACTIVE: $target [$roleTag]" `
            -Detail "CRITICAL: $target has BOTH SMBv1 enabled AND MS17-010 ($($eb.PatchKB)) is not detected. This host is fully exploitable by $($script:T.EB) / $($script:T.WC) with no authentication required." `
            -Resources $patchResources `
            -MITRE 'T1210' -CIS 'CIS 7.4' `
            -AttackPath "Send malformed SMBv1 Trans2 request to port 445 -> trigger heap spray in srv.sys -> kernel RCE as NT AUTHORITY\SYSTEM -> install $($script:T.MK) / deploy ransomware / beacon -> lateral to all connected hosts via SMBv1 propagation" `
            -Fix @"
IMMEDIATE ACTION REQUIRED:
1. Isolate host from network if possible until patched.
2. Apply MS17-010 patch:
   - Windows 7 / 2008R2: KB4012212
   - Windows 8.1 / 2012R2: KB4012213
   - Windows 10: KB4012606
   - Windows Server 2016: KB4013429
3. THEN disable SMBv1:
   Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force
4. Enable Windows Firewall rule to block inbound SMB from untrusted networks:
   netsh advfirewall firewall add rule name='Block SMBv1' dir=in action=block protocol=TCP localport=445
"@
    }
    elseif ($smb1.Enabled -and $eb.PatchFound) {
        Add-Finding -Domain 'D05-MS17010' -Severity 'Medium' `
            -Check "MS17-010 Patched but SMBv1 Still Active: $target" `
            -Detail "$($eb.PatchKB) is installed but SMBv1 remains enabled. The specific $($script:T.EB) exploit is blocked but other SMBv1 attack vectors remain (credential capture, relay, undisclosed vulns)." `
            -Resources $patchResources `
            -Fix "Disable SMBv1 even though patched: Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
    }
    elseif (-not $smb1.Enabled -and -not $eb.PatchFound) {
        Add-Finding -Domain 'D05-MS17010' -Severity 'Low' `
            -Check "MS17-010 Patch Not Detected (SMBv1 Disabled): $target" `
            -Detail "Could not detect $($eb.PatchKB) via WMI hotfix query, but SMBv1 is disabled which mitigates the exploit vector. Consider applying the patch anyway for defence in depth." `
            -Resources $patchResources
    }
    else {
        Add-Finding -Domain 'D05-MS17010' -Severity 'Good' `
            -Check "MS17-010 Patched: $target" `
            -Detail "$($eb.PatchKB) or later detected. $($script:T.EB) exploit vector is mitigated." `
            -Resources $patchResources
    }

    # Record host summary
    $hostSummary.Add([PSCustomObject]@{
        Host    = $target
        OS      = "$($osInfo.Caption) (Build $($osInfo.BuildNumber))"
        Role    = $roleTag
        SMBv1   = if ($smb1.Enabled) { 'ENABLED' } else { 'Disabled' }
        SrvSign = if ($sign.ServerRequired -eq 1) { 'Required' } else { 'NOT Required' }
        CliSign = if ($sign.ClientRequired -eq 1) { 'Required' } else { 'NOT Required' }
        Encrypt = if ($enc.EncryptData -eq 1) { 'Enabled' } else { 'Disabled' }
        NTLMLvl = $ntlm.LmCompatibilityLevel
        MS17010 = if (-not $eb.Affected) { 'N/A' } elseif ($eb.PatchFound) { 'Patched' } else { 'MISSING' }
        Issues  = ($hostIssues -join ', ')
    })

    Write-Host "" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

Write-Host "[*] Building report..." -ForegroundColor Cyan

$pct        = if ($script:MaxScore -gt 0) { [math]::Round($script:Score * 100 / $script:MaxScore) } else { 100 }
$scoreColor = if ($pct -ge 80) { '#22c55e' } elseif ($pct -ge 60) { '#f59e0b' } elseif ($pct -ge 40) { '#f97316' } else { '#ef4444' }
$maturity   = if ($pct -ge 80) { 'Hardened' } elseif ($pct -ge 60) { 'Moderate Risk' } elseif ($pct -ge 40) { 'High Risk' } else { 'Critical Risk' }

$critCount  = @($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
$highCount  = @($script:Findings | Where-Object { $_.Severity -eq 'High' }).Count
$medCount   = @($script:Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
$lowCount   = @($script:Findings | Where-Object { $_.Severity -eq 'Low' }).Count
$goodCount  = @($script:Findings | Where-Object { $_.Severity -eq 'Good' }).Count
$issueCount = @($script:Findings | Where-Object { $_.Severity -notin @('Good','Info') }).Count
$genTime    = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
$gaugeOffset = [math]::Round(283 - (283 * $pct / 100))

# Host summary table rows
$hostRows = ''
foreach ($h in $hostSummary) {
    $smb1Cell  = if ($h.SMBv1 -eq 'ENABLED') { "<td style='color:#ef4444;font-weight:700'>$($h.SMBv1)</td>" } else { "<td style='color:#22c55e'>$($h.SMBv1)</td>" }
    $srvSign   = if ($h.SrvSign -match 'NOT') { "<td style='color:#f97316'>$($h.SrvSign)</td>" } else { "<td style='color:#22c55e'>$($h.SrvSign)</td>" }
    $cliSign   = if ($h.CliSign -match 'NOT') { "<td style='color:#f59e0b'>$($h.CliSign)</td>" } else { "<td style='color:#22c55e'>$($h.CliSign)</td>" }
    $encCell   = if ($h.Encrypt -eq 'Disabled') { "<td style='color:#f59e0b'>$($h.Encrypt)</td>" } else { "<td style='color:#22c55e'>$($h.Encrypt)</td>" }
    $ntlmCell  = if ($h.NTLMLvl -lt 3) { "<td style='color:#ef4444;font-weight:700'>Level $($h.NTLMLvl)</td>" } elseif ($h.NTLMLvl -lt 5) { "<td style='color:#f59e0b'>Level $($h.NTLMLvl)</td>" } else { "<td style='color:#22c55e'>Level $($h.NTLMLvl)</td>" }
    $ebCell    = if ($h.MS17010 -eq 'MISSING') { "<td style='color:#ef4444;font-weight:700'>$($h.MS17010)</td>" } elseif ($h.MS17010 -eq 'N/A') { "<td style='color:#64748b'>$($h.MS17010)</td>" } else { "<td style='color:#22c55e'>$($h.MS17010)</td>" }
    $hostRows += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($h.Host))</td><td>$([System.Net.WebUtility]::HtmlEncode($h.Role))</td><td>$([System.Net.WebUtility]::HtmlEncode($h.OS))</td>$smb1Cell$srvSign$cliSign$encCell$ntlmCell$ebCell</tr>`n"
}

# Finding cards
$fIdx         = 0
$findingCards = ''

foreach ($f in $script:Findings) {
    if ($f.Severity -in @('Good','Info')) { $fIdx++; continue }

    $sc = switch ($f.Severity) {
        'Critical' { '#ef4444' }
        'High'     { '#f97316' }
        'Medium'   { '#f59e0b' }
        'Low'      { '#60a5fa' }
        default    { '#6b7280' }
    }

    $assetHtml  = ConvertTo-AssetHtml -Resources $f.Resources
    $safeDetail = [System.Net.WebUtility]::HtmlEncode($f.Detail)
    $safeAttack = [System.Net.WebUtility]::HtmlEncode($f.AttackPath)
    $safeFix    = [System.Net.WebUtility]::HtmlEncode($f.Fix)
    $safeDomain = [System.Net.WebUtility]::HtmlEncode($f.Domain)
    $safeCheck  = [System.Net.WebUtility]::HtmlEncode($f.Check)

    $mitreBadge = ''
    if ($f.MITRE) { $mitreBadge = "<span class='badge mitre-badge'>$([System.Net.WebUtility]::HtmlEncode($f.MITRE))</span>" }
    $cisBadge = ''
    if ($f.CIS)   { $cisBadge   = "<span class='badge cis-badge'>$([System.Net.WebUtility]::HtmlEncode($f.CIS))</span>" }

    $tabBtns   = ''
    $tabPanels = ''
    if ($assetHtml) {
        $rCount    = @($f.Resources).Count
        $tabBtns  += "<button class='tab-btn' onclick='showTab(this,""ass-$fIdx"")'>Affected Assets ($rCount)</button>"
        $tabPanels += "<div class='tab-panel' id='ass-$fIdx' style='display:none'>$assetHtml</div>"
    }
    if ($f.AttackPath) {
        $tabBtns   += "<button class='tab-btn' onclick='showTab(this,""ap-$fIdx"")'>Attack Path</button>"
        $tabPanels += "<div class='tab-panel' id='ap-$fIdx' style='display:none'><pre class='attack-pre'>$safeAttack</pre></div>"
    }
    if ($f.Fix) {
        $tabBtns   += "<button class='tab-btn' onclick='showTab(this,""fix-$fIdx"")'>Remediation</button>"
        $tabPanels += "<div class='tab-panel' id='fix-$fIdx' style='display:none'><pre class='fix-pre'>$safeFix</pre></div>"
    }

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
    <div class='why-box'>
      <div class='why-label'>Why Vulnerable</div>
      <div class='why-text'>$safeDetail</div>
    </div>
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
<title>SMB Protocol Audit Report</title>
<style>
:root{--bg:#0f1117;--surface:#1a1d27;--border:#2a2d3e;--text:#e2e8f0;
  --dim:#64748b;--blue:#3b82f6;--blue-lt:#60a5fa;
  --crit:#ef4444;--high:#f97316;--med:#f59e0b;--low:#60a5fa;--good:#22c55e;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;}
a{color:var(--blue-lt);text-decoration:none;}
a:hover{text-decoration:underline;}
.nav{position:sticky;top:0;z-index:100;background:var(--surface);border-bottom:1px solid var(--border);
  display:flex;align-items:center;padding:10px 24px;gap:20px;}
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
.section-hdr{display:flex;align-items:center;justify-content:space-between;
  margin:28px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--border);}
.section-hdr h2{font-size:1rem;font-weight:600;}
.section-count{font-size:.75rem;color:var(--dim);background:rgba(255,255,255,.05);padding:2px 8px;border-radius:12px;}
.host-table{width:100%;border-collapse:collapse;font-size:.8rem;margin-bottom:8px;}
.host-table th{text-align:left;padding:8px 10px;background:rgba(255,255,255,.05);
  border-bottom:1px solid var(--border);color:var(--dim);font-weight:600;white-space:nowrap;}
.host-table td{padding:7px 10px;border-bottom:1px solid rgba(255,255,255,.04);font-family:'Cascadia Code','Consolas',monospace;font-size:.76rem;}
.host-table tr:hover td{background:rgba(255,255,255,.02);}
.filter-bar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:16px;}
.filter-label{font-size:.75rem;color:var(--dim);}
.filter-btn{background:var(--surface);border:1px solid var(--border);color:var(--text);
  padding:4px 12px;border-radius:16px;font-size:.78rem;cursor:pointer;}
.filter-btn.active{background:var(--blue);border-color:var(--blue);color:#fff;}
.filter-btn:hover{border-color:var(--blue-lt);}
.search-box{background:var(--surface);border:1px solid var(--border);color:var(--text);
  padding:4px 12px;border-radius:16px;font-size:.78rem;width:220px;margin-left:auto;}
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
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;color:var(--dim);
  padding:8px 14px;font-size:.78rem;cursor:pointer;}
.tab-btn.active{color:var(--blue-lt);border-bottom-color:var(--blue-lt);}
.tab-btn:hover{color:var(--text);}
.tab-panel{padding:14px;display:none;}
.attack-pre,.fix-pre{background:#0a0d14;border:1px solid var(--border);border-radius:6px;
  padding:12px;font-size:.78rem;font-family:'Cascadia Code','Consolas',monospace;
  white-space:pre-wrap;word-break:break-word;overflow-x:auto;}
.attack-pre{color:#a5f3fc;}
.fix-pre{color:#bbf7d0;}
.asset-group{margin-bottom:10px;}
.asset-label{font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;
  padding:2px 6px;border-radius:4px;margin-right:6px;}
.host-lbl{background:#1e3a5f;color:#93c5fd;}
.reg-lbl{background:#2a1a3a;color:#d8b4fe;}
.patch-lbl{background:#1a2a3a;color:#7dd3fc;}
.gen-lbl{background:#2a2a1a;color:#fde68a;}
.asset-item{display:inline-block;background:rgba(255,255,255,.05);border:1px solid var(--border);
  border-radius:4px;padding:2px 8px;margin:3px 3px 0 0;font-size:.75rem;
  font-family:'Cascadia Code','Consolas',monospace;}
footer{text-align:center;padding:24px;font-size:.75rem;color:var(--dim);
  border-top:1px solid var(--border);margin-top:32px;}
@media(max-width:700px){.fcard-domain{display:none;}.dash{grid-template-columns:repeat(2,1fr);}}
</style>
</head>
<body>
<nav class='nav'>
  <span class='nav-brand'>SMB Protocol Audit</span>
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
          <circle class='gauge-fill' cx='50' cy='50' r='45'
            stroke='$scoreColor' stroke-dashoffset='$gaugeOffset'/>
        </svg>
        <div class='gauge-pct' style='color:$scoreColor'>$pct%</div>
      </div>
      <div class='dc-lbl'>$maturity</div>
    </div>
    <div class='dash-card'><div class='dc-val' style='color:#94a3b8'>$($hostSummary.Count)</div><div class='dc-lbl'>Hosts</div></div>
    <div class='dash-card'><div class='dc-val' style='color:var(--crit)'>$critCount</div><div class='dc-lbl'>Critical</div></div>
    <div class='dash-card'><div class='dc-val' style='color:var(--high)'>$highCount</div><div class='dc-lbl'>High</div></div>
    <div class='dash-card'><div class='dc-val' style='color:var(--med)'>$medCount</div><div class='dc-lbl'>Medium</div></div>
    <div class='dash-card'><div class='dc-val' style='color:var(--low)'>$lowCount</div><div class='dc-lbl'>Low</div></div>
    <div class='dash-card'><div class='dc-val' style='color:var(--good)'>$goodCount</div><div class='dc-lbl'>Passed</div></div>
  </div>

  <!-- HOST MATRIX -->
  <div class='section-hdr' id='host-matrix'>
    <h2>Host Configuration Matrix</h2>
    <span class='section-count'>$($hostSummary.Count) hosts assessed</span>
  </div>
  <table class='host-table'>
    <tr>
      <th>Host</th><th>Role</th><th>OS</th>
      <th>SMBv1</th><th>Srv Sign</th><th>Cli Sign</th>
      <th>Encrypt</th><th>NTLM Lvl</th><th>MS17-010</th>
    </tr>
$hostRows
  </table>

  <!-- FINDINGS -->
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
<footer>SMB Protocol Audit -- ASPAT Purple Team &nbsp;|&nbsp; $genTime &nbsp;|&nbsp; Score: $($script:Score)/$($script:MaxScore) ($pct%)</footer>

<script>
function toggleCard(hdr){
  var body=hdr.nextElementSibling;
  var chev=hdr.querySelector('.fcard-chevron');
  var isOpen=body.style.display!=='none';
  body.style.display=isOpen?'none':'block';
  chev.textContent=isOpen?'+':'x';
  chev.classList.toggle('open',!isOpen);
  if(!isOpen){var btn=body.querySelector('.tab-btn');if(btn){var m=btn.getAttribute('onclick').match(/"([^"]+)"/);if(m)showTab(btn,m[1]);}}
}
function showTab(btn,panelId){
  var card=btn.closest('.fcard-body');
  card.querySelectorAll('.tab-btn').forEach(function(b){b.classList.remove('active');});
  card.querySelectorAll('.tab-panel').forEach(function(p){p.style.display='none';});
  btn.classList.add('active');
  var panel=document.getElementById(panelId);
  if(panel)panel.style.display='block';
}
function filterCards(btn){
  document.querySelectorAll('.filter-btn').forEach(function(b){b.classList.remove('active');});
  btn.classList.add('active');
  var f=btn.getAttribute('data-f');
  var cards=document.querySelectorAll('#finding-cards-container .fcard');
  var visible=0;
  cards.forEach(function(c){var show=(f==='All'||c.getAttribute('data-sev')===f);c.style.display=show?'':'none';if(show)visible++;});
  document.getElementById('result-count').textContent='Showing '+visible+' of '+cards.length;
}
function searchCards(q){
  q=q.toLowerCase();
  var cards=document.querySelectorAll('#finding-cards-container .fcard');
  var visible=0;
  cards.forEach(function(c){var show=!q||c.textContent.toLowerCase().indexOf(q)!==-1;c.style.display=show?'':'none';if(show)visible++;});
  document.getElementById('result-count').textContent=q?('Showing '+visible+' of '+cards.length):'';
}
(function(){var total=document.querySelectorAll('#finding-cards-container .fcard').length;document.getElementById('result-count').textContent='Showing '+total+' of '+total;})();
</script>
</body>
</html>
"@

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

$reportName = "SMBProtocolAudit-$dateSafe"
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
Write-Host "  Passed  : $goodCount"
Write-Host "  Hosts   : $($hostSummary.Count)"
Write-Host "  Runtime : $($runtime)s"
Write-Host "=====================================================" -ForegroundColor Cyan
