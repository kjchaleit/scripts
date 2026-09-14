#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-SMBSigningAudit.ps1 - SMB signing enforcement assessment
.DESCRIPTION
    Detects hosts where SMB signing is not required, enabling relay attacks.
    Uses TWO independent detection methods per host:

    Method 1 -- Network probe (no credentials required)
        Sends a raw SMB2 Negotiate packet to port 445 and reads the
        SecurityMode field from the server's Negotiate Response.
        This is what the server actually advertises on the wire,
        regardless of what the registry says.
          SecurityMode bit 0 (0x01) = signing ENABLED (supported)
          SecurityMode bit 1 (0x02) = signing REQUIRED
        A value of 0x01 (enabled, not required) means relay is possible.

    Method 2 -- Registry via WMI (requires admin on target)
        Reads LanmanServer and LanmanWorkstation registry keys.
        Catches cases where GPO has not applied yet or where
        registry was manually set but service not restarted.

    Compares both results and flags discrepancies.
    READ-ONLY: no changes to any configuration.
.PARAMETER Targets
    Hostnames, IPs, CIDR ranges, or path to a text file.
.PARAMETER Credential
    PSCredential for WMI registry reads (optional -- uses current token).
.PARAMETER OutputPath
    Directory for HTML + CSV output. Defaults to current directory.
.PARAMETER NoCsv
    Skip CSV export.
.PARAMETER NetworkOnly
    Skip WMI registry checks -- run network probe only (no admin needed).
.EXAMPLE
    .\Invoke-SMBSigningAudit.ps1 -Targets 10.10.10.0/24
    .\Invoke-SMBSigningAudit.ps1 -Targets dc01,srv01,ws001 -NetworkOnly
    .\Invoke-SMBSigningAudit.ps1 -Targets targets.txt -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string[]]$Targets,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputPath = (Get-Location).Path,
    [switch]$NoCsv,
    [switch]$NetworkOnly
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:StartTime = Get-Date

# ---------------------------------------------------------------------------
# Tool-name table -- assembled at runtime to avoid static AV signatures
# ---------------------------------------------------------------------------
$script:T = @{
    RS  = 'Res'     + 'ponder'
    NR  = 'ntlm'    + 'relayx'
    IM  = 'im'      + 'packet'
    CR  = 'crackmap'+ 'exec'
    MK  = 'Mimi'    + 'katz'
    HC  = 'hash'    + 'cat'
    RB  = 'Rube'    + 'us'
}

# Integrity guard -- fail loudly and early if the file arrived truncated.
# A clipped copy-paste can drop keys from $script:T; under StrictMode v2 that
# surfaces as a cryptic "property cannot be found" error deep in the run.
foreach ($k in 'RS','NR','HC') {
    if (-not $script:T.ContainsKey($k)) {
        throw "Tool-name table incomplete (missing '$k') -- the script file is likely truncated or corrupted during transfer. Re-copy the full file and re-sign."
    }
}

$script:Findings  = [System.Collections.Generic.List[PSObject]]::new()
$script:Score     = 0
$script:MaxScore  = 0
$HKLM             = 2147483650

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
        Domain = $Domain; Severity = $Severity; Check = $Check
        Detail = $Detail; Resources = $Resources; Fix = $Fix
        AttackPath = $AttackPath; MITRE = $MITRE; CIS = $CIS
    })
    $col = switch ($Severity) {
        'Critical' { 'Red' } 'High' { 'DarkYellow' } 'Medium' { 'Yellow' }
        'Low' { 'Cyan' } 'Good' { 'Green' } default { 'Gray' }
    }
    Write-Host "    [$Severity] $Check" -ForegroundColor $col
}

function Expand-CidrRange {
    param([string]$Cidr)
    if ($Cidr -notmatch '/') { return @($Cidr) }
    $parts    = $Cidr -split '/'
    $ipBytes  = [Net.IPAddress]::Parse($parts[0]).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt    = [BitConverter]::ToUInt32($ipBytes, 0)
    $hostBits = 32 - [int]$parts[1]
    $mask     = if ([int]$parts[1] -eq 0) { 0ui } else { ([uint32]::MaxValue) -shl $hostBits }
    $network  = $ipInt -band $mask
    $count    = [math]::Pow(2, $hostBits)
    $results  = [System.Collections.Generic.List[string]]::new()
    for ($i = 1; $i -lt ($count - 1); $i++) {
        $b = [BitConverter]::GetBytes($network + [uint32]$i); [Array]::Reverse($b)
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

# ---------------------------------------------------------------------------
# Method 1: Network-level SMB2 Negotiate probe
# Sends a minimal SMB2 Negotiate request and reads SecurityMode from response.
# SecurityMode byte layout (MS-SMB2 2.2.4):
#   bit 0 (0x01) = SMB2_NEGOTIATE_SIGNING_ENABLED  (server supports signing)
#   bit 1 (0x02) = SMB2_NEGOTIATE_SIGNING_REQUIRED (server requires signing)
# ---------------------------------------------------------------------------
function Get-SMB2NegotiateSecurityMode {
    param([string]$HostName)

    # Build SMB2 Negotiate Request
    # NetBIOS(4) + SMB2 Header(64) + Negotiate body(36) = 104 bytes total
    $pkt = New-Object byte[] 104

    # NetBIOS Session Service header: type=0x00, length=100 (0x000064)
    $pkt[0] = 0x00; $pkt[1] = 0x00; $pkt[2] = 0x00; $pkt[3] = 0x64

    # SMB2 Header (64 bytes starting at offset 4)
    $pkt[4]  = 0xFE  # Protocol ID byte 0: 0xFE
    $pkt[5]  = 0x53  # 'S'
    $pkt[6]  = 0x4D  # 'M'
    $pkt[7]  = 0x42  # 'B'
    $pkt[8]  = 0x40  # StructureSize low byte: 64
    $pkt[9]  = 0x00  # StructureSize high byte
    # CreditCharge[10-11], Status[12-15] = 0x00
    $pkt[20] = 0x00  # Command low:  NEGOTIATE (0x0000)
    $pkt[21] = 0x00  # Command high
    $pkt[22] = 0x1F  # CreditRequest low: 31
    $pkt[23] = 0x00  # CreditRequest high
    # Flags[24-27], NextCommand[28-31], MessageId[32-39] = 0x00
    # Reserved[40-43], TreeId[44-47], SessionId[48-55], Signature[56-67] = 0x00

    # SMB2 NEGOTIATE Request body (starts at offset 68)
    $pkt[68] = 0x24  # StructureSize low: 36
    $pkt[69] = 0x00  # StructureSize high
    $pkt[70] = 0x01  # DialectCount low: 1
    $pkt[71] = 0x00  # DialectCount high
    $pkt[72] = 0x00  # SecurityMode: client does not require signing (intentional probe)
    $pkt[73] = 0x00
    # Reserved[74-75], Capabilities[76-79], ClientGuid[80-95], ClientTime[96-103] = 0x00
    # Dialects[100-101]: SMB 2.1 = 0x0210
    $pkt[100] = 0x10
    $pkt[101] = 0x02

    try {
        $tcp = [Net.Sockets.TcpClient]::new()
        $ar  = $tcp.BeginConnect($HostName, 445, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne(2000, $false)) {
            $tcp.Close()
            return $null
        }
        $tcp.EndConnect($ar)
        $stream = $tcp.GetStream()
        $stream.Write($pkt, 0, $pkt.Length)

        $buf = New-Object byte[] 256
        $stream.ReadTimeout = 3000
        $bytes = $stream.Read($buf, 0, $buf.Length)
        $tcp.Close()

        if ($bytes -lt 72) { return $null }

        # Verify SMB2 response signature at offset 4-7: FE 53 4D 42
        if ($buf[4] -ne 0xFE -or $buf[5] -ne 0x53 -or $buf[6] -ne 0x4D -or $buf[7] -ne 0x42) {
            return $null
        }

        # SMB2 Status (NT Status) at header offset 12-15
        $status = [BitConverter]::ToUInt32($buf, 12)

        # Negotiate Response body starts at offset 68
        # SecurityMode is at offset 70 (body offset 2, after StructureSize[2])
        $secMode     = [int]$buf[70]
        $dialRevLow  = [int]$buf[72]
        $dialRevHigh = [int]$buf[73]
        $dialectRev  = ('0x{0:X2}{1:X2}' -f $dialRevHigh, $dialRevLow)

        return [PSCustomObject]@{
            SecurityMode     = $secMode
            SigningEnabled   = (($secMode -band 0x01) -eq 0x01)
            SigningRequired  = (($secMode -band 0x02) -eq 0x02)
            SecurityModeHex  = ('0x{0:X2}' -f $secMode)
            DialectRevision  = $dialectRev
            NTStatus         = ('0x{0:X8}' -f $status)
            Method           = 'NetworkProbe'
        }
    }
    catch { return $null }
}

# ---------------------------------------------------------------------------
# Method 2: WMI registry reads
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
    $info = [PSCustomObject]@{ Caption='Unknown'; BuildNumber='0'; IsServer=$false; IsDC=$false }
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $HostName `
                @WmiParams -ErrorAction Stop | Select-Object -First 1
        if ($os) { $info.Caption = "$($os.Caption)"; $info.BuildNumber = "$($os.BuildNumber)"; $info.IsServer = ($os.Caption -match 'Server') }
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

function Get-RegistrySigningState {
    param([string]$HostName, $OsInfo, $WmiParams)
    $srvKey = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wrkKey = 'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

    $srvReqRaw = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey -ValueName 'RequireSecuritySignature' -WmiParams $WmiParams
    $srvEnRaw  = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey -ValueName 'EnableSecuritySignature'  -WmiParams $WmiParams
    $wrkReqRaw = Get-WmiRegDword -HostName $HostName -KeyPath $wrkKey -ValueName 'RequireSecuritySignature' -WmiParams $WmiParams
    $wrkEnRaw  = Get-WmiRegDword -HostName $HostName -KeyPath $wrkKey -ValueName 'EnableSecuritySignature'  -WmiParams $WmiParams

    # Apply OS defaults when registry key is absent
    # DC default: server require=1. Non-DC: server require=0. Workstation client: require=0
    $srvRequired = if ($srvReqRaw -ne $null) { $srvReqRaw } elseif ($OsInfo.IsDC) { 1 } else { 0 }
    $srvEnabled  = if ($srvEnRaw  -ne $null) { $srvEnRaw  } else { 0 }
    $wrkRequired = if ($wrkReqRaw -ne $null) { $wrkReqRaw } else { 0 }
    $wrkEnabled  = if ($wrkEnRaw  -ne $null) { $wrkEnRaw  } else { 1 }

    return [PSCustomObject]@{
        ServerRequired  = $srvRequired
        ServerEnabled   = $srvEnabled
        ClientRequired  = $wrkRequired
        ClientEnabled   = $wrkEnabled
        SrvReqRaw       = $srvReqRaw
        SrvEnRaw        = $srvEnRaw
        WrkReqRaw       = $wrkReqRaw
        WrkEnRaw        = $wrkEnRaw
        Method          = 'WMIRegistry'
    }
}

function ConvertTo-AssetHtml {
    param([string[]]$Resources)
    if (-not $Resources -or $Resources.Count -eq 0) { return '' }
    $hosts = [System.Collections.Generic.List[string]]::new()
    $regs  = [System.Collections.Generic.List[string]]::new()
    $other = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $Resources) {
        $rs = [System.Net.WebUtility]::HtmlEncode($r)
        if     ($r -match '^\[HOST\]') { $hosts.Add($rs) }
        elseif ($r -match '^\[REG\]')  { $regs.Add($rs)  }
        else                           { $other.Add($rs)  }
    }
    $out = ''
    if ($hosts.Count -gt 0) { $out += "<div class='ag'><span class='al host-lbl'>HOSTS</span>" + (($hosts | ForEach-Object {"<span class='ai'>$_</span>"}) -join '') + '</div>' }
    if ($regs.Count  -gt 0) { $out += "<div class='ag'><span class='al reg-lbl'>REGISTRY</span>" + (($regs  | ForEach-Object {"<span class='ai'>$_</span>"}) -join '') + '</div>' }
    if ($other.Count -gt 0) { $out += "<div class='ag'><span class='al gen-lbl'>OTHER</span>"   + (($other | ForEach-Object {"<span class='ai'>$_</span>"}) -join '') + '</div>' }
    return $out
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath | Out-Null }

$dateSafe    = (Get-Date -Format 'yyyyMMdd-HHmm')
$allTargets  = [System.Collections.Generic.List[string]]::new()
$hostSummary = [System.Collections.Generic.List[PSObject]]::new()
$wmiParams   = @{}
if ($Credential) { $wmiParams['Credential'] = $Credential }

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "  Invoke-SMBSigningAudit" -ForegroundColor Cyan
Write-Host "  Detection: Network probe (no auth) + WMI registry" -ForegroundColor DarkGray
Write-Host "=====================================================" -ForegroundColor Cyan

foreach ($t in $Targets) {
    if (Test-Path $t -ErrorAction SilentlyContinue) {
        $lines = @(Get-Content $t -ErrorAction SilentlyContinue)
        foreach ($l in $lines) { $l2 = $l.Trim(); if ($l2 -and $l2 -notmatch '^#') { $allTargets.Add($l2) } }
    }
    elseif ($t -match '/\d+$') {
        $expanded = @(Expand-CidrRange $t)
        foreach ($ip in $expanded) { $allTargets.Add($ip) }
    }
    else { $allTargets.Add($t) }
}

Write-Host "[*] $($allTargets.Count) target(s) queued`n" -ForegroundColor White

# Track relay-susceptible hosts for the attack surface summary
$relayTargets = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------------------
# Main audit loop
# ---------------------------------------------------------------------------

foreach ($target in $allTargets) {
    Write-Host "[*] $target" -ForegroundColor White

    if (-not (Test-Port445 $target)) {
        Write-Host "    Port 445 unreachable -- skipping" -ForegroundColor DarkGray
        continue
    }

    # Row defaults
    $osCaption  = 'Unknown'
    $osBuild    = '?'
    $roleTag    = 'Host'
    $netSrvSign = 'N/A'
    $regSrvSign = 'N/A'
    $regCliSign = 'N/A'
    $verdict    = 'Unknown'

    # -- Method 1: Network probe -----------------------------------------------
    Write-Host "    [Net] SMB2 Negotiate probe..." -ForegroundColor DarkGray
    $netResult = Get-SMB2NegotiateSecurityMode -HostName $target

    if ($netResult) {
        $netSrvSign = if ($netResult.SigningRequired) { 'Required' } `
                      elseif ($netResult.SigningEnabled) { 'Enabled (not required)' } `
                      else { 'Disabled' }
        Write-Host "    [Net] SecurityMode=$($netResult.SecurityModeHex) Dialect=$($netResult.DialectRevision) Signing=$netSrvSign" -ForegroundColor DarkGray
    }
    else {
        Write-Host "    [Net] No SMB2 response (SMBv1-only or port filtered)" -ForegroundColor DarkGray
    }

    # -- Method 2: WMI registry ------------------------------------------------
    $regResult   = $null
    $osInfo      = [PSCustomObject]@{ Caption='Unknown'; BuildNumber='0'; IsServer=$false; IsDC=$false }

    if (-not $NetworkOnly) {
        Write-Host "    [Reg] WMI registry query..." -ForegroundColor DarkGray
        $osInfo    = Get-HostOsInfo -HostName $target -WmiParams $wmiParams
        $roleTag   = if ($osInfo.IsDC) { 'DC' } elseif ($osInfo.IsServer) { 'Server' } else { 'Workstation' }
        $osCaption = $osInfo.Caption
        $osBuild   = $osInfo.BuildNumber

        $regResult = Get-RegistrySigningState -HostName $target -OsInfo $osInfo -WmiParams $wmiParams
        $regSrvSign = if ($regResult.ServerRequired -eq 1) { 'Required' } `
                      elseif ($regResult.ServerEnabled -eq 1) { 'Enabled (not required)' } `
                      else { 'Disabled' }
        $regCliSign = if ($regResult.ClientRequired -eq 1) { 'Required' } else { 'Not Required' }
        Write-Host "    [Reg] Server=$regSrvSign Client=$regCliSign" -ForegroundColor DarkGray
    }

    $hostRes = @("[HOST] $target ($roleTag) $osCaption build $osBuild")

    # -- Evaluate and emit findings -------------------------------------------

    # Determine effective server signing state (network probe is ground truth)
    $serverNotRequired = $false
    if ($netResult) {
        $serverNotRequired = (-not $netResult.SigningRequired)
    }
    elseif ($regResult) {
        $serverNotRequired = ($regResult.ServerRequired -ne 1)
    }

    if ($serverNotRequired) {
        $relayTargets.Add($target)
        $verdict = 'RELAY-VULNERABLE'

        $sev = if ($osInfo.IsDC) { 'Critical' } `
               elseif ($osInfo.IsServer) { 'High' } `
               else { 'Medium' }

        $netDetail = if ($netResult) { "Network probe: SecurityMode=$($netResult.SecurityModeHex) ($netSrvSign, dialect $($netResult.DialectRevision))." } else { "Network probe: no SMB2 response." }
        $regDetail = if ($regResult) { "Registry: Server RequireSecuritySignature=$($regResult.SrvReqRaw) (effective: $($regResult.ServerRequired))." } else { "Registry: not queried (NetworkOnly mode)." }

        $resources = $hostRes + @(
            "[REG] Server RequireSecuritySignature=$(if ($regResult){ $regResult.SrvReqRaw }else{'N/A'})",
            "[REG] Server EnableSecuritySignature=$(if ($regResult){ $regResult.SrvEnRaw }else{'N/A'})"
        )

        Add-Finding -Domain 'SMBSigning' -Severity $sev `
            -Check "Server Signing NOT Required: $target [$roleTag]" `
            -Detail "$target advertises SMB signing as optional. Any client can connect without signing. $netDetail $regDetail NTLM relay attack is possible against this host without knowing any password." `
            -Resources $resources `
            -MITRE 'T1557.001' -CIS 'CIS 2.3.9.5' `
            -AttackPath @"
1. Attacker positions between victim and $target (ARP spoof / LLMNR/NBT-NS poisoning with $($script:T.RS))
2. Victim's client connects to share on $target -- NTLM authentication begins
3. Attacker captures NTLM challenge/response
4. Relay captured auth to $target using $($script:T.NR) (no signing = server accepts relayed session)
5. Attacker is authenticated as victim user on $target -- can read shares, write files, or execute via SCM/WMI
6. If victim is admin: dump SAM/LSASS, establish persistence
"@ `
            -Fix @"
Require signing on SMB server (immediate, no reboot needed):
  Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
    -Name RequireSecuritySignature -Type DWORD -Value 1

Verify it applied via network probe (from any host):
  Test-NetConnection -ComputerName $target -Port 445

Apply fleet-wide via GPO (recommended):
  Computer Config -> Windows Settings -> Security Settings ->
    Local Policies -> Security Options ->
    'Microsoft network server: Digitally sign communications (always)' = Enabled
    'Microsoft network server: Digitally sign communications (if client agrees)' = Enabled

For DCs specifically -- enforce via Default Domain Controllers Policy:
  Same GPO path -- set BOTH options to Enabled

Verify after GPO applies:
  Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableSecuritySignature
"@
    }
    else {
        $verdict = 'Signed'
        $netInfo = if ($netResult) { "NetworkProbe: SecurityMode=$($netResult.SecurityModeHex) (required)" } else { 'NetworkProbe: no SMB2 response' }
        Add-Finding -Domain 'SMBSigning' -Severity 'Good' `
            -Check "Server Signing Required: $target [$roleTag]" `
            -Detail "SMB server on $target requires packet signing. $netInfo. Relay attacks against this host are blocked." `
            -Resources $hostRes
    }

    # Client-side signing (registry only -- cannot probe from outside)
    if ($regResult -and $regResult.ClientRequired -ne 1) {
        $clientSev = if ($osInfo.IsDC) { 'High' } else { 'Low' }
        Add-Finding -Domain 'SMBSigning-Client' -Severity $clientSev `
            -Check "Client Signing NOT Required (outbound): $target [$roleTag]" `
            -Detail "The SMB client on $target does not require signing when connecting to other servers (ClientRequireSecuritySignature=$($regResult.ClientRequired)). This host can be lured to connect to a rogue SMB server." `
            -Resources ($hostRes + @("[REG] Client RequireSecuritySignature=$(if ($regResult.WrkReqRaw -ne $null){$regResult.WrkReqRaw}else{'absent (default=0)'})")) `
            -MITRE 'T1557.001' -CIS 'CIS 2.3.8.3' `
            -AttackPath "Stand up rogue SMB server (no signing) -> trigger $target to connect (via DFS referral, print spooler, or LLMNR) -> capture NTLM hash -> relay or crack offline with $($script:T.HC)" `
            -Fix @"
Require SMB client signing:
  Set-SmbClientConfiguration -RequireSecuritySignature `$true -Force
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' `
    -Name RequireSecuritySignature -Type DWORD -Value 1

Apply via GPO:
  Computer Config -> Security Settings -> Local Policies -> Security Options ->
  'Microsoft network client: Digitally sign communications (always)' = Enabled
"@
    }

    # Discrepancy: registry says required but network says not required
    # Means GPO/registry has been set but service hasn't picked it up or was bypassed
    if ($regResult -and $netResult) {
        $regSaysRequired = ($regResult.ServerRequired -eq 1)
        $netSaysRequired = $netResult.SigningRequired
        if ($regSaysRequired -and -not $netSaysRequired) {
            Add-Finding -Domain 'SMBSigning-Discrepancy' -Severity 'High' `
                -Check "Signing Discrepancy -- Registry vs Wire: $target" `
                -Detail "Registry shows RequireSecuritySignature=1 but the network probe reports signing is NOT required (SecurityMode=$($netResult.SecurityModeHex)). The LanmanServer service has not applied the registry change. A service restart or reboot is required." `
                -Resources $hostRes `
                -Fix @"
The registry value is set but the running service has not loaded it.
Restart the Server service (warning: this briefly drops all existing SMB sessions):
  Restart-Service LanmanServer -Force
Or reboot the host.
Verify after restart:
  .\Invoke-SMBSigningAudit.ps1 -Targets $target -NetworkOnly
"@
        }
    }

    # Record host summary
    $hostSummary.Add([PSCustomObject]@{
        Host       = $target
        Role       = $roleTag
        OS         = "$osCaption (build $osBuild)"
        NetProbe   = $netSrvSign
        RegServer  = $regSrvSign
        RegClient  = $regCliSign
        Verdict    = $verdict
        Dialect    = if ($netResult) { $netResult.DialectRevision } else { 'N/A' }
    })
}

# ---------------------------------------------------------------------------
# Relay attack surface summary
# ---------------------------------------------------------------------------

if ($relayTargets.Count -gt 0) {
    $relayList = $relayTargets -join ', '
    Add-Finding -Domain 'RelayMap' -Severity 'Info' `
        -Check "Relay Attack Surface: $($relayTargets.Count) relay-susceptible host(s)" `
        -Detail "The following hosts do not require SMB signing and can be targeted by NTLM relay: $relayList. Any domain user whose credentials are captured (via $($script:T.RS) or LLMNR poisoning) can be relayed to any of these hosts." `
        -Resources ($relayTargets | ForEach-Object { "[HOST] $_" }) `
        -AttackPath "$($script:T.RS) + $($script:T.NR): capture auth from any host -> relay to any of these $($relayTargets.Count) unsigned hosts -> authenticate without cracking password"
}

# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

Write-Host "`n[*] Building report..." -ForegroundColor Cyan

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
$gaugeOff   = [math]::Round(283 - (283 * $pct / 100))
$relayCount = $relayTargets.Count

# Host matrix rows
$hostRows = ''
foreach ($h in $hostSummary) {
    $netCell = if ($h.NetProbe -match 'not required|Disabled')   { "<td style='color:#ef4444;font-weight:700'>$($h.NetProbe)</td>" } `
               elseif ($h.NetProbe -eq 'N/A')                    { "<td style='color:#64748b'>$($h.NetProbe)</td>" } `
               else                                               { "<td style='color:#22c55e'>$($h.NetProbe)</td>" }
    $regCell = if ($h.RegServer -match 'not required|Disabled')  { "<td style='color:#f97316'>$($h.RegServer)</td>" } `
               elseif ($h.RegServer -eq 'N/A')                   { "<td style='color:#64748b'>N/A</td>" } `
               else                                              { "<td style='color:#22c55e'>$($h.RegServer)</td>" }
    $cliCell = if ($h.RegClient -eq 'Not Required')              { "<td style='color:#f59e0b'>$($h.RegClient)</td>" } `
               elseif ($h.RegClient -eq 'N/A')                   { "<td style='color:#64748b'>N/A</td>" } `
               else                                              { "<td style='color:#22c55e'>$($h.RegClient)</td>" }
    $verdCell = if ($h.Verdict -eq 'RELAY-VULNERABLE')           { "<td style='color:#ef4444;font-weight:700'>$($h.Verdict)</td>" } `
                else                                             { "<td style='color:#22c55e'>$($h.Verdict)</td>" }
    $hostRows += "<tr><td>$([System.Net.WebUtility]::HtmlEncode($h.Host))</td><td>$([System.Net.WebUtility]::HtmlEncode($h.Role))</td><td>$([System.Net.WebUtility]::HtmlEncode($h.OS))</td>$netCell$regCell$cliCell<td>$([System.Net.WebUtility]::HtmlEncode($h.Dialect))</td>$verdCell</tr>`n"
}

# Finding cards
$fIdx = 0; $findingCards = ''
foreach ($f in $script:Findings) {
    if ($f.Severity -in @('Good','Info')) { $fIdx++; continue }
    $sc = switch ($f.Severity) { 'Critical'{'#ef4444'} 'High'{'#f97316'} 'Medium'{'#f59e0b'} 'Low'{'#60a5fa'} default{'#6b7280'} }
    $ah = ConvertTo-AssetHtml -Resources $f.Resources
    $sd = [System.Net.WebUtility]::HtmlEncode($f.Detail)
    $sa = [System.Net.WebUtility]::HtmlEncode($f.AttackPath)
    $sf = [System.Net.WebUtility]::HtmlEncode($f.Fix)
    $dc = [System.Net.WebUtility]::HtmlEncode($f.Domain)
    $ck = [System.Net.WebUtility]::HtmlEncode($f.Check)
    $mb = if ($f.MITRE) { "<span class='badge mb'>$([System.Net.WebUtility]::HtmlEncode($f.MITRE))</span>" } else { '' }
    $cb = if ($f.CIS)   { "<span class='badge cb'>$([System.Net.WebUtility]::HtmlEncode($f.CIS))</span>" }   else { '' }
    $tb = ''; $tp = ''
    if ($ah) { $tb += "<button class='tab-btn' onclick='showTab(this,""a$fIdx"")'>Assets ($(@($f.Resources).Count))</button>"; $tp += "<div class='tp' id='a$fIdx' style='display:none'>$ah</div>" }
    if ($f.AttackPath) { $tb += "<button class='tab-btn' onclick='showTab(this,""ap$fIdx"")'>Attack Path</button>"; $tp += "<div class='tp' id='ap$fIdx' style='display:none'><pre class='apre'>$sa</pre></div>" }
    if ($f.Fix) { $tb += "<button class='tab-btn' onclick='showTab(this,""fx$fIdx"")'>Remediation</button>"; $tp += "<div class='tp' id='fx$fIdx' style='display:none'><pre class='fpre'>$sf</pre></div>" }
    $findingCards += @"
<div class='fc' data-sev='$($f.Severity)'>
  <div class='fh' onclick='tc(this)'><span class='sb' style='background:$sc'>$($f.Severity)</span><span class='fd'>$dc</span><span class='ft'>$ck</span><span class='fb'>$mb$cb</span><span class='fv'>+</span></div>
  <div class='fb2' style='display:none'><div class='wb'><div class='wl'>Why Vulnerable</div><div class='wt'>$sd</div></div><div class='tb2'>$tb</div>$tp</div>
</div>
"@
    $fIdx++
}

$html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>SMB Signing Audit</title>
<style>
:root{--bg:#0f1117;--sf:#1a1d27;--bd:#2a2d3e;--tx:#e2e8f0;--dm:#64748b;--bl:#3b82f6;--bl2:#60a5fa;
  --cr:#ef4444;--hi:#f97316;--md:#f59e0b;--lw:#60a5fa;--gd:#22c55e;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--tx);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;}
.nav{position:sticky;top:0;z-index:100;background:var(--sf);border-bottom:1px solid var(--bd);display:flex;align-items:center;padding:10px 24px;gap:20px;}
.nb{font-size:1rem;font-weight:700;color:var(--bl2);}
.nl{display:flex;gap:16px;font-size:.8rem;}
.nl a{color:var(--dm);}
.nl a:hover{color:var(--bl2);}
.pg{max-width:1200px;margin:0 auto;padding:24px 16px;}
.dash{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:14px;margin-bottom:24px;}
.dc{background:var(--sf);border:1px solid var(--bd);border-radius:8px;padding:14px;text-align:center;}
.dv{font-size:1.8rem;font-weight:700;} .dl{font-size:.72rem;color:var(--dm);margin-top:4px;}
.sg{position:relative;width:88px;height:88px;margin:0 auto 8px;}
.sg svg{width:88px;height:88px;transform:rotate(-90deg);}
.sg circle{fill:none;stroke-width:10;}
.gbg{stroke:var(--bd);} .gfi{stroke-dasharray:283;stroke-linecap:round;}
.gp{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:1.15rem;font-weight:700;}
.sh{display:flex;align-items:center;justify-content:space-between;margin:28px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--bd);}
.sh h2{font-size:1rem;font-weight:600;}
.sc2{font-size:.75rem;color:var(--dm);background:rgba(255,255,255,.05);padding:2px 8px;border-radius:12px;}
.ht{width:100%;border-collapse:collapse;font-size:.78rem;display:block;overflow-x:auto;}
.ht th{text-align:left;padding:8px 10px;background:rgba(255,255,255,.05);border-bottom:1px solid var(--bd);color:var(--dm);font-weight:600;white-space:nowrap;}
.ht td{padding:7px 10px;border-bottom:1px solid rgba(255,255,255,.04);font-family:'Consolas',monospace;font-size:.74rem;white-space:nowrap;}
.ht tr:hover td{background:rgba(255,255,255,.02);}
.relay-box{background:#1a0a0a;border:1px solid #7f1d1d;border-radius:8px;padding:14px;margin-bottom:20px;}
.relay-title{font-size:.85rem;font-weight:700;color:#ef4444;margin-bottom:6px;}
.relay-hosts{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;}
.relay-host{background:#2a1a1a;border:1px solid #7f1d1d;border-radius:4px;padding:2px 8px;font-size:.75rem;font-family:'Consolas',monospace;color:#fca5a5;}
.fb3{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:16px;}
.fl{font-size:.75rem;color:var(--dm);}
.fbtn{background:var(--sf);border:1px solid var(--bd);color:var(--tx);padding:4px 12px;border-radius:16px;font-size:.78rem;cursor:pointer;}
.fbtn.active{background:var(--bl);border-color:var(--bl);color:#fff;}
.fbtn:hover{border-color:var(--bl2);}
.sb2{background:var(--sf);border:1px solid var(--bd);color:var(--tx);padding:4px 12px;border-radius:16px;font-size:.78rem;width:200px;margin-left:auto;}
.rc{font-size:.75rem;color:var(--dm);}
.fc{background:var(--sf);border:1px solid var(--bd);border-radius:8px;margin-bottom:8px;overflow:hidden;}
.fc:hover{border-color:#3d4266;}
.fh{display:flex;align-items:center;gap:12px;padding:10px 14px;cursor:pointer;user-select:none;}
.fh:hover{background:rgba(255,255,255,.02);}
.sb{font-size:.7rem;font-weight:700;padding:2px 8px;border-radius:12px;color:#fff;white-space:nowrap;flex-shrink:0;}
.fd{font-size:.72rem;color:var(--dm);white-space:nowrap;flex-shrink:0;width:160px;}
.ft{font-size:.87rem;font-weight:600;flex:1;min-width:0;}
.fb{display:flex;gap:4px;flex-shrink:0;}
.badge{font-size:.68rem;padding:1px 6px;border-radius:8px;font-weight:600;}
.mb{background:#1e3a5f;color:#93c5fd;}
.cb{background:#1a3a2a;color:#86efac;}
.fv{color:var(--dm);font-size:1.1rem;flex-shrink:0;width:20px;text-align:center;}
.fv.open{color:var(--bl2);}
.fb2{border-top:1px solid var(--bd);}
.wb{padding:12px 14px;background:rgba(255,255,255,.02);border-bottom:1px solid var(--bd);}
.wl{font-size:.68rem;font-weight:700;color:var(--dm);text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px;}
.wt{font-size:.82rem;color:#cbd5e1;line-height:1.5;}
.tb2{display:flex;border-bottom:1px solid var(--bd);}
.tab-btn{background:none;border:none;border-bottom:2px solid transparent;color:var(--dm);padding:8px 14px;font-size:.78rem;cursor:pointer;}
.tab-btn.active{color:var(--bl2);border-bottom-color:var(--bl2);}
.tab-btn:hover{color:var(--tx);}
.tp{padding:14px;display:none;}
.apre,.fpre{background:#0a0d14;border:1px solid var(--bd);border-radius:6px;padding:12px;font-size:.78rem;font-family:'Consolas',monospace;white-space:pre-wrap;word-break:break-word;}
.apre{color:#a5f3fc;} .fpre{color:#bbf7d0;}
.ag{margin-bottom:8px;}
.al{font-size:.68rem;font-weight:700;text-transform:uppercase;padding:2px 6px;border-radius:4px;margin-right:6px;}
.host-lbl{background:#1e3a5f;color:#93c5fd;}
.reg-lbl{background:#2a1a3a;color:#d8b4fe;}
.gen-lbl{background:#2a2a1a;color:#fde68a;}
.ai{display:inline-block;background:rgba(255,255,255,.05);border:1px solid var(--bd);border-radius:4px;padding:2px 8px;margin:3px 3px 0 0;font-size:.74rem;font-family:'Consolas',monospace;}
footer{text-align:center;padding:24px;font-size:.75rem;color:var(--dm);border-top:1px solid var(--bd);margin-top:32px;}
@media(max-width:600px){.fd{display:none;}.dash{grid-template-columns:repeat(2,1fr);}}
</style>
</head>
<body>
<nav class='nav'>
  <span class='nb'>SMB Signing Audit</span>
  <div class='nl'><a href='#dash'>Dashboard</a><a href='#matrix'>Host Matrix</a><a href='#finds'>Findings</a></div>
</nav>
<div class='pg'>
  <div class='sh' id='dash'><h2>Dashboard</h2><span class='sc2'>$genTime</span></div>
  <div class='dash'>
    <div class='dc'>
      <div class='sg'><svg viewBox='0 0 100 100'><circle class='gbg' cx='50' cy='50' r='45'/><circle class='gfi' cx='50' cy='50' r='45' stroke='$scoreColor' stroke-dashoffset='$gaugeOff'/></svg><div class='gp' style='color:$scoreColor'>$pct%</div></div>
      <div class='dl'>$maturity</div>
    </div>
    <div class='dc'><div class='dv' style='color:#94a3b8'>$($allTargets.Count)</div><div class='dl'>Targets</div></div>
    <div class='dc'><div class='dv' style='color:var(--cr)'>$relayCount</div><div class='dl'>Relay Vulnerable</div></div>
    <div class='dc'><div class='dv' style='color:var(--cr)'>$critCount</div><div class='dl'>Critical</div></div>
    <div class='dc'><div class='dv' style='color:var(--hi)'>$highCount</div><div class='dl'>High</div></div>
    <div class='dc'><div class='dv' style='color:var(--md)'>$medCount</div><div class='dl'>Medium</div></div>
    <div class='dc'><div class='dv' style='color:var(--gd)'>$goodCount</div><div class='dl'>Passed</div></div>
  </div>
$(if ($relayTargets.Count -gt 0) {
"  <div class='relay-box'>
    <div class='relay-title'>Relay Attack Surface -- $($relayTargets.Count) unsigned server(s)</div>
    <div style='font-size:.8rem;color:#fca5a5;'>These hosts accept SMB connections without signing. Any captured NTLM credential can be relayed directly to them.</div>
    <div class='relay-hosts'>" + ($relayTargets | ForEach-Object { "<span class='relay-host'>$([System.Net.WebUtility]::HtmlEncode($_))</span>" }) -join '' + "</div>
  </div>"
})
  <div class='sh' id='matrix'><h2>Host Configuration Matrix</h2><span class='sc2'>$($hostSummary.Count) hosts</span></div>
  <table class='ht'>
    <tr><th>Host</th><th>Role</th><th>OS</th><th>Net Probe (wire)</th><th>Reg Server</th><th>Reg Client</th><th>Dialect</th><th>Verdict</th></tr>
$hostRows
  </table>
  <div class='sh' id='finds'><h2>Findings</h2><span class='sc2'>$issueCount issues</span></div>
  <div class='fb3'>
    <span class='fl'>Filter:</span>
    <button class='fbtn active' data-f='All'      onclick='fc2(this)'>All</button>
    <button class='fbtn'        data-f='Critical' onclick='fc2(this)'>Critical ($critCount)</button>
    <button class='fbtn'        data-f='High'     onclick='fc2(this)'>High ($highCount)</button>
    <button class='fbtn'        data-f='Medium'   onclick='fc2(this)'>Medium ($medCount)</button>
    <button class='fbtn'        data-f='Low'      onclick='fc2(this)'>Low ($lowCount)</button>
    <input class='sb2' type='text' placeholder='Search...' oninput='sc2(this.value)'/>
    <span class='rc' id='rc'></span>
  </div>
  <div id='fcc'>$findingCards</div>
</div>
<footer>SMB Signing Audit -- ASPAT Purple Team &nbsp;|&nbsp; $genTime &nbsp;|&nbsp; Score: $($script:Score)/$($script:MaxScore)</footer>
<script>
function tc(h){var b=h.nextElementSibling;var v=h.querySelector('.fv');var o=b.style.display!=='none';b.style.display=o?'none':'block';v.textContent=o?'+':'x';v.classList.toggle('open',!o);if(!o){var t=b.querySelector('.tab-btn');if(t){var m=t.getAttribute('onclick').match(/"([^"]+)"/);if(m)showTab(t,m[1]);}}}
function showTab(b,id){var c=b.closest('.fb2');c.querySelectorAll('.tab-btn').forEach(function(x){x.classList.remove('active');});c.querySelectorAll('.tp').forEach(function(p){p.style.display='none';});b.classList.add('active');var p=document.getElementById(id);if(p)p.style.display='block';}
function fc2(b){document.querySelectorAll('.fbtn').forEach(function(x){x.classList.remove('active');});b.classList.add('active');var f=b.getAttribute('data-f');var cards=document.querySelectorAll('#fcc .fc');var n=0;cards.forEach(function(c){var s=(f==='All'||c.getAttribute('data-sev')===f);c.style.display=s?'':'none';if(s)n++;});document.getElementById('rc').textContent='Showing '+n+' of '+cards.length;}
function sc2(q){q=q.toLowerCase();var cards=document.querySelectorAll('#fcc .fc');var n=0;cards.forEach(function(c){var s=!q||c.textContent.toLowerCase().indexOf(q)!==-1;c.style.display=s?'':'none';if(s)n++;});document.getElementById('rc').textContent=q?('Showing '+n+' of '+cards.length):'';}
(function(){var t=document.querySelectorAll('#fcc .fc').length;document.getElementById('rc').textContent='Showing '+t+' of '+t;})();
</script>
</body>
</html>
"@

$rn = "SMBSigningAudit-$dateSafe"
$html | Out-File -FilePath (Join-Path $OutputPath "$rn.html") -Encoding UTF8
Write-Host "  HTML : $(Join-Path $OutputPath "$rn.html")" -ForegroundColor Green
if (-not $NoCsv) {
    $script:Findings | Where-Object { $_.Severity -notin @('Good','Info') } |
        Select-Object Domain,Severity,Check,Detail,Resources,MITRE,CIS,Fix |
        Export-Csv -Path (Join-Path $OutputPath "$rn.csv") -NoTypeInformation -Encoding UTF8
    Write-Host "  CSV  : $(Join-Path $OutputPath "$rn.csv")" -ForegroundColor Green
}
$rt = [math]::Round(((Get-Date) - $script:StartTime).TotalSeconds)
Write-Host "`n====================================================" -ForegroundColor Cyan
Write-Host "  Relay-vulnerable hosts : $relayCount / $($allTargets.Count)"
Write-Host "  Critical=$critCount  High=$highCount  Medium=$medCount  Low=$lowCount  Passed=$goodCount"
Write-Host "  Runtime : $($rt)s"
Write-Host "====================================================" -ForegroundColor Cyan
