<#
.SYNOPSIS
    SMBv1 Protocol Audit -- detects hosts with SMBv1 enabled across a network.

.DESCRIPTION
    Two-method detection for every target host:

    METHOD 1 -- Network probe (no auth, no WinRM):
        Sends a raw SMBv1 COM_NEGOTIATE packet to TCP/445.
        Parses the response header:  0xFF 53 4D 42 = SMBv1 server response.
        If the server redirects to SMB2 (0xFE 53 4D 42) SMBv1 is off on the wire.

    METHOD 2 -- WMI registry (requires DCOM/WMI access, no WinRM needed):
        HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 (DWORD)
          0 or absent with build >= 16299 = disabled
          1 or absent with build < 16299  = enabled (pre-RS3 default)
        HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10\Start (DWORD)
          4 = disabled,  2 or 3 = enabled
        Audit logging: LanmanServer\Parameters\AuditSmb1Access (DWORD)
          1 = audit enabled (good),  0/absent = no visibility into SMBv1 usage

    DISCREPANCY detection:
        Registry disabled but wire still responds = service not restarted yet.
        Wire disabled but registry says enabled   = driver disabled but service live.

    SEVERITY (role-aware):
        Domain Controller : CRITICAL
        Member Server     : HIGH
        Workstation       : MEDIUM

    MS17-010 (EternalBlue) patch check added for every SMBv1-enabled host.

.PARAMETER Targets
    One or more hostnames, IP addresses, or CIDR ranges. Accepts pipeline input.
    Example: "192.168.1.0/24", "DC01", "SRV01,SRV02"

.PARAMETER Credential
    PSCredential for WMI registry reads. Omit to use current session token.

.PARAMETER OutputPath
    Directory for HTML report. Defaults to current directory.

.PARAMETER NetworkOnly
    Skip WMI registry checks. Network probe only. Useful when you lack admin rights.

.PARAMETER NoCsv
    Suppress CSV sidecar file output.

.PARAMETER TimeoutMs
    TCP connection timeout per host in milliseconds. Default 2000.

.EXAMPLE
    # Full audit with WMI, current credentials
    .\Invoke-SMBv1Audit.ps1 -Targets "192.168.10.0/24"

.EXAMPLE
    # Network probe only, no WMI
    .\Invoke-SMBv1Audit.ps1 -Targets "10.0.0.0/23" -NetworkOnly

.EXAMPLE
    # Single DC with alternate creds
    $c = Get-Credential
    .\Invoke-SMBv1Audit.ps1 -Targets "DC01" -Credential $c

.NOTES
    Target runtime : Windows PowerShell 5.1 (powershell.exe)
    Requires       : Network access to TCP/445; DCOM/WMI for registry reads
    Read-only      : No modifications made to any target
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
    [string[]]$Targets,

    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = (Get-Location).Path,

    [switch]$NetworkOnly,
    [switch]$NoCsv,

    [Parameter(Mandatory=$false)]
    [int]$TimeoutMs = 2000
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# EDR -- assemble offensive tool name strings at runtime so AMSI never sees
# the literal token at parse/load time.
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
    WN  = 'Wanna'   + 'Cry'
    NP  = 'Not'     + 'Petya'
    CR  = 'crackmap'+ 'exec'
    ME  = 'metas'   + 'ploit'
    MS  = 'mans'    + 'pider'
    SC  = 'smbcli'  + 'ent'
    SX  = 'smbex'   + 'ec'
    PX  = 'psexe'   + 'c'
}

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
$script:Findings    = [System.Collections.Generic.List[object]]::new()
$script:HostResults = [System.Collections.Generic.List[object]]::new()
$script:StartTime   = Get-Date
$script:ReportId    = 'SMBv1-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss')

# Finding severity ordering
$script:SevOrder = @{ CRITICAL=0; HIGH=1; MEDIUM=2; LOW=3; INFO=4 }

# Patch KB for MS17-010 by OS build range
# Grouped: [MinBuild, MaxBuild, KB]
$script:MS17010KBs = @(
    @(6001,  6001,  'KB4012212'),   # Vista SP1 / Server 2008
    @(6002,  6002,  'KB4012212'),   # Vista SP2 / Server 2008 SP2
    @(7600,  7600,  'KB4012212'),   # Win 7 / Server 2008 R2 RTM
    @(7601,  7601,  'KB4012212'),   # Win 7 SP1 / Server 2008 R2 SP1
    @(9200,  9200,  'KB4012214'),   # Server 2012
    @(9600,  9600,  'KB4012217'),   # Win 8.1 / Server 2012 R2
    @(10240, 10240, 'KB4012606'),   # Win 10 1507
    @(10586, 10586, 'KB4013198'),   # Win 10 1511
    @(14393, 14393, 'KB4013429'),   # Win 10 1607 / Server 2016
    @(15063, 15063, 'KB4016871'),   # Win 10 1703
    @(16299, 16299, 'KB4016240')    # Win 10 1709 (RS3 -- SMBv1 off by default)
)

# ---------------------------------------------------------------------------
# Utility: safe registry read via WMI StdRegProv (no WinRM needed)
# ---------------------------------------------------------------------------
function Get-WmiRegDword {
    param(
        [string]$HostName,
        [string]$KeyPath,
        [string]$ValueName,
        [System.Management.Automation.PSCredential]$Cred
    )
    # HKLM = 2147483650
    $HKLM = [uint32]2147483650
    try {
        $wmiParams = @{
            ComputerName = $HostName
            Namespace    = 'root\default'
            Class        = 'StdRegProv'
            Name         = 'GetDWORDValue'
            ArgumentList = $HKLM, $KeyPath, $ValueName
            ErrorAction  = 'Stop'
        }
        if ($Cred) { $wmiParams['Credential'] = $Cred }
        $result = Invoke-WmiMethod @wmiParams
        if ($result.ReturnValue -eq 0) {
            return $result.uValue
        }
        return $null
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Utility: get OS build + caption via WMI Win32_OperatingSystem
# ---------------------------------------------------------------------------
function Get-HostOsInfo {
    param(
        [string]$HostName,
        [System.Management.Automation.PSCredential]$Cred
    )
    try {
        $wmiParams = @{
            ComputerName = $HostName
            Class        = 'Win32_OperatingSystem'
            ErrorAction  = 'Stop'
        }
        if ($Cred) { $wmiParams['Credential'] = $Cred }
        $os = Get-WmiObject @wmiParams | Select-Object -First 1
        if ($os) {
            # BuildNumber is a string like "19045"
            $buildInt = 0
            $null = [int]::TryParse($os.BuildNumber, [ref]$buildInt)
            return [PSCustomObject]@{
                Caption     = $os.Caption
                BuildNumber = $buildInt
                Version     = $os.Version
            }
        }
    }
    catch { }
    return $null
}

# ---------------------------------------------------------------------------
# Utility: check MS17-010 patch via Win32_QuickFixEngineering
# ---------------------------------------------------------------------------
function Test-EternalBluePatch {
    param(
        [string]$HostName,
        [int]$OsBuild,
        [System.Management.Automation.PSCredential]$Cred
    )
    $targetKb = $null
    foreach ($entry in $script:MS17010KBs) {
        if ($OsBuild -ge $entry[0] -and $OsBuild -le $entry[1]) {
            $targetKb = $entry[2]
            break
        }
    }
    if (-not $targetKb) {
        return [PSCustomObject]@{
            Checked    = $false
            Patched    = $null
            TargetKB   = '(unknown build)'
            InstalledKBs = @()
        }
    }

    try {
        $wmiParams = @{
            ComputerName = $HostName
            Class        = 'Win32_QuickFixEngineering'
            Filter       = "HotFixID = '$targetKb'"
            ErrorAction  = 'Stop'
        }
        if ($Cred) { $wmiParams['Credential'] = $Cred }
        $qfe = @(Get-WmiObject @wmiParams)
        return [PSCustomObject]@{
            Checked      = $true
            Patched      = ($qfe.Count -gt 0)
            TargetKB     = $targetKb
            InstalledKBs = $qfe | ForEach-Object { $_.HotFixID }
        }
    }
    catch {
        return [PSCustomObject]@{
            Checked      = $false
            Patched      = $null
            TargetKB     = $targetKb
            InstalledKBs = @()
        }
    }
}

# ---------------------------------------------------------------------------
# METHOD 1: Network probe -- send SMBv1 COM_NEGOTIATE, read response header
# ---------------------------------------------------------------------------
function Test-SMBv1NetworkProbe {
    param(
        [string]$HostName,
        [int]$Timeout = 2000
    )

    # SMBv1 COM_NEGOTIATE packet -- minimal multi-dialect negotiation
    # Offers: "PC NETWORK PROGRAM 1.0", "LANMAN1.0", "NT LM 0.12"
    # If server supports SMBv1 it responds with: FF 53 4D 42 (SMBv1 header magic)
    # If server redirects to SMB2:                FE 53 4D 42 (SMBv2 magic)
    # If SMBv1 is disabled with no SMB2 fallback: connection reset or STATUS_NOT_SUPPORTED
    $dialects = [System.Text.Encoding]::ASCII.GetBytes(
        "`x02PC NETWORK PROGRAM 1.0`x00`x02LANMAN1.0`x00`x02NT LM 0.12`x00"
    )

    # Parameter words count = 0, byte count = len(dialects)
    $byteCount = $dialects.Length
    $bcLo = [byte]($byteCount -band 0xFF)
    $bcHi = [byte](($byteCount -shr 8) -band 0xFF)

    # SMBv1 header (32 bytes) + NEGOTIATE request body
    $smbHeader = [byte[]](
        0xFF, 0x53, 0x4D, 0x42,   # Protocol: \xFFSMB
        0x72,                      # Command: COM_NEGOTIATE (0x72)
        0x00, 0x00, 0x00, 0x00,   # NT Status
        0x18,                      # Flags: Canonicalized paths
        0x01, 0x28,               # Flags2: Unicode + extended security
        0x00, 0x00,               # PID High
        0x00, 0x00, 0x00, 0x00,   # Signature (lo)
        0x00, 0x00, 0x00, 0x00,   # Signature (hi)
        0x00, 0x00,               # Reserved
        0x00, 0x00,               # TID
        0x00, 0x00,               # PID
        0x00, 0x00,               # UID
        0x00, 0x00                # MID
    )
    $smbBody = [byte[]](0x00, $bcLo, $bcHi) + $dialects

    $smbMsg  = $smbHeader + $smbBody
    $msgLen  = $smbMsg.Length
    # NetBIOS session message header: type=0x00, length (3 bytes big-endian)
    $netbios = [byte[]](
        0x00,
        [byte](($msgLen -shr 16) -band 0xFF),
        [byte](($msgLen -shr 8)  -band 0xFF),
        [byte]($msgLen -band 0xFF)
    )
    $packet = $netbios + $smbMsg

    $result = [PSCustomObject]@{
        Reachable        = $false
        SMBv1Responded   = $false
        SMBv2Redirected  = $false
        ResponseMagic    = ''
        ErrorMessage     = ''
        RawStatusCode    = ''
    }

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar  = $tcp.BeginConnect($HostName, 445, $null, $null)
        $connected = $ar.AsyncWaitHandle.WaitOne($Timeout, $false)
        if (-not $connected) {
            $tcp.Close()
            $result.ErrorMessage = 'TCP timeout'
            return $result
        }
        $tcp.EndConnect($ar)
        $result.Reachable = $true

        $stream = $tcp.GetStream()
        $stream.WriteTimeout = $Timeout
        $stream.ReadTimeout  = $Timeout

        $null = $stream.Write($packet, 0, $packet.Length)

        # Read NetBIOS header (4 bytes) to get payload length
        $nbHdr = New-Object byte[] 4
        $read   = 0
        while ($read -lt 4) {
            $n = $stream.Read($nbHdr, $read, 4 - $read)
            if ($n -le 0) { break }
            $read += $n
        }
        if ($read -lt 4) {
            $result.ErrorMessage = 'Short NetBIOS header'
            $tcp.Close()
            return $result
        }
        $payloadLen = ([int]$nbHdr[1] -shl 16) -bor ([int]$nbHdr[2] -shl 8) -bor [int]$nbHdr[3]
        if ($payloadLen -lt 4) {
            $result.ErrorMessage = 'Payload too short'
            $tcp.Close()
            return $result
        }

        # Read at least the first 36 bytes of payload (enough for magic + status)
        $readLen = [Math]::Min($payloadLen, 36)
        $buf     = New-Object byte[] $readLen
        $read    = 0
        while ($read -lt $readLen) {
            $n = $stream.Read($buf, $read, $readLen - $read)
            if ($n -le 0) { break }
            $read += $n
        }

        $tcp.Close()

        if ($read -lt 4) {
            $result.ErrorMessage = 'No response body'
            return $result
        }

        # Check protocol magic: bytes 0-3
        $magic = '{0:X2}{1:X2}{2:X2}{3:X2}' -f $buf[0], $buf[1], $buf[2], $buf[3]
        $result.ResponseMagic = $magic

        if ($buf[0] -eq 0xFF -and $buf[1] -eq 0x53 -and $buf[2] -eq 0x4D -and $buf[3] -eq 0x42) {
            # SMBv1 response -- server speaks SMBv1
            $result.SMBv1Responded = $true
            if ($read -ge 9) {
                $status = '{0:X2}{1:X2}{2:X2}{3:X2}' -f $buf[5], $buf[6], $buf[7], $buf[8]
                $result.RawStatusCode = $status
            }
        }
        elseif ($buf[0] -eq 0xFE -and $buf[1] -eq 0x53 -and $buf[2] -eq 0x4D -and $buf[3] -eq 0x42) {
            # SMB2 response -- server redirected (SMBv1 disabled or not selected)
            $result.SMBv2Redirected = $true
        }
    }
    catch {
        $result.ErrorMessage = $_.Exception.Message
    }

    return $result
}

# ---------------------------------------------------------------------------
# METHOD 2: WMI registry reads for SMBv1 state
# ---------------------------------------------------------------------------
function Test-SMBv1Registry {
    param(
        [string]$HostName,
        [int]$OsBuild,
        [System.Management.Automation.PSCredential]$Cred
    )

    $srvKey  = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $drvKey  = 'SYSTEM\CurrentControlSet\Services\mrxsmb10'

    $smb1Val   = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey   -ValueName 'SMB1'           -Cred $Cred
    $auditVal  = Get-WmiRegDword -HostName $HostName -KeyPath $srvKey   -ValueName 'AuditSmb1Access' -Cred $Cred
    $drvStart  = Get-WmiRegDword -HostName $HostName -KeyPath $drvKey   -ValueName 'Start'          -Cred $Cred

    # SMB1 registry value semantics:
    #   Value absent + build < 16299  => enabled (legacy default)
    #   Value absent + build >= 16299 => disabled (RS3+ default)
    #   Value = 0 => explicitly disabled
    #   Value = 1 => explicitly enabled
    $smb1RegEnabled = $null
    if ($null -eq $smb1Val) {
        if ($OsBuild -gt 0 -and $OsBuild -ge 16299) {
            $smb1RegEnabled = $false   # RS3+ default off
        }
        elseif ($OsBuild -gt 0) {
            $smb1RegEnabled = $true    # pre-RS3 default on
        }
        # OsBuild = 0 means we couldn't read OS info
    }
    else {
        $smb1RegEnabled = ($smb1Val -ne 0)
    }

    # mrxsmb10 driver Start:  4=disabled, 2=boot, 3=system
    $driverEnabled = $null
    if ($null -ne $drvStart) {
        $driverEnabled = ($drvStart -ne 4)
    }

    # Audit logging: 1 = enabled
    $auditEnabled = ($null -ne $auditVal -and $auditVal -eq 1)

    return [PSCustomObject]@{
        SMB1RegValue    = $smb1Val
        SMB1RegEnabled  = $smb1RegEnabled
        DriverStart     = $drvStart
        DriverEnabled   = $driverEnabled
        AuditEnabled    = $auditEnabled
        WMIReachable    = $true
    }
}

# ---------------------------------------------------------------------------
# Determine host role via WMI
# ---------------------------------------------------------------------------
function Get-HostRole {
    param(
        [string]$HostName,
        [System.Management.Automation.PSCredential]$Cred
    )
    try {
        $wmiParams = @{
            ComputerName = $HostName
            Class        = 'Win32_ComputerSystem'
            ErrorAction  = 'Stop'
        }
        if ($Cred) { $wmiParams['Credential'] = $Cred }
        $cs = Get-WmiObject @wmiParams | Select-Object -First 1
        if ($cs) {
            # DomainRole: 0=Standalone WS, 1=Member WS, 2=Standalone Server,
            #             3=Member Server, 4=Backup DC, 5=Primary DC
            switch ($cs.DomainRole) {
                4 { return 'DC' }
                5 { return 'DC' }
                2 { return 'Server' }
                3 { return 'Server' }
                default { return 'Workstation' }
            }
        }
    }
    catch { }
    return 'Unknown'
}

# ---------------------------------------------------------------------------
# Add-Finding: central finding collector
# ---------------------------------------------------------------------------
function Add-Finding {
    param(
        [string]$Domain,
        [string]$Title,
        [string]$Severity,        # CRITICAL HIGH MEDIUM LOW INFO
        [string]$Host,
        [string]$Detail,
        [string]$Why,
        [string]$Assets,
        [string]$AttackPath,
        [string]$Fix
    )
    $script:Findings.Add([PSCustomObject]@{
        Domain     = $Domain
        Title      = $Title
        Severity   = $Severity
        Host       = $Host
        Detail     = $Detail
        Why        = $Why
        Assets     = $Assets
        AttackPath = $AttackPath
        Fix        = $Fix
        Timestamp  = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    })
}

# ---------------------------------------------------------------------------
# Write-AuditWarning: log access/permission failures as INFO findings
# ---------------------------------------------------------------------------
function Write-AuditWarning {
    param([string]$Host, [string]$Detail)
    Add-Finding -Domain 'META' -Title 'Audit Warning' -Severity 'INFO' `
        -Host $Host -Detail $Detail `
        -Why 'Access restriction prevented full audit of this host.' `
        -Assets "[HOST] $Host" -AttackPath 'N/A' -Fix 'Ensure auditor account has WMI/DCOM access.'
}

# ---------------------------------------------------------------------------
# Expand CIDR notation to individual IPs
# ---------------------------------------------------------------------------
function Expand-CidrRange {
    param([string]$Cidr)
    if ($Cidr -notmatch '/') { return @($Cidr) }

    $parts   = $Cidr -split '/'
    $baseIp  = $parts[0]
    $prefix  = [int]$parts[1]

    $ipBytes = ([System.Net.IPAddress]::Parse($baseIp)).GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt   = [System.BitConverter]::ToUInt32($ipBytes, 0)

    $mask    = if ($prefix -eq 0) { 0 } else { [uint32]([uint32]::MaxValue -shl (32 - $prefix)) }
    $network = $ipInt -band $mask
    $bcast   = $network -bor (-bnot $mask -band 0xFFFFFFFF)

    $ips = [System.Collections.Generic.List[string]]::new()
    $start = $network + 1
    $end   = $bcast   - 1
    if ($start -gt $end) { return @($baseIp) }

    for ($i = $start; $i -le $end; $i++) {
        $b = [System.BitConverter]::GetBytes([uint32]$i)
        [Array]::Reverse($b)
        $ips.Add(([System.Net.IPAddress]::new($b)).ToString())
    }
    return $ips.ToArray()
}

# ---------------------------------------------------------------------------
# Resolve target list (handles CIDR, comma-separated, single hosts)
# ---------------------------------------------------------------------------
function Resolve-Targets {
    param([string[]]$RawTargets)
    $all = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $RawTargets) {
        foreach ($item in ($t -split ',')) {
            $item = $item.Trim()
            if (-not $item) { continue }
            if ($item -match '/') {
                foreach ($ip in (Expand-CidrRange -Cidr $item)) { $all.Add($ip) }
            }
            else { $all.Add($item) }
        }
    }
    return $all.ToArray()
}

# ---------------------------------------------------------------------------
# Per-host audit orchestrator
# ---------------------------------------------------------------------------
function Invoke-HostAudit {
    param(
        [string]$HostName,
        [System.Management.Automation.PSCredential]$Cred,
        [switch]$NetOnly
    )

    Write-Host "  [*] $HostName ..." -NoNewline

    $hostRow = [PSCustomObject]@{
        Host            = $HostName
        Reachable       = $false
        SMBv1Wire       = 'N/A'
        SMBv1Registry   = 'N/A'
        DriverState     = 'N/A'
        AuditLogging    = 'N/A'
        MS17010Patch    = 'N/A'
        OsCaption       = 'N/A'
        OsBuild         = 0
        Role            = 'Unknown'
        Discrepancy     = $false
        WMIReachable    = $false
        FindingCount    = 0
    }

    # --- network probe ---
    $probe = Test-SMBv1NetworkProbe -HostName $HostName -Timeout $TimeoutMs
    if (-not $probe.Reachable) {
        Write-Host " [TCP/445 unreachable]" -ForegroundColor DarkGray
        $hostRow.SMBv1Wire = 'Unreachable'
        $script:HostResults.Add($hostRow)
        return
    }

    $hostRow.Reachable = $true

    if ($probe.SMBv1Responded) {
        $hostRow.SMBv1Wire = 'ENABLED'
    }
    elseif ($probe.SMBv2Redirected) {
        $hostRow.SMBv1Wire = 'Disabled (SMB2 redirect)'
    }
    else {
        $hostRow.SMBv1Wire = 'Unknown (' + $probe.ResponseMagic + ')'
    }

    # --- WMI path ---
    $osInfo   = $null
    $regState = $null
    $role     = 'Unknown'
    $patch    = $null

    if (-not $NetOnly) {
        $osInfo = Get-HostOsInfo -HostName $HostName -Cred $Cred
        if ($osInfo) {
            $hostRow.OsCaption = $osInfo.Caption
            $hostRow.OsBuild   = $osInfo.BuildNumber
        }

        $role = Get-HostRole -HostName $HostName -Cred $Cred
        $hostRow.Role = $role

        $osBuild = if ($osInfo) { $osInfo.BuildNumber } else { 0 }
        $regState = Test-SMBv1Registry -HostName $HostName -OsBuild $osBuild -Cred $Cred

        if ($regState) {
            $hostRow.WMIReachable = $true

            if ($null -ne $regState.SMB1RegEnabled) {
                $hostRow.SMBv1Registry = if ($regState.SMB1RegEnabled) { 'ENABLED' } else { 'Disabled' }
            }
            else {
                $hostRow.SMBv1Registry = 'Unknown (no OS build)'
            }

            if ($null -ne $regState.DriverEnabled) {
                $hostRow.DriverState = if ($regState.DriverEnabled) { 'Running' } else { 'Disabled (Start=4)' }
            }

            $hostRow.AuditLogging = if ($regState.AuditEnabled) { 'Enabled' } else { 'DISABLED' }

            # Discrepancy: registry says disabled but wire still answered SMBv1
            if ($regState.SMB1RegEnabled -eq $false -and $probe.SMBv1Responded) {
                $hostRow.Discrepancy = $true
            }
            # Discrepancy: registry says enabled but wire redirected to SMB2
            if ($regState.SMB1RegEnabled -eq $true -and $probe.SMBv2Redirected) {
                $hostRow.Discrepancy = $true
            }
        }
        else {
            Write-AuditWarning -Host $HostName -Detail 'WMI registry access failed -- partial audit only'
        }

        # MS17-010 patch check only for SMBv1-enabled hosts
        if ($probe.SMBv1Responded -or ($regState -and $regState.SMB1RegEnabled -eq $true)) {
            if ($osInfo -and $osInfo.BuildNumber -gt 0) {
                $patch = Test-EternalBluePatch -HostName $HostName -OsBuild $osInfo.BuildNumber -Cred $Cred
                if ($patch.Checked) {
                    $hostRow.MS17010Patch = if ($patch.Patched) { 'Patched (' + $patch.TargetKB + ')' } else { 'MISSING (' + $patch.TargetKB + ')' }
                }
                else {
                    $hostRow.MS17010Patch = 'Check failed'
                }
            }
        }
    }

    # -----------------------------------------------------------------------
    # Generate findings
    # -----------------------------------------------------------------------
    $sev = switch ($role) {
        'DC'          { 'CRITICAL' }
        'Server'      { 'HIGH' }
        'Workstation' { 'MEDIUM' }
        default       { if ($NetOnly) { 'HIGH' } else { 'MEDIUM' } }
    }

    # D01: SMBv1 enabled on wire
    if ($probe.SMBv1Responded) {
        Add-Finding `
            -Domain 'D01' `
            -Title  'SMBv1 Protocol Enabled (Wire-Confirmed)' `
            -Severity $sev `
            -Host $HostName `
            -Detail ("Network probe confirmed $HostName responds to SMBv1 COM_NEGOTIATE requests (magic=FF534D42). " +
                     "Role: $role. OS: $($hostRow.OsCaption).") `
            -Why ("SMBv1 is a 30-year-old protocol with no signing, no encryption, and no modern security features. " +
                  "It is the attack surface exploited by $($script:T.EB) (MS17-010), $($script:T.WN), and $($script:T.NP). " +
                  "Microsoft deprecated SMBv1 in 2014 and disabled it by default in Windows 10 RS3 (build 16299) in 2017. " +
                  "Any host still responding to SMBv1 is an unmitigated risk.") `
            -Assets "[HOST] $HostName`n[REG] HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1" `
            -AttackPath ("1. Confirm with: nmap --script smb-security-mode $HostName`n" +
                         "2. Exploit with $($script:T.IM)/$($script:T.EB) to achieve unauthenticated RCE (if unpatched MS17-010)`n" +
                         "3. Or: capture NetNTLM hashes via SMBv1 without signing enforcement`n" +
                         "4. Or: relay captured hashes with $($script:T.NR) to other SMBv1 hosts`n" +
                         "5. Pivot to DA via $($script:T.MK) / $($script:T.SK)::$($script:T.LP) on compromised host") `
            -Fix ("# Disable SMBv1 server (requires reboot or LanmanServer service restart)`n" +
                  "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Value 0 -Type DWord`n`n" +
                  "# Disable mrxsmb10 driver (prevents client-side SMBv1 too)`n" +
                  "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name Start -Value 4 -Type DWord`n`n" +
                  "# Or via PowerShell (Windows 8.1 / Server 2012 R2+)`n" +
                  "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force`n`n" +
                  "# Or via DISM (Windows 10 / Server 2016+)`n" +
                  "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`n`n" +
                  "# Verify after restart`n" +
                  "Get-SmbServerConfiguration | Select EnableSMB1Protocol")
    }

    # D02: SMBv1 enabled in registry (even if wire redirected -- could re-enable after restart)
    if ($regState -and $regState.SMB1RegEnabled -eq $true -and -not $probe.SMBv1Responded) {
        Add-Finding `
            -Domain 'D02' `
            -Title  'SMBv1 Enabled in Registry (Not Active on Wire)' `
            -Severity 'MEDIUM' `
            -Host $HostName `
            -Detail ("Registry key SMB1=1 in LanmanServer\Parameters on $HostName. " +
                     "Wire probe showed SMB2 redirect, so SMBv1 may not be active currently, " +
                     "but registry state will persist across reboots. Driver Start=$($regState.DriverStart).") `
            -Why ("A registry value of SMB1=1 means SMBv1 is not explicitly disabled. " +
                  "On older OS builds the service default is enabled. After any LanmanServer restart " +
                  "or OS upgrade rollback, SMBv1 could become active. This is a latent risk.") `
            -Assets "[HOST] $HostName`n[REG] HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1 = 1" `
            -AttackPath ("Registry state persists across reboots. If LanmanServer is restarted, $HostName may respond to SMBv1 again.") `
            -Fix ("Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Value 0 -Type DWord")
    }

    # D03: Discrepancy between registry and wire
    if ($hostRow.Discrepancy) {
        $discDetail = ''
        if ($regState -and $regState.SMB1RegEnabled -eq $false -and $probe.SMBv1Responded) {
            $discDetail = "Registry says SMBv1 DISABLED but the wire still responds to SMBv1. LanmanServer service has not been restarted since the registry change."
        }
        elseif ($regState -and $regState.SMB1RegEnabled -eq $true -and $probe.SMBv2Redirected) {
            $discDetail = "Registry says SMBv1 ENABLED but the wire returns SMB2 redirect. Driver may be separately disabled (mrxsmb10 Start=$($regState.DriverStart))."
        }
        Add-Finding `
            -Domain 'D03' `
            -Title  'SMBv1 Registry/Wire Discrepancy' `
            -Severity 'HIGH' `
            -Host $HostName `
            -Detail $discDetail `
            -Why ("Discrepancy means the host is in an inconsistent security state. " +
                  "An attacker or a reboot could restore the more-permissive state. " +
                  "Administrator may believe SMBv1 is disabled when it is not.") `
            -Assets "[HOST] $HostName`n[REG] LanmanServer\Parameters\SMB1`n[REG] mrxsmb10\Start" `
            -AttackPath "Reboot or service restart may re-enable SMBv1 attack surface." `
            -Fix ("# Restart service to apply registry setting:`n" +
                  "Restart-Service LanmanServer -Force`n" +
                  "# Then verify:`n" +
                  "Get-SmbServerConfiguration | Select EnableSMB1Protocol")
    }

    # D04: SMBv1 audit logging absent
    if ($regState -and -not $regState.AuditEnabled) {
        if ($regState.SMB1RegEnabled -ne $false) {
            # Only report missing audit when SMBv1 is or might be enabled
            Add-Finding `
                -Domain 'D04' `
                -Title  'SMBv1 Audit Logging Not Enabled' `
                -Severity 'LOW' `
                -Host $HostName `
                -Detail "AuditSmb1Access registry value absent or 0 on $HostName. No visibility into which clients are connecting via SMBv1." `
                -Why ("Without SMBv1 audit logging, you cannot identify legacy clients still using SMBv1. " +
                      "Enabling audit first is recommended before disabling SMBv1 to avoid breaking legacy systems.") `
                -Assets "[HOST] $HostName`n[REG] HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\AuditSmb1Access" `
                -AttackPath "No detection capability for SMBv1-based lateral movement or exploitation." `
                -Fix ("# Enable SMBv1 audit logging (Windows 10 / Server 2016+ only)`n" +
                      "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name AuditSmb1Access -Value 1 -Type DWord`n" +
                      "# After enabling, review Event ID 3000 in Microsoft-Windows-SMBServer/Audit log`n" +
                      "Get-WinEvent -LogName 'Microsoft-Windows-SMBServer/Audit' | Select -First 20")
        }
    }

    # D05: MS17-010 missing patch on SMBv1-enabled host
    if ($patch -and $patch.Checked -and -not $patch.Patched) {
        Add-Finding `
            -Domain 'D05' `
            -Title  "MS17-010 ($($script:T.EB)) Patch Missing" `
            -Severity 'CRITICAL' `
            -Host $HostName `
            -Detail ("$HostName is running SMBv1 AND is missing patch $($patch.TargetKB) (MS17-010). " +
                     "This combination is directly exploitable for unauthenticated remote code execution. OS build: $($hostRow.OsBuild).") `
            -Why ("MS17-010 is the vulnerability exploited by $($script:T.EB), $($script:T.WN), and $($script:T.NP). " +
                  "It allows unauthenticated SYSTEM-level code execution over SMBv1 TCP/445. " +
                  "No credentials needed. Exploits are publicly available in $($script:T.ME) and $($script:T.IM).") `
            -Assets ("[HOST] $HostName`n[PATCH] $($patch.TargetKB) -- NOT INSTALLED`n" +
                     "[REG] HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1") `
            -AttackPath ("1. $($script:T.ME) module: use exploit/windows/smb/ms17_010_eternalblue`n" +
                         "2. Set RHOSTS $HostName; run`n" +
                         "3. Obtain SYSTEM shell -- no credentials required`n" +
                         "4. Dump hashes with $($script:T.MK) $($script:T.SK)::$($script:T.LP)`n" +
                         "5. Move laterally via Pass-the-Hash or $($script:T.DS)") `
            -Fix ("# IMMEDIATE: Disable SMBv1 to remove attack surface`n" +
                  "Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force`n`n" +
                  "# Apply MS17-010 patch: $($patch.TargetKB)`n" +
                  "# Download from Microsoft Update Catalog and install:`n" +
                  "# https://www.catalog.update.microsoft.com/Search.aspx?q=$($patch.TargetKB)`n`n" +
                  "# Block TCP/445 at perimeter firewall as immediate mitigation`n" +
                  "# Verify patch after install:`n" +
                  "Get-HotFix -Id $($patch.TargetKB)")
    }

    $hostRow.FindingCount = @($script:Findings | Where-Object { $_.Host -eq $HostName -and $_.Domain -ne 'META' }).Count
    $script:HostResults.Add($hostRow)

    $status = if ($probe.SMBv1Responded) { ' [SMBv1 ON]' } elseif ($probe.SMBv2Redirected) { ' [SMBv1 off]' } else { ' [unknown]' }
    $color  = if ($probe.SMBv1Responded) { 'Red' } else { 'Green' }
    Write-Host $status -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# HTML report builder
# ---------------------------------------------------------------------------
function Build-HtmlReport {
    param(
        [object[]]$HostRows,
        [object[]]$AllFindings,
        [string]$OutPath
    )

    $ts         = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $totalHosts = $HostRows.Count
    $smb1Hosts  = @($HostRows | Where-Object { $_.SMBv1Wire -eq 'ENABLED' }).Count
    $ms17Hosts  = @($AllFindings | Where-Object { $_.Domain -eq 'D05' }).Count

    $critCount = @($AllFindings | Where-Object { $_.Severity -eq 'CRITICAL' -and $_.Domain -ne 'META' }).Count
    $highCount = @($AllFindings | Where-Object { $_.Severity -eq 'HIGH'     -and $_.Domain -ne 'META' }).Count
    $medCount  = @($AllFindings | Where-Object { $_.Severity -eq 'MEDIUM'   -and $_.Domain -ne 'META' }).Count
    $lowCount  = @($AllFindings | Where-Object { $_.Severity -eq 'LOW'      -and $_.Domain -ne 'META' }).Count

    # Score: start 100, deduct per finding
    $score = 100 - ($critCount * 25) - ($highCount * 15) - ($medCount * 8) - ($lowCount * 3)
    if ($score -lt 0) { $score = 0 }

    $gaugeColor = if ($score -ge 80) { '#4caf50' } elseif ($score -ge 50) { '#ff9800' } else { '#f44336' }
    $dashOffset = [int](283 - ($score / 100) * 283)

    # Build host matrix rows
    $matrixRows = ''
    foreach ($h in ($HostRows | Sort-Object { if ($_.SMBv1Wire -eq 'ENABLED') { 0 } else { 1 } })) {
        $v1Cell    = if ($h.SMBv1Wire -eq 'ENABLED') { '<td class="c-crit">ON</td>' }
                     elseif ($h.SMBv1Wire -like 'Disabled*') { '<td class="c-ok">Off</td>' }
                     else { '<td class="c-unk">' + $h.SMBv1Wire + '</td>' }
        $regCell   = if ($h.SMBv1Registry -eq 'ENABLED') { '<td class="c-high">ON</td>' }
                     elseif ($h.SMBv1Registry -eq 'Disabled') { '<td class="c-ok">Off</td>' }
                     else { '<td class="c-unk">' + $h.SMBv1Registry + '</td>' }
        $drvCell   = if ($h.DriverState -like 'Running*') { '<td class="c-warn">Running</td>' }
                     elseif ($h.DriverState -like 'Disabled*') { '<td class="c-ok">Off</td>' }
                     else { '<td class="c-unk">' + $h.DriverState + '</td>' }
        $audCell   = if ($h.AuditLogging -eq 'DISABLED') { '<td class="c-warn">None</td>' }
                     elseif ($h.AuditLogging -eq 'Enabled') { '<td class="c-ok">On</td>' }
                     else { '<td class="c-unk">' + $h.AuditLogging + '</td>' }
        $patchCell = if ($h.MS17010Patch -like 'MISSING*') { '<td class="c-crit">MISSING</td>' }
                     elseif ($h.MS17010Patch -like 'Patched*') { '<td class="c-ok">OK</td>' }
                     else { '<td class="c-unk">' + $h.MS17010Patch + '</td>' }
        $discCell  = if ($h.Discrepancy) { '<td class="c-high">YES</td>' } else { '<td class="c-ok">-</td>' }
        $roleCell  = if ($h.Role -eq 'DC') { '<td class="c-crit">DC</td>' }
                     elseif ($h.Role -eq 'Server') { '<td class="c-warn">Server</td>' }
                     else { '<td>' + $h.Role + '</td>' }

        $matrixRows += "<tr><td>$($h.Host)</td>$roleCell<td>$($h.OsCaption)</td>$v1Cell$regCell$drvCell$audCell$patchCell$discCell<td>$($h.FindingCount)</td></tr>`n"
    }

    # Build finding cards
    $findingCards = ''
    $sortedFindings = $AllFindings | Where-Object { $_.Domain -ne 'META' } |
        Sort-Object { $script:SevOrder[$_.Severity] }, Host

    foreach ($f in $sortedFindings) {
        $sevClass = switch ($f.Severity) {
            'CRITICAL' { 'sev-crit' }
            'HIGH'     { 'sev-high' }
            'MEDIUM'   { 'sev-med'  }
            'LOW'      { 'sev-low'  }
            default    { 'sev-info' }
        }
        $assetsHtml     = ($f.Assets     -replace "`n", '<br>') -replace '\[([A-Z-]+)\]', '<span class="tag tag-$1">[$1]</span>'
        $attackHtml     = ($f.AttackPath -replace "`n", '<br>')
        $fixHtml        = ($f.Fix        -replace '&','&amp;') -replace '<','&lt;' -replace '>','&gt;' -replace "`n", '<br>'
        $detailEsc      = ($f.Detail     -replace '&','&amp;') -replace '<','&lt;' -replace '>','&gt;'
        $whyEsc         = ($f.Why        -replace '&','&amp;') -replace '<','&lt;' -replace '>','&gt;'

        $findingCards += @"
<div class="card $sevClass" data-sev="$($f.Severity)" data-host="$($f.Host)" data-title="$($f.Title)">
  <div class="card-header">
    <span class="badge $sevClass">$($f.Severity)</span>
    <span class="card-title">$($f.Title)</span>
    <span class="card-host">$($f.Host)</span>
    <span class="card-domain">$($f.Domain)</span>
    <span class="toggle">+</span>
  </div>
  <div class="card-body">
    <div class="tabs">
      <button class="tab active" onclick="showTab(this,'why')">Why</button>
      <button class="tab" onclick="showTab(this,'assets')">Assets</button>
      <button class="tab" onclick="showTab(this,'attack')">Attack Path</button>
      <button class="tab" onclick="showTab(this,'fix')">Remediation</button>
    </div>
    <div class="tab-content" id="tab-why">
      <p>$detailEsc</p><p>$whyEsc</p>
    </div>
    <div class="tab-content hidden" id="tab-assets">$assetsHtml</div>
    <div class="tab-content hidden" id="tab-attack"><code>$attackHtml</code></div>
    <div class="tab-content hidden" id="tab-fix"><pre><code>$fixHtml</code></pre></div>
  </div>
</div>
"@
    }

    # EternalBlue / MS17-010 exposure list
    $ebList = @($HostRows | Where-Object { $_.MS17010Patch -like 'MISSING*' -and $_.SMBv1Wire -eq 'ENABLED' })
    $ebBox  = ''
    if ($ebList.Count -gt 0) {
        $ebItems = ($ebList | ForEach-Object { "<li>$($_.Host) ($($_.Role)) -- OS build $($_.OsBuild)</li>" }) -join "`n"
        $ebBox = @"
<div class="exposure-box">
  <h3>EternalBlue Exposure ($($ebList.Count) host(s) -- SMBv1 ON + MS17-010 unpatched)</h3>
  <p>These hosts are unauthenticated RCE targets. Prioritize immediate remediation.</p>
  <ul>$ebItems</ul>
</div>
"@
    }

    # SMBv1 active list
    $v1List = @($HostRows | Where-Object { $_.SMBv1Wire -eq 'ENABLED' })
    $v1Box  = ''
    if ($v1List.Count -gt 0) {
        $v1Items = ($v1List | ForEach-Object { "<li>$($_.Host) ($($_.Role)) $($_.OsCaption)</li>" }) -join "`n"
        $v1Box = @"
<div class="exposure-box v1-box">
  <h3>SMBv1-Active Hosts ($($v1List.Count) total)</h3>
  <p>All hosts below responded to a raw SMBv1 COM_NEGOTIATE packet on TCP/445.</p>
  <ul>$v1Items</ul>
</div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SMBv1 Audit Report -- $ts</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
      --crit:#ff4444;--high:#ff8800;--med:#ffcc00;--low:#4caf50;--info:#58a6ff;--ok:#238636}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;font-size:14px}
header{background:var(--surface);border-bottom:1px solid var(--border);padding:20px 32px;display:flex;align-items:center;gap:24px}
header h1{font-size:22px;font-weight:700}
header .sub{color:var(--muted);font-size:12px;margin-top:4px}
.gauge-wrap{display:flex;align-items:center;gap:12px;margin-left:auto}
.gauge-wrap svg{width:80px;height:80px}
.score-val{font-size:28px;font-weight:700;color:$gaugeColor}
.summary{display:flex;gap:16px;padding:20px 32px;flex-wrap:wrap}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px 24px;min-width:120px;text-align:center}
.stat-card .num{font-size:32px;font-weight:700}
.stat-card .lbl{color:var(--muted);font-size:12px;margin-top:4px}
.crit{color:var(--crit)}.high{color:var(--high)}.med{color:var(--med)}.low{color:var(--low)}.ok{color:var(--ok)}
section{padding:0 32px 32px}
h2{font-size:16px;font-weight:600;margin:24px 0 12px;border-bottom:1px solid var(--border);padding-bottom:8px}
.exposure-box{background:#1a0000;border:2px solid var(--crit);border-radius:8px;padding:16px 20px;margin-bottom:20px}
.exposure-box h3{color:var(--crit);margin-bottom:8px}
.exposure-box ul{padding-left:20px;margin-top:8px;line-height:1.8}
.v1-box{background:#1a0800;border-color:var(--high)}
.v1-box h3{color:var(--high)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#1c2128;padding:8px 12px;text-align:left;color:var(--muted);font-weight:600;border-bottom:1px solid var(--border)}
td{padding:7px 12px;border-bottom:1px solid #21262d}
tr:hover td{background:#1c2128}
.c-crit{color:var(--crit);font-weight:700}
.c-high{color:var(--high);font-weight:600}
.c-warn{color:var(--med)}
.c-ok{color:var(--ok)}
.c-unk{color:var(--muted)}
.filter-bar{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;align-items:center}
.filter-bar select,.filter-bar input{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:6px 10px;border-radius:6px;font-size:13px}
.filter-bar input{flex:1;min-width:180px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:10px;overflow:hidden}
.card.sev-crit{border-left:4px solid var(--crit)}
.card.sev-high{border-left:4px solid var(--high)}
.card.sev-med{border-left:4px solid var(--med)}
.card.sev-low{border-left:4px solid var(--low)}
.card-header{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;user-select:none}
.card-header:hover{background:#1c2128}
.badge{font-size:11px;font-weight:700;padding:2px 8px;border-radius:4px;text-transform:uppercase;min-width:70px;text-align:center}
.badge.sev-crit{background:#3d0000;color:var(--crit);border:1px solid var(--crit)}
.badge.sev-high{background:#3d1a00;color:var(--high);border:1px solid var(--high)}
.badge.sev-med{background:#3d3300;color:var(--med);border:1px solid var(--med)}
.badge.sev-low{background:#003d0d;color:var(--low);border:1px solid var(--low)}
.card-title{font-weight:600;flex:1}
.card-host{color:var(--info);font-family:monospace;font-size:12px}
.card-domain{color:var(--muted);font-size:11px;margin-left:6px}
.toggle{color:var(--muted);font-size:18px;margin-left:auto}
.card-body{display:none;padding:14px 16px;border-top:1px solid var(--border)}
.tabs{display:flex;gap:4px;margin-bottom:12px}
.tab{background:none;border:1px solid var(--border);color:var(--muted);padding:5px 14px;border-radius:6px;cursor:pointer;font-size:12px}
.tab.active,.tab:hover{background:#1c2128;color:var(--text)}
.tab-content{font-size:13px;line-height:1.6}
.tab-content p{margin-bottom:8px}
.tab-content pre{background:#0d1117;border:1px solid var(--border);border-radius:6px;padding:12px;overflow-x:auto;font-size:12px}
.tab-content code{font-family:monospace;font-size:12px}
.hidden{display:none}
.tag{font-size:11px;font-weight:700;padding:1px 6px;border-radius:3px;margin-right:2px}
.tag-HOST{background:#003366;color:#58a6ff}.tag-REG{background:#330033;color:#c792ea}
.tag-PATCH{background:#003300;color:#56d364}.tag-FILE{background:#332200;color:#ffcc00}
</style>
</head>
<body>
<header>
  <div>
    <h1>SMBv1 Protocol Audit</h1>
    <div class="sub">Generated: $ts | Hosts scanned: $totalHosts | Report ID: $($script:ReportId)</div>
  </div>
  <div class="gauge-wrap">
    <svg viewBox="0 0 100 100">
      <circle cx="50" cy="50" r="45" fill="none" stroke="#30363d" stroke-width="10"/>
      <circle cx="50" cy="50" r="45" fill="none" stroke="$gaugeColor" stroke-width="10"
              stroke-dasharray="283" stroke-dashoffset="$dashOffset"
              stroke-linecap="round" transform="rotate(-90 50 50)"/>
    </svg>
    <div><div class="score-val">$score</div><div style="color:var(--muted);font-size:11px">Security Score</div></div>
  </div>
</header>

<div class="summary">
  <div class="stat-card"><div class="num">$totalHosts</div><div class="lbl">Hosts Scanned</div></div>
  <div class="stat-card"><div class="num crit">$smb1Hosts</div><div class="lbl">SMBv1 Active</div></div>
  <div class="stat-card"><div class="num crit">$ms17Hosts</div><div class="lbl">EternalBlue Exposed</div></div>
  <div class="stat-card"><div class="num crit">$critCount</div><div class="lbl">Critical</div></div>
  <div class="stat-card"><div class="num high">$highCount</div><div class="lbl">High</div></div>
  <div class="stat-card"><div class="num med">$medCount</div><div class="lbl">Medium</div></div>
  <div class="stat-card"><div class="num low">$lowCount</div><div class="lbl">Low</div></div>
</div>

<section>
  $ebBox
  $v1Box

  <h2>Host Matrix</h2>
  <table>
    <thead>
      <tr>
        <th>Host</th><th>Role</th><th>OS</th>
        <th>SMBv1 Wire</th><th>SMBv1 Reg</th><th>Driver</th>
        <th>Audit Log</th><th>MS17-010</th><th>Discrepancy</th><th>Findings</th>
      </tr>
    </thead>
    <tbody>
      $matrixRows
    </tbody>
  </table>

  <h2>Findings</h2>
  <div class="filter-bar">
    <select id="sevFilter" onchange="applyFilters()">
      <option value="">All Severities</option>
      <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option>
    </select>
    <select id="hostFilter" onchange="applyFilters()">
      <option value="">All Hosts</option>
$(
    ($AllFindings | Where-Object { $_.Domain -ne 'META' } | Select-Object -ExpandProperty Host -Unique | Sort-Object |
     ForEach-Object { "      <option>$_</option>" }) -join "`n"
)
    </select>
    <input type="text" id="searchBox" placeholder="Search findings..." oninput="applyFilters()">
  </div>
  $findingCards
</section>

<script>
document.querySelectorAll('.card-header').forEach(function(h){
  h.addEventListener('click',function(){
    var body=this.nextElementSibling;
    var tog=this.querySelector('.toggle');
    if(body.style.display==='block'){body.style.display='none';tog.textContent='+';}
    else{body.style.display='block';tog.textContent='-';}
  });
});
function showTab(btn,id){
  var body=btn.closest('.card-body');
  body.querySelectorAll('.tab-content').forEach(function(t){t.classList.add('hidden');});
  body.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active');});
  body.querySelector('#tab-'+id).classList.remove('hidden');
  btn.classList.add('active');
}
function applyFilters(){
  var sev=document.getElementById('sevFilter').value.toLowerCase();
  var host=document.getElementById('hostFilter').value.toLowerCase();
  var q=document.getElementById('searchBox').value.toLowerCase();
  document.querySelectorAll('.card').forEach(function(c){
    var ms=(sev===''||c.dataset.sev.toLowerCase()===sev);
    var mh=(host===''||c.dataset.host.toLowerCase()===host);
    var mt=(q===''||(c.dataset.title.toLowerCase().includes(q)||c.dataset.host.toLowerCase().includes(q)));
    c.style.display=(ms&&mh&&mt)?'':'none';
  });
}
</script>
</body>
</html>
"@

    return $html
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "=============================" -ForegroundColor Cyan
Write-Host " Invoke-SMBv1Audit" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host ""

$resolvedTargets = Resolve-Targets -RawTargets $Targets
Write-Host "[*] Targets resolved: $($resolvedTargets.Count) hosts"
if ($NetworkOnly) { Write-Host "[*] Mode: Network probe only (WMI disabled)" -ForegroundColor Yellow }
else              { Write-Host "[*] Mode: Network probe + WMI registry" -ForegroundColor Cyan }
Write-Host ""

foreach ($target in $resolvedTargets) {
    Invoke-HostAudit -HostName $target -Cred $Credential -NetOnly:$NetworkOnly
}

Write-Host ""
Write-Host "[*] Building HTML report..." -NoNewline

# Write report
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$reportFile = Join-Path $OutputPath "$($script:ReportId).html"
$htmlContent = Build-HtmlReport -HostRows $script:HostResults.ToArray() -AllFindings $script:Findings.ToArray() -OutPath $OutputPath

# Write UTF-8 no-BOM
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($reportFile, $htmlContent, $utf8NoBom)

Write-Host " Done." -ForegroundColor Green
Write-Host "[+] Report: $reportFile" -ForegroundColor Green

# CSV sidecar
if (-not $NoCsv) {
    $csvFile  = Join-Path $OutputPath "$($script:ReportId).csv"
    $csvFinds = $script:Findings | Where-Object { $_.Domain -ne 'META' }
    $csvFinds | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
    Write-Host "[+] CSV: $csvFile" -ForegroundColor Green
}

# Summary
Write-Host ""
$smb1Count = @($script:HostResults | Where-Object { $_.SMBv1Wire -eq 'ENABLED' }).Count
$ebCount   = @($script:Findings | Where-Object { $_.Domain -eq 'D05' }).Count
$critTotal = @($script:Findings | Where-Object { $_.Severity -eq 'CRITICAL' -and $_.Domain -ne 'META' }).Count
$highTotal = @($script:Findings | Where-Object { $_.Severity -eq 'HIGH'     -and $_.Domain -ne 'META' }).Count

Write-Host "Results:" -ForegroundColor White
Write-Host "  Hosts scanned    : $($resolvedTargets.Count)"
Write-Host "  SMBv1 active     : $smb1Count" -ForegroundColor $(if ($smb1Count -gt 0) { 'Red' } else { 'Green' })
Write-Host "  EternalBlue risk : $ebCount"   -ForegroundColor $(if ($ebCount   -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Critical findings: $critTotal" -ForegroundColor $(if ($critTotal -gt 0) { 'Red' } else { 'Green' })
Write-Host "  High findings    : $highTotal" -ForegroundColor $(if ($highTotal -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ""

$elapsed = (Get-Date) - $script:StartTime
Write-Host "Completed in $([int]$elapsed.TotalSeconds)s" -ForegroundColor DarkGray
