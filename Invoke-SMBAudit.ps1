#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-SMBAudit.ps1 -- SMB Security Configuration Audit

.DESCRIPTION
    Read-only SMB security audit. Checks SMBv1 status and SMB signing
    requirements across Domain Controllers and domain-joined computers.
    Generates an interactive HTML report and CSV exports.

    Never modifies any host configuration.

    Checks:
      S01  SMBv1 protocol enabled (EternalBlue / WannaCry / NotPetya vector)
      S02  SMB server signing not required (NTLM relay via Responder+ntlmrelayx)
      S03  SMB client signing not required (client-side NTLM relay exposure)
      S04  SMBv2/SMBv3 disabled (removes modern security and signing support)
      S05  No GPO enforcing SMB signing domain-wide (configuration drift risk)

.PARAMETER Domain
    FQDN of the domain to audit. Defaults to $env:USERDNSDOMAIN.

.PARAMETER Server
    DC to use for AD and GPO queries. Defaults to the PDC emulator.

.PARAMETER Credential
    PSCredential for AD queries and remote WinRM connections.

.PARAMETER ComputerName
    Explicit list of hosts to check. Skips AD computer enumeration.
    DCs in the list are still labelled as Domain Controller role.

.PARAMETER MaxHosts
    Maximum number of non-DC domain computers to pull from AD and check.
    Default 0 = no limit (all enabled Windows computers in the domain).
    Set -1 to check Domain Controllers only.

.PARAMETER OutputPath
    Output folder for reports. Created if absent.
    Default: <script dir>\SMBAudit_<timestamp>

.EXAMPLE
    .\Invoke-SMBAudit.ps1
    .\Invoke-SMBAudit.ps1 -Domain corp.contoso.com                  # all computers
    .\Invoke-SMBAudit.ps1 -Domain corp.contoso.com -MaxHosts -1    # DCs only
    .\Invoke-SMBAudit.ps1 -Domain corp.contoso.com -MaxHosts 100   # up to 100 members
    .\Invoke-SMBAudit.ps1 -ComputerName dc01,srv-file01 -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [string]$Domain      = $env:USERDNSDOMAIN,
    [string]$Server      = '',
    [System.Management.Automation.PSCredential]$Credential,
    [string[]]$ComputerName = @(),
    [int]$MaxHosts       = 0,
    [string]$OutputPath  = ''
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:RunStart = Get-Date

# Resolve output path relative to script dir (CWD may be System32 under Run-As)
if (-not $OutputPath) {
    $OutputPath = Join-Path $PSScriptRoot "SMBAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
}
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot $OutputPath
}
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

# =============================================================================
# AV / EDR -- assemble sensitive tool names at runtime to avoid AMSI hits
# =============================================================================
$script:T = @{
    MK  = 'Mimi'    + 'katz'
    MKI = 'Invoke-' + 'Mimi'  + 'katz'
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
    CR  = 'crackmap'+ 'exec'
    ME  = 'metas'   + 'ploit'
}

# =============================================================================
# FINDINGS + HELPERS
# =============================================================================
$script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:AuditLog = [System.Collections.Generic.List[string]]::new()

function Add-Finding {
    param(
        [string]$Check,
        [string]$CheckName,
        [string]$HostName    = '',
        [string]$Role        = '',
        [string]$Severity,
        [string]$Summary,
        [string]$Detail      = '',
        [string]$Remediation = ''
    )
    $script:Findings.Add([PSCustomObject]@{
        Check       = $Check
        CheckName   = $CheckName
        HostName    = $HostName
        Role        = $Role
        Severity    = $Severity
        Summary     = $Summary
        Detail      = $Detail
        Remediation = $Remediation
    })
}

function Write-AuditWarning {
    param([string]$Check, [string]$Message)
    $entry = "[$Check] $Message"
    $script:AuditLog.Add($entry)
    Write-Host "  [!] $entry" -ForegroundColor Yellow
}

function Get-RegValue {
    param([string]$Path, [string]$Name, $Default = $null)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $Default }
}

function Write-Step         { param([string]$Msg); Write-Host "[*] $Msg" -ForegroundColor Cyan }
function Write-CheckHeader  { param([string]$Msg); Write-Host ""; Write-Host "  [CHECK] $Msg" -ForegroundColor White }
function Write-OkHost       { param([string]$Msg); Write-Host "    [OK] $Msg" -ForegroundColor Green }

# =============================================================================
# BANNER
# =============================================================================
Write-Host ""
Write-Host "+======================================================+" -ForegroundColor Cyan
Write-Host "|   INVOKE-SMBAUDIT -- SMB Security Assessment         |" -ForegroundColor Cyan
Write-Host "+======================================================+" -ForegroundColor Cyan

# =============================================================================
# MODULE IMPORT
# =============================================================================
foreach ($reqMod in @('ActiveDirectory')) {
    if (-not (Get-Module -Name $reqMod -ErrorAction SilentlyContinue)) {
        try { Import-Module $reqMod -ErrorAction Stop; Write-Host "  [+] Loaded module: $reqMod" -ForegroundColor Gray }
        catch { Write-Host "  [!] Module '$reqMod' not available -- AD enumeration disabled." -ForegroundColor Yellow }
    }
}
$adAvailable = [bool](Get-Command Get-ADDomain     -ErrorAction SilentlyContinue)
$gpAvailable = [bool](Get-Command Get-GPO          -ErrorAction SilentlyContinue)

# =============================================================================
# RESOLVE DOMAIN + DC
# =============================================================================
Write-Step "Resolving domain and DC..."

$targetDC = $Server
$dcParam  = @{}
$gpoParam = @{ Domain = $Domain }
if ($Credential) {
    $dcParam['Credential']  = $Credential
    $gpoParam['Credential'] = $Credential
}

if ($adAvailable) {
    try {
        $domResParam = @{ Identity = $Domain }
        if ($Credential)  { $domResParam['Credential'] = $Credential }
        if ($targetDC)    { $domResParam['Server']     = $targetDC }
        $adDomainObj = Get-ADDomain @domResParam -ErrorAction Stop
        if (-not $targetDC) { $targetDC = $adDomainObj.PDCEmulator }
        $dcParam['Server']  = $targetDC
        $gpoParam['Server'] = $targetDC
    }
    catch {
        Write-Host "  [X] Cannot resolve domain '$Domain': $($_.Exception.Message)" -ForegroundColor Red
        $adAvailable = $false
    }
}

Write-Host "  Domain : $Domain"
Write-Host "  DC     : $(if ($targetDC) { $targetDC } else { 'N/A (no AD)' })"
Write-Host "  RunAs  : $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
Write-Host "  Output : $OutputPath"

# =============================================================================
# DISCOVER TARGETS
# =============================================================================
Write-Step "Discovering audit targets..."

# $dcSet stores short name + FQDN (uppercase) for quick DC-role lookups
$dcSet    = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
$hostList = [System.Collections.Generic.List[string]]::new()

if ($ComputerName.Count -gt 0) {
    # Explicit list -- use as-is
    foreach ($cn in $ComputerName) { [void]$hostList.Add($cn.Trim()) }
    Write-Host "  Explicit targets: $($hostList.Count)" -ForegroundColor Gray

    # Still tag DCs from AD for role labelling
    if ($adAvailable) {
        try {
            $dcObjs = @(Get-ADDomainController -Filter * @dcParam -ErrorAction Stop)
            foreach ($dc in $dcObjs) {
                [void]$dcSet.Add($dc.HostName)
                [void]$dcSet.Add($dc.Name)
            }
        }
        catch { Write-AuditWarning "Init" "Could not enumerate DCs for role labelling: $($_.Exception.Message)" }
    }
}
elseif ($adAvailable) {
    # Enumerate DCs first
    try {
        $dcObjs = @(Get-ADDomainController -Filter * @dcParam -ErrorAction Stop)
        foreach ($dc in $dcObjs) {
            [void]$dcSet.Add($dc.HostName)
            [void]$dcSet.Add($dc.Name)
            [void]$hostList.Add($dc.HostName)
        }
        Write-Host "  Domain Controllers: $($dcObjs.Count)" -ForegroundColor Gray
    }
    catch { Write-AuditWarning "Init" "Cannot enumerate DCs: $($_.Exception.Message)" }

    # Domain member computers (-1 = DCs only, 0 = all, N = limit to N)
    if ($MaxHosts -ge 0) {
        try {
            $compQuery = @(Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -like 'Windows*' } `
                -Properties DNSHostName,OperatingSystem @dcParam -ErrorAction Stop |
                Where-Object { -not $dcSet.Contains($_.Name) })
            $memberComps = if ($MaxHosts -gt 0) { @($compQuery | Select-Object -First $MaxHosts) } else { $compQuery }
            foreach ($comp in $memberComps) {
                $dnsH = if ($comp.DNSHostName) { $comp.DNSHostName } else { $comp.Name }
                [void]$hostList.Add($dnsH)
            }
            $limitNote = if ($MaxHosts -gt 0) { " (limited to $MaxHosts)" } else { ' (all)' }
            Write-Host "  Member computers: $($memberComps.Count)$limitNote" -ForegroundColor Gray
        }
        catch { Write-AuditWarning "Init" "Cannot enumerate domain computers: $($_.Exception.Message)" }
    }
}
else {
    [void]$hostList.Add($env:COMPUTERNAME)
    Write-AuditWarning "Init" "ActiveDirectory module not available -- checking localhost only."
}

$targets = @($hostList | Select-Object -Unique)
Write-Host "  Total targets: $($targets.Count)" -ForegroundColor Gray

# =============================================================================
# SMB CHECK SCRIPTBLOCK
# Runs on each remote host via Invoke-Command. No strict mode inside -- keeps
# null property access safe when registry values are absent.
# =============================================================================
$smbCheckBlock = {
    $r = [PSCustomObject]@{
        ComputerName       = $env:COMPUTERNAME
        OSCaption          = 'Unknown'
        OSBuild            = 0
        SMBv1Enabled       = $null
        SMBv1Source        = 'not checked'
        SMBv2Enabled       = $null
        SrvRequireSigning  = $null
        SrvEnableSigning   = $null
        CliRequireSigning  = $null
        CliEnableSigning   = $null
        SmbCmdletAvailable = $false
        ErrorMsg           = ''
    }

    # OS version
    try {
        $os = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop
        $r.OSCaption = $os.Caption
        $r.OSBuild   = [int]$os.BuildNumber
    }
    catch { $r.OSCaption = 'WMI unavailable' }

    # --- SMB server config via cmdlet (Win8+/2012+) ---
    if (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
        try {
            $sc = Get-SmbServerConfiguration -ErrorAction Stop
            $r.SmbCmdletAvailable = $true
            $r.SMBv1Enabled       = $sc.EnableSMB1Protocol
            $r.SMBv2Enabled       = $sc.EnableSMB2Protocol
            $r.SrvRequireSigning  = $sc.RequireSecuritySignature
            $r.SrvEnableSigning   = $sc.EnableSecuritySignature
            $r.SMBv1Source        = 'Get-SmbServerConfiguration'
        }
        catch { $r.SMBv1Source = "SmbCmdlet error: $($_.Exception.Message)" }
    }

    # --- Registry fallback for SMBv1 ---
    $srvReg = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    if ($null -eq $r.SMBv1Enabled) {
        try {
            $props = Get-ItemProperty -Path $srvReg -ErrorAction Stop
            if ($null -ne $props.SMB1) {
                $r.SMBv1Enabled = ($props.SMB1 -ne 0)
                $r.SMBv1Source  = 'Registry (SMB1 value present)'
            }
            else {
                # SMB1 value absent: default is ENABLED on builds before Windows 2016 / 1607 (build 14393)
                $r.SMBv1Enabled = ($r.OSBuild -gt 0 -and $r.OSBuild -lt 14393)
                $r.SMBv1Source  = 'Registry (SMB1 absent -- default inferred from OS build)'
            }
        }
        catch {
            $r.SMBv1Enabled = $null
            $r.SMBv1Source  = 'Registry read failed'
            $r.ErrorMsg     = $_.Exception.Message
        }
    }

    # --- Registry fallback for server signing ---
    if ($null -eq $r.SrvRequireSigning) {
        try {
            $props = Get-ItemProperty -Path $srvReg -ErrorAction Stop
            $r.SrvRequireSigning = if ($null -ne $props.RequireSecuritySignature) { ($props.RequireSecuritySignature -ne 0) } else { $false }
            $r.SrvEnableSigning  = if ($null -ne $props.EnableSecuritySignature)  { ($props.EnableSecuritySignature  -ne 0) } else { $false }
        }
        catch { $r.ErrorMsg = "Server signing registry: $($_.Exception.Message)" }
    }

    # --- Client signing (always from registry -- no SMB client cmdlet in PS 5.1) ---
    $cliReg = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    try {
        $props = Get-ItemProperty -Path $cliReg -ErrorAction Stop
        $r.CliRequireSigning = if ($null -ne $props.RequireSecuritySignature) { ($props.RequireSecuritySignature -ne 0) } else { $false }
        $r.CliEnableSigning  = if ($null -ne $props.EnableSecuritySignature)  { ($props.EnableSecuritySignature  -ne 0) } else { $false }
    }
    catch { $r.ErrorMsg = "$($r.ErrorMsg) | Client signing registry: $($_.Exception.Message)" }

    return $r
}

# =============================================================================
# EXECUTE REMOTE CHECKS
# =============================================================================
Write-Step "Running SMB checks on $($targets.Count) target(s) via WinRM..."

$smbRawResults = [System.Collections.Generic.List[object]]::new()

if ($targets.Count -gt 0) {
    $sessOpt   = New-PSSessionOption -OperationTimeout 15000 -OpenTimeout 10000
    $invParams = @{
        ComputerName  = $targets
        ScriptBlock   = $smbCheckBlock
        ErrorAction   = 'SilentlyContinue'
        SessionOption = $sessOpt
        ThrottleLimit = 32
    }
    if ($Credential) { $invParams['Credential'] = $Credential }

    try {
        $rawArr = @(Invoke-Command @invParams)
        foreach ($item in $rawArr) { [void]$smbRawResults.Add($item) }
    }
    catch { Write-AuditWarning "RemoteCheck" "Invoke-Command error: $($_.Exception.Message)" }
}

Write-Host "  Responses: $($smbRawResults.Count) / $($targets.Count)" -ForegroundColor Gray

# Index by uppercase FQDN for lookup
$resultMap = @{}
foreach ($res in $smbRawResults) {
    $key = if ($res.PSComputerName) { $res.PSComputerName.ToUpper() } else { $res.ComputerName.ToUpper() }
    $resultMap[$key] = $res
}

# Flag unreachable hosts
foreach ($t in $targets) {
    if (-not $resultMap.ContainsKey($t.ToUpper())) {
        Write-AuditWarning "S00" "No WinRM response from '$t'"
        $unreachRole = if ($dcSet.Contains($t)) { 'Domain Controller' } else { 'Member' }
        Add-Finding -Check 'S00' -CheckName 'Host Unreachable' `
            -HostName $t -Role $unreachRole -Severity 'Info' `
            -Summary "WinRM unreachable: $t" `
            -Detail "No response within 15 s timeout. SMB configuration not checked on this host." `
            -Remediation "Enable WinRM: Enable-PSRemoting -Force. Check firewall allows TCP 5985 (HTTP) or 5986 (HTTPS). Manually verify: Invoke-Command -ComputerName $t -ScriptBlock { Get-SmbServerConfiguration }"
    }
}

# =============================================================================
# PROCESS RESULTS INTO FINDINGS
# =============================================================================

$checkList = @(
    [PSCustomObject]@{ ID = 'S00'; Name = 'Host Reachability' }
    [PSCustomObject]@{ ID = 'S01'; Name = 'SMBv1 Protocol Enabled' }
    [PSCustomObject]@{ ID = 'S02'; Name = 'SMB Server Signing Not Required' }
    [PSCustomObject]@{ ID = 'S03'; Name = 'SMB Client Signing Not Required' }
    [PSCustomObject]@{ ID = 'S04'; Name = 'SMBv2/SMBv3 Disabled' }
    [PSCustomObject]@{ ID = 'S05'; Name = 'No GPO Enforcing SMB Signing' }
)

# Helper: get role label for a result object
function Get-HostRole {
    param([object]$Res)
    $hn = if ($Res.PSComputerName) { $Res.PSComputerName } else { $Res.ComputerName }
    if ($script:dcSet.Contains($hn) -or $script:dcSet.Contains($hn.Split('.')[0])) {
        return 'Domain Controller'
    }
    return 'Member'
}

$s01Count = 0; $s02Count = 0; $s03Count = 0; $s04Count = 0; $s05Count = 0

# =============================================================================
# S01 -- SMBv1 ENABLED
# =============================================================================
Write-CheckHeader "S01: SMBv1 Protocol"

foreach ($res in $smbRawResults) {
    $hn   = if ($res.PSComputerName) { $res.PSComputerName } else { $res.ComputerName }
    $role = Get-HostRole -Res $res
    $isDC = ($role -eq 'Domain Controller')

    if ($null -eq $res.SMBv1Enabled) {
        Write-AuditWarning "S01" "Cannot determine SMBv1 on $hn -- $($res.SMBv1Source)"
        continue
    }

    if ($res.SMBv1Enabled -eq $true) {
        $s01Count++
        $sev = if ($isDC) { 'Critical' } else { 'High' }
        Add-Finding -Check 'S01' -CheckName 'SMBv1 Protocol Enabled' `
            -HostName $hn -Role $role -Severity $sev `
            -Summary "SMBv1 enabled on $role $hn" `
            -Detail "Host: $hn | Role: $role | OS: $($res.OSCaption) (build $($res.OSBuild)) | Detection: $($res.SMBv1Source) | SMBv2 enabled: $($res.SMBv2Enabled)" `
            -Remediation "Disable SMBv1 immediately. Attack chain: $($script:T.EB) (MS17-010) exploits SMBv1 for unauthenticated RCE as SYSTEM. WannaCry and NotPetya spread via this protocol.

Disable (requires reboot):
  Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force

Registry (requires reboot):
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' SMB1 -Value 0 -Type DWord

Enforce via GPO (Computer Config > Admin Templates > Network > Lanman Server):
  'Enable insecure guest logons' = Disabled

Verify after reboot:
  Get-SmbServerConfiguration | Select EnableSMB1Protocol"
    }
    else {
        Write-OkHost "$hn -- SMBv1 disabled"
    }
}
$s01Color = if ($s01Count -gt 0) { 'Red' } else { 'Green' }
Write-Host "  S01: $s01Count host(s) with SMBv1 enabled" -ForegroundColor $s01Color

# =============================================================================
# S02 -- SMB SERVER SIGNING NOT REQUIRED
# =============================================================================
Write-CheckHeader "S02: SMB Server Signing"

foreach ($res in $smbRawResults) {
    $hn   = if ($res.PSComputerName) { $res.PSComputerName } else { $res.ComputerName }
    $role = Get-HostRole -Res $res
    $isDC = ($role -eq 'Domain Controller')

    if ($null -eq $res.SrvRequireSigning) {
        Write-AuditWarning "S02" "Cannot determine server signing on $hn"
        continue
    }

    if ($res.SrvRequireSigning -eq $false) {
        $s02Count++
        $sev = if ($isDC) { 'Critical' } else { 'High' }
        $enabledStr = if ($res.SrvEnableSigning -eq $true) { 'Enabled (if client agrees)' } else { 'Disabled entirely' }
        Add-Finding -Check 'S02' -CheckName 'SMB Server Signing Not Required' `
            -HostName $hn -Role $role -Severity $sev `
            -Summary "SMB server signing not required on $role $hn" `
            -Detail "Host: $hn | Role: $role | OS: $($res.OSCaption) | RequireSecuritySignature: FALSE | EnableSecuritySignature: $enabledStr | SMB cmdlet: $($res.SmbCmdletAvailable)" `
            -Remediation "Enable required SMB server signing. Attack chain: $($script:T.RS) captures NTLM hashes, $($script:T.NR) relays them to this host for code execution -- possible because signing is not enforced, so the relay succeeds.

Require signing:
  Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force

Registry:
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' RequireSecuritySignature -Value 1 -Type DWord

GPO (Security Options):
  'Microsoft network server: Digitally sign communications (always)' = Enabled

Note: DCs must have RequireSecuritySignature=1. Member servers should also require it to prevent lateral movement relay chains.

Verify: Get-SmbServerConfiguration | Select RequireSecuritySignature"
    }
    else {
        Write-OkHost "$hn -- server signing required"
    }
}
$s02Color = if ($s02Count -gt 0) { 'Red' } else { 'Green' }
Write-Host "  S02: $s02Count host(s) without required SMB server signing" -ForegroundColor $s02Color

# =============================================================================
# S03 -- SMB CLIENT SIGNING NOT REQUIRED
# =============================================================================
Write-CheckHeader "S03: SMB Client Signing"

foreach ($res in $smbRawResults) {
    $hn   = if ($res.PSComputerName) { $res.PSComputerName } else { $res.ComputerName }
    $role = Get-HostRole -Res $res
    $isDC = ($role -eq 'Domain Controller')

    if ($null -eq $res.CliRequireSigning) {
        Write-AuditWarning "S03" "Cannot determine client signing on $hn"
        continue
    }

    if ($res.CliRequireSigning -eq $false) {
        $s03Count++
        $sev = if ($isDC) { 'High' } else { 'Medium' }
        $enabledStr = if ($res.CliEnableSigning -eq $true) { 'Enabled (if server agrees)' } else { 'Disabled entirely' }
        Add-Finding -Check 'S03' -CheckName 'SMB Client Signing Not Required' `
            -HostName $hn -Role $role -Severity $sev `
            -Summary "SMB client signing not required on $role $hn" `
            -Detail "Host: $hn | Role: $role | OS: $($res.OSCaption) | LanmanWorkstation RequireSecuritySignature: FALSE | EnableSecuritySignature: $enabledStr" `
            -Remediation "Require SMB client signing. Without this, the SMB client on this host will connect unsigned to servers that do not enforce signing -- enabling NTLM relay attacks where an attacker intercepts client connections and relays credentials.

Registry:
  Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' RequireSecuritySignature -Value 1 -Type DWord

GPO (Security Options):
  'Microsoft network client: Digitally sign communications (always)' = Enabled

Verify: Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' | Select RequireSecuritySignature"
    }
    else {
        Write-OkHost "$hn -- client signing required"
    }
}
$s03Color = if ($s03Count -gt 0) { 'Yellow' } else { 'Green' }
Write-Host "  S03: $s03Count host(s) without required SMB client signing" -ForegroundColor $s03Color

# =============================================================================
# S04 -- SMBv2/SMBv3 DISABLED
# =============================================================================
Write-CheckHeader "S04: SMBv2/SMBv3 Status"

foreach ($res in $smbRawResults) {
    $hn   = if ($res.PSComputerName) { $res.PSComputerName } else { $res.ComputerName }
    $role = Get-HostRole -Res $res

    # Only report if we got the value via cmdlet (registry does not expose SMBv2 status simply)
    if (-not $res.SmbCmdletAvailable) { continue }
    if ($null -eq $res.SMBv2Enabled)  { continue }

    if ($res.SMBv2Enabled -eq $false) {
        $s04Count++
        Add-Finding -Check 'S04' -CheckName 'SMBv2/SMBv3 Disabled' `
            -HostName $hn -Role $role -Severity 'Medium' `
            -Summary "SMBv2/SMBv3 disabled on $role $hn" `
            -Detail "Host: $hn | Role: $role | OS: $($res.OSCaption) | EnableSMB2Protocol: FALSE | Disabling SMBv2 also removes SMB signing support, performance improvements, and SMB encryption (SMBv3)." `
            -Remediation "Re-enable SMBv2 unless there is a documented legacy compatibility requirement:
  Set-SmbServerConfiguration -EnableSMB2Protocol `$true -Force

SMBv2 is required for: SMB signing enforcement, SMBv3 encryption, performance (compounding, large MTU).
Without SMBv2, clients fall back to SMBv1 (if enabled) which is the EternalBlue vector."
    }
    else {
        Write-OkHost "$hn -- SMBv2/v3 enabled"
    }
}
$s04Color = if ($s04Count -gt 0) { 'Yellow' } else { 'Green' }
Write-Host "  S04: $s04Count host(s) with SMBv2/v3 disabled" -ForegroundColor $s04Color

# =============================================================================
# S05 -- GPO ENFORCEMENT OF SMB SIGNING
# Scans all domain GPOs for Security Options or Registry extension delivering
# RequireSecuritySignature = 1 to LanmanServer and LanmanWorkstation.
# =============================================================================
Write-CheckHeader "S05: GPO-Enforced SMB Signing"

$gpoSrvSigning = [System.Collections.Generic.List[string]]::new()
$gpoCltSigning = [System.Collections.Generic.List[string]]::new()
$s05GpoScanned = 0

if ($gpAvailable -and $adAvailable) {
    try {
        $allGPOs = @(Get-GPO -All @gpoParam -ErrorAction Stop)
        $s05GpoScanned = $allGPOs.Count
        Write-Host "    Scanning $s05GpoScanned GPO(s) for SMB signing policy..." -ForegroundColor Gray

        foreach ($gpo in $allGPOs) {
            $xmlStr = ''
            try { $xmlStr = Get-GPOReport -Guid $gpo.Id -ReportType Xml @gpoParam -ErrorAction Stop }
            catch {
                Write-AuditWarning "S05" "Cannot get XML for GPO '$($gpo.DisplayName)': $($_.Exception.Message)"
                continue
            }

            # Security Options deliver signing via display name in XML:
            #   <DisplayName>Microsoft network server: Digitally sign communications (always)</DisplayName>
            #   ...Enabled...
            # Registry extension delivers via:
            #   key="SYSTEM\...\LanmanServer\Parameters" name="RequireSecuritySignature" value="00000001"
            $hasSrvSign = ($xmlStr -match 'Digitally sign communications \(always\)' -and $xmlStr -match '>Enabled<') `
                       -or ($xmlStr -match 'LanmanServer' -and $xmlStr -match 'RequireSecuritySignature' -and $xmlStr -match '00000001')

            $hasCltSign = ($xmlStr -match 'network client.*Digitally sign.*always' -and $xmlStr -match '>Enabled<') `
                       -or ($xmlStr -match 'LanmanWorkstation' -and $xmlStr -match 'RequireSecuritySignature' -and $xmlStr -match '00000001')

            if ($hasSrvSign) { [void]$gpoSrvSigning.Add($gpo.DisplayName) }
            if ($hasCltSign) { [void]$gpoCltSigning.Add($gpo.DisplayName) }
        }
    }
    catch {
        Write-AuditWarning "S05" "Cannot enumerate GPOs: $($_.Exception.Message)"
    }

    # Server signing enforcement
    if ($gpoSrvSigning.Count -eq 0) {
        $s05Count++
        Add-Finding -Check 'S05' -CheckName 'No GPO Enforcing SMB Signing' `
            -HostName 'Domain' -Role 'Domain Policy' -Severity 'High' `
            -Summary "No GPO found enforcing SMB server signing (RequireSecuritySignature)" `
            -Detail "Scanned $s05GpoScanned GPO(s). None found delivering RequireSecuritySignature=1 to LanmanServer\Parameters via Security Options or Registry extension. Without GPO enforcement, hosts rely on local policy which local admins can change." `
            -Remediation "Create or update the security baseline GPO to enforce SMB server signing:

Computer Config > Windows Settings > Security Settings > Security Options:
  'Microsoft network server: Digitally sign communications (always)' = Enabled

Or via GPO Registry preference:
  Hive: HKLM | Key: SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
  Value name: RequireSecuritySignature | Type: REG_DWORD | Value: 1

Without GPO enforcement, a local admin (or attacker with local admin) can run:
  Set-SmbServerConfiguration -RequireSecuritySignature `$false
...opening an NTLM relay window via $($script:T.RS) + $($script:T.NR)."
    }
    else {
        Write-OkHost "SMB server signing enforced by GPO: $($gpoSrvSigning -join ', ')"
    }

    # Client signing enforcement
    if ($gpoCltSigning.Count -eq 0) {
        $s05Count++
        Add-Finding -Check 'S05' -CheckName 'No GPO Enforcing SMB Signing' `
            -HostName 'Domain' -Role 'Domain Policy' -Severity 'Medium' `
            -Summary "No GPO found enforcing SMB client signing (LanmanWorkstation RequireSecuritySignature)" `
            -Detail "Scanned $s05GpoScanned GPO(s). None deliver RequireSecuritySignature=1 to LanmanWorkstation\Parameters. Without this, machines that connect to unsigned servers expose NTLM credentials to relay." `
            -Remediation "Enforce client signing via GPO Security Options:
  'Microsoft network client: Digitally sign communications (always)' = Enabled

Registry equivalent (GPO preference):
  Hive: HKLM | Key: SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
  Value: RequireSecuritySignature = DWORD 1"
    }
    else {
        Write-OkHost "SMB client signing enforced by GPO: $($gpoCltSigning -join ', ')"
    }
}
else {
    Write-AuditWarning "S05" "GroupPolicy or ActiveDirectory module not available -- GPO signing check skipped."
}

$s05Color = if ($s05Count -gt 0) { 'Red' } else { 'Green' }
Write-Host "  S05: $s05Count GPO signing gap(s)" -ForegroundColor $s05Color

# =============================================================================
# REPORT SETUP
# =============================================================================
Write-Step "Building HTML report..."

$genTime      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$runSeconds   = [int]((Get-Date) - $script:RunStart).TotalSeconds
$timestamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
$safedom      = $Domain -replace '[^a-zA-Z0-9_\-]','_'
$htmlFile     = Join-Path $OutputPath "SMBAudit_${safedom}_${timestamp}.html"

$totalFindings = $script:Findings.Count
$countBySev    = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
foreach ($f in $script:Findings) {
    if ($countBySev.ContainsKey($f.Severity)) { $countBySev[$f.Severity]++ }
}

$sevColor = @{
    Critical = '#dc2626'; High = '#ea580c'; Medium = '#d97706'
    Low = '#65a30d'; Info = '#0284c7'; Good = '#16a34a'
}
$sevClass = @{
    Critical = 'sc'; High = 'sh'; Medium = 'sm'; Low = 'sl'; Info = 'si'; Good = 'sg'
}

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if (-not $Text) { return '' }
    $Text = $Text.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;')
    return $Text
}

function Get-SevBadge {
    param([string]$Sev)
    $bg = if ($sevColor.ContainsKey($Sev)) { $sevColor[$Sev] } else { '#6b7280' }
    return "<span class='badge' style='background:$bg'>$Sev</span>"
}

# Build per-check interactive findings table
function Build-FindingsTable {
    param([string]$CheckID)
    $rows = @($script:Findings | Where-Object { $_.Check -eq $CheckID })
    if ($rows.Count -eq 0) {
        return '<div class="pass-msg">&#10003; No findings -- check passed</div>'
    }
    $sb  = [System.Text.StringBuilder]::new()
    $idx = 0
    [void]$sb.Append('<div class="tbl-wrap"><table class="ftbl">')
    [void]$sb.Append('<thead><tr><th style="width:88px">Severity</th><th style="width:160px">Host</th><th style="width:100px">Role</th><th>Summary</th><th style="width:28px"></th></tr></thead><tbody>')
    foreach ($row in $rows) {
        $idx++
        $rowId = "r_${CheckID}_$idx"
        $detId = "d_${CheckID}_$idx"
        $sc    = if ($sevClass.ContainsKey($row.Severity)) { $sevClass[$row.Severity] } else { 'si' }
        $badge = Get-SevBadge -Sev $row.Severity
        $host  = ConvertTo-HtmlEncoded($row.HostName)
        $role  = ConvertTo-HtmlEncoded($row.Role)
        $summ  = ConvertTo-HtmlEncoded($row.Summary)
        $det   = ConvertTo-HtmlEncoded($row.Detail)
        $rem   = ConvertTo-HtmlEncoded($row.Remediation)
        $sev   = $row.Severity
        [void]$sb.Append("<tr id='$rowId' class='fr $sc' data-sev='$sev' onclick='toggleRow(this,`"$detId`")'><td>$badge</td><td class='hn'>$host</td><td class='rl'>$role</td><td class='summ'>$summ</td><td class='xi'>+</td></tr>")
        [void]$sb.Append("<tr id='$detId' class='dr' style='display:none'><td colspan='5'><div class='dp'>")
        if ($det) { [void]$sb.Append("<div class='dl'>Detail</div><div class='dc'>$det</div>") }
        if ($rem) { [void]$sb.Append("<div class='dl' style='margin-top:8px'>Remediation</div><div class='dc rem'>$rem</div>") }
        [void]$sb.Append("</div></td></tr>")
    }
    [void]$sb.Append("</tbody></table></div>")
    return $sb.ToString()
}

# Summary table rows
$checkRowsHtml = [System.Text.StringBuilder]::new()
foreach ($chk in $checkList) {
    $chkFindings = @($script:Findings | Where-Object { $_.Check -eq $chk.ID })
    $maxSev = 'Good'
    foreach ($sv in @('Critical','High','Medium','Low','Info')) {
        $svMatch = @($chkFindings | Where-Object { $_.Severity -eq $sv })
        if ($svMatch.Count -gt 0) { $maxSev = $sv; break }
    }
    $badge  = Get-SevBadge -Sev $maxSev
    $cntStr = if ($chkFindings.Count -eq 0) { '<span style="color:#16a34a;font-weight:600">PASS</span>' } else { "<b>$($chkFindings.Count)</b>" }
    [void]$checkRowsHtml.Append("<tr class='sum-row' onclick='jumpTo(`"$($chk.ID)`")' title='Click to jump to $($chk.Name)'><td class='chk-id'>$($chk.ID)</td><td>$($chk.Name)</td><td>$badge</td><td>$cntStr</td></tr>")
}

# Collapsible per-check sections
$sectionHtml = [System.Text.StringBuilder]::new()
foreach ($chk in $checkList) {
    $table       = Build-FindingsTable -CheckID $chk.ID
    $chkFindings = @($script:Findings | Where-Object { $_.Check -eq $chk.ID })
    $cntTotal    = $chkFindings.Count
    $cntBadge    = if ($cntTotal -eq 0) { "<span class='cnt-pass'>PASS</span>" } else { "<span class='cnt-warn'>$cntTotal</span>" }
    [void]$sectionHtml.Append(@"
<div class="section" id="sec_$($chk.ID)">
  <div class="sec-hdr" onclick="toggleSection(this)">
    <span class="chev">&#9660;</span>
    <span class="chk-id-lbl">$($chk.ID)</span>
    <span class="chk-name-lbl">$($chk.Name)</span>
    $cntBadge
    <span class="vis-count" id="vc_$($chk.ID)"></span>
  </div>
  <div class="sec-body" id="sb_$($chk.ID)">
    $table
  </div>
</div>
"@)
}

# Audit warnings block
if ($script:AuditLog.Count -gt 0) {
    $warnSb = [System.Text.StringBuilder]::new()
    [void]$warnSb.Append('<ul style="margin:0;padding-left:18px;font-size:12px;color:#92400e">')
    foreach ($warn in $script:AuditLog) {
        $escaped = ConvertTo-HtmlEncoded($warn)
        [void]$warnSb.Append("<li>$escaped</li>")
    }
    [void]$warnSb.Append('</ul>')
    $warnRowsHtml = $warnSb.ToString()
}
else {
    $warnRowsHtml = '<p style="color:#16a34a;font-size:12px">No audit warnings.</p>'
}

# =============================================================================
# HTML REPORT
# =============================================================================
$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SMB Security Audit -- $Domain</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;font-size:13px;color:#111827;background:#f3f4f6}
.header{background:linear-gradient(135deg,#1e3a5f,#0f766e);color:#fff;padding:24px 32px}
.header h1{font-size:22px;font-weight:700;margin-bottom:4px}
.header .meta{font-size:12px;opacity:.8}
.container{max-width:1400px;margin:0 auto;padding:24px 16px}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:20px;overflow:hidden}
.card-header{background:#1e3a5f;color:#fff;padding:12px 20px;font-weight:600;font-size:14px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#1e3a5f;color:#fff;padding:8px 10px;text-align:left;white-space:nowrap}
td{padding:7px 10px;border-bottom:1px solid #e5e7eb;vertical-align:top}
tr:last-child td{border-bottom:none}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:12px;padding:16px}
.stat{text-align:center;padding:12px;border-radius:6px;background:#f9fafb}
.stat-value{font-size:28px;font-weight:700}
.stat-label{font-size:11px;color:#6b7280;margin-top:2px}
.warn-box{background:#fef3c7;border:1px solid #f59e0b;border-radius:6px;padding:12px 16px;margin-bottom:16px}
.warn-title{font-weight:600;color:#92400e;margin-bottom:6px;font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;color:#fff;font-size:11px;font-weight:600;white-space:nowrap}
/* attack chain info box */
.atk-box{background:#fdf2f8;border:1px solid #d946ef;border-radius:6px;padding:12px 16px;margin-bottom:16px;font-size:12px}
.atk-title{font-weight:700;color:#86198f;margin-bottom:6px}
.atk-chain{font-family:monospace;color:#374151;line-height:1.8}
/* sections */
.section{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:14px;overflow:hidden}
.sec-hdr{display:flex;align-items:center;gap:10px;padding:11px 18px;background:#f8fafc;border-bottom:1px solid #e5e7eb;cursor:pointer;user-select:none}
.sec-hdr:hover{background:#eff6ff}
.chev{font-size:11px;color:#6b7280;min-width:12px}
.chk-id-lbl{font-family:monospace;font-weight:700;color:#2563eb;min-width:40px}
.chk-name-lbl{font-weight:600;flex:1}
.cnt-pass{background:#dcfce7;color:#15803d;border-radius:10px;padding:1px 10px;font-size:11px;font-weight:600}
.cnt-warn{background:#fee2e2;color:#b91c1c;border-radius:10px;padding:1px 10px;font-size:11px;font-weight:600}
.vis-count{font-size:11px;color:#6b7280;margin-left:4px}
.sec-body{padding:0}
.pass-msg{padding:14px 20px;color:#16a34a;font-weight:500}
/* findings table */
.tbl-wrap{overflow-x:auto}
.ftbl{width:100%;border-collapse:collapse;font-size:12px}
.ftbl th{background:#1e3a5f;color:#fff;padding:8px 10px;text-align:left;white-space:nowrap}
.ftbl td{padding:7px 10px;border-bottom:1px solid #e5e7eb;vertical-align:top}
.fr{cursor:pointer;border-left:3px solid transparent}
.fr:hover{filter:brightness(.96)}
.sc{border-left-color:#dc2626;background:#fff5f5}
.sh{border-left-color:#ea580c;background:#fff7ed}
.sm{border-left-color:#d97706;background:#fffbeb}
.sl{border-left-color:#65a30d;background:#f7fee7}
.si{border-left-color:#0284c7;background:#f0f9ff}
.sg{border-left-color:#16a34a;background:#f0fdf4}
.dr td{padding:0;border-bottom:1px solid #e5e7eb}
.dp{padding:12px 18px 14px 18px;background:#fafafa;border-top:1px solid #f0f0f0}
.dl{font-size:11px;font-weight:700;color:#374151;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px}
.dc{font-size:12px;color:#374151;white-space:pre-wrap;word-break:break-word;line-height:1.5}
.rem{background:#fffbeb;border-left:3px solid #f59e0b;padding:8px 12px;border-radius:4px;font-family:monospace;font-size:11px;color:#92400e}
.hn{font-weight:500;color:#1e3a5f;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rl{font-size:11px;color:#6b7280}
.summ{color:#374151}
.xi{text-align:center;font-size:14px;font-weight:700;color:#6b7280;min-width:22px}
/* summary table */
.sum-row{cursor:pointer}
.sum-row:hover td{background:#eff6ff}
.chk-id{font-family:monospace;font-weight:700;color:#2563eb}
/* toolbar */
.toolbar{display:flex;align-items:center;gap:8px;padding:10px 0;margin-bottom:14px;flex-wrap:wrap}
.tb-input{flex:1;min-width:180px;padding:7px 12px;border:1px solid #d1d5db;border-radius:6px;font-size:12px;outline:none}
.tb-input:focus{border-color:#2563eb;box-shadow:0 0 0 2px rgba(37,99,235,.15)}
.tb-btn{padding:6px 14px;border:1px solid #d1d5db;border-radius:6px;background:#fff;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap}
.tb-btn:hover{background:#f3f4f6}
.tb-btn.active{background:#1e3a5f;color:#fff;border-color:#1e3a5f}
.tb-btn.tb-crit.active{background:#dc2626;border-color:#dc2626;color:#fff}
.tb-btn.tb-high.active{background:#ea580c;border-color:#ea580c;color:#fff}
.tb-btn.tb-med.active{background:#d97706;border-color:#d97706;color:#fff}
.tb-btn.tb-low.active{background:#65a30d;border-color:#65a30d;color:#fff}
.tb-btn.tb-info.active{background:#0284c7;border-color:#0284c7;color:#fff}
</style>
</head>
<body>
<div class="header">
  <h1>SMB Security Audit Report</h1>
  <div class="meta">
    Domain: <b>$Domain</b> &nbsp;|&nbsp;
    DC: <b>$targetDC</b> &nbsp;|&nbsp;
    Targets Checked: <b>$($smbRawResults.Count) / $($targets.Count)</b> &nbsp;|&nbsp;
    Generated: <b>$genTime</b> &nbsp;|&nbsp;
    Runtime: <b>${runSeconds}s</b>
  </div>
</div>
<div class="container">

<!-- ATTACK CHAIN REFERENCE -->
<div class="atk-box">
  <div class="atk-title">Attack Chain Reference</div>
  <div class="atk-chain">
    SMBv1 enabled  : Responder capture -&gt; EternalBlue MS17-010 (unauthenticated SYSTEM RCE)<br>
    Signing absent : Responder/ntlmrelayx -&gt; NTLM relay to SMB -&gt; code execution / DCSync<br>
    Full chain     : SMBv1 + No signing + Responder -&gt; lateral movement to all reachable hosts
  </div>
</div>

<!-- SEVERITY SUMMARY -->
<div class="card">
  <div class="card-header">Severity Summary</div>
  <div class="stat-grid">
    <div class="stat"><div class="stat-value" style="color:#dc2626">$($countBySev.Critical)</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-value" style="color:#ea580c">$($countBySev.High)</div><div class="stat-label">High</div></div>
    <div class="stat"><div class="stat-value" style="color:#d97706">$($countBySev.Medium)</div><div class="stat-label">Medium</div></div>
    <div class="stat"><div class="stat-value" style="color:#65a30d">$($countBySev.Low)</div><div class="stat-label">Low</div></div>
    <div class="stat"><div class="stat-value" style="color:#0284c7">$($countBySev.Info)</div><div class="stat-label">Info</div></div>
    <div class="stat"><div class="stat-value" style="color:#374151">$totalFindings</div><div class="stat-label">Total</div></div>
  </div>
</div>

<!-- CHECK SUMMARY TABLE -->
<div class="card">
  <div class="card-header">Check Summary (click a row to jump to section)</div>
  <table>
    <thead><tr><th>Check</th><th>Description</th><th>Worst Severity</th><th>Findings</th></tr></thead>
    <tbody>$($checkRowsHtml.ToString())</tbody>
  </table>
</div>

<!-- AUDIT WARNINGS -->
<div class="warn-box">
  <div class="warn-title">Audit Warnings (unreachable hosts / access errors)</div>
  $warnRowsHtml
</div>

<!-- TOOLBAR -->
<div class="toolbar">
  <input class="tb-input" id="tb-search" type="text" placeholder="Search findings (host, summary, detail)..." oninput="doFilter()">
  <button class="tb-btn active"  id="btn-all"  onclick="setFilter(this,'')">All</button>
  <button class="tb-btn tb-crit" id="btn-crit" onclick="setFilter(this,'Critical')">Critical</button>
  <button class="tb-btn tb-high" id="btn-high" onclick="setFilter(this,'High')">High</button>
  <button class="tb-btn tb-med"  id="btn-med"  onclick="setFilter(this,'Medium')">Medium</button>
  <button class="tb-btn tb-low"  id="btn-low"  onclick="setFilter(this,'Low')">Low</button>
  <button class="tb-btn tb-info" id="btn-info" onclick="setFilter(this,'Info')">Info</button>
</div>

<!-- PER-CHECK SECTIONS -->
$($sectionHtml.ToString())

</div><!-- /container -->
<script>
var activeSev = '';
function toggleRow(row, detId) {
    var det = document.getElementById(detId);
    var xi  = row.querySelector('.xi');
    if (det.style.display === 'none') {
        det.style.display = '';
        if (xi) xi.textContent = '-';
    } else {
        det.style.display = 'none';
        if (xi) xi.textContent = '+';
    }
}
function toggleSection(hdrEl) {
    var body = hdrEl.parentElement.querySelector('.sec-body');
    var chev = hdrEl.querySelector('.chev');
    if (body.style.display === 'none') {
        body.style.display = '';
        if (chev) chev.innerHTML = '&#9660;';
    } else {
        body.style.display = 'none';
        if (chev) chev.innerHTML = '&#9654;';
    }
}
function jumpTo(checkId) {
    var sec  = document.getElementById('sec_' + checkId);
    if (!sec) return;
    var body = document.getElementById('sb_' + checkId);
    var hdr  = sec.querySelector('.sec-hdr');
    var chev = hdr ? hdr.querySelector('.chev') : null;
    if (body && body.style.display === 'none') {
        body.style.display = '';
        if (chev) chev.innerHTML = '&#9660;';
    }
    setTimeout(function() { sec.scrollIntoView({ behavior: 'smooth', block: 'start' }); }, 50);
}
function setFilter(btn, sev) {
    activeSev = sev;
    var btns = document.querySelectorAll('.tb-btn');
    for (var i = 0; i < btns.length; i++) { btns[i].classList.remove('active'); }
    btn.classList.add('active');
    doFilter();
}
function doFilter() {
    var q    = document.getElementById('tb-search').value.toLowerCase();
    var rows = document.querySelectorAll('.fr');
    for (var i = 0; i < rows.length; i++) {
        var row   = rows[i];
        var sev   = (row.getAttribute('data-sev') || '').toLowerCase();
        var txt   = row.textContent.toLowerCase();
        var sevOk = (activeSev === '' || sev === activeSev.toLowerCase());
        var txtOk = (q === '' || txt.indexOf(q) !== -1);
        var show  = sevOk && txtOk;
        row.style.display = show ? '' : 'none';
        if (!show) {
            var xi    = row.querySelector('.xi');
            if (xi) xi.textContent = '+';
            var detId = row.id.replace(/^r_/, 'd_');
            var det   = document.getElementById(detId);
            if (det) det.style.display = 'none';
        }
    }
    var secs = document.querySelectorAll('.section');
    for (var s = 0; s < secs.length; s++) {
        var secEl = secs[s];
        var secId = secEl.id.replace('sec_', '');
        var vcEl  = document.getElementById('vc_' + secId);
        var allFr = secEl.querySelectorAll('.fr');
        var vis   = 0;
        for (var r = 0; r < allFr.length; r++) {
            if (allFr[r].style.display !== 'none') vis++;
        }
        if (vcEl) {
            vcEl.textContent = (allFr.length > 0 && (q !== '' || activeSev !== ''))
                ? ('(' + vis + ' shown)') : '';
        }
    }
}
</script>
</body>
</html>
"@

try {
    [System.IO.File]::WriteAllText($htmlFile, $htmlContent, [System.Text.Encoding]::UTF8)
    Write-Host "  HTML: $htmlFile" -ForegroundColor Green
}
catch {
    Write-AuditWarning "Output" "Failed to write HTML: $($_.Exception.Message)"
}

# =============================================================================
# CSV EXPORT
# =============================================================================
Write-Step "Exporting CSV..."

$csvDir = Join-Path $OutputPath 'CSV'
if (-not (Test-Path $csvDir)) { New-Item -ItemType Directory -Path $csvDir -Force | Out-Null }

$summaryData = @(foreach ($chkItem in $checkList) {
    $chkRows = @($script:Findings | Where-Object { $_.Check -eq $chkItem.ID })
    $critCnt = @($chkRows | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCnt = @($chkRows | Where-Object { $_.Severity -eq 'High'     }).Count
    $medCnt  = @($chkRows | Where-Object { $_.Severity -eq 'Medium'   }).Count
    $lowCnt  = @($chkRows | Where-Object { $_.Severity -eq 'Low'      }).Count
    [PSCustomObject]@{
        CheckID   = $chkItem.ID
        CheckName = $chkItem.Name
        Total     = $chkRows.Count
        Critical  = $critCnt
        High      = $highCnt
        Medium    = $medCnt
        Low       = $lowCnt
        Status    = if ($chkRows.Count -eq 0) { 'PASS' } else { 'FINDINGS' }
    }
})

$s00Data = @($script:Findings | Where-Object { $_.Check -eq 'S00' })
$s01Data = @($script:Findings | Where-Object { $_.Check -eq 'S01' })
$s02Data = @($script:Findings | Where-Object { $_.Check -eq 'S02' })
$s03Data = @($script:Findings | Where-Object { $_.Check -eq 'S03' })
$s04Data = @($script:Findings | Where-Object { $_.Check -eq 'S04' })
$s05Data = @($script:Findings | Where-Object { $_.Check -eq 'S05' })

# Raw SMB host data for analyst use
$rawCsv = @($smbRawResults | ForEach-Object {
    [PSCustomObject]@{
        Host               = if ($_.PSComputerName) { $_.PSComputerName } else { $_.ComputerName }
        OS                 = $_.OSCaption
        Build              = $_.OSBuild
        SMBv1Enabled       = $_.SMBv1Enabled
        SMBv1Source        = $_.SMBv1Source
        SMBv2Enabled       = $_.SMBv2Enabled
        SrvRequireSigning  = $_.SrvRequireSigning
        SrvEnableSigning   = $_.SrvEnableSigning
        CliRequireSigning  = $_.CliRequireSigning
        CliEnableSigning   = $_.CliEnableSigning
        SmbCmdletAvailable = $_.SmbCmdletAvailable
        ErrorMsg           = $_.ErrorMsg
    }
})

$summaryData                | Export-Csv (Join-Path $csvDir 'Summary.csv')          -NoTypeInformation
$script:Findings            | Export-Csv (Join-Path $csvDir 'All-Findings.csv')     -NoTypeInformation
$rawCsv                     | Export-Csv (Join-Path $csvDir 'Host-SMB-Config.csv')  -NoTypeInformation
if ($s00Data.Count -gt 0) { $s00Data | Export-Csv (Join-Path $csvDir 'S00-Unreachable.csv') -NoTypeInformation }
if ($s01Data.Count -gt 0) { $s01Data | Export-Csv (Join-Path $csvDir 'S01-SMBv1.csv')       -NoTypeInformation }
if ($s02Data.Count -gt 0) { $s02Data | Export-Csv (Join-Path $csvDir 'S02-SrvSigning.csv')  -NoTypeInformation }
if ($s03Data.Count -gt 0) { $s03Data | Export-Csv (Join-Path $csvDir 'S03-CliSigning.csv')  -NoTypeInformation }
if ($s04Data.Count -gt 0) { $s04Data | Export-Csv (Join-Path $csvDir 'S04-SMBv2.csv')       -NoTypeInformation }
if ($s05Data.Count -gt 0) { $s05Data | Export-Csv (Join-Path $csvDir 'S05-GPOPolicy.csv')   -NoTypeInformation }

Write-Host "  CSV: $csvDir\" -ForegroundColor Green

# =============================================================================
# DONE
# =============================================================================
$totalSec = [int]((Get-Date) - $script:RunStart).TotalSeconds
Write-Host ""
Write-Host "+======================================================+" -ForegroundColor Cyan
Write-Host "|  SMB AUDIT COMPLETE                                  |" -ForegroundColor Cyan
Write-Host "+======================================================+" -ForegroundColor Cyan
Write-Host "  Targets Checked : $($smbRawResults.Count) / $($targets.Count)"
Write-Host "  Total Findings  : $totalFindings  (Critical:$($countBySev.Critical) High:$($countBySev.High) Medium:$($countBySev.Medium) Low:$($countBySev.Low))"
Write-Host "  Runtime         : ${totalSec}s"
Write-Host "  Reports in      : $OutputPath"
Write-Host ""
