#Requires -Version 5.1
<#
.SYNOPSIS
    BloodHound-compatible AD collector -- ADSI edition, no RSAT, no admin required.
    Produces SharpHound v4 JSON files for import into BloodHound / Neo4j.

.DESCRIPTION
    Drop-in replacement for Invoke-BHCollector.ps1 that uses only
    System.DirectoryServices (ADSI / DirectorySearcher) -- no ActiveDirectory
    module, no elevated rights, works as a standard domain user.

    Collects: Users, Computers, Groups, Domains, GPOs, OUs, ACEs.
    Output: timestamped ZIP + individual JSON files (SharpHound v4 format).

.PARAMETER DomainController
    FQDN or IP of a DC.  Required -- no automatic discovery without AD module.

.PARAMETER DomainDN
    Distinguished Name of the domain root.
    Example: DC=ae,DC=local

.PARAMETER Credential
    PSCredential for explicit auth.  Omit to use current Windows session token.

.PARAMETER OutputPath
    Folder where JSON + ZIP are written.
    Default: $env:USERPROFILE\Documents\BHCollect

.PARAMETER NoCompress
    Write raw JSON files only; skip ZIP creation.

.PARAMETER SkipACL
    Skip DACL collection (faster; ACE edges will be absent in BloodHound).

.EXAMPLE
    .\Invoke-BHCollector-NoAdmin.ps1 -DomainController ae-we-ae-dc1.ae.local -DomainDN DC=ae,DC=local

    .\Invoke-BHCollector-NoAdmin.ps1 -DomainController ae-we-ae-dc1.ae.local `
        -DomainDN DC=ae,DC=local -Credential (Get-Credential) -OutputPath C:\Temp\BH
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DomainController,
    [Parameter(Mandatory)][string]$DomainDN,
    [System.Management.Automation.PSCredential]$Credential,
    [string]$OutputPath = "$env:USERPROFILE\Documents\BHCollect",
    [switch]$NoCompress,
    [switch]$SkipACL
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# BloodHound ACE GUIDs
# ---------------------------------------------------------------------------
$GUID_GetChanges         = [Guid]'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
$GUID_GetChangesAll      = [Guid]'1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
$GUID_GetChangesFiltered = [Guid]'89e95b76-444d-4c62-991a-0facbeda640c'
$GUID_ForceChangePwd     = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
$GUID_MemberAttr         = [Guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'
$GUID_AllowedToAct       = [Guid]'3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'
$GUID_Empty              = [Guid]::Empty

$script:SidMap  = @{}
$script:DomSID  = ''
$script:DomFQDN = ''

# ---------------------------------------------------------------------------
# Helper -- build a DirectoryEntry with optional explicit credentials
# ---------------------------------------------------------------------------
function New-DE {
    param([string]$Path)
    $authSecure = [System.DirectoryServices.AuthenticationTypes]::Secure
    if ($Credential) {
        return New-Object System.DirectoryServices.DirectoryEntry(
            $Path,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password,
            $authSecure
        )
    }
    # Use Secure (Negotiate) so NTLM is attempted when no Kerberos ticket exists.
    # Pass empty strings -- .NET uses the current process token when user/pass are empty.
    return New-Object System.DirectoryServices.DirectoryEntry($Path, '', '', $authSecure)
}

# ---------------------------------------------------------------------------
# Helper -- build a paged DirectorySearcher
# ---------------------------------------------------------------------------
function New-Searcher {
    param([string]$Filter, [string[]]$Props, [string]$Base = '')
    $basePath = if ($Base) { $Base } else { "LDAP://$DomainController/$DomainDN" }
    $de = New-DE $basePath
    $s  = New-Object System.DirectoryServices.DirectorySearcher($de)
    $s.Filter   = $Filter
    $s.PageSize = 1000
    $s.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
    return $s
}

# ---------------------------------------------------------------------------
# Helper -- safely get single property value from SearchResult
# ---------------------------------------------------------------------------
function GProp {
    param($Props, [string]$Name, $Default = $null)
    if ($Props.Contains($Name) -and $Props[$Name].Count -gt 0) {
        return $Props[$Name][0]
    }
    return $Default
}

# ---------------------------------------------------------------------------
# Helper -- get all values of a multi-value property
# ---------------------------------------------------------------------------
function GProps {
    param($Props, [string]$Name)
    if ($Props.Contains($Name)) { return @($Props[$Name]) }
    return @()
}

# ---------------------------------------------------------------------------
# Helper -- FileTime -> Unix epoch
# ---------------------------------------------------------------------------
function ToUnix {
    param($val)
    if ($null -eq $val -or $val -le 0) { return -1 }
    try { return [int64]([DateTime]::FromFileTimeUtc([int64]$val) - [DateTime]'1970-01-01').TotalSeconds }
    catch { return -1 }
}

# ---------------------------------------------------------------------------
# Helper -- byte[] SID -> string
# ---------------------------------------------------------------------------
function BytesToSid {
    param([byte[]]$bytes)
    if (-not $bytes) { return '' }
    try {
        return (New-Object System.Security.Principal.SecurityIdentifier($bytes, 0)).Value
    } catch { return '' }
}

# ---------------------------------------------------------------------------
# Helper -- add SID to map
# ---------------------------------------------------------------------------
function Register-Sid {
    param([string]$Sid, [string]$Type)
    if ($Sid -and -not $script:SidMap.ContainsKey($Sid)) { $script:SidMap[$Sid] = $Type }
}

# ---------------------------------------------------------------------------
# Helper -- get BH type from SID
# ---------------------------------------------------------------------------
function Get-SidType {
    param([string]$Sid)
    if (-not $Sid) { return 'Unknown' }
    if ($Sid -match '^S-1-5-32-|^S-1-1-0$|^S-1-5-11$|^S-1-5-9$') { return 'Group' }
    if ($Sid -match '^S-1-5-18$|^S-1-3-0$') { return 'User' }
    $rid = 0
    if ([int]::TryParse(($Sid -split '-')[-1],[ref]$rid)) {
        if ($rid -ge 512 -and $rid -le 522) { return 'Group' }
    }
    if ($script:SidMap.ContainsKey($Sid)) { return $script:SidMap[$Sid] }
    return 'Unknown'
}

# ---------------------------------------------------------------------------
# ACL -- convert one AccessRule to BH ACE hashtable
# ---------------------------------------------------------------------------
function Convert-Ace {
    param(
        [System.Security.AccessControl.ActiveDirectoryAccessRule]$Ace,
        [string]$TargetType
    )
    if ($Ace.AccessControlType -ne 'Allow') { return $null }

    $principalSid = ''
    try {
        $principalSid = $Ace.IdentityReference.Translate(
            [System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        $v = $Ace.IdentityReference.Value
        if ($v -match '^S-1-') { $principalSid = $v }
    }
    if (-not $principalSid) { return $null }
    if ($principalSid -match '^S-1-5-18$|^S-1-5-10$|^S-1-5-20$') { return $null }

    $rights   = $Ace.ActiveDirectoryRights
    $objType  = $Ace.ObjectType
    $right    = $null

    $hasGA  = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll)    -ne 0
    $hasWD  = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)     -ne 0
    $hasWO  = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)    -ne 0
    $hasGW  = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite)  -ne 0
    $hasExt = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -ne 0
    $hasWP  = ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty) -ne 0
    $hasSelf= ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::Self)          -ne 0

    if     ($hasGA)  { $right = 'GenericAll' }
    elseif ($hasWD)  { $right = 'WriteDacl' }
    elseif ($hasWO)  { $right = 'WriteOwner' }
    elseif ($hasGW)  { $right = 'GenericWrite' }
    elseif ($hasExt) {
        if     ($objType -eq $GUID_GetChanges)         { $right = 'GetChanges' }
        elseif ($objType -eq $GUID_GetChangesAll)      { $right = 'GetChangesAll' }
        elseif ($objType -eq $GUID_GetChangesFiltered) { $right = 'GetChangesInFilteredSet' }
        elseif ($objType -eq $GUID_ForceChangePwd)     { $right = 'ForceChangePassword' }
        elseif ($objType -eq $GUID_Empty)              { $right = 'AllExtendedRights' }
    } elseif ($hasWP) {
        if     ($objType -eq $GUID_MemberAttr)   { $right = if ($TargetType -eq 'Group') { 'AddMember' } else { 'WriteProperty' } }
        elseif ($objType -eq $GUID_AllowedToAct) { $right = 'WriteAccountRestrictions' }
        elseif ($objType -eq $GUID_Empty)        { $right = 'GenericWrite' }
    } elseif ($hasSelf) {
        if ($objType -eq $GUID_MemberAttr) { $right = 'AddSelf' }
    }

    if (-not $right) { return $null }

    return [ordered]@{
        PrincipalSID  = $principalSid
        PrincipalType = Get-SidType $principalSid
        RightName     = $right
        IsInherited   = $Ace.IsInherited
    }
}

# ---------------------------------------------------------------------------
# ACL -- get all BH ACEs for a DN using DirectoryEntry (no AD module)
# ---------------------------------------------------------------------------
function Get-BHAces {
    param([string]$DN, [string]$TargetType)
    $list = [System.Collections.Generic.List[object]]::new()
    if ($SkipACL) { return $list }
    try {
        $de = New-DE "LDAP://$DomainController/$DN"
        $de.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl
        $de.RefreshCache('nTSecurityDescriptor')
        $acl = $de.ObjectSecurity
        if ($null -eq $acl) { return $list }
        foreach ($ace in $acl.Access) {
            $bh = Convert-Ace -Ace $ace -TargetType $TargetType
            if ($null -ne $bh) { $list.Add($bh) }
        }
    } catch {}
    return $list
}

# ---------------------------------------------------------------------------
# Writer -- serialize to SharpHound v4 JSON
# ---------------------------------------------------------------------------
function Write-BHJson {
    param([string]$Type, [object[]]$Data, [string]$Dir, [string]$Stamp)
    $arr = @($Data)
    $payload = [ordered]@{
        data = $arr
        meta = [ordered]@{ methods=0; type=$Type; count=$arr.Count; version=4 }
    }
    $path = Join-Path $Dir ($Stamp + '_' + $Type + '.json')
    [System.IO.File]::WriteAllText($path,
        ($payload | ConvertTo-Json -Depth 20 -Compress),
        [System.Text.Encoding]::UTF8)
    Write-Host "  [+] $Type : $($arr.Count) objects -> $path" -ForegroundColor Green
    return $path
}

# ===========================================================================
# COLLECTION: DOMAIN
# ===========================================================================
function Get-BHDomain {
    Write-Host '[*] Collecting domain ...' -ForegroundColor Cyan

    # Base query on domain NC
    $s = New-Searcher -Filter '(objectClass=domain)' `
        -Props @('name','dc','distinguishedName','objectSid','whenCreated',
                 'msDS-Behavior-Version','gPLink','trustAttributes') `
        -Base "LDAP://$DomainController/$DomainDN"
    $s.SearchScope = [System.DirectoryServices.SearchScope]::Base
    $r = $s.FindOne()
    if (-not $r) { throw 'Cannot read domain root -- check DC and credentials' }

    $p   = $r.Properties
    $sid = BytesToSid (GProp $p 'objectsid')
    $script:DomSID  = $sid
    $script:DomFQDN = (GProp $p 'name' '').ToUpper() + '.LOCAL'

    # Functional level
    $fl = switch ([int](GProp $p 'msds-behavior-version' 0)) {
        0 { '2000' } 1 { '2003 Interim' } 2 { '2003' } 3 { '2008' }
        4 { '2008 R2' } 5 { '2012' } 6 { '2012 R2' } 7 { '2016' }
        default { 'Unknown' }
    }

    # GPO links on domain root
    $links = [System.Collections.Generic.List[object]]::new()
    $gpl = GProp $p 'gplink' ''
    if ($gpl) {
        foreach ($m in [regex]::Matches($gpl, '\{([0-9A-Fa-f\-]+)\}([^[]*)\[(\d+)\]')) {
            $enforced = ($m.Groups[3].Value -match '^[23]$')
            $links.Add([ordered]@{ GUID=$m.Groups[1].Value.ToUpper(); IsEnforced=$enforced })
        }
    }

    # Trusts
    $trusts = [System.Collections.Generic.List[object]]::new()
    try {
        $ts = New-Searcher '(objectClass=trustedDomain)' `
            @('name','trustDirection','trustType','trustAttributes',
              'securityIdentifier','flatName') `
            -Base "LDAP://$DomainController/CN=System,$DomainDN"
        $ts.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
        foreach ($t in $ts.FindAll()) {
            $tp = $t.Properties
            $dir = switch ([int](GProp $tp 'trustdirection' 0)) {
                0{'Disabled'} 1{'Inbound'} 2{'Outbound'} 3{'Bidirectional'} default{'Unknown'}
            }
            $trusts.Add([ordered]@{
                TargetDomainSid     = BytesToSid (GProp $tp 'securityidentifier')
                TargetDomainName    = (GProp $tp 'name' '').ToUpper()
                IsTransitive        = ([int](GProp $tp 'trustattributes' 0) -band 8) -ne 0
                TrustDirection      = $dir
                TrustType           = 'ParentChild'
                SidFilteringEnabled = ([int](GProp $tp 'trustattributes' 0) -band 4) -ne 0
            })
        }
    } catch { Write-Warning "[Domain] Trust enum failed: $_" }

    $aces = Get-BHAces -DN $DomainDN -TargetType 'Domain'

    $node = [ordered]@{
        ObjectIdentifier = $sid
        Properties       = [ordered]@{
            domain            = $script:DomFQDN
            name              = $script:DomFQDN
            distinguishedname = $DomainDN.ToUpper()
            domainsid         = $sid
            objectid          = $sid
            highvalue         = $true
            description       = ''
            functionallevel   = $fl
            whencreated       = -1
        }
        Aces             = @($aces)
        Links            = @($links)
        ChildObjects     = @()
        Trusts           = @($trusts)
        IsDeleted        = $false
        IsACLProtected   = $false
    }
    return @($node)
}

# ===========================================================================
# COLLECTION: USERS
# ===========================================================================
function Get-BHUsers {
    Write-Host '[*] Collecting users ...' -ForegroundColor Cyan

    $props = @('sAMAccountName','userPrincipalName','distinguishedName','objectSid',
               'userAccountControl','adminCount','description','displayName','title',
               'homeDirectory','servicePrincipalName','sIDHistory',
               'lastLogon','lastLogonTimestamp','pwdLastSet','whenCreated',
               'primaryGroupID','msDS-AllowedToDelegateTo','memberOf','mail')

    $s    = New-Searcher '(&(objectCategory=person)(objectClass=user))' $props
    $list = [System.Collections.Generic.List[object]]::new()

    foreach ($r in $s.FindAll()) {
        $p   = $r.Properties
        $sid = BytesToSid (GProp $p 'objectsid')
        if (-not $sid) { continue }
        Register-Sid $sid 'User'

        $uac    = [int](GProp $p 'useraccountcontrol' 0)
        $enabled= ($uac -band 2) -eq 0
        $pgroup = [int](GProp $p 'primarygroupid' 513)
        $pgSid  = "$script:DomSID-$pgroup"

        # Delegation
        $unconstrained   = ($uac -band 524288) -ne 0
        $constrained     = ($uac -band 16777216) -ne 0
        $delegateTo      = @(GProps $p 'msds-allowedtodelegateto')

        # SPNs
        $spns = @(GProps $p 'serviceprincipalname')

        # SID history
        $sidHist = @(GProps $p 'sidhistory' | ForEach-Object { BytesToSid $_ } | Where-Object { $_ })

        # Last logon (take max of both attributes)
        $ll1 = [int64](GProp $p 'lastlogon' 0)
        $ll2 = [int64](GProp $p 'lastlogontimestamp' 0)
        $lastLogon = ToUnix ([math]::Max($ll1,$ll2))

        $aces = Get-BHAces -DN (GProp $p 'distinguishedname') -TargetType 'User'

        $node = [ordered]@{
            ObjectIdentifier = $sid
            Properties       = [ordered]@{
                domain                    = $script:DomFQDN
                name                      = ((GProp $p 'samaccountname' '') + '@' + $script:DomFQDN).ToUpper()
                distinguishedname         = (GProp $p 'distinguishedname' '').ToUpper()
                objectid                  = $sid
                domainsid                 = $script:DomSID
                highvalue                 = [bool]([int](GProp $p 'admincount' 0))
                enabled                   = $enabled
                admincount                = [bool]([int](GProp $p 'admincount' 0))
                description               = GProp $p 'description' ''
                title                     = GProp $p 'title' ''
                displayname               = GProp $p 'displayname' ''
                email                     = GProp $p 'mail' ''
                homedirectory             = GProp $p 'homedirectory' ''
                userpassword              = ''
                unicodepassword           = ''
                unixpassword              = ''
                sfupassword               = ''
                logonscript               = ''
                passwordnotreqd           = ($uac -band 32) -ne 0
                passwordneverexpires      = ($uac -band 65536) -ne 0
                sensitive                 = ($uac -band 1048576) -ne 0
                dontreqpreauth            = ($uac -band 4194304) -ne 0
                trustedtoauth             = $constrained
                unconstraineddelegation   = $unconstrained
                lastlogon                 = $lastLogon
                lastlogontimestamp        = ToUnix ([int64](GProp $p 'lastlogontimestamp' 0))
                pwdlastset                = ToUnix ([int64](GProp $p 'pwdlastset' 0))
                whencreated               = ToUnix ([int64](0))
                serviceprincipalnames     = $spns
                hasspn                    = ($spns.Count -gt 0)
                sidhistory                = $sidHist
                primarygroupsid           = $pgSid
            }
            Aces             = @($aces)
            SPNTargets       = @()
            AllowedToDelegate= @($delegateTo | ForEach-Object {
                [ordered]@{ ObjectIdentifier=''; ObjectType='Computer' }
            })
            IsDeleted        = $false
            IsACLProtected   = $false
        }
        $list.Add($node)
    }
    Write-Host "    Found $($list.Count) users" -ForegroundColor DarkGray
    return $list
}

# ===========================================================================
# COLLECTION: GROUPS
# ===========================================================================
function Get-BHGroups {
    Write-Host '[*] Collecting groups ...' -ForegroundColor Cyan

    $props = @('sAMAccountName','distinguishedName','objectSid','description',
               'adminCount','member','whenCreated','groupType')

    $s    = New-Searcher '(objectCategory=group)' $props
    $list = [System.Collections.Generic.List[object]]::new()

    foreach ($r in $s.FindAll()) {
        $p   = $r.Properties
        $sid = BytesToSid (GProp $p 'objectsid')
        if (-not $sid) { continue }
        Register-Sid $sid 'Group'

        $dn   = GProp $p 'distinguishedname' ''
        $name = (GProp $p 'samaccountname' '').ToUpper() + '@' + $script:DomFQDN

        # Members -- resolve each member DN to SID via searcher
        $members = [System.Collections.Generic.List[object]]::new()
        foreach ($mDN in @(GProps $p 'member')) {
            $ms = New-Searcher "(distinguishedName=$([regex]::Escape($mDN)))" `
                @('objectSid','objectClass','sAMAccountName')
            $ms.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $mr = $ms.FindOne()
            if ($mr) {
                $mSid  = BytesToSid (GProp $mr.Properties 'objectsid')
                $mType = @($mr.Properties['objectclass'])[-1]
                $bhType= switch ($mType) {
                    'user'     { 'User' }
                    'group'    { 'Group' }
                    'computer' { 'Computer' }
                    default    { 'Unknown' }
                }
                if ($mSid) {
                    Register-Sid $mSid $bhType
                    $members.Add([ordered]@{ ObjectIdentifier=$mSid; ObjectType=$bhType })
                }
            }
        }

        $aces = Get-BHAces -DN $dn -TargetType 'Group'

        $node = [ordered]@{
            ObjectIdentifier = $sid
            Properties       = [ordered]@{
                domain            = $script:DomFQDN
                name              = $name
                distinguishedname = $dn.ToUpper()
                objectid          = $sid
                domainsid         = $script:DomSID
                highvalue         = [bool]([int](GProp $p 'admincount' 0))
                description       = GProp $p 'description' ''
                admincount        = [bool]([int](GProp $p 'admincount' 0))
                whencreated       = -1
            }
            Members          = @($members)
            Aces             = @($aces)
            IsDeleted        = $false
            IsACLProtected   = $false
        }
        $list.Add($node)
    }
    Write-Host "    Found $($list.Count) groups" -ForegroundColor DarkGray
    return $list
}

# ===========================================================================
# COLLECTION: COMPUTERS
# ===========================================================================
function Get-BHComputers {
    Write-Host '[*] Collecting computers ...' -ForegroundColor Cyan

    $props = @('name','dNSHostName','distinguishedName','objectSid','description',
               'operatingSystem','operatingSystemVersion','operatingSystemServicePack',
               'userAccountControl','adminCount','whenCreated',
               'lastLogon','lastLogonTimestamp','pwdLastSet',
               'servicePrincipalName','msDS-AllowedToDelegateTo',
               'msDS-AllowedToActOnBehalfOfOtherIdentity','primaryGroupID')

    $s    = New-Searcher '(objectCategory=computer)' $props
    $list = [System.Collections.Generic.List[object]]::new()

    foreach ($r in $s.FindAll()) {
        $p   = $r.Properties
        $sid = BytesToSid (GProp $p 'objectsid')
        if (-not $sid) { continue }
        Register-Sid $sid 'Computer'

        $uac         = [int](GProp $p 'useraccountcontrol' 0)
        $enabled     = ($uac -band 2) -eq 0
        $isDC        = ($uac -band 8192) -ne 0
        $unconstrained= ($uac -band 524288) -ne 0
        $constrained  = ($uac -band 16777216) -ne 0
        $delegateTo   = @(GProps $p 'msds-allowedtodelegateto')
        $pgroup       = [int](GProp $p 'primarygroupid' 515)
        $pgSid        = "$script:DomSID-$pgroup"

        $ll1      = [int64](GProp $p 'lastlogon' 0)
        $ll2      = [int64](GProp $p 'lastlogontimestamp' 0)
        $lastLogon= ToUnix ([math]::Max($ll1,$ll2))

        $dn   = GProp $p 'distinguishedname' ''
        $dns  = GProp $p 'dnshostname' ''
        $name = if ($dns) { $dns.ToUpper() } else { (GProp $p 'name' '').ToUpper() + '.' + $script:DomFQDN }

        $aces = Get-BHAces -DN $dn -TargetType 'Computer'

        $node = [ordered]@{
            ObjectIdentifier = $sid
            Properties       = [ordered]@{
                domain                    = $script:DomFQDN
                name                      = $name
                distinguishedname         = $dn.ToUpper()
                objectid                  = $sid
                domainsid                 = $script:DomSID
                highvalue                 = $isDC
                enabled                   = $enabled
                unconstraineddelegation   = $unconstrained
                trustedtoauth             = $constrained
                isdc                      = $isDC
                description               = GProp $p 'description' ''
                operatingsystem           = GProp $p 'operatingsystem' ''
                operatingsystemversion    = GProp $p 'operatingsystemversion' ''
                lastlogon                 = $lastLogon
                lastlogontimestamp        = ToUnix ([int64](GProp $p 'lastlogontimestamp' 0))
                pwdlastset                = ToUnix ([int64](GProp $p 'pwdlastset' 0))
                whencreated               = -1
                serviceprincipalnames     = @(GProps $p 'serviceprincipalname')
                haslaps                   = $false
                admincount                = [bool]([int](GProp $p 'admincount' 0))
                primarygroupsid           = $pgSid
            }
            Aces                = @($aces)
            AllowedToDelegate   = @($delegateTo | ForEach-Object {
                [ordered]@{ ObjectIdentifier=''; ObjectType='Computer' }
            })
            AllowedToAct        = @()
            Sessions            = @()
            LocalAdmins         = @()
            RemoteDesktopUsers  = @()
            DcomUsers           = @()
            PSRemoteUsers       = @()
            IsDeleted           = $false
            IsACLProtected      = $false
        }
        $list.Add($node)
    }
    Write-Host "    Found $($list.Count) computers" -ForegroundColor DarkGray
    return $list
}

# ===========================================================================
# COLLECTION: GPOs
# ===========================================================================
function Get-BHGpos {
    Write-Host '[*] Collecting GPOs ...' -ForegroundColor Cyan

    $s    = New-Searcher '(objectClass=groupPolicyContainer)' `
        @('displayName','cn','distinguishedName','objectSid','whenCreated','flags',
          'gPCFileSysPath','versionNumber') `
        -Base "LDAP://$DomainController/CN=Policies,CN=System,$DomainDN"
    $s.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
    $list = [System.Collections.Generic.List[object]]::new()

    foreach ($r in $s.FindAll()) {
        $p    = $r.Properties
        $guid = (GProp $p 'cn' '').Trim('{}').ToUpper()
        if (-not $guid) { continue }
        $dn   = GProp $p 'distinguishedname' ''
        $aces = Get-BHAces -DN $dn -TargetType 'GPO'

        $node = [ordered]@{
            ObjectIdentifier = $guid
            Properties       = [ordered]@{
                domain            = $script:DomFQDN
                name              = (GProp $p 'displayname' $guid).ToUpper() + '@' + $script:DomFQDN
                distinguishedname = $dn.ToUpper()
                objectid          = $guid
                highvalue         = $false
                description       = ''
                gpcpath           = GProp $p 'gpcfilesyspath' ''
                whencreated       = -1
            }
            Aces         = @($aces)
            IsDeleted    = $false
            IsACLProtected= $false
        }
        $list.Add($node)
    }
    Write-Host "    Found $($list.Count) GPOs" -ForegroundColor DarkGray
    return $list
}

# ===========================================================================
# COLLECTION: OUs
# ===========================================================================
function Get-BHOus {
    Write-Host '[*] Collecting OUs ...' -ForegroundColor Cyan

    $s    = New-Searcher '(objectClass=organizationalUnit)' `
        @('ou','distinguishedName','objectGUID','description','gPLink','gPOptions','whenCreated')
    $list = [System.Collections.Generic.List[object]]::new()

    foreach ($r in $s.FindAll()) {
        $p    = $r.Properties
        $dn   = GProp $p 'distinguishedname' ''
        $guid = ''
        if ($p.Contains('objectguid') -and $p['objectguid'].Count -gt 0) {
            $guidBytes = $p['objectguid'][0]
            if ($guidBytes -is [byte[]]) {
                $guid = [Guid]::new([byte[]]$guidBytes).ToString().ToUpper()
            }
        }
        if (-not $guid) { continue }

        # GPO links
        $links = [System.Collections.Generic.List[object]]::new()
        $gpl   = GProp $p 'gplink' ''
        if ($gpl) {
            foreach ($m in [regex]::Matches($gpl, '\{([0-9A-Fa-f\-]+)\}([^[]*)\[(\d+)\]')) {
                $enforced = ($m.Groups[3].Value -match '^[23]$')
                $links.Add([ordered]@{ GUID=$m.Groups[1].Value.ToUpper(); IsEnforced=$enforced })
            }
        }

        $blocked = ([int](GProp $p 'gpoptions' 0) -band 1) -eq 1
        $aces    = Get-BHAces -DN $dn -TargetType 'OU'

        $node = [ordered]@{
            ObjectIdentifier   = $guid
            Properties         = [ordered]@{
                domain            = $script:DomFQDN
                name              = (GProp $p 'ou' '').ToUpper() + '@' + $script:DomFQDN
                distinguishedname = $dn.ToUpper()
                objectid          = $guid
                description       = GProp $p 'description' ''
                whencreated       = -1
                blocksinheritance = $blocked
            }
            Aces               = @($aces)
            Links              = @($links)
            ChildObjects       = @()
            IsDeleted          = $false
            IsACLProtected     = $false
        }
        $list.Add($node)
    }
    Write-Host "    Found $($list.Count) OUs" -ForegroundColor DarkGray
    return $list
}

# ===========================================================================
# MAIN
# ===========================================================================
Write-Host "`n[BHCollector-NoAdmin] Starting collection against $DomainController" -ForegroundColor Yellow
Write-Host "  Base DN  : $DomainDN" -ForegroundColor Yellow
Write-Host "  Output   : $OutputPath" -ForegroundColor Yellow
if ($SkipACL) { Write-Host "  ACL      : SKIPPED" -ForegroundColor DarkYellow }
Write-Host ""

# ---------------------------------------------------------------------------
# Connection test -- detect "no domain token" and auto-prompt for credentials
# ---------------------------------------------------------------------------
Write-Host "[*] Testing LDAP connectivity..." -ForegroundColor Cyan
$testOk = $false
try {
    $testDe = New-DE "LDAP://$DomainController/$DomainDN"
    $testS  = New-Object System.DirectoryServices.DirectorySearcher($testDe)
    $testS.Filter   = '(objectClass=domain)'
    $testS.PageSize = 1
    $testS.PropertiesToLoad.Add('name') | Out-Null
    [void]$testS.FindOne()
    $testOk = $true
    Write-Host "    LDAP connection OK (session token)" -ForegroundColor Green
} catch {
    Write-Host "    Session token failed: $_" -ForegroundColor Yellow
    Write-Host "    Prompting for domain credentials..." -ForegroundColor Yellow
    if (-not $Credential) {
        $Credential = Get-Credential -Message "Enter domain credentials for $DomainController (e.g. DOMAIN\username)"
    }
    # Retry with supplied credentials
    try {
        $testDe2 = New-DE "LDAP://$DomainController/$DomainDN"
        $testS2  = New-Object System.DirectoryServices.DirectorySearcher($testDe2)
        $testS2.Filter   = '(objectClass=domain)'
        $testS2.PageSize = 1
        $testS2.PropertiesToLoad.Add('name') | Out-Null
        [void]$testS2.FindOne()
        $testOk = $true
        Write-Host "    LDAP connection OK (explicit credentials)" -ForegroundColor Green
    } catch {
        Write-Error "LDAP connection failed after credential prompt: $_"
        Write-Host ""
        Write-Host "Troubleshooting tips:" -ForegroundColor Yellow
        Write-Host "  1. Try IP instead of hostname: -DomainController 10.200.1.11  (forces NTLM)" -ForegroundColor Yellow
        Write-Host "  2. Verify credentials: Enter-PSSession -ComputerName $DomainController -Credential (Get-Credential)" -ForegroundColor Yellow
        Write-Host "  3. Check Kerberos: klist  then  nltest /sc_query:<domain>" -ForegroundColor Yellow
        exit 1
    }
}

# Create output dir
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }

$stamp   = Get-Date -Format 'yyyyMMddHHmmss'
$outFiles= [System.Collections.Generic.List[string]]::new()

# Collect
$domains   = Get-BHDomain
$users     = Get-BHUsers
$groups    = Get-BHGroups
$computers = Get-BHComputers
$gpos      = Get-BHGpos
$ous       = Get-BHOus

Write-Host ""

# Write JSON
$outFiles.Add((Write-BHJson 'domains'   $domains   $OutputPath $stamp))
$outFiles.Add((Write-BHJson 'users'     $users     $OutputPath $stamp))
$outFiles.Add((Write-BHJson 'groups'    $groups    $OutputPath $stamp))
$outFiles.Add((Write-BHJson 'computers' $computers $OutputPath $stamp))
$outFiles.Add((Write-BHJson 'gpos'      $gpos      $OutputPath $stamp))
$outFiles.Add((Write-BHJson 'ous'       $ous       $OutputPath $stamp))

# ZIP
if (-not $NoCompress) {
    $zipPath = Join-Path $OutputPath ($stamp + '_BHCollect.zip')
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::Open(
            $zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
        foreach ($f in $outFiles) {
            if (Test-Path $f) {
                [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $zip, $f, [System.IO.Path]::GetFileName($f))
            }
        }
        $zip.Dispose()
        Write-Host "`n[+] ZIP : $zipPath" -ForegroundColor Cyan
    } catch {
        Write-Warning "ZIP creation failed: $_  -- JSON files still available."
    }
}

Write-Host "`n[BHCollector-NoAdmin] Complete." -ForegroundColor Green
Write-Host "  Domain SID : $script:DomSID"
Write-Host "  Domain FQDN: $script:DomFQDN"
Write-Host "  Users      : $($users.Count)"
Write-Host "  Computers  : $($computers.Count)"
Write-Host "  Groups     : $($groups.Count)"
Write-Host "  GPOs       : $($gpos.Count)"
Write-Host "  OUs        : $($ous.Count)"
Write-Host ""
Write-Host "  Drag the ZIP into BloodHound 'Upload Data' to build the attack graph." -ForegroundColor Yellow
