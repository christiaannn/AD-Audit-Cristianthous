<#
.SYNOPSIS
    Comprehensive Active Directory security and inventory audit with HTML reporting.

.DESCRIPTION
    Invoke-ADSecurityAudit collects an exhaustive inventory of an Active Directory
    forest/domain and produces a single, self-contained HTML report. The report is
    designed for two purposes:

        1. Cybersecurity assessment   - surface misconfigurations, weak settings,
                                        privileged accounts, delegation abuse paths,
                                        stale objects and other attack surface.

        2. Disaster recovery / rebuild - capture enough configuration detail to be
                                        able to recreate the directory (topology,
                                        policies, OU structure, GPO links, trusts,
                                        DNS, schema, etc.).

    The script is read-only. It never modifies the directory. Where a query is not
    supported (e.g. a module is missing or rights are insufficient) the section is
    skipped gracefully and the error is recorded in the report.

.PARAMETER OutputPath
    Folder where the HTML report (and optional CSV exports) are written.
    Defaults to the current directory.

.PARAMETER Server
    Optional specific domain controller to target. Defaults to the nearest DC.

.PARAMETER Credential
    Optional alternate credentials used for all queries.

.PARAMETER InactiveDays
    Number of days without logon/password change after which an account is
    considered stale. Default: 90.

.PARAMETER ExportCsv
    Also export every collected dataset to CSV files next to the HTML report.

.PARAMETER IncludeGPOReport
    Generate the full native GPO settings report (HTML) and link it. Can be slow
    on environments with many GPOs.

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1 -OutputPath C:\Audit -ExportCsv -Verbose

.EXAMPLE
    .\Invoke-ADSecurityAudit.ps1 -Server dc01.corp.local -Credential (Get-Credential)

.NOTES
    Author : AD Security Audit
    Requires: RSAT ActiveDirectory module (mandatory).
              RSAT GroupPolicy, DnsServer and ADCSAdministration modules (optional,
              for the respective sections).
    Run from a domain-joined machine, ideally as a member of Domain Admins or with
    delegated read rights, in an elevated PowerShell session.

    READ-ONLY: this script performs no write operations against Active Directory.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Get-Location).Path,
    [string]$Server,
    [System.Management.Automation.PSCredential]$Credential,
    [int]$InactiveDays = 90,
    [switch]$ExportCsv,
    [switch]$IncludeGPOReport
)

#region ---------------------------------------------------------------- Helpers

$ErrorActionPreference = 'Continue'
$script:StartTime      = Get-Date
$script:Sections       = [System.Collections.Generic.List[object]]::new()
$script:Findings       = [System.Collections.Generic.List[object]]::new()
$script:Datasets       = @{}   # name -> object[]  (used for CSV export)
$script:Errors         = [System.Collections.Generic.List[object]]::new()

# Common splat for AD cmdlets so Server/Credential are applied consistently.
$script:ADParams = @{}
if ($Server)     { $script:ADParams['Server']     = $Server }
if ($Credential) { $script:ADParams['Credential'] = $Credential }

function Write-Step {
    param([string]$Message)
    Write-Verbose $Message
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Add-AuditError {
    param([string]$Area, [string]$Message)
    $script:Errors.Add([pscustomobject]@{ Area = $Area; Message = $Message })
    Write-Warning "$Area : $Message"
}

# Records a security finding for the executive summary / risk section.
function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail,
        [int]$Count
    )
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Category = $Category
        Title    = $Title
        Detail   = $Detail
        Count    = $Count
    })
}

# Registers a dataset and returns it (so it can be reused / exported).
function Register-Dataset {
    param([string]$Name, $Data)
    if ($null -ne $Data) {
        $arr = @($Data)
        $script:Datasets[$Name] = $arr
        return $arr
    }
    return @()
}

# Adds a section to the report. Body can be HTML produced by Convert-ToHtmlTable
# or any custom HTML string.
function Add-Section {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [string]$Description,
        [string]$Body
    )
    $script:Sections.Add([pscustomobject]@{
        Id          = $Id
        Title       = $Title
        Description = $Description
        Body        = $Body
    })
}

function Encode-Html {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    [System.Net.WebUtility]::HtmlEncode($Text)
}

# Converts a collection of objects to an HTML table with selected/ordered columns.
function Convert-ToHtmlTable {
    param(
        $Data,
        [string[]]$Properties,
        [string]$EmptyMessage = 'No data / no objects found.'
    )
    $rows = @($Data)
    if ($rows.Count -eq 0) {
        return "<p class='empty'>$(Encode-Html $EmptyMessage)</p>"
    }
    if (-not $Properties) {
        $Properties = $rows[0].PSObject.Properties.Name
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<div class='tablewrap'><table><thead><tr>")
    foreach ($p in $Properties) {
        [void]$sb.Append("<th>$(Encode-Html $p)</th>")
    }
    [void]$sb.Append("</tr></thead><tbody>")

    foreach ($row in $rows) {
        [void]$sb.Append("<tr>")
        foreach ($p in $Properties) {
            $val = $row.$p
            if ($val -is [System.Array] -or $val -is [System.Collections.IEnumerable] -and $val -isnot [string]) {
                $val = ($val | ForEach-Object { "$_" }) -join '; '
            }
            $cell = Encode-Html ("$val")
            # Highlight boolean-style risk values.
            $class = ''
            if ("$val" -eq 'True')  { $class = " class='flag-true'" }
            if ("$val" -eq 'False') { $class = " class='flag-false'" }
            [void]$sb.Append("<td$class>$cell</td>")
        }
        [void]$sb.Append("</tr>")
    }
    [void]$sb.Append("</tbody></table></div>")
    [void]$sb.Append("<p class='count'>Total objects: $($rows.Count)</p>")
    return $sb.ToString()
}

# Converts a hashtable / ordered dictionary to a two-column key/value HTML table.
function Convert-ToKvTable {
    param([System.Collections.IDictionary]$Data)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<div class='tablewrap'><table class='kv'><tbody>")
    foreach ($key in $Data.Keys) {
        $val = $Data[$key]
        if ($val -is [System.Array]) { $val = ($val -join '; ') }
        [void]$sb.Append("<tr><th>$(Encode-Html $key)</th><td>$(Encode-Html "$val")</td></tr>")
    }
    [void]$sb.Append("</tbody></table></div>")
    return $sb.ToString()
}

# Safe conversion of AD LargeInteger / FileTime values to DateTime.
function ConvertTo-DateTimeSafe {
    param($Value)
    if ($null -eq $Value) { return $null }
    try {
        if ($Value -is [datetime]) { return $Value }
        $long = [int64]$Value
        if ($long -le 0 -or $long -eq [int64]::MaxValue) { return $null }
        return [datetime]::FromFileTime($long)
    } catch { return $null }
}

#endregion

#region ---------------------------------------------------------------- Prereqs

Write-Step "Starting Active Directory security audit"

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is required (install RSAT). Aborting."
    return
}
Import-Module ActiveDirectory -ErrorAction Stop

$hasGPO  = [bool](Get-Module -ListAvailable -Name GroupPolicy)
$hasDns  = [bool](Get-Module -ListAvailable -Name DnsServer)
$hasADCS = [bool](Get-Module -ListAvailable -Name ADCSAdministration)
if ($hasGPO)  { Import-Module GroupPolicy -ErrorAction SilentlyContinue }
if ($hasDns)  { Import-Module DnsServer   -ErrorAction SilentlyContinue }

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportFile = Join-Path $OutputPath "AD_Security_Audit_$stamp.html"
$csvFolder  = Join-Path $OutputPath "AD_Audit_CSV_$stamp"

#endregion

#region ------------------------------------------------- 1. Forest & Domain

try {
    Write-Step "Collecting forest information"
    $forest = Get-ADForest @script:ADParams

    $forestInfo = [ordered]@{
        'Forest Name'                 = $forest.Name
        'Root Domain'                 = $forest.RootDomain
        'Forest Functional Level'     = $forest.ForestMode
        'Domains'                     = ($forest.Domains -join ', ')
        'Global Catalogs'             = ($forest.GlobalCatalogs -join ', ')
        'Sites'                       = ($forest.Sites -join ', ')
        'UPN Suffixes'                = ($forest.UPNSuffixes -join ', ')
        'SPN Suffixes'                = ($forest.SPNSuffixes -join ', ')
        'Schema Master'               = $forest.SchemaMaster
        'Domain Naming Master'        = $forest.DomainNamingMaster
        'Schema Naming Context'       = $forest.PartitionsContainer
    }

    # Schema version (object version of the schema container).
    try {
        $schema = Get-ADObject @script:ADParams -Identity $forest.SchemaMaster -ErrorAction SilentlyContinue
    } catch {}
    try {
        $schemaNc = (Get-ADRootDSE @script:ADParams).schemaNamingContext
        $schemaObj = Get-ADObject @script:ADParams -Identity $schemaNc -Properties objectVersion
        $forestInfo['Schema Version (objectVersion)'] = $schemaObj.objectVersion
    } catch {}

    Add-Section -Id 'forest' -Title '1. Forest Information' `
        -Description 'Top level forest configuration, functional level and forest-wide FSMO roles.' `
        -Body (Convert-ToKvTable $forestInfo)

    if ($forest.ForestMode -match '2000|2003|2008') {
        Add-Finding -Severity 'Medium' -Category 'Functional Level' `
            -Title "Forest functional level is legacy ($($forest.ForestMode))" `
            -Detail 'Older functional levels miss modern security features. Plan to raise it.'
    }
} catch { Add-AuditError -Area 'Forest' -Message $_.Exception.Message }

try {
    Write-Step "Collecting domain information"
    $domain = Get-ADDomain @script:ADParams

    $domainInfo = [ordered]@{
        'Domain DNS Name'            = $domain.DNSRoot
        'NetBIOS Name'               = $domain.NetBIOSName
        'Distinguished Name'         = $domain.DistinguishedName
        'Domain SID'                 = $domain.DomainSID
        'Domain Functional Level'    = $domain.DomainMode
        'PDC Emulator'               = $domain.PDCEmulator
        'RID Master'                 = $domain.RIDMaster
        'Infrastructure Master'      = $domain.InfrastructureMaster
        'Domain Controllers'         = ($domain.ReplicaDirectoryServers -join ', ')
        'Read-Only DCs'              = ($domain.ReadOnlyReplicaDirectoryServers -join ', ')
        'Computers Container'        = $domain.ComputersContainer
        'Users Container'            = $domain.UsersContainer
        'Domain Controllers OU'      = $domain.DomainControllersContainer
        'Deleted Objects Container'  = $domain.DeletedObjectsContainer
    }
    Add-Section -Id 'domain' -Title '2. Domain Information' `
        -Description 'Domain identity, SID, functional level, well-known containers and domain FSMO roles.' `
        -Body (Convert-ToKvTable $domainInfo)
} catch { Add-AuditError -Area 'Domain' -Message $_.Exception.Message }

# Tombstone lifetime & AD recycle bin (important for recovery planning).
try {
    $configNc = (Get-ADRootDSE @script:ADParams).configurationNamingContext
    $tombstone = (Get-ADObject @script:ADParams -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$configNc" `
                    -Properties tombstoneLifetime -ErrorAction SilentlyContinue).tombstoneLifetime
    $recycleBin = $false
    try {
        $optional = Get-ADOptionalFeature @script:ADParams -Filter "name -eq 'Recycle Bin Feature'" -ErrorAction SilentlyContinue
        $recycleBin = ($optional.EnabledScopes.Count -gt 0)
    } catch {}

    $recovery = [ordered]@{
        'Tombstone Lifetime (days)' = if ($tombstone) { $tombstone } else { '60 (default, not explicitly set)' }
        'AD Recycle Bin Enabled'    = $recycleBin
    }
    Add-Section -Id 'recovery' -Title '3. Recovery & Retention Settings' `
        -Description 'Settings that affect object recovery and backups.' `
        -Body (Convert-ToKvTable $recovery)

    if (-not $recycleBin) {
        Add-Finding -Severity 'Medium' -Category 'Resilience' `
            -Title 'Active Directory Recycle Bin is not enabled' `
            -Detail 'Enabling the Recycle Bin greatly simplifies recovery of deleted objects.'
    }
} catch { Add-AuditError -Area 'Recovery' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 4. Domain Controllers

try {
    Write-Step "Enumerating domain controllers"
    $dcs = Get-ADDomainController @script:ADParams -Filter * | ForEach-Object {
        [pscustomobject]@{
            HostName            = $_.HostName
            Site                = $_.Site
            IPv4Address         = $_.IPv4Address
            IPv6Address         = $_.IPv6Address
            OperatingSystem     = $_.OperatingSystem
            OSVersion           = $_.OperatingSystemVersion
            IsGlobalCatalog     = $_.IsGlobalCatalog
            IsReadOnly          = $_.IsReadOnly
            Enabled             = $_.Enabled
            OperationMasterRoles= ($_.OperationMasterRoles -join ', ')
            LdapPort            = $_.LdapPort
            SslPort             = $_.SslPort
        }
    }
    $dcs = Register-Dataset 'DomainControllers' $dcs
    Add-Section -Id 'dcs' -Title '4. Domain Controllers' `
        -Description 'All domain controllers including OS version, site, GC/RODC status and FSMO roles held.' `
        -Body (Convert-ToHtmlTable $dcs)

    $legacyDc = $dcs | Where-Object { $_.OperatingSystem -match '2003|2008|2012' }
    if ($legacyDc) {
        Add-Finding -Severity 'High' -Category 'Patch Management' `
            -Title 'Domain controllers running end-of-life Windows Server' `
            -Detail (($legacyDc | ForEach-Object { "$($_.HostName) ($($_.OperatingSystem))" }) -join '; ') `
            -Count $legacyDc.Count
    }
} catch { Add-AuditError -Area 'DomainControllers' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 5. Trusts

try {
    Write-Step "Enumerating domain trusts"
    $trusts = Get-ADTrust @script:ADParams -Filter * -ErrorAction SilentlyContinue | ForEach-Object {
        [pscustomobject]@{
            Source        = $_.Source
            Target        = $_.Target
            Direction     = $_.Direction
            TrustType     = $_.TrustType
            ForestTransitive = $_.ForestTransitive
            IntraForest   = $_.IntraForest
            Transitive    = (-not $_.DisallowTransivity)
            SidFiltering  = $_.SIDFilteringQuarantined
            SelectiveAuth = $_.SelectiveAuthentication
        }
    }
    $trusts = Register-Dataset 'Trusts' $trusts
    Add-Section -Id 'trusts' -Title '5. Domain & Forest Trusts' `
        -Description 'Trust relationships. SID filtering disabled on external trusts is a known lateral-movement risk.' `
        -Body (Convert-ToHtmlTable $trusts)

    $riskyTrusts = $trusts | Where-Object { -not $_.IntraForest -and -not $_.SidFiltering }
    if ($riskyTrusts) {
        Add-Finding -Severity 'High' -Category 'Trusts' `
            -Title 'External/forest trust without SID filtering' `
            -Detail (($riskyTrusts | ForEach-Object { $_.Target }) -join '; ') `
            -Count $riskyTrusts.Count
    }
} catch { Add-AuditError -Area 'Trusts' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 6. Sites / Subnets / Replication

try {
    Write-Step "Collecting sites, subnets and replication topology"
    $configNc = (Get-ADRootDSE @script:ADParams).configurationNamingContext

    $sites = Get-ADReplicationSite @script:ADParams -Filter * | Select-Object Name, Description, DistinguishedName
    $sites = Register-Dataset 'Sites' $sites

    $subnets = Get-ADReplicationSubnet @script:ADParams -Filter * -Properties siteObject, location |
        ForEach-Object {
            [pscustomobject]@{
                Subnet   = $_.Name
                Site     = ($_.siteObject -replace '^CN=([^,]+).*','$1')
                Location = $_.location
            }
        }
    $subnets = Register-Dataset 'Subnets' $subnets

    $siteLinks = Get-ADReplicationSiteLink @script:ADParams -Filter * -Properties cost, replInterval, siteList |
        ForEach-Object {
            [pscustomobject]@{
                Name         = $_.Name
                Cost         = $_.cost
                ReplInterval = $_.replInterval
                Sites        = (($_.siteList | ForEach-Object { ($_ -replace '^CN=([^,]+).*','$1') }) -join ', ')
            }
        }
    $siteLinks = Register-Dataset 'SiteLinks' $siteLinks

    $body  = "<h3>Sites</h3>"     + (Convert-ToHtmlTable $sites)
    $body += "<h3>Subnets</h3>"   + (Convert-ToHtmlTable $subnets)
    $body += "<h3>Site Links</h3>"+ (Convert-ToHtmlTable $siteLinks)

    Add-Section -Id 'sites' -Title '6. Sites, Subnets & Replication' `
        -Description 'Replication topology required to rebuild the physical AD layout.' -Body $body

    # Replication failures.
    try {
        $replFail = Get-ADReplicationFailure @script:ADParams -Target $domain.DNSRoot -Scope Domain -ErrorAction SilentlyContinue |
            Where-Object { $_.FailureCount -gt 0 } |
            Select-Object Server, FirstFailureTime, FailureCount, FailureType, LastError
        if ($replFail) {
            Add-Section -Id 'replfail' -Title '6b. Replication Failures' `
                -Description 'Active replication failures detected.' -Body (Convert-ToHtmlTable $replFail)
            Add-Finding -Severity 'High' -Category 'Replication' `
                -Title 'Active Directory replication failures detected' -Count @($replFail).Count
        }
    } catch {}
} catch { Add-AuditError -Area 'Sites' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 7. Password & Lockout Policy

try {
    Write-Step "Collecting password and lockout policies"
    $pp = Get-ADDefaultDomainPasswordPolicy @script:ADParams
    $ppInfo = [ordered]@{
        'Minimum Password Length'      = $pp.MinPasswordLength
        'Password History Count'       = $pp.PasswordHistoryCount
        'Maximum Password Age'         = $pp.MaxPasswordAge
        'Minimum Password Age'         = $pp.MinPasswordAge
        'Complexity Enabled'           = $pp.ComplexityEnabled
        'Reversible Encryption Enabled'= $pp.ReversibleEncryptionEnabled
        'Lockout Threshold'            = $pp.LockoutThreshold
        'Lockout Duration'             = $pp.LockoutDuration
        'Lockout Observation Window'   = $pp.LockoutObservationWindow
    }
    Add-Section -Id 'pwdpolicy' -Title '7. Default Domain Password Policy' `
        -Description 'Baseline password and account lockout policy for the domain.' `
        -Body (Convert-ToKvTable $ppInfo)

    if ($pp.MinPasswordLength -lt 14) {
        Add-Finding -Severity 'Medium' -Category 'Password Policy' `
            -Title "Minimum password length is $($pp.MinPasswordLength) (recommended >= 14)"
    }
    if (-not $pp.ComplexityEnabled) {
        Add-Finding -Severity 'High' -Category 'Password Policy' -Title 'Password complexity is disabled'
    }
    if ($pp.ReversibleEncryptionEnabled) {
        Add-Finding -Severity 'Critical' -Category 'Password Policy' `
            -Title 'Reversible encryption is enabled domain-wide' `
            -Detail 'Passwords can be retrieved in clear text.'
    }
    if ($pp.LockoutThreshold -eq 0) {
        Add-Finding -Severity 'Medium' -Category 'Password Policy' `
            -Title 'Account lockout threshold is 0 (no lockout)' `
            -Detail 'Accounts are exposed to unlimited online password guessing.'
    }

    # Fine-grained password policies (PSO).
    try {
        $psos = Get-ADFineGrainedPasswordPolicy @script:ADParams -Filter * -ErrorAction SilentlyContinue |
            ForEach-Object {
                [pscustomobject]@{
                    Name             = $_.Name
                    Precedence       = $_.Precedence
                    MinPwdLength     = $_.MinPasswordLength
                    Complexity       = $_.ComplexityEnabled
                    MaxPwdAge        = $_.MaxPasswordAge
                    LockoutThreshold = $_.LockoutThreshold
                    AppliesTo        = ($_.AppliesTo -join '; ')
                }
            }
        if ($psos) {
            Add-Section -Id 'pso' -Title '7b. Fine-Grained Password Policies' `
                -Description 'Per-group/user password policies that override the default policy.' `
                -Body (Convert-ToHtmlTable $psos)
            Register-Dataset 'FineGrainedPasswordPolicies' $psos | Out-Null
        }
    } catch {}
} catch { Add-AuditError -Area 'PasswordPolicy' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 8. Users (detailed security)

try {
    Write-Step "Collecting user accounts (this may take a while)"
    $userProps = @(
        'SamAccountName','Name','UserPrincipalName','Enabled','DistinguishedName',
        'whenCreated','whenChanged','LastLogonDate','PasswordLastSet','PasswordNeverExpires',
        'PasswordNotRequired','CannotChangePassword','PasswordExpired','AccountExpirationDate',
        'LockedOut','SmartcardLogonRequired','adminCount','servicePrincipalName',
        'TrustedForDelegation','TrustedToAuthForDelegation','msDS-AllowedToDelegateTo',
        'DoesNotRequirePreAuth','msDS-SupportedEncryptionTypes','SIDHistory',
        'Description','Title','Department','Company','mail','MemberOf','primaryGroupID',
        'msDS-AllowedToActOnBehalfOfOtherIdentity'
    )
    $users = Get-ADUser @script:ADParams -Filter * -Properties $userProps

    $inactiveCutoff = (Get-Date).AddDays(-$InactiveDays)

    $userTable = foreach ($u in $users) {
        $kerberoastable = [bool]($u.servicePrincipalName)
        $rbcd = [bool]($u.'msDS-AllowedToActOnBehalfOfOtherIdentity')
        [pscustomobject]@{
            SamAccountName        = $u.SamAccountName
            Name                  = $u.Name
            Enabled               = $u.Enabled
            LastLogonDate         = $u.LastLogonDate
            PasswordLastSet       = $u.PasswordLastSet
            PwdNeverExpires       = $u.PasswordNeverExpires
            PwdNotRequired        = $u.PasswordNotRequired
            PwdExpired            = $u.PasswordExpired
            SmartcardRequired     = $u.SmartcardLogonRequired
            AccountExpires        = $u.AccountExpirationDate
            LockedOut             = $u.LockedOut
            AdminCount            = $u.adminCount
            Kerberoastable_SPN    = $kerberoastable
            ASREP_NoPreAuth       = $u.DoesNotRequirePreAuth
            UnconstrainedDeleg    = $u.TrustedForDelegation
            ConstrainedDeleg      = [bool]($u.'msDS-AllowedToDelegateTo')
            RBCD_Configured       = $rbcd
            HasSIDHistory         = [bool]($u.SIDHistory)
            WhenCreated           = $u.whenCreated
            Description           = $u.Description
            UPN                   = $u.UserPrincipalName
            DistinguishedName     = $u.DistinguishedName
        }
    }
    $userTable = Register-Dataset 'Users' $userTable

    # Summary of user posture.
    $enabledUsers   = @($userTable | Where-Object Enabled)
    $disabledUsers  = @($userTable | Where-Object { -not $_.Enabled })
    $stale          = @($userTable | Where-Object { $_.Enabled -and $_.LastLogonDate -and $_.LastLogonDate -lt $inactiveCutoff })
    $neverLoggedOn  = @($userTable | Where-Object { $_.Enabled -and -not $_.LastLogonDate })
    $pwdNeverExp    = @($userTable | Where-Object { $_.Enabled -and $_.PwdNeverExpires })
    $pwdNotReq      = @($userTable | Where-Object { $_.Enabled -and $_.PwdNotRequired })
    $kerberoast     = @($userTable | Where-Object { $_.Enabled -and $_.Kerberoastable_SPN })
    $asrep          = @($userTable | Where-Object { $_.Enabled -and $_.ASREP_NoPreAuth })
    $sidHistory     = @($userTable | Where-Object { $_.HasSIDHistory })

    $summary = [ordered]@{
        'Total user objects'           = $userTable.Count
        'Enabled users'                = $enabledUsers.Count
        'Disabled users'               = $disabledUsers.Count
        "Stale (no logon > $InactiveDays d)" = $stale.Count
        'Enabled, never logged on'     = $neverLoggedOn.Count
        'Password never expires'       = $pwdNeverExp.Count
        'Password not required'        = $pwdNotReq.Count
        'Kerberoastable (has SPN)'     = $kerberoast.Count
        'AS-REP roastable (no preauth)'= $asrep.Count
        'With SID history'             = $sidHistory.Count
    }

    $body  = "<h3>User Posture Summary</h3>" + (Convert-ToKvTable $summary)
    $body += "<h3>All Users</h3>" + (Convert-ToHtmlTable $userTable)

    Add-Section -Id 'users' -Title '8. User Accounts' `
        -Description 'Full user inventory with security-relevant attributes (delegation, SPN, preauth, password flags).' `
        -Body $body

    if ($kerberoast.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Kerberos' `
            -Title 'Kerberoastable user accounts (SPN set on a user)' `
            -Detail (($kerberoast | Select-Object -First 25 -ExpandProperty SamAccountName) -join ', ') `
            -Count $kerberoast.Count
    }
    if ($asrep.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Kerberos' `
            -Title 'AS-REP roastable accounts (Kerberos pre-auth not required)' `
            -Detail (($asrep | Select-Object -ExpandProperty SamAccountName) -join ', ') `
            -Count $asrep.Count
    }
    if ($pwdNotReq.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Accounts' `
            -Title 'Enabled accounts with PASSWD_NOTREQD set' -Count $pwdNotReq.Count
    }
    if ($pwdNeverExp.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'Accounts' `
            -Title 'Enabled accounts with non-expiring passwords' -Count $pwdNeverExp.Count
    }
    if ($sidHistory.Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'Accounts' `
            -Title 'Accounts with SID history' `
            -Detail 'SID history can be abused to hide privilege. Verify it is expected (migrations).' `
            -Count $sidHistory.Count
    }
} catch { Add-AuditError -Area 'Users' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 9. krbtgt & built-in accounts

try {
    Write-Step "Checking krbtgt and built-in accounts"
    $krbtgt = Get-ADUser @script:ADParams -Identity krbtgt -Properties PasswordLastSet, whenCreated -ErrorAction SilentlyContinue
    if ($krbtgt) {
        $age = if ($krbtgt.PasswordLastSet) { (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days } else { $null }
        $kv = [ordered]@{
            'krbtgt Password Last Set' = $krbtgt.PasswordLastSet
            'Password Age (days)'      = $age
        }
        Add-Section -Id 'krbtgt' -Title '9. KRBTGT Account' `
            -Description 'The krbtgt account password signs all Kerberos tickets. Stale passwords enable Golden Ticket persistence.' `
            -Body (Convert-ToKvTable $kv)
        if ($age -and $age -gt 180) {
            Add-Finding -Severity 'Medium' -Category 'Kerberos' `
                -Title "krbtgt password is $age days old" `
                -Detail 'Rotate the krbtgt password (twice, with replication between) periodically.'
        }
    }
} catch { Add-AuditError -Area 'krbtgt' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 10. Privileged groups

try {
    Write-Step "Enumerating privileged group membership"
    $privGroups = @(
        'Domain Admins','Enterprise Admins','Schema Admins','Administrators',
        'Account Operators','Backup Operators','Server Operators','Print Operators',
        'Cert Publishers','DnsAdmins','Group Policy Creator Owners',
        'Read-only Domain Controllers','Enterprise Key Admins','Key Admins',
        'Protected Users','Distributed COM Users','Remote Desktop Users'
    )

    $privMembers = foreach ($g in $privGroups) {
        try {
            $grp = Get-ADGroup @script:ADParams -Identity $g -ErrorAction Stop
            $members = Get-ADGroupMember @script:ADParams -Identity $grp -Recursive -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                $detail = $null
                if ($m.objectClass -eq 'user') {
                    $detail = Get-ADUser @script:ADParams -Identity $m.SamAccountName -Properties Enabled, LastLogonDate, PasswordLastSet -ErrorAction SilentlyContinue
                }
                [pscustomobject]@{
                    Group           = $g
                    Member          = $m.SamAccountName
                    Name            = $m.Name
                    Class           = $m.objectClass
                    Enabled         = $detail.Enabled
                    LastLogonDate   = $detail.LastLogonDate
                    PasswordLastSet = $detail.PasswordLastSet
                }
            }
        } catch {}
    }
    $privMembers = Register-Dataset 'PrivilegedGroupMembers' $privMembers

    Add-Section -Id 'privgroups' -Title '10. Privileged Group Membership' `
        -Description 'Recursive membership of high-value groups. The core of any AD attack surface and the priority for rebuild.' `
        -Body (Convert-ToHtmlTable $privMembers)

    $da = @($privMembers | Where-Object { $_.Group -eq 'Domain Admins' -and $_.Class -eq 'user' })
    $ea = @($privMembers | Where-Object { $_.Group -eq 'Enterprise Admins' -and $_.Class -eq 'user' })
    if ($da.Count -gt 10) {
        Add-Finding -Severity 'High' -Category 'Privilege' `
            -Title "Large Domain Admins membership ($($da.Count) users)" `
            -Detail 'Minimise standing privileged membership.'
    }
    $staleAdmins = @($privMembers | Where-Object { $_.Enabled -eq $true -and $_.LastLogonDate -and $_.LastLogonDate -lt (Get-Date).AddDays(-$InactiveDays) })
    if ($staleAdmins.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Privilege' `
            -Title 'Stale but enabled privileged accounts' `
            -Detail (($staleAdmins | ForEach-Object { "$($_.Member)/$($_.Group)" } | Select-Object -Unique) -join ', ') `
            -Count $staleAdmins.Count
    }
} catch { Add-AuditError -Area 'PrivilegedGroups' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 11. All Groups

try {
    Write-Step "Collecting all groups"
    $groups = Get-ADGroup @script:ADParams -Filter * -Properties GroupCategory, GroupScope, member, whenCreated, Description, adminCount, managedBy |
        ForEach-Object {
            [pscustomobject]@{
                Name        = $_.Name
                Sam         = $_.SamAccountName
                Category    = $_.GroupCategory
                Scope       = $_.GroupScope
                MemberCount = @($_.member).Count
                AdminCount  = $_.adminCount
                ManagedBy   = $_.managedBy
                Description = $_.Description
                WhenCreated = $_.whenCreated
                DN          = $_.DistinguishedName
            }
        }
    $groups = Register-Dataset 'Groups' $groups
    Add-Section -Id 'groups' -Title '11. Groups Inventory' `
        -Description 'All security and distribution groups with scope, category and member counts.' `
        -Body (Convert-ToHtmlTable $groups)

    $emptyGroups = @($groups | Where-Object { $_.MemberCount -eq 0 })
    if ($emptyGroups.Count -gt 0) {
        Add-Finding -Severity 'Low' -Category 'Hygiene' `
            -Title 'Empty groups present' -Count $emptyGroups.Count
    }
} catch { Add-AuditError -Area 'Groups' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 12. Computers

try {
    Write-Step "Collecting computer accounts"
    $compProps = @('OperatingSystem','OperatingSystemVersion','LastLogonDate','PasswordLastSet',
                   'Enabled','whenCreated','IPv4Address','TrustedForDelegation',
                   'msDS-AllowedToDelegateTo','msDS-AllowedToActOnBehalfOfOtherIdentity',
                   'ms-Mcs-AdmPwd','description','DistinguishedName')
    $computers = Get-ADComputer @script:ADParams -Filter * -Properties $compProps

    $compTable = foreach ($c in $computers) {
        [pscustomobject]@{
            Name               = $c.Name
            Enabled            = $c.Enabled
            OperatingSystem    = $c.OperatingSystem
            OSVersion          = $c.OperatingSystemVersion
            LastLogonDate      = $c.LastLogonDate
            PasswordLastSet    = $c.PasswordLastSet
            IPv4Address        = $c.IPv4Address
            UnconstrainedDeleg = $c.TrustedForDelegation
            ConstrainedDeleg   = [bool]($c.'msDS-AllowedToDelegateTo')
            RBCD_Configured    = [bool]($c.'msDS-AllowedToActOnBehalfOfOtherIdentity')
            LAPS_Present        = [bool]($c.'ms-Mcs-AdmPwd')
            WhenCreated        = $c.whenCreated
            DN                 = $c.DistinguishedName
        }
    }
    $compTable = Register-Dataset 'Computers' $compTable

    $inactiveCutoff = (Get-Date).AddDays(-$InactiveDays)
    $staleComp = @($compTable | Where-Object { $_.Enabled -and $_.LastLogonDate -and $_.LastLogonDate -lt $inactiveCutoff })
    $eolOs     = @($compTable | Where-Object { $_.OperatingSystem -match 'XP|Vista|2000|2003|2008|Windows 7|2012' })

    $osBreakdown = $compTable | Group-Object OperatingSystem |
        Sort-Object Count -Descending |
        ForEach-Object { [pscustomobject]@{ OperatingSystem = $_.Name; Count = $_.Count } }

    $body  = "<h3>Operating System Breakdown</h3>" + (Convert-ToHtmlTable $osBreakdown)
    $body += "<h3>All Computers</h3>" + (Convert-ToHtmlTable $compTable)
    Add-Section -Id 'computers' -Title '12. Computer Accounts' `
        -Description 'Computer inventory with OS, last logon, delegation flags and LAPS presence.' -Body $body

    if ($eolOs.Count -gt 0) {
        Add-Finding -Severity 'High' -Category 'Patch Management' `
            -Title 'Computers running end-of-life operating systems' -Count $eolOs.Count
    }
    if ($staleComp.Count -gt 0) {
        Add-Finding -Severity 'Low' -Category 'Hygiene' `
            -Title "Stale computer accounts (no logon > $InactiveDays days)" -Count $staleComp.Count
    }
} catch { Add-AuditError -Area 'Computers' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 13. Kerberos delegation

try {
    Write-Step "Analyzing Kerberos delegation"
    $unconstrained = @()
    $unconstrained += Get-ADUser @script:ADParams -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
        Select-Object @{n='Type';e={'User'}}, SamAccountName, DistinguishedName
    $unconstrained += Get-ADComputer @script:ADParams -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
        Where-Object { $_.DistinguishedName -notmatch 'OU=Domain Controllers' } |
        Select-Object @{n='Type';e={'Computer'}}, @{n='SamAccountName';e={$_.Name}}, DistinguishedName

    $constrained = @()
    $constrained += Get-ADObject @script:ADParams -Filter { msDS-AllowedToDelegateTo -like '*' } -Properties msDS-AllowedToDelegateTo, samAccountName |
        ForEach-Object {
            [pscustomobject]@{
                SamAccountName = $_.samAccountName
                AllowedTo      = ($_.'msDS-AllowedToDelegateTo' -join '; ')
                DN             = $_.DistinguishedName
            }
        }

    $rbcd = Get-ADObject @script:ADParams -Filter { msDS-AllowedToActOnBehalfOfOtherIdentity -like '*' } -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, samAccountName |
        Select-Object samAccountName, DistinguishedName

    $body  = "<h3>Unconstrained Delegation (excludes DCs)</h3>" + (Convert-ToHtmlTable $unconstrained)
    $body += "<h3>Constrained Delegation</h3>" + (Convert-ToHtmlTable $constrained)
    $body += "<h3>Resource-Based Constrained Delegation (RBCD)</h3>" + (Convert-ToHtmlTable $rbcd)
    Add-Section -Id 'delegation' -Title '13. Kerberos Delegation' `
        -Description 'Delegation is a primary privilege-escalation and lateral-movement vector. Unconstrained delegation on non-DC objects is especially dangerous.' `
        -Body $body
    Register-Dataset 'UnconstrainedDelegation' $unconstrained | Out-Null
    Register-Dataset 'ConstrainedDelegation' $constrained | Out-Null
    Register-Dataset 'RBCD' $rbcd | Out-Null

    if (@($unconstrained).Count -gt 0) {
        Add-Finding -Severity 'Critical' -Category 'Kerberos' `
            -Title 'Unconstrained delegation on non-DC objects' `
            -Detail (($unconstrained | ForEach-Object { $_.SamAccountName }) -join ', ') `
            -Count @($unconstrained).Count
    }
    if (@($rbcd).Count -gt 0) {
        Add-Finding -Severity 'Medium' -Category 'Kerberos' `
            -Title 'Resource-based constrained delegation configured' -Count @($rbcd).Count
    }
} catch { Add-AuditError -Area 'Delegation' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 14. Organizational Units

try {
    Write-Step "Collecting OU structure"
    $ous = Get-ADOrganizationalUnit @script:ADParams -Filter * -Properties whenCreated, Description, gPLink, ProtectedFromAccidentalDeletion |
        ForEach-Object {
            [pscustomobject]@{
                Name              = $_.Name
                DistinguishedName = $_.DistinguishedName
                Protected         = $_.ProtectedFromAccidentalDeletion
                LinkedGPOs        = (([regex]::Matches($_.gPLink, 'cn=\{[^}]+\}')).Count)
                Description       = $_.Description
                WhenCreated       = $_.whenCreated
            }
        } | Sort-Object DistinguishedName
    $ous = Register-Dataset 'OrganizationalUnits' $ous
    Add-Section -Id 'ous' -Title '14. Organizational Units' `
        -Description 'Complete OU hierarchy with GPO link counts and accidental-deletion protection. Essential for rebuild.' `
        -Body (Convert-ToHtmlTable $ous)

    $unprotected = @($ous | Where-Object { -not $_.Protected })
    if ($unprotected.Count -gt 0) {
        Add-Finding -Severity 'Low' -Category 'Resilience' `
            -Title 'OUs without accidental-deletion protection' -Count $unprotected.Count
    }
} catch { Add-AuditError -Area 'OUs' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 15. Group Policy

if ($hasGPO) {
    try {
        Write-Step "Collecting Group Policy objects"
        $gpoParams = @{}
        if ($Server) { $gpoParams['Server'] = $Server }
        $gpos = Get-GPO -All @gpoParams -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                DisplayName      = $_.DisplayName
                Id               = $_.Id
                GpoStatus        = $_.GpoStatus
                CreationTime     = $_.CreationTime
                ModificationTime = $_.ModificationTime
                ComputerVersion  = $_.Computer.DSVersion
                UserVersion      = $_.User.DSVersion
                WmiFilter        = $_.WmiFilter.Name
            }
        }
        $gpos = Register-Dataset 'GPOs' $gpos
        Add-Section -Id 'gpos' -Title '15. Group Policy Objects' `
            -Description 'All GPOs with status and versions. Use -IncludeGPOReport for full settings export.' `
            -Body (Convert-ToHtmlTable $gpos)

        # GPO links per OU (from gPLink).
        $gpoLinks = foreach ($ou in (Get-ADOrganizationalUnit @script:ADParams -Filter * -Properties gPLink)) {
            if ($ou.gPLink) {
                foreach ($m in [regex]::Matches($ou.gPLink, '\[LDAP://(cn=\{[^}]+\})[^\]]*;(\d)\]')) {
                    $gpoGuid = $m.Groups[1].Value -replace 'cn=',''
                    $gpoObj  = $gpos | Where-Object { "{$($_.Id)}" -eq $gpoGuid }
                    [pscustomobject]@{
                        OU      = $ou.DistinguishedName
                        GPOName = if ($gpoObj) { $gpoObj.DisplayName } else { $gpoGuid }
                        Options = switch ($m.Groups[2].Value) { '0'{'Enabled'} '1'{'Disabled'} '2'{'Enforced'} '3'{'Enforced+Disabled'} default {$m.Groups[2].Value} }
                    }
                }
            }
        }
        if ($gpoLinks) {
            Add-Section -Id 'gpolinks' -Title '15b. GPO Links' `
                -Description 'Which GPOs are linked to which OUs (and enforcement state). Required to recreate policy application.' `
                -Body (Convert-ToHtmlTable $gpoLinks)
            Register-Dataset 'GPOLinks' $gpoLinks | Out-Null
        }

        $unlinked = @($gpos | Where-Object { $_.DisplayName -notin ($gpoLinks.GPOName) })
        if ($unlinked.Count -gt 0) {
            Add-Finding -Severity 'Low' -Category 'Hygiene' `
                -Title 'Unlinked GPOs (no OU link found)' -Count $unlinked.Count
        }

        if ($IncludeGPOReport) {
            Write-Step "Generating full GPO settings report"
            $gpoHtml = Join-Path $OutputPath "AD_GPO_FullReport_$stamp.html"
            try {
                Get-GPOReport -All -ReportType Html -Path $gpoHtml @gpoParams -ErrorAction Stop
                Add-Section -Id 'gporeport' -Title '15c. Full GPO Settings Report' `
                    -Description "A separate, complete GPO settings report was generated." `
                    -Body "<p><a href='$(Split-Path $gpoHtml -Leaf)'>Open full GPO settings report</a></p>"
            } catch { Add-AuditError -Area 'GPOReport' -Message $_.Exception.Message }
        }
    } catch { Add-AuditError -Area 'GPO' -Message $_.Exception.Message }
} else {
    Add-Section -Id 'gpos' -Title '15. Group Policy Objects' `
        -Description 'GroupPolicy module not available - section skipped.' `
        -Body "<p class='empty'>Install RSAT GroupPolicy module to include GPO data.</p>"
}

#endregion

#region ------------------------------------------------- 16. AdminSDHolder & ACL

try {
    Write-Step "Collecting protected accounts (adminCount)"
    $protected = Get-ADObject @script:ADParams -LDAPFilter '(adminCount=1)' -Properties adminCount, objectClass, samAccountName |
        Where-Object { $_.objectClass -in 'user','group','computer' } |
        Select-Object samAccountName, objectClass, DistinguishedName
    $protected = Register-Dataset 'AdminSDHolderProtected' $protected
    Add-Section -Id 'adminsdholder' -Title '16. AdminSDHolder-Protected Objects' `
        -Description 'Objects with adminCount=1 are protected by AdminSDHolder. Orphaned protected objects (no longer privileged) should be reviewed.' `
        -Body (Convert-ToHtmlTable $protected)
} catch { Add-AuditError -Area 'AdminSDHolder' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 17. DNS

if ($hasDns -and $Server) {
    try {
        Write-Step "Collecting DNS zones"
        $zones = Get-DnsServerZone -ComputerName $Server -ErrorAction SilentlyContinue |
            Select-Object ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, DynamicUpdate, IsAutoCreated
        if ($zones) {
            Add-Section -Id 'dns' -Title '17. DNS Zones' `
                -Description 'AD-integrated DNS zones and their update settings.' `
                -Body (Convert-ToHtmlTable $zones)
            Register-Dataset 'DnsZones' $zones | Out-Null

            $insecure = @($zones | Where-Object { $_.DynamicUpdate -eq 'NonsecureAndSecure' })
            if ($insecure.Count -gt 0) {
                Add-Finding -Severity 'Medium' -Category 'DNS' `
                    -Title 'DNS zones allowing nonsecure dynamic updates' -Count $insecure.Count
            }
        }
    } catch { Add-AuditError -Area 'DNS' -Message $_.Exception.Message }
} else {
    Add-Section -Id 'dns' -Title '17. DNS Zones' `
        -Description 'DNS data requires the DnsServer module and a -Server target. Skipped.' `
        -Body "<p class='empty'>Run with -Server &lt;dc&gt; and the DnsServer RSAT module to include DNS zones.</p>"
}

#endregion

#region ------------------------------------------------- 18. AD CS (Certificate Services)

try {
    Write-Step "Checking for AD Certificate Services"
    $configNc = (Get-ADRootDSE @script:ADParams).configurationNamingContext
    $caPath   = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNc"
    $cas = Get-ADObject @script:ADParams -SearchBase $caPath -LDAPFilter '(objectClass=pKIEnrollmentService)' `
              -Properties dNSHostName, cACertificateDN, certificateTemplates -ErrorAction SilentlyContinue |
        ForEach-Object {
            [pscustomobject]@{
                CAName       = $_.Name
                DnsHostName  = $_.dNSHostName
                CACertDN     = $_.cACertificateDN
                TemplateCount= @($_.certificateTemplates).Count
                Templates    = ($_.certificateTemplates -join '; ')
            }
        }
    if ($cas) {
        Add-Section -Id 'adcs' -Title '18. Active Directory Certificate Services' `
            -Description 'Enterprise CAs and published certificate templates. Misconfigured templates (ESC1-ESC8) are a major escalation path - review with a dedicated tool such as Certify/Locksmith.' `
            -Body (Convert-ToHtmlTable $cas)
        Register-Dataset 'CertificateAuthorities' $cas | Out-Null
        Add-Finding -Severity 'Info' -Category 'PKI' `
            -Title 'AD Certificate Services present - review template ACLs/EKUs for ESC vulnerabilities' -Count @($cas).Count
    } else {
        Add-Section -Id 'adcs' -Title '18. Active Directory Certificate Services' `
            -Description 'No enterprise CA found in the configuration partition.' `
            -Body "<p class='empty'>No AD CS enrollment services detected.</p>"
    }
} catch { Add-AuditError -Area 'ADCS' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 19. Service / SPN accounts

try {
    Write-Step "Collecting service accounts and SPNs"
    $spnUsers = Get-ADUser @script:ADParams -Filter { servicePrincipalName -like '*' } `
                  -Properties servicePrincipalName, PasswordLastSet, PasswordNeverExpires, Enabled, memberOf |
        ForEach-Object {
            [pscustomobject]@{
                SamAccountName  = $_.SamAccountName
                Enabled         = $_.Enabled
                SPNs            = ($_.servicePrincipalName -join '; ')
                PasswordLastSet = $_.PasswordLastSet
                PwdNeverExpires = $_.PasswordNeverExpires
            }
        }
    $spnUsers = Register-Dataset 'ServiceAccounts_SPN' $spnUsers

    # Managed service accounts (gMSA/sMSA).
    $msa = @()
    try {
        $msa = Get-ADServiceAccount @script:ADParams -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword, Enabled, whenCreated -ErrorAction SilentlyContinue |
            Select-Object Name, SamAccountName, Enabled, ObjectClass, whenCreated
    } catch {}

    $body  = "<h3>User Accounts with SPNs</h3>" + (Convert-ToHtmlTable $spnUsers)
    $body += "<h3>Managed Service Accounts (gMSA/sMSA)</h3>" + (Convert-ToHtmlTable $msa)
    Add-Section -Id 'serviceaccounts' -Title '19. Service Accounts' `
        -Description 'Accounts carrying SPNs (Kerberoasting targets) and managed service accounts. Prefer gMSA over standard service accounts.' `
        -Body $body
    Register-Dataset 'ManagedServiceAccounts' $msa | Out-Null
} catch { Add-AuditError -Area 'ServiceAccounts' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 20. LAPS

try {
    Write-Step "Checking LAPS deployment"
    $lapsAttr = Get-ADObject @script:ADParams -LDAPFilter '(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*))' `
                  -Properties name -ErrorAction SilentlyContinue
    $lapsCount = @($lapsAttr).Count
    $totalComp = if ($script:Datasets['Computers']) { @($script:Datasets['Computers'] | Where-Object Enabled).Count } else { 0 }
    $kv = [ordered]@{
        'Computers with LAPS password attribute' = $lapsCount
        'Enabled computers total'                = $totalComp
    }
    Add-Section -Id 'laps' -Title '20. LAPS Coverage' `
        -Description 'Local Administrator Password Solution coverage (legacy and Windows LAPS attributes).' `
        -Body (Convert-ToKvTable $kv)
    if ($totalComp -gt 0 -and $lapsCount -lt ($totalComp * 0.5)) {
        Add-Finding -Severity 'Medium' -Category 'Credential Hygiene' `
            -Title 'Low LAPS coverage' `
            -Detail "Only $lapsCount of $totalComp enabled computers have a LAPS-managed local admin password."
    }
} catch { Add-AuditError -Area 'LAPS' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- CSV export

if ($ExportCsv) {
    Write-Step "Exporting datasets to CSV"
    if (-not (Test-Path $csvFolder)) { New-Item -ItemType Directory -Path $csvFolder -Force | Out-Null }
    foreach ($name in $script:Datasets.Keys) {
        try {
            $script:Datasets[$name] | Export-Csv -Path (Join-Path $csvFolder "$name.csv") -NoTypeInformation -Encoding UTF8
        } catch { Add-AuditError -Area "CSV:$name" -Message $_.Exception.Message }
    }
}

#endregion

#region ------------------------------------------------- HTML assembly

Write-Step "Building HTML report"

$sevOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
$sortedFindings = $script:Findings | Sort-Object { $sevOrder[$_.Severity] }, Category

$sevCount = @{
    Critical = @($script:Findings | Where-Object Severity -eq 'Critical').Count
    High     = @($script:Findings | Where-Object Severity -eq 'High').Count
    Medium   = @($script:Findings | Where-Object Severity -eq 'Medium').Count
    Low      = @($script:Findings | Where-Object Severity -eq 'Low').Count
    Info     = @($script:Findings | Where-Object Severity -eq 'Info').Count
}

$findingRows = foreach ($f in $sortedFindings) {
    $cnt = if ($f.Count) { $f.Count } else { '' }
    "<tr class='sev-$($f.Severity.ToLower())'>" +
    "<td><span class='badge badge-$($f.Severity.ToLower())'>$($f.Severity)</span></td>" +
    "<td>$(Encode-Html $f.Category)</td>" +
    "<td>$(Encode-Html $f.Title)</td>" +
    "<td>$cnt</td>" +
    "<td>$(Encode-Html $f.Detail)</td></tr>"
}
$findingsHtml = if ($findingRows) {
    "<div class='tablewrap'><table><thead><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Count</th><th>Detail</th></tr></thead><tbody>$($findingRows -join '')</tbody></table></div>"
} else {
    "<p class='empty'>No findings recorded.</p>"
}

# Table of contents.
$tocItems = foreach ($s in $script:Sections) {
    "<li><a href='#$($s.Id)'>$(Encode-Html $s.Title)</a></li>"
}

# Section bodies.
$sectionHtml = foreach ($s in $script:Sections) {
    $desc = if ($s.Description) { "<p class='desc'>$(Encode-Html $s.Description)</p>" } else { '' }
    "<section id='$($s.Id)'><h2>$(Encode-Html $s.Title) <a class='top' href='#top'>&uarr; top</a></h2>$desc$($s.Body)</section>"
}

# Errors section.
$errorHtml = if ($script:Errors.Count -gt 0) {
    $rows = foreach ($e in $script:Errors) { "<tr><td>$(Encode-Html $e.Area)</td><td>$(Encode-Html $e.Message)</td></tr>" }
    "<section id='errors'><h2>Collection Errors / Skipped Items <a class='top' href='#top'>&uarr; top</a></h2><p class='desc'>Items that could not be collected (insufficient rights, missing module, or unsupported query).</p><div class='tablewrap'><table><thead><tr><th>Area</th><th>Message</th></tr></thead><tbody>$($rows -join '')</tbody></table></div></section>"
} else { '' }

$domainLabel = if ($domain) { $domain.DNSRoot } else { 'Active Directory' }

$duration = (New-TimeSpan -Start $script:StartTime -End (Get-Date)).ToString('hh\:mm\:ss')
$runContext = [ordered]@{
    'Report generated' = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    'Generated by'     = "$env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME"
    'Target domain'    = if ($domain) { $domain.DNSRoot } else { 'n/a' }
    'Target server'    = if ($Server) { $Server } else { 'auto (nearest DC)' }
    'Inactive threshold (days)' = $InactiveDays
    'Collection duration'       = $duration
    'PowerShell version'        = $PSVersionTable.PSVersion.ToString()
}

$css = @'
:root{--bg:#0f172a;--card:#1e293b;--muted:#94a3b8;--text:#e2e8f0;--accent:#38bdf8;
--crit:#dc2626;--high:#ea580c;--med:#d97706;--low:#2563eb;--info:#0891b2;--ok:#16a34a;}
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}
header{background:linear-gradient(135deg,#1e3a8a,#0f172a);padding:32px 40px;border-bottom:3px solid var(--accent)}
header h1{margin:0;font-size:26px}
header .sub{color:var(--muted);margin-top:6px}
.container{display:flex;gap:24px;padding:24px 40px;align-items:flex-start}
nav{position:sticky;top:16px;flex:0 0 260px;background:var(--card);border-radius:10px;padding:16px;max-height:90vh;overflow:auto}
nav h3{margin:0 0 8px;font-size:14px;color:var(--accent);text-transform:uppercase;letter-spacing:.05em}
nav ul{list-style:none;margin:0;padding:0}
nav li{margin:2px 0}
nav a{color:var(--text);text-decoration:none;font-size:13px;display:block;padding:4px 6px;border-radius:6px}
nav a:hover{background:#334155;color:var(--accent)}
main{flex:1;min-width:0}
section{background:var(--card);border-radius:10px;padding:20px 24px;margin-bottom:22px}
h2{margin-top:0;font-size:19px;border-bottom:1px solid #334155;padding-bottom:8px;display:flex;justify-content:space-between;align-items:center}
h3{font-size:15px;color:var(--accent);margin:18px 0 8px}
.desc{color:var(--muted);font-size:13px;margin-top:0}
.top{font-size:11px;color:var(--muted);text-decoration:none;font-weight:normal}
.tablewrap{overflow-x:auto;border-radius:8px;border:1px solid #334155}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{padding:7px 10px;text-align:left;border-bottom:1px solid #334155;white-space:nowrap;max-width:480px;overflow:hidden;text-overflow:ellipsis}
thead th{background:#0b1220;color:var(--accent);position:sticky;top:0}
tbody tr:hover{background:#293548}
table.kv th{width:300px;color:var(--muted);background:#0b1220}
.count{color:var(--muted);font-size:12px;margin:6px 2px 0}
.empty{color:var(--muted);font-style:italic}
.flag-true{color:#fca5a5;font-weight:600}
.flag-false{color:#86efac}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin:8px 0 4px}
.card{flex:1;min-width:130px;background:#0b1220;border-radius:10px;padding:14px 16px;border-left:4px solid var(--accent)}
.card .n{font-size:28px;font-weight:700}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card.crit{border-color:var(--crit)} .card.high{border-color:var(--high)}
.card.med{border-color:var(--med)} .card.low{border-color:var(--low)} .card.info{border-color:var(--info)}
.badge{padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;color:#fff}
.badge-critical{background:var(--crit)} .badge-high{background:var(--high)}
.badge-medium{background:var(--med)} .badge-low{background:var(--low)} .badge-info{background:var(--info)}
tr.sev-critical td:first-child,tr.sev-high td:first-child{font-weight:700}
a{color:var(--accent)}
footer{color:var(--muted);text-align:center;padding:20px;font-size:12px}
'@

$cards = @"
<div class='cards'>
<div class='card crit'><div class='n'>$($sevCount.Critical)</div><div class='l'>Critical</div></div>
<div class='card high'><div class='n'>$($sevCount.High)</div><div class='l'>High</div></div>
<div class='card med'><div class='n'>$($sevCount.Medium)</div><div class='l'>Medium</div></div>
<div class='card low'><div class='n'>$($sevCount.Low)</div><div class='l'>Low</div></div>
<div class='card info'><div class='n'>$($sevCount.Info)</div><div class='l'>Info</div></div>
</div>
"@

$html = @"
<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Active Directory Security Audit - $(Encode-Html $domainLabel)</title>
<style>$css</style>
</head>
<body>
<a id='top'></a>
<header>
  <h1>Active Directory Security Audit</h1>
  <div class='sub'>$(Encode-Html $domainLabel) &mdash; generated $(Get-Date -Format 'yyyy-MM-dd HH:mm')</div>
</header>
<div class='container'>
  <nav>
    <h3>Contents</h3>
    <ul>
      <li><a href='#summary'>Executive Summary</a></li>
      <li><a href='#runinfo'>Run Information</a></li>
      $($tocItems -join "`n")
      $(if ($errorHtml) { "<li><a href='#errors'>Collection Errors</a></li>" })
    </ul>
  </nav>
  <main>
    <section id='summary'>
      <h2>Executive Summary <a class='top' href='#top'>&uarr; top</a></h2>
      <p class='desc'>Security findings detected during the audit, ordered by severity. This report is read-only; remediation must be performed separately.</p>
      $cards
      $findingsHtml
    </section>
    <section id='runinfo'>
      <h2>Run Information <a class='top' href='#top'>&uarr; top</a></h2>
      $(Convert-ToKvTable $runContext)
    </section>
    $($sectionHtml -join "`n")
    $errorHtml
  </main>
</div>
<footer>Generated by Invoke-ADSecurityAudit.ps1 &mdash; read-only Active Directory audit. Handle this report as confidential.</footer>
</body>
</html>
"@

$html | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host ""
Write-Host "[+] Audit complete." -ForegroundColor Green
Write-Host "[+] HTML report : $reportFile" -ForegroundColor Green
if ($ExportCsv) { Write-Host "[+] CSV exports : $csvFolder" -ForegroundColor Green }
Write-Host "[+] Findings    : Critical=$($sevCount.Critical) High=$($sevCount.High) Medium=$($sevCount.Medium) Low=$($sevCount.Low) Info=$($sevCount.Info)" -ForegroundColor Yellow

#endregion
