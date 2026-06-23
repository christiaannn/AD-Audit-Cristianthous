<#
.SYNOPSIS
    In-depth Kerberos diagnostics for Azure Files SMB shares, with a self-contained
    HTML report in Microsoft/Fluent style.

.DESCRIPTION
    Invoke-AzureFilesKerberosDiagnostics reproduces and dissects every link in the
    Kerberos authentication chain used to mount an Azure Files share over SMB and
    pinpoints why CIFS/Kerberos authentication fails. It was written to chase down
    the classic failure pattern:

        Mounting \\<account>.file.core.windows.net\<share> fails on every
        AD-joined or Entra-joined Windows 11 client with:
            0x80090303  SEC_E_TARGET_UNKNOWN  ("target is unknown or unreachable")
            0x6fb       (1787) ERROR_NO_TRUST_SAM_ACCOUNT

    The script runs on the client and inspects, in order:

        1.  System / identity context (domain vs Entra join, scenario detection)
        2.  DNS resolution of the storage account FQDN (public / private endpoint)
        3.  TCP reachability (445 / 443)
        4.  Time synchronisation / Kerberos clock skew vs a domain controller
        5.  Client Kerberos configuration (encryption types, Cloud Kerberos, realms)
        6.  SPN registration in AD (missing / duplicate / wrong object)
        7.  The AD identity object that backs the storage account (etypes, UAC,
            password/kerb-key age, SID)
        8.  A LIVE Kerberos ticket request for cifs/<account>.file... (klist get)
        9.  Optional: storage account config via Az.Storage (DirectoryServiceOptions,
            ActiveDirectoryProperties, SamAccountName/SID cross-check)
        10. Optional: a real SMB mount test with exact Win32 error capture
        11. SMB / LSA / Kerberos event-log harvest
        12. A synthesised, ranked ROOT-CAUSE analysis mapped to the observed codes

    The script is read-only by default. The only state-changing actions
    (-PurgeTickets, -IncludeMountTest) are opt-in and clearly flagged.

.PARAMETER StorageAccountName
    The Azure Storage account name (the label only, e.g. "contosofiles").

.PARAMETER FileShareName
    Optional share name, used by the optional SMB mount test.

.PARAMETER StorageSuffix
    DNS suffix for the Files endpoint. Default 'file.core.windows.net'
    (use the sovereign-cloud suffix for Azure Government / China / etc.).

.PARAMETER DomainController
    Optional specific DC to target for the AD / SPN / time queries.

.PARAMETER StorageResourceGroup
    Optional resource group; if supplied and Az.Storage is available (and you are
    logged in with Connect-AzAccount) the storage account's identity config is read
    and cross-checked against AD.

.PARAMETER OutputPath
    Folder for the HTML report (and optional CSV/JSON). Default: current directory.

.PARAMETER MaxClockSkewSeconds
    Skew (seconds) above which the clock is flagged. Default 300 (Kerberos default).

.PARAMETER IncludeMountTest
    Attempt a real SMB mount of \\<fqdn>\<share> and capture the exact error.
    Changes session state (creates and then removes an SMB mapping).

.PARAMETER PurgeTickets
    Purge the Kerberos ticket cache (klist purge) before the live ticket test so
    the request is forced fresh. Modifies the current logon session ticket cache.

.PARAMETER ExportCsv
    Also export every collected dataset to CSV next to the HTML report.

.EXAMPLE
    .\Invoke-AzureFilesKerberosDiagnostics.ps1 -StorageAccountName contosofiles -Verbose

.EXAMPLE
    .\Invoke-AzureFilesKerberosDiagnostics.ps1 -StorageAccountName contosofiles `
        -FileShareName projects -IncludeMountTest -PurgeTickets -OutputPath C:\Temp

.EXAMPLE
    .\Invoke-AzureFilesKerberosDiagnostics.ps1 -StorageAccountName contosofiles `
        -StorageResourceGroup rg-files -ExportCsv

.NOTES
    Author  : Azure Files Kerberos Diagnostics
    Requires: Windows PowerShell 5.1 or PowerShell 7+ on a Windows client.
              No RSAT required (AD is queried via System.DirectoryServices / setspn).
              Az.Storage is optional and only used when -StorageResourceGroup is set.
    Run from the affected Windows 11 client, in an elevated session for full event-log
    and time-service access.

    READ-ONLY by default. State-changing steps are opt-in (-PurgeTickets / -IncludeMountTest).
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$StorageAccountName,
    [string]$FileShareName,
    [string]$StorageSuffix = 'file.core.windows.net',
    [string]$DomainController,
    [string]$StorageResourceGroup,
    [string]$OutputPath = (Get-Location).Path,
    [int]$MaxClockSkewSeconds = 300,
    [switch]$IncludeMountTest,
    [switch]$PurgeTickets,
    [switch]$ExportCsv
)

#region ---------------------------------------------------------------- Globals

$ErrorActionPreference = 'Continue'
$script:StartTime = Get-Date
$script:Sections  = [System.Collections.Generic.List[object]]::new()
$script:Findings  = [System.Collections.Generic.List[object]]::new()
$script:Causes    = [System.Collections.Generic.List[object]]::new()
$script:Datasets  = @{}
$script:Errors    = [System.Collections.Generic.List[object]]::new()
$script:Facts     = @{}   # cross-section signals used by the root-cause engine

$script:SaFqdn = "$StorageAccountName.$StorageSuffix".ToLower()
$script:Spn    = "cifs/$script:SaFqdn"

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

# Records a finding for the executive summary.
function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail
    )
    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity; Category = $Category; Title = $Title; Detail = $Detail
    })
}

# Records a ranked root-cause hypothesis with remediation guidance.
function Add-Cause {
    param(
        [Parameter(Mandatory)][int]$Confidence,           # 0-100
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Why,               # evidence observed
        [Parameter(Mandatory)][string[]]$Fix,             # remediation steps
        [string[]]$Links
    )
    $script:Causes.Add([pscustomobject]@{
        Confidence = $Confidence; Title = $Title; Why = $Why; Fix = $Fix; Links = $Links
    })
}

function Register-Dataset {
    param([string]$Name, $Data)
    if ($null -ne $Data) { $arr = @($Data); $script:Datasets[$Name] = $arr; return $arr }
    return @()
}

function Add-Section {
    param([Parameter(Mandatory)][string]$Id,[Parameter(Mandatory)][string]$Title,[string]$Description,[string]$Body)
    $script:Sections.Add([pscustomobject]@{ Id=$Id; Title=$Title; Description=$Description; Body=$Body })
}

function Encode-Html {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    [System.Net.WebUtility]::HtmlEncode($Text)
}

function Convert-ToHtmlTable {
    param($Data,[string[]]$Properties,[string[]]$RiskColumns,[string]$EmptyMessage='Sin datos / no se encontraron objetos.')
    $rows = @($Data)
    if ($rows.Count -eq 0) { return "<p class='empty'>$(Encode-Html $EmptyMessage)</p>" }
    if (-not $Properties) { $Properties = $rows[0].PSObject.Properties.Name }
    $riskSet = @{}; foreach ($rc in $RiskColumns) { $riskSet[$rc] = $true }
    $tid = 't' + [guid]::NewGuid().ToString('N').Substring(0,8)
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<div class='tabletools'><input type='text' class='tsearch' placeholder='Filtrar filas...' data-target='$tid'></div>")
    [void]$sb.Append("<div class='tablewrap'><table id='$tid' class='sortable'><thead><tr>")
    foreach ($p in $Properties) { [void]$sb.Append("<th title='Clic para ordenar'>$(Encode-Html $p)</th>") }
    [void]$sb.Append("</tr></thead><tbody>")
    foreach ($row in $rows) {
        [void]$sb.Append("<tr>")
        foreach ($p in $Properties) {
            $val = $row.$p
            if (($val -is [System.Array]) -or (($val -is [System.Collections.IEnumerable]) -and ($val -isnot [string]))) {
                $val = ($val | ForEach-Object { "$_" }) -join '; '
            }
            $cell = Encode-Html ("$val"); $class = ''
            if ($riskSet.ContainsKey($p)) {
                if ("$val" -eq 'True')  { $class = " class='flag-true'" }
                if ("$val" -eq 'False') { $class = " class='flag-false'" }
                if ("$val" -in @('OK','PASS','Yes','Sí')) { $class = " class='flag-ok'" }
                if ("$val" -in @('FAIL','NO','Missing','Falta')) { $class = " class='flag-bad'" }
            }
            [void]$sb.Append("<td$class>$cell</td>")
        }
        [void]$sb.Append("</tr>")
    }
    [void]$sb.Append("</tbody></table></div>")
    [void]$sb.Append("<p class='count'>Total: $($rows.Count)</p>")
    return $sb.ToString()
}

function Convert-ToKvTable {
    param([System.Collections.IDictionary]$Data,[string[]]$RiskKeys)
    $riskSet = @{}; foreach ($rk in $RiskKeys) { $riskSet[$rk] = $true }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<div class='tablewrap'><table class='kv'><tbody>")
    foreach ($key in $Data.Keys) {
        $val = $Data[$key]; if ($val -is [System.Array]) { $val = ($val -join '; ') }
        $class = ''
        if ($riskSet.ContainsKey($key)) {
            if ("$val" -match '^(FAIL|NO|Missing|Falta|Deshabilitad|Disabled)') { $class = " class='flag-bad'" }
            if ("$val" -match '^(OK|PASS|Sí|Yes|Habilitad|Enabled)') { $class = " class='flag-ok'" }
        }
        [void]$sb.Append("<tr><th>$(Encode-Html $key)</th><td$class>$(Encode-Html "$val")</td></tr>")
    }
    [void]$sb.Append("</tbody></table></div>")
    return $sb.ToString()
}

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

# Decodes a msDS-SupportedEncryptionTypes bitmask into friendly names.
function ConvertFrom-EtypeBitmask {
    param([int]$Value)
    if ($null -eq $Value) { return @() }
    $map = [ordered]@{
        0x1='DES-CBC-CRC'; 0x2='DES-CBC-MD5'; 0x4='RC4-HMAC'
        0x8='AES128-CTS-HMAC-SHA1-96'; 0x10='AES256-CTS-HMAC-SHA1-96'; 0x20='AES256-CTS-HMAC-SHA1-96-SK'
    }
    $out = foreach ($bit in $map.Keys) { if ($Value -band $bit) { $map[$bit] } }
    @($out)
}

#endregion

#region ------------------------------------------------- Error knowledge base

# Maps the SSPI / Kerberos error codes we may encounter to a human meaning, the
# typical Azure Files root cause, and the fix. Keyed by the hex/string tokens that
# appear in klist / SMB / event-log output.
$script:ErrorKb = @(
    [pscustomobject]@{ Code='0x80090303'; Name='SEC_E_TARGET_UNKNOWN'
        Meaning='The specified target is unknown or unreachable.'
        Cause='The SPN cifs/<account>.file.core.windows.net is NOT registered in AD (or you are mounting via a name that does not match the SPN, e.g. a private-endpoint/privatelink name, an IP, or an alias). The KDC returns KDC_ERR_S_PRINCIPAL_UNKNOWN and SSPI surfaces TARGET_UNKNOWN.'
        Fix='Register the SPN on the AD identity object that backs the storage account and always mount using the exact FQDN <account>.file.core.windows.net.' }
    [pscustomobject]@{ Code='0x6fb'; Name='ERROR_NO_TRUST_SAM_ACCOUNT (1787)'
        Meaning='The security database on the server does not have a computer account for this workstation trust relationship.'
        Cause='The AD identity object (computer or service account) created for the storage account is missing, deleted, disabled, or its SID no longer matches the AzureStorageSid configured on the storage account.'
        Fix='Re-create / re-link the AD identity with Join-AzStorageAccountForAuth (AzFilesHybrid) or Set-AzStorageAccount, ensure the object is enabled, and confirm the SID matches.' }
    [pscustomobject]@{ Code='0x7'; Name='KDC_ERR_S_PRINCIPAL_UNKNOWN'
        Meaning='The server principal (SPN) is unknown to the KDC.'
        Cause='No AD object holds the SPN cifs/<account>.file.core.windows.net.'
        Fix='setspn -S cifs/<account>.file.core.windows.net <ADObjectSamAccountName>.' }
    [pscustomobject]@{ Code='0xe'; Name='KDC_ERR_ETYPE_NOTSUPP'
        Meaning='KDC has no support for the requested encryption type.'
        Cause='Encryption-type mismatch: the storage account expects AES-256 but the AD object / client only offers RC4 (or vice versa).'
        Fix='Align msDS-SupportedEncryptionTypes on the AD object with the storage accounts Kerberos setting (AES-256 recommended).' }
    [pscustomobject]@{ Code='0x18'; Name='KDC_ERR_PREAUTH_FAILED'
        Meaning='Pre-authentication failed (bad key/password).'
        Cause='The kerb key on the storage account was rotated but the password on the AD identity object was not updated (or vice versa) - the shared key no longer matches.'
        Fix='Rotate/synchronise the kerb key: Update-AzStorageAccountADObjectPassword / re-run the join so the AD object password equals the active kerb key.' }
    [pscustomobject]@{ Code='0x25'; Name='KRB_AP_ERR_SKEW'
        Meaning='Clock skew too great.'
        Cause='Client time differs from the KDC by more than 5 minutes.'
        Fix='Fix time sync (w32tm) on the client / DC.' }
    [pscustomobject]@{ Code='0x29'; Name='KRB_AP_ERR_MODIFIED'
        Meaning='Message stream modified / wrong service key.'
        Cause='The SPN is registered on the WRONG account, is duplicated across accounts, or the service key is out of sync.'
        Fix='Ensure the SPN is unique and on the correct AD identity object; resync the kerb key.' }
    [pscustomobject]@{ Code='0x8009030c'; Name='SEC_E_LOGON_DENIED'
        Meaning='The logon attempt failed.'
        Cause='Credentials / key rejected - often a kerb-key mismatch or disabled object.'
        Fix='Resync the kerb key and confirm the AD object is enabled.' }
    [pscustomobject]@{ Code='0x80090322'; Name='SEC_E_WRONG_PRINCIPAL'
        Meaning='The target principal name is incorrect.'
        Cause='Mounting with a name that does not match the SPN, or SPN on the wrong object.'
        Fix='Mount using the exact <account>.file.core.windows.net and fix SPN placement.' }
)

function Resolve-ErrorCode {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $t = $Text.ToLower()
    $hits = foreach ($e in $script:ErrorKb) {
        $code = $e.Code.ToLower()
        if ($t -match [regex]::Escape($code) -or $t -match [regex]::Escape($e.Name.ToLower())) { $e }
    }
    @($hits | Sort-Object Code -Unique)
}

#endregion

#region ------------------------------------------------- Prereqs / output

Write-Step "Iniciando diagnóstico Kerberos para Azure Files: $script:SaFqdn"
if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$stamp      = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportFile = Join-Path $OutputPath "AzureFiles_Kerberos_Diag_$stamp.html"
$csvFolder  = Join-Path $OutputPath "AzureFiles_Kerberos_CSV_$stamp"

# Build an LDAP path honouring an explicit DC, else the joined domain.
function Get-LdapRoot {
    if ($DomainController) { return "LDAP://$DomainController" }
    return 'LDAP://RootDSE'
}
function Get-LdapBase {
    try {
        $rootPath = if ($DomainController) { "LDAP://$DomainController/RootDSE" } else { 'LDAP://RootDSE' }
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry($rootPath)
        return [string]$rootDse.Properties['defaultNamingContext'].Value
    } catch { return $null }
}

#endregion

#region ------------------------------------------------- 1. System & identity

try {
    Write-Step "Recopilando contexto del sistema e identidad"
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue

    $joinType = 'Workgroup / desconocido'
    if ($cs) {
        if ($cs.PartOfDomain) { $joinType = "Unido a dominio AD ($($cs.Domain))" }
        else { $joinType = "No unido a dominio ($($cs.Domain))" }
    }

    # dsregcmd /status tells us the real join story (AzureAdJoined / DomainJoined / Hybrid).
    $dsreg = @{}
    try {
        $raw = & dsregcmd /status 2>$null
        foreach ($line in $raw) {
            if ($line -match '^\s*([A-Za-z0-9_ ]+?)\s*:\s*(.+?)\s*$') {
                $k = $matches[1].Trim(); $v = $matches[2].Trim()
                if ($k -and -not $dsreg.ContainsKey($k)) { $dsreg[$k] = $v }
            }
        }
    } catch {}

    $azureAdJoined = $dsreg['AzureAdJoined']
    $domainJoined  = $dsreg['DomainJoined']
    $enterpriseJoined = $dsreg['EnterpriseJoined']

    # Scenario detection drives the whole analysis.
    $scenario = 'Indeterminado'
    if ($domainJoined -eq 'YES' -and $azureAdJoined -eq 'YES') { $scenario = 'Hybrid Entra joined (AD DS + Entra)' }
    elseif ($domainJoined -eq 'YES') { $scenario = 'On-premises AD DS joined' }
    elseif ($azureAdJoined -eq 'YES') { $scenario = 'Microsoft Entra joined (cloud)' }
    $script:Facts['Scenario'] = $scenario
    $script:Facts['DomainJoined'] = ($domainJoined -eq 'YES')
    $script:Facts['EntraJoined']  = ($azureAdJoined -eq 'YES')

    $ctx = [ordered]@{
        'Equipo'                       = $env:COMPUTERNAME
        'Usuario actual'               = "$env:USERDOMAIN\$env:USERNAME"
        'Sistema operativo'            = if ($os) { "$($os.Caption) (build $($os.BuildNumber))" } else { 'n/d' }
        'Tipo de unión (WMI)'          = $joinType
        'DomainJoined (dsregcmd)'      = $domainJoined
        'AzureAdJoined (dsregcmd)'     = $azureAdJoined
        'EnterpriseJoined (dsregcmd)'  = $enterpriseJoined
        'Tenant (dsregcmd)'            = $dsreg['TenantName']
        'Escenario detectado'          = $scenario
        'Cuenta de almacenamiento'     = $StorageAccountName
        'FQDN destino'                 = $script:SaFqdn
        'SPN esperado'                 = $script:Spn
        'Share (opcional)'             = if ($FileShareName) { $FileShareName } else { '(no especificado)' }
    }
    Add-Section -Id 'context' -Title '1. Contexto del sistema e identidad' `
        -Description 'Tipo de unión del equipo y escenario de autenticación. Que el fallo ocurra tanto en equipos AD como Entra ya orienta la causa hacia el lado servidor/identidad.' `
        -Body (Convert-ToKvTable $ctx)

    if ($scenario -eq 'Microsoft Entra joined (cloud)') {
        Add-Finding -Severity 'Info' -Category 'Escenario' -Title 'Cliente Entra joined (cloud)' `
            -Detail 'Para equipos solo-Entra, Azure Files requiere Microsoft Entra Kerberos habilitado en la cuenta de almacenamiento y CloudKerberosTicketRetrievalEnabled=1 en el cliente.'
    }
} catch { Add-AuditError -Area 'Contexto' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 2. DNS resolution

try {
    Write-Step "Resolviendo DNS de $script:SaFqdn"
    $dnsRows = @()
    $cnameChain = @(); $ips = @()
    try {
        $rec = Resolve-DnsName -Name $script:SaFqdn -ErrorAction Stop
        foreach ($r in $rec) {
            $dnsRows += [pscustomobject]@{
                Nombre = $r.Name; Tipo = $r.Type
                Valor  = ($r.NameHost, $r.IPAddress, $r.CNAME | Where-Object { $_ }) -join ''
                TTL    = $r.TTL
            }
            if ($r.Type -eq 'CNAME') { $cnameChain += $r.NameHost }
            if ($r.IPAddress) { $ips += $r.IPAddress }
        }
    } catch {
        Add-Finding -Severity 'Critical' -Category 'DNS' -Title "El FQDN $script:SaFqdn no se resuelve" `
            -Detail 'Sin resolución DNS no hay Kerberos posible. Verifique el nombre de la cuenta, el sufijo y el DNS (endpoint privado vs público).'
        $script:Facts['DnsResolves'] = $false
    }
    $script:Facts['DnsResolves'] = ($ips.Count -gt 0)
    $script:Facts['DnsIps'] = $ips
    $script:Facts['PrivateEndpoint'] = [bool]($cnameChain -join ' ' -match 'privatelink')

    $dnsKv = [ordered]@{
        'IPs resueltas'        = if ($ips) { $ips -join ', ' } else { '(ninguna)' }
        'Cadena CNAME'         = if ($cnameChain) { $cnameChain -join ' -> ' } else { '(directa, sin CNAME)' }
        'Endpoint privado'     = if ($script:Facts['PrivateEndpoint']) { 'Sí (privatelink detectado)' } else { 'No (parece endpoint público)' }
    }
    $body = (Convert-ToKvTable $dnsKv) + (Convert-ToHtmlTable (Register-Dataset 'DNS' $dnsRows))
    Add-Section -Id 'dns' -Title '2. Resolución DNS del endpoint' `
        -Description 'El nombre con el que se monta el share debe coincidir con el SPN cifs/<cuenta>.file.core.windows.net. Si se usa un nombre de endpoint privado/alias distinto, Kerberos devuelve TARGET_UNKNOWN.' `
        -Body $body

    if ($script:Facts['PrivateEndpoint']) {
        Add-Finding -Severity 'Medium' -Category 'DNS' -Title 'Endpoint privado (privatelink) en uso' `
            -Detail 'Asegúrese de montar SIEMPRE con <cuenta>.file.core.windows.net (el CNAME a privatelink es transparente). Montar directamente con el nombre privatelink o una IP rompe Kerberos (TARGET_UNKNOWN).'
    }
} catch { Add-AuditError -Area 'DNS' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 3. Network reachability

try {
    Write-Step "Probando conectividad TCP (445/443)"
    $netRows = @()
    foreach ($port in 445,443) {
        $ok = $false; $msg = ''
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $iar = $client.BeginConnect($script:SaFqdn, $port, $null, $null)
            $ok = $iar.AsyncWaitHandle.WaitOne(5000, $false)
            if ($ok -and $client.Connected) { $ok = $true } else { $ok = $false; $msg = 'timeout/rechazado' }
            $client.Close()
        } catch { $ok = $false; $msg = $_.Exception.Message }
        $netRows += [pscustomobject]@{ Puerto = $port; Servicio = (if ($port -eq 445) {'SMB'} else {'HTTPS/REST'}); Estado = (if ($ok) {'OK'} else {'FAIL'}); Detalle = $msg }
        if ($port -eq 445) { $script:Facts['Port445'] = $ok }
    }
    Add-Section -Id 'net' -Title '3. Conectividad de red' `
        -Description 'Kerberos sobre SMB necesita el puerto 445/TCP abierto hasta el endpoint. Un 445 bloqueado da errores distintos (no TARGET_UNKNOWN) pero se verifica por completitud.' `
        -Body (Convert-ToHtmlTable (Register-Dataset 'Red' $netRows) -RiskColumns @('Estado'))
    if (-not $script:Facts['Port445']) {
        Add-Finding -Severity 'High' -Category 'Red' -Title 'Puerto 445/TCP no alcanzable' `
            -Detail 'Muchos ISP/firewalls bloquean el 445 saliente. Esto impide SMB por completo (síntoma distinto a 0x80090303, pero hay que descartarlo).'
    }
} catch { Add-AuditError -Area 'Red' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 4. Clock skew

try {
    Write-Step "Comprobando sincronización de reloj (skew Kerberos)"
    $skewKv = [ordered]@{}
    $localUtc = (Get-Date).ToUniversalTime()
    $skewKv['Hora local (UTC)'] = $localUtc.ToString('yyyy-MM-dd HH:mm:ss')

    # Read the DC time straight from RootDSE.currentTime (no special rights needed).
    $dcTime = $null
    try {
        $rootPath = if ($DomainController) { "LDAP://$DomainController/RootDSE" } else { 'LDAP://RootDSE' }
        $rootDse = New-Object System.DirectoryServices.DirectoryEntry($rootPath)
        $ct = [string]$rootDse.Properties['currentTime'].Value
        if ($ct) {
            # Generalized time: yyyyMMddHHmmss.0Z
            $dcTime = [datetime]::ParseExact($ct.Substring(0,14),'yyyyMMddHHmmss',$null,[System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
        }
    } catch {}

    if ($dcTime) {
        $skew = [math]::Abs((New-TimeSpan -Start $localUtc -End $dcTime).TotalSeconds)
        $skewKv['Hora DC (UTC)']   = $dcTime.ToString('yyyy-MM-dd HH:mm:ss')
        $skewKv['Desfase (seg)']   = [math]::Round($skew,1)
        $skewKv['Umbral (seg)']    = $MaxClockSkewSeconds
        $skewKv['Veredicto']       = if ($skew -le $MaxClockSkewSeconds) { 'OK' } else { 'FAIL - skew excesivo' }
        $script:Facts['ClockSkew'] = $skew
        if ($skew -gt $MaxClockSkewSeconds) {
            Add-Finding -Severity 'High' -Category 'Tiempo' -Title "Desfase de reloj excesivo ($([math]::Round($skew))s)" `
                -Detail 'Kerberos rechaza tickets con más de 5 min de desfase (KRB_AP_ERR_SKEW 0x25). Corrija w32tm.'
        }
    } else {
        $skewKv['Hora DC (UTC)'] = 'No disponible (sin DC alcanzable o equipo no unido a dominio)'
    }

    # w32tm time source for context.
    try { $skewKv['w32tm origen'] = ((& w32tm /query /source 2>$null) -join ' ') } catch {}

    Add-Section -Id 'time' -Title '4. Sincronización de reloj' `
        -Description 'Kerberos es sensible al tiempo: un desfase > 5 minutos provoca fallos de pre-autenticación.' `
        -Body (Convert-ToKvTable $skewKv -RiskKeys @('Veredicto'))
} catch { Add-AuditError -Area 'Tiempo' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 5. Client Kerberos config

try {
    Write-Step "Inspeccionando configuración Kerberos del cliente"
    $kKv = [ordered]@{}

    # Supported encryption types (client side) - LSA Kerberos parameters + policy.
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters'
    $polPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kerberos\Parameters'
    $setVal = $null
    foreach ($p in $polPath,$lsaPath) {
        try {
            $v = (Get-ItemProperty -Path $p -Name 'SupportedEncryptionTypes' -ErrorAction Stop).SupportedEncryptionTypes
            if ($null -ne $v) { $setVal = [int]$v; $kKv["SupportedEncryptionTypes ($p)"] = ("0x{0:X} -> {1}" -f $v, ((ConvertFrom-EtypeBitmask $v) -join ', ')) ; break }
        } catch {}
    }
    if ($null -eq $setVal) { $kKv['SupportedEncryptionTypes'] = 'No configurado (se usa el default de Windows: AES + RC4)' }
    $script:Facts['ClientEtypes'] = if ($null -ne $setVal) { ConvertFrom-EtypeBitmask $setVal } else { @('AES256-CTS-HMAC-SHA1-96','AES128-CTS-HMAC-SHA1-96','RC4-HMAC') }

    # Cloud Kerberos retrieval (required for Entra Kerberos scenarios).
    $cloudKerb = $null
    foreach ($p in $polPath,$lsaPath) {
        try { $v = (Get-ItemProperty -Path $p -Name 'CloudKerberosTicketRetrievalEnabled' -ErrorAction Stop).CloudKerberosTicketRetrievalEnabled; if ($null -ne $v) { $cloudKerb = [int]$v; break } } catch {}
    }
    $kKv['CloudKerberosTicketRetrievalEnabled'] = if ($null -ne $cloudKerb) { $cloudKerb } else { '0 / no configurado' }
    $script:Facts['CloudKerb'] = ($cloudKerb -eq 1)

    if ($script:Facts['EntraJoined'] -and -not $script:Facts['DomainJoined'] -and $cloudKerb -ne 1) {
        Add-Finding -Severity 'High' -Category 'Kerberos cliente' -Title 'CloudKerberosTicketRetrievalEnabled no está en 1 (cliente Entra)' `
            -Detail 'Equipos solo-Entra necesitan esta clave en 1 para obtener tickets Kerberos de Microsoft Entra Kerberos.'
    }

    # Realm / host-to-realm mappings (ksetup) - relevant for Entra Kerberos realm.
    try {
        $ks = (& ksetup 2>$null) -join "`n"
        if ($ks) { $kKv['ksetup (realms/mappings)'] = ($ks -replace '\s+',' ').Trim() }
    } catch {}

    Add-Section -Id 'kclient' -Title '5. Configuración Kerberos del cliente' `
        -Description 'Tipos de cifrado soportados por el cliente, recuperación de tickets en la nube (Entra Kerberos) y mapeos de realm.' `
        -Body (Convert-ToKvTable $kKv)
} catch { Add-AuditError -Area 'Kerberos cliente' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 6 & 7. SPN + AD object

try {
    Write-Step "Buscando el SPN $script:Spn en Active Directory"
    $spnObjects = @()
    $adObj = $null

    if ($script:Facts['DomainJoined']) {
        $base = Get-LdapBase
        if ($base) {
            try {
                $ldapPath = if ($DomainController) { "LDAP://$DomainController/$base" } else { "LDAP://$base" }
                $de = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                $ds = New-Object System.DirectoryServices.DirectorySearcher($de)
                $ds.Filter = "(servicePrincipalName=$script:Spn)"
                $ds.PageSize = 100
                foreach ($pn in 'samAccountName','distinguishedName','objectClass','userAccountControl','msDS-SupportedEncryptionTypes','pwdLastSet','servicePrincipalName','whenCreated','objectSid','dNSHostName') {
                    [void]$ds.PropertiesToLoad.Add($pn)
                }
                $results = $ds.FindAll()
                foreach ($r in $results) {
                    $p = $r.Properties
                    $uac = if ($p['useraccountcontrol'].Count) { [int]$p['useraccountcontrol'][0] } else { $null }
                    $etv = if ($p['msds-supportedencryptiontypes'].Count) { [int]$p['msds-supportedencryptiontypes'][0] } else { $null }
                    $pls = if ($p['pwdlastset'].Count) { ConvertTo-DateTimeSafe ([int64]$p['pwdlastset'][0]) } else { $null }
                    $sid = $null
                    if ($p['objectsid'].Count) { try { $sid = (New-Object System.Security.Principal.SecurityIdentifier($p['objectsid'][0],0)).Value } catch {} }
                    $disabled = if ($null -ne $uac) { [bool]($uac -band 0x2) } else { $null }
                    $spnObjects += [pscustomobject]@{
                        sAMAccountName = if ($p['samaccountname'].Count) { [string]$p['samaccountname'][0] } else { '' }
                        DN             = if ($p['distinguishedname'].Count) { [string]$p['distinguishedname'][0] } else { '' }
                        objectClass    = if ($p['objectclass'].Count) { ($p['objectclass'] | Select-Object -Last 1) } else { '' }
                        Deshabilitado  = $disabled
                        EtypesSoportados = (ConvertFrom-EtypeBitmask $etv) -join ', '
                        EtypesRaw      = if ($null -ne $etv) { "0x{0:X}" -f $etv } else { '(no definido -> RC4 por defecto)' }
                        PwdLastSet     = if ($pls) { $pls.ToString('yyyy-MM-dd') } else { '' }
                        PwdEdadDias    = if ($pls) { [math]::Round((New-TimeSpan -Start $pls -End (Get-Date)).TotalDays) } else { '' }
                        SID            = $sid
                        SPNs           = ($p['serviceprincipalname'] | ForEach-Object { "$_" }) -join '; '
                    }
                }
                $results.Dispose()
            } catch { Add-AuditError -Area 'SPN/AD' -Message $_.Exception.Message }
        }

        # Fallback / corroboration via setspn.exe if present.
        try {
            $spnQuery = (& setspn -Q $script:Spn 2>$null) -join "`n"
            if ($spnQuery) { $script:Facts['SetspnRaw'] = $spnQuery }
        } catch {}
    } else {
        Add-Finding -Severity 'Info' -Category 'SPN' -Title 'Equipo no unido a AD DS: consulta de SPN omitida' `
            -Detail 'La verificación de SPN en AD requiere un equipo unido al dominio. Ejecute también el script en un equipo AD DS, o verifique con setspn en un DC.'
    }

    $script:Facts['SpnCount'] = $spnObjects.Count
    $script:Facts['SpnObjects'] = $spnObjects

    # Findings driven by the SPN search result.
    if ($script:Facts['DomainJoined']) {
        if ($spnObjects.Count -eq 0) {
            Add-Finding -Severity 'Critical' -Category 'SPN' -Title "SPN $script:Spn NO registrado en AD" `
                -Detail 'Causa directa de 0x80090303 / KDC_ERR_S_PRINCIPAL_UNKNOWN. El KDC no puede emitir un ticket de servicio. Registre el SPN en el objeto de identidad de la cuenta de almacenamiento.'
        } elseif ($spnObjects.Count -gt 1) {
            Add-Finding -Severity 'Critical' -Category 'SPN' -Title "SPN $script:Spn DUPLICADO en $($spnObjects.Count) objetos" `
                -Detail 'Un SPN duplicado rompe Kerberos (KRB_AP_ERR_MODIFIED / autenticación inconsistente). Debe existir en un único objeto. Elimine los duplicados.'
        } else {
            $o = $spnObjects[0]
            if ($o.Deshabilitado -eq $true) {
                Add-Finding -Severity 'Critical' -Category 'Identidad' -Title "El objeto AD de la cuenta ($($o.sAMAccountName)) está DESHABILITADO" `
                    -Detail 'Un objeto deshabilitado produce 0x6fb (ERROR_NO_TRUST_SAM_ACCOUNT) / logon denied. Habilítelo.'
            }
            if ($o.EtypesRaw -match 'no definido' -or $o.EtypesSoportados -notmatch 'AES') {
                Add-Finding -Severity 'High' -Category 'Cifrado' -Title 'El objeto AD no anuncia AES' `
                    -Detail "msDS-SupportedEncryptionTypes = $($o.EtypesRaw). Si la cuenta de almacenamiento exige AES-256, habrá KDC_ERR_ETYPE_NOTSUPP. Configure AES-256 en el objeto."
            }
            if ($o.PwdEdadDias -ne '' -and [int]$o.PwdEdadDias -gt 90) {
                Add-Finding -Severity 'Medium' -Category 'Kerb key' -Title "La contraseña/kerb-key del objeto tiene $($o.PwdEdadDias) días" `
                    -Detail 'Si la kerb key se rotó en la cuenta de almacenamiento sin actualizar el objeto AD (o al revés), la clave compartida no coincide -> KDC_ERR_PREAUTH_FAILED (0x18).'
            }
        }
    }

    $spnBody = ''
    if ($spnObjects.Count) {
        $spnBody = "<h3>Objeto(s) AD que poseen el SPN</h3>" + (Convert-ToHtmlTable $spnObjects -RiskColumns @('Deshabilitado'))
    } else {
        $spnBody = "<p class='empty'>No se encontró ningún objeto en AD con el SPN <code>$(Encode-Html $script:Spn)</code>.</p>"
    }
    if ($script:Facts['SetspnRaw']) {
        $spnBody += "<h3>Salida de setspn -Q</h3><pre class='raw'>$(Encode-Html $script:Facts['SetspnRaw'])</pre>"
    }
    Add-Section -Id 'spn' -Title '6/7. SPN y objeto de identidad en AD' `
        -Description "Se busca quién posee el SPN $script:Spn. El SPN debe existir en EXACTAMENTE un objeto (el que respalda la cuenta de almacenamiento), habilitado y con los etypes correctos." `
        -Body $spnBody
} catch { Add-AuditError -Area 'SPN/AD' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 8. Live Kerberos ticket test

try {
    Write-Step "Solicitando ticket Kerberos en vivo para $script:Spn"
    if ($PurgeTickets) {
        Write-Step "Purgando caché de tickets (klist purge)"
        & klist purge 2>$null | Out-Null
    }

    $getOut = (& klist get $script:Spn 2>&1) -join "`n"
    $listOut = (& klist 2>&1) -join "`n"
    $script:Facts['KlistGetRaw'] = $getOut

    $hitCodes = Resolve-ErrorCode $getOut
    $script:Facts['KlistErrorHits'] = $hitCodes
    # Success: klist printed the cached service ticket for the SPN and no error code appeared.
    $script:Facts['GotTicket'] = (-not ($getOut -match '0x[0-9a-fA-F]{2,}')) -and ($getOut -match [regex]::Escape($script:Spn))

    $kv = [ordered]@{
        'Resultado'      = if ($script:Facts['GotTicket']) { 'OK - ticket de servicio obtenido' } else { 'FAIL - no se pudo obtener el ticket de servicio' }
        'SPN solicitado' = $script:Spn
    }
    if ($hitCodes.Count) { $kv['Códigos detectados'] = ($hitCodes | ForEach-Object { "$($_.Code) $($_.Name)" }) -join ' | ' }

    $body = (Convert-ToKvTable $kv -RiskKeys @('Resultado'))
    $body += "<h3>klist get $([System.Net.WebUtility]::HtmlEncode($script:Spn))</h3><pre class='raw'>$(Encode-Html $getOut)</pre>"
    $body += "<h3>klist (tickets en caché)</h3><pre class='raw'>$(Encode-Html $listOut)</pre>"
    if ($hitCodes.Count) {
        $kbRows = $hitCodes | ForEach-Object { [pscustomobject]@{ Código=$_.Code; Nombre=$_.Name; Significado=$_.Meaning; 'Causa típica en Azure Files'=$_.Cause; Remediación=$_.Fix } }
        $body += "<h3>Interpretación de los códigos observados</h3>" + (Convert-ToHtmlTable $kbRows)
    }

    Add-Section -Id 'ticket' -Title '8. Prueba de ticket Kerberos en vivo' `
        -Description 'Reproducción directa del fallo: se pide al KDC un ticket de servicio para el SPN del share. La salida real de klist confirma el código exacto y su causa.' `
        -Body $body

    if (-not $script:Facts['GotTicket']) {
        Add-Finding -Severity 'Critical' -Category 'Kerberos' -Title 'No se obtiene ticket de servicio para el share' `
            -Detail "klist get $script:Spn falló. Es la confirmación en vivo del problema reportado."
    }
} catch { Add-AuditError -Area 'Ticket Kerberos' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 9. Storage account config (Az)

if ($StorageResourceGroup) {
    try {
        Write-Step "Leyendo configuración de la cuenta de almacenamiento (Az.Storage)"
        if (Get-Module -ListAvailable -Name Az.Storage) {
            Import-Module Az.Storage -ErrorAction Stop
            $ctxAz = Get-AzContext -ErrorAction SilentlyContinue
            if (-not $ctxAz) { throw 'No hay sesión de Az. Ejecute Connect-AzAccount primero.' }
            $sa = Get-AzStorageAccount -ResourceGroupName $StorageResourceGroup -Name $StorageAccountName -ErrorAction Stop
            $idb = $sa.AzureFilesIdentityBasedAuth
            $adp = $idb.ActiveDirectoryProperties
            $saKv = [ordered]@{
                'DirectoryServiceOptions' = $idb.DirectoryServiceOptions
                'DefaultSharePermission'  = $idb.DefaultSharePermission
                'AD DomainName'           = $adp.DomainName
                'AD NetBiosDomainName'    = $adp.NetBiosDomainName
                'AD ForestName'           = $adp.ForestName
                'AD DomainGuid'           = $adp.DomainGuid
                'AD DomainSid'            = $adp.DomainSid
                'AzureStorageSid'         = $adp.AzureStorageSid
                'SamAccountName'          = $adp.SamAccountName
                'AccountType'             = $adp.AccountType
            }
            $script:Facts['StorageSamAccountName'] = $adp.SamAccountName
            $script:Facts['AzureStorageSid'] = $adp.AzureStorageSid
            $script:Facts['DirectoryServiceOptions'] = $idb.DirectoryServiceOptions

            # Cross-check the SID/sam from the storage account against the AD object found.
            $crossNotes = @()
            if ($script:Facts['SpnObjects'] -and $script:Facts['SpnObjects'].Count -eq 1) {
                $o = $script:Facts['SpnObjects'][0]
                if ($adp.SamAccountName -and $o.sAMAccountName -and ($adp.SamAccountName -ne $o.sAMAccountName)) {
                    $crossNotes += "El SamAccountName de la cuenta ($($adp.SamAccountName)) NO coincide con el objeto que posee el SPN ($($o.sAMAccountName))."
                    Add-Finding -Severity 'Critical' -Category 'Identidad' -Title 'SamAccountName de la cuenta no coincide con el objeto del SPN' `
                        -Detail $crossNotes[-1]
                }
                if ($adp.AzureStorageSid -and $o.SID -and ($adp.AzureStorageSid -ne $o.SID)) {
                    $crossNotes += "El AzureStorageSid ($($adp.AzureStorageSid)) NO coincide con el SID del objeto AD ($($o.SID)) -> causa típica de 0x6fb."
                    Add-Finding -Severity 'Critical' -Category 'Identidad' -Title 'AzureStorageSid no coincide con el SID del objeto AD' `
                        -Detail $crossNotes[-1]
                }
            }
            if ($idb.DirectoryServiceOptions -eq 'None') {
                Add-Finding -Severity 'Critical' -Category 'Configuración' -Title 'La cuenta NO tiene autenticación basada en identidad habilitada' `
                    -Detail 'DirectoryServiceOptions = None. Debe ser AD / AADDS / AADKERB para usar Kerberos.'
            }

            $body = (Convert-ToKvTable $saKv)
            if ($crossNotes.Count) { $body += "<h3>Verificación cruzada AD &harr; Storage</h3><ul>" + (($crossNotes | ForEach-Object { "<li>$(Encode-Html $_)</li>" }) -join '') + "</ul>" }
            Add-Section -Id 'storage' -Title '9. Configuración de identidad de la cuenta de almacenamiento' `
                -Description 'Configuración real de la cuenta (DirectoryServiceOptions, dominio, SID) y verificación cruzada contra el objeto AD encontrado.' `
                -Body $body
        } else {
            Add-AuditError -Area 'Storage/Az' -Message 'Módulo Az.Storage no instalado; sección omitida. Install-Module Az.Storage para habilitarla.'
        }
    } catch { Add-AuditError -Area 'Storage/Az' -Message $_.Exception.Message }
}

#endregion

#region ------------------------------------------------- 10. SMB mount test (opt-in)

if ($IncludeMountTest) {
    try {
        Write-Step "Prueba de montaje SMB real (opt-in)"
        $share = if ($FileShareName) { $FileShareName } else { $null }
        $mountKv = [ordered]@{}
        if (-not $share) {
            $mountKv['Estado'] = 'Omitido: especifique -FileShareName para la prueba de montaje.'
        } else {
            $remote = "\\$script:SaFqdn\$share"
            $mountKv['Ruta'] = $remote
            $err = ''
            try {
                $netUse = (& net use $remote 2>&1) -join "`n"
                $mountKv['Salida net use'] = $netUse
                $err = $netUse
                # Clean up if it actually mapped.
                & net use $remote /delete /y 2>$null | Out-Null
            } catch { $err = $_.Exception.Message; $mountKv['Error'] = $err }
            $hits = Resolve-ErrorCode $err
            if ($hits.Count) { $mountKv['Códigos detectados'] = ($hits | ForEach-Object { "$($_.Code) $($_.Name)" }) -join ' | ' }
            $mountKv['Resultado'] = if ($err -match 'completed successfully|se ha completado') { 'OK' } else { 'FAIL' }
        }
        Add-Section -Id 'mount' -Title '10. Prueba de montaje SMB' `
            -Description 'Intento real de montar el share para capturar el error Win32 exacto. (Acción opt-in; el mapeo se elimina al terminar.)' `
            -Body (Convert-ToKvTable $mountKv -RiskKeys @('Resultado'))
    } catch { Add-AuditError -Area 'Montaje SMB' -Message $_.Exception.Message }
}

#endregion

#region ------------------------------------------------- 11. Event log harvest

try {
    Write-Step "Recolectando eventos SMB / LSA / Kerberos recientes"
    $events = @()
    $logs = @(
        @{ Log='Microsoft-Windows-SMBClient/Security';     Name='SMBClient/Security' }
        @{ Log='Microsoft-Windows-SMBClient/Connectivity'; Name='SMBClient/Connectivity' }
        @{ Log='System';                                    Name='System' }
    )
    $since = (Get-Date).AddDays(-7)
    foreach ($l in $logs) {
        try {
            $evs = Get-WinEvent -FilterHashtable @{ LogName=$l.Log; StartTime=$since } -MaxEvents 400 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.LevelDisplayName -in @('Error','Warning') -and
                    ($_.Message -match 'Kerberos|0x80090303|0x6fb|SPN|cifs|file.core.windows.net|encryption|SMB' )
                } | Select-Object -First 40
            foreach ($e in $evs) {
                $events += [pscustomobject]@{
                    Hora = $e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    Log  = $l.Name; Id = $e.Id; Nivel = $e.LevelDisplayName
                    Mensaje = ($e.Message -replace '\s+',' ').Substring(0, [math]::Min(300, ($e.Message -replace '\s+',' ').Length))
                }
            }
        } catch {}
    }
    $events = $events | Sort-Object Hora -Descending
    Add-Section -Id 'events' -Title '11. Eventos relevantes (últimos 7 días)' `
        -Description 'Errores/avisos de SMBClient, LSA y Kerberos relacionados con el share o con autenticación.' `
        -Body (Convert-ToHtmlTable (Register-Dataset 'Eventos' $events) -EmptyMessage 'No se encontraron eventos relevantes en la ventana analizada.')
} catch { Add-AuditError -Area 'Eventos' -Message $_.Exception.Message }

#endregion

#region ------------------------------------------------- 12. Root-cause engine

Write-Step "Sintetizando análisis de causa raíz"

$f = $script:Facts

# Primary hypothesis: SPN missing -> 0x80090303 / TARGET_UNKNOWN.
if ($f['DomainJoined'] -and $f['SpnCount'] -eq 0) {
    Add-Cause -Confidence 92 -Title "SPN $script:Spn ausente en Active Directory" `
        -Why "La búsqueda LDAP no encontró ningún objeto con el SPN. Esto produce exactamente 0x80090303 (SEC_E_TARGET_UNKNOWN) / KDC_ERR_S_PRINCIPAL_UNKNOWN en TODOS los clientes, coincidiendo con el síntoma reportado." `
        -Fix @(
            'Identifique el objeto AD que respalda la cuenta (computer o service account creado por AzFilesHybrid).',
            "Registre el SPN: setspn -S cifs/$script:SaFqdn <SamAccountNameDelObjeto>",
            "Añada también el SPN host si falta: setspn -S host/$script:SaFqdn <SamAccountNameDelObjeto>",
            'Si nunca se ejecutó el join: Join-AzStorageAccountForAuth (módulo AzFilesHybrid) crea el objeto y el SPN automáticamente.',
            'Monte siempre con el FQDN exacto: \\' + $script:SaFqdn + '\<share>'
        ) `
        -Links @('https://learn.microsoft.com/azure/storage/files/storage-files-identity-ad-ds-enable','https://learn.microsoft.com/azure/storage/files/storage-troubleshoot-windows-file-connection-problems')
}

# Duplicate SPN.
if ($f['SpnCount'] -gt 1) {
    Add-Cause -Confidence 85 -Title 'SPN duplicado en varios objetos AD' `
        -Why "El SPN aparece en $($f['SpnCount']) objetos. Kerberos requiere unicidad; un duplicado provoca KRB_AP_ERR_MODIFIED y autenticación errática." `
        -Fix @('Determine cuál objeto es el correcto (el de la cuenta de almacenamiento).','Elimine el SPN de los objetos sobrantes: setspn -D cifs/'+$script:SaFqdn+' <ObjetoIncorrecto>') `
        -Links @('https://learn.microsoft.com/troubleshoot/windows-server/windows-security/troubleshoot-kerberos-related-issues')
}

# Disabled / SID mismatch -> 0x6fb.
$disabledObj = $false
if ($f['SpnObjects']) { foreach ($o in $f['SpnObjects']) { if ($o.Deshabilitado -eq $true) { $disabledObj = $true } } }
if ($disabledObj -or ($f['AzureStorageSid'] -and $f['SpnObjects'] -and $f['SpnObjects'].Count -eq 1 -and $f['SpnObjects'][0].SID -and $f['AzureStorageSid'] -ne $f['SpnObjects'][0].SID)) {
    Add-Cause -Confidence 80 -Title 'Objeto de identidad deshabilitado o SID descuadrado (explica 0x6fb)' `
        -Why '0x6fb (ERROR_NO_TRUST_SAM_ACCOUNT) indica que la "cuenta de máquina" que respalda el servicio no es válida: objeto deshabilitado, borrado, o con un SID distinto al AzureStorageSid de la cuenta de almacenamiento.' `
        -Fix @('Habilite el objeto AD si está deshabilitado.','Verifique que AzureStorageSid (en la cuenta) == objectSid del objeto AD.','Si no coinciden, re-ejecute el join (Join-AzStorageAccountForAuth) para recrear/realinear la identidad.') `
        -Links @('https://learn.microsoft.com/azure/storage/files/storage-troubleshoot-windows-file-connection-problems')
}

# Encryption type mismatch.
if ($f['SpnObjects'] -and $f['SpnObjects'].Count -eq 1 -and $f['SpnObjects'][0].EtypesSoportados -notmatch 'AES') {
    Add-Cause -Confidence 55 -Title 'Desajuste de tipos de cifrado (AES vs RC4)' `
        -Why "El objeto AD no anuncia AES en msDS-SupportedEncryptionTypes. Si la cuenta exige AES-256, el KDC devuelve KDC_ERR_ETYPE_NOTSUPP (0x0E)." `
        -Fix @('Configure el objeto AD con AES-256 (msDS-SupportedEncryptionTypes = 0x10 o combinaciones que incluyan AES).','Asegure que la política "Network security: Configure encryption types allowed for Kerberos" del cliente incluye AES.') `
        -Links @('https://learn.microsoft.com/azure/storage/files/storage-troubleshoot-windows-file-connection-problems')
}

# Clock skew.
if ($f['ClockSkew'] -and $f['ClockSkew'] -gt $MaxClockSkewSeconds) {
    Add-Cause -Confidence 60 -Title 'Desfase de reloj excesivo' `
        -Why "Desfase de $([math]::Round($f['ClockSkew']))s respecto al DC (> $MaxClockSkewSeconds). Kerberos rechaza tickets (KRB_AP_ERR_SKEW 0x25)." `
        -Fix @('w32tm /resync en el cliente.','Verifique que el DC PDC emulator sincroniza con una fuente fiable.')
}

# Name mismatch / private endpoint.
if ($f['PrivateEndpoint']) {
    Add-Cause -Confidence 40 -Title 'Posible montaje con nombre que no coincide con el SPN (endpoint privado)' `
        -Why 'Se detectó privatelink. Si algún equipo monta usando el nombre privatelink, una IP o un alias en vez de <cuenta>.file.core.windows.net, Kerberos da TARGET_UNKNOWN porque el SPN solo cubre el FQDN público.' `
        -Fix @('Estandarice el montaje con \\'+$script:SaFqdn+'\<share>.','Si se necesita otro nombre, añada un SPN adicional para ese nombre en el mismo objeto AD.')
}

# Entra-only client.
if ($f['EntraJoined'] -and -not $f['DomainJoined'] -and -not $f['CloudKerb']) {
    Add-Cause -Confidence 50 -Title 'Cliente Entra sin Cloud Kerberos para escenario AADKERB' `
        -Why 'Equipo solo-Entra y CloudKerberosTicketRetrievalEnabled != 1. Para Entra Kerberos el cliente no podrá obtener el TGT en la nube.' `
        -Fix @('Habilite por GPO/registro CloudKerberosTicketRetrievalEnabled=1.','Habilite Microsoft Entra Kerberos en la cuenta de almacenamiento (DirectoryServiceOptions=AADKERB).') `
        -Links @('https://learn.microsoft.com/azure/storage/files/storage-files-identity-auth-hybrid-identities-enable')
}

# Catch-all if the live test failed but nothing above fired.
if ((-not $f['GotTicket']) -and $script:Causes.Count -eq 0) {
    $hits = $f['KlistErrorHits']
    $why = 'klist get falló al pedir el ticket de servicio.'
    if ($hits -and $hits.Count) { $why += ' Códigos: ' + (($hits | ForEach-Object { "$($_.Code) ($($_.Name)): $($_.Cause)" }) -join ' | ') }
    Add-Cause -Confidence 45 -Title 'Fallo de emisión de ticket de servicio (causa específica en la salida de klist)' `
        -Why $why `
        -Fix @('Revise la sección 8 (salida cruda de klist) y la tabla de interpretación de códigos.','Ejecute el script también desde un DC con RSAT para confirmar el SPN con setspn -Q.')
}

# Rank causes and build the highlighted block.
$rankedCauses = $script:Causes | Sort-Object Confidence -Descending
$causeHtml = ''
if ($rankedCauses.Count) {
    $top = $rankedCauses[0]
    $causeHtml += "<div class='rootcard'><div class='rc-h'>Causa más probable ($($top.Confidence)% de confianza)</div><div class='rc-t'>$(Encode-Html $top.Title)</div><div class='rc-w'>$(Encode-Html $top.Why)</div></div>"
    foreach ($c in $rankedCauses) {
        $fixItems = ($c.Fix | ForEach-Object { "<li>$(Encode-Html $_)</li>" }) -join ''
        $linkItems = ''
        if ($c.Links) { $linkItems = "<div class='rc-links'>" + (($c.Links | ForEach-Object { "<a href='$_' target='_blank'>$(Encode-Html $_)</a>" }) -join '<br>') + "</div>" }
        $causeHtml += "<div class='cause'><div class='cause-head'><span class='conf'>$($c.Confidence)%</span> $(Encode-Html $c.Title)</div><p class='cause-why'>$(Encode-Html $c.Why)</p><div class='cause-fix'><strong>Remediación:</strong><ol>$fixItems</ol>$linkItems</div></div>"
    }
} else {
    $causeHtml = "<p class='empty'>No se identificó una causa raíz automática. Revise las secciones de SPN, ticket en vivo y eventos. Si el equipo no está unido a AD DS, ejecute el script desde un equipo del dominio para validar el SPN.</p>"
}

Add-Section -Id 'rootcause' -Title '12. Análisis de causa raíz' `
    -Description 'Hipótesis priorizadas por confianza, correlacionando todas las señales recogidas con los códigos 0x80090303 y 0x6fb reportados.' `
    -Body $causeHtml

#endregion

#region ------------------------------------------------- CSV export

if ($ExportCsv) {
    try {
        if (-not (Test-Path $csvFolder)) { New-Item -ItemType Directory -Path $csvFolder -Force | Out-Null }
        foreach ($name in $script:Datasets.Keys) {
            $data = $script:Datasets[$name]
            if ($data -and $data.Count) {
                $data | Export-Csv -Path (Join-Path $csvFolder "$name.csv") -NoTypeInformation -Encoding UTF8
            }
        }
        Write-Host "[+] CSV exportados a $csvFolder" -ForegroundColor Green
    } catch { Add-AuditError -Area 'CSV' -Message $_.Exception.Message }
}

#endregion

#region ------------------------------------------------- HTML assembly

# Severity counters.
$sevCount = [ordered]@{ Critical=0; High=0; Medium=0; Low=0; Info=0 }
foreach ($fi in $script:Findings) { $sevCount[$fi.Severity]++ }

# Findings table.
$findingsHtml = ''
if ($script:Findings.Count) {
    $order = @{ Critical=0; High=1; Medium=2; Low=3; Info=4 }
    $sorted = $script:Findings | Sort-Object @{ Expression = { $order[$_.Severity] } }
    $rows = foreach ($fi in $sorted) {
        $badge = "<span class='badge badge-$($fi.Severity.ToLower())'>$($fi.Severity)</span>"
        "<tr class='sev-$($fi.Severity.ToLower())'><td>$badge</td><td>$(Encode-Html $fi.Category)</td><td>$(Encode-Html $fi.Title)</td><td>$(Encode-Html $fi.Detail)</td></tr>"
    }
    $findingsHtml = "<div class='tablewrap'><table><thead><tr><th>Severidad</th><th>Categoría</th><th>Hallazgo</th><th>Detalle</th></tr></thead><tbody>$($rows -join '')</tbody></table></div>"
} else {
    $findingsHtml = "<p class='empty'>No se registraron hallazgos. Revise igualmente el análisis de causa raíz.</p>"
}

# TOC.
$tocItems = foreach ($s in $script:Sections) { "<li><a href='#$($s.Id)'>$(Encode-Html $s.Title)</a></li>" }

$sectionHtml = foreach ($s in $script:Sections) {
    $desc = if ($s.Description) { "<p class='desc'>$(Encode-Html $s.Description)</p>" } else { '' }
    "<section id='$($s.Id)'><h2>$(Encode-Html $s.Title) <a class='top' href='#top'>&uarr; arriba</a></h2>$desc$($s.Body)</section>"
}

$errorHtml = if ($script:Errors.Count -gt 0) {
    $rows = foreach ($e in $script:Errors) { "<tr><td>$(Encode-Html $e.Area)</td><td>$(Encode-Html $e.Message)</td></tr>" }
    "<section id='errors'><h2>Errores de recolección / omisiones <a class='top' href='#top'>&uarr; arriba</a></h2><p class='desc'>Elementos que no se pudieron recoger (permisos, módulo ausente o consulta no soportada).</p><div class='tablewrap'><table><thead><tr><th>Área</th><th>Mensaje</th></tr></thead><tbody>$($rows -join '')</tbody></table></div></section>"
} else { '' }

$duration = (New-TimeSpan -Start $script:StartTime -End (Get-Date)).ToString('hh\:mm\:ss')
$runContext = [ordered]@{
    'Informe generado'      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    'Generado por'          = "$env:USERDOMAIN\$env:USERNAME en $env:COMPUTERNAME"
    'Cuenta de almacenamiento' = $StorageAccountName
    'FQDN / SPN'            = "$script:SaFqdn  /  $script:Spn"
    'DC objetivo'           = if ($DomainController) { $DomainController } else { 'auto (DC más cercano)' }
    'Duración'              = $duration
    'Versión de PowerShell' = $PSVersionTable.PSVersion.ToString()
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
nav{position:sticky;top:16px;flex:0 0 280px;background:var(--card);border-radius:10px;padding:16px;max-height:90vh;overflow:auto}
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
th,td{padding:7px 10px;text-align:left;border-bottom:1px solid #334155;vertical-align:top}
thead th{background:#0b1220;color:var(--accent);position:sticky;top:0;white-space:nowrap}
tbody tr:hover{background:#293548}
table.kv th{width:320px;color:var(--muted);background:#0b1220;white-space:nowrap}
.count{color:var(--muted);font-size:12px;margin:6px 2px 0}
.empty{color:var(--muted);font-style:italic}
.flag-true,.flag-bad{color:#fca5a5;font-weight:600}
.flag-false,.flag-ok{color:#86efac}
pre.raw{background:#0b1220;border:1px solid #334155;border-radius:8px;padding:12px;overflow:auto;font-size:12px;color:#cbd5e1;white-space:pre-wrap;word-break:break-word}
code{background:#0b1220;padding:1px 5px;border-radius:4px;color:#7dd3fc}
.cards{display:flex;gap:14px;flex-wrap:wrap;margin:8px 0 4px}
.card{flex:1;min-width:120px;background:#0b1220;border-radius:10px;padding:14px 16px;border-left:4px solid var(--accent)}
.card .n{font-size:28px;font-weight:700}
.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card.crit{border-color:var(--crit)} .card.high{border-color:var(--high)}
.card.med{border-color:var(--med)} .card.low{border-color:var(--low)} .card.info{border-color:var(--info)}
.badge{padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;color:#fff}
.badge-critical{background:var(--crit)} .badge-high{background:var(--high)}
.badge-medium{background:var(--med)} .badge-low{background:var(--low)} .badge-info{background:var(--info)}
a{color:var(--accent)}
footer{color:var(--muted);text-align:center;padding:20px;font-size:12px}
.tabletools{margin:6px 0}
.tsearch{width:280px;max-width:100%;padding:6px 10px;border-radius:6px;border:1px solid #334155;background:#0b1220;color:var(--text);font-size:13px}
table.sortable thead th{cursor:pointer;user-select:none}
table.sortable thead th:hover{color:#fff}
table.sortable thead th.asc::after{content:" \25B2";font-size:9px;color:var(--accent)}
table.sortable thead th.desc::after{content:" \25BC";font-size:9px;color:var(--accent)}
.rootcard{background:linear-gradient(135deg,#7f1d1d,#1e293b);border:1px solid var(--crit);border-radius:12px;padding:18px 20px;margin-bottom:18px}
.rootcard .rc-h{color:#fecaca;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.rootcard .rc-t{font-size:20px;font-weight:700;margin:6px 0}
.rootcard .rc-w{color:#e2e8f0;font-size:13.5px}
.cause{background:#0b1220;border-left:4px solid var(--accent);border-radius:8px;padding:14px 16px;margin:12px 0}
.cause-head{font-size:15px;font-weight:700}
.cause-head .conf{display:inline-block;min-width:46px;background:var(--accent);color:#04263a;border-radius:6px;padding:1px 7px;font-size:12px;margin-right:8px;text-align:center}
.cause-why{color:var(--muted);font-size:13px}
.cause-fix ol{margin:6px 0 0 18px;font-size:13px}
.rc-links{margin-top:8px;font-size:12px;word-break:break-all}
'@

$cards = @"
<div class='cards'>
<div class='card crit'><div class='n'>$($sevCount.Critical)</div><div class='l'>Crítico</div></div>
<div class='card high'><div class='n'>$($sevCount.High)</div><div class='l'>Alto</div></div>
<div class='card med'><div class='n'>$($sevCount.Medium)</div><div class='l'>Medio</div></div>
<div class='card low'><div class='n'>$($sevCount.Low)</div><div class='l'>Bajo</div></div>
<div class='card info'><div class='n'>$($sevCount.Info)</div><div class='l'>Info</div></div>
</div>
"@

$html = @"
<!DOCTYPE html>
<html lang='es'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>Diagnóstico Kerberos Azure Files - $(Encode-Html $script:SaFqdn)</title>
<style>$css</style>
</head>
<body>
<a id='top'></a>
<header>
  <h1>Diagnóstico Kerberos &mdash; Azure Files</h1>
  <div class='sub'>$(Encode-Html $script:SaFqdn) &mdash; generado $(Get-Date -Format 'yyyy-MM-dd HH:mm') &mdash; síntoma: 0x80090303 / 0x6fb</div>
</header>
<div class='container'>
  <nav>
    <h3>Contenido</h3>
    <ul>
      <li><a href='#summary'>Resumen ejecutivo</a></li>
      <li><a href='#runinfo'>Información de ejecución</a></li>
      $($tocItems -join "`n")
      $(if ($errorHtml) { "<li><a href='#errors'>Errores de recolección</a></li>" })
    </ul>
  </nav>
  <main>
    <section id='summary'>
      <h2>Resumen ejecutivo <a class='top' href='#top'>&uarr; arriba</a></h2>
      <p class='desc'>Hallazgos detectados durante el diagnóstico, ordenados por severidad. El análisis de causa raíz priorizado está en la sección 12.</p>
      $cards
      $findingsHtml
    </section>
    <section id='runinfo'>
      <h2>Información de ejecución <a class='top' href='#top'>&uarr; arriba</a></h2>
      $(Convert-ToKvTable $runContext)
    </section>
    $($sectionHtml -join "`n")
    $errorHtml
  </main>
</div>
<footer>Generado por Invoke-AzureFilesKerberosDiagnostics.ps1 &mdash; diagnóstico de solo lectura. Trate este informe como confidencial.</footer>
<script>
document.addEventListener('DOMContentLoaded', function () {
  document.querySelectorAll('.tsearch').forEach(function (box) {
    box.addEventListener('input', function () {
      var table = document.getElementById(box.getAttribute('data-target'));
      if (!table) { return; }
      var term = box.value.toLowerCase();
      table.querySelectorAll('tbody tr').forEach(function (tr) {
        tr.style.display = tr.textContent.toLowerCase().indexOf(term) > -1 ? '' : 'none';
      });
    });
  });
  document.querySelectorAll('table.sortable thead th').forEach(function (th, idx) {
    th.addEventListener('click', function () {
      var table = th.closest('table');
      var tbody = table.querySelector('tbody');
      var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
      var asc = !th.classList.contains('asc');
      table.querySelectorAll('thead th').forEach(function (h) { h.classList.remove('asc', 'desc'); });
      th.classList.add(asc ? 'asc' : 'desc');
      rows.sort(function (a, b) {
        var x = a.children[idx] ? a.children[idx].textContent.trim() : '';
        var y = b.children[idx] ? b.children[idx].textContent.trim() : '';
        var nx = parseFloat(x.replace(/[^0-9.\-]/g, ''));
        var ny = parseFloat(y.replace(/[^0-9.\-]/g, ''));
        var bothNum = !isNaN(nx) && !isNaN(ny) && x !== '' && y !== '';
        var cmp = bothNum ? (nx - ny) : x.localeCompare(y, undefined, { numeric: true });
        return asc ? cmp : -cmp;
      });
      rows.forEach(function (r) { tbody.appendChild(r); });
    });
  });
});
</script>
</body>
</html>
"@

$html | Out-File -FilePath $reportFile -Encoding UTF8

Write-Host ""
Write-Host "[+] Diagnóstico completado." -ForegroundColor Green
Write-Host "[+] Informe HTML : $reportFile" -ForegroundColor Green
if ($ExportCsv) { Write-Host "[+] CSV          : $csvFolder" -ForegroundColor Green }
Write-Host "[+] Hallazgos    : Crítico=$($sevCount.Critical) Alto=$($sevCount.High) Medio=$($sevCount.Medium) Bajo=$($sevCount.Low) Info=$($sevCount.Info)" -ForegroundColor Yellow
if ($rankedCauses.Count) { Write-Host "[+] Causa más probable: $($rankedCauses[0].Title) ($($rankedCauses[0].Confidence)%)" -ForegroundColor Magenta }

#endregion
