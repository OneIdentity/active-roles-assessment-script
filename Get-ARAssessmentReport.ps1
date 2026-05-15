<#
Copyright header
Copyright 2026 One Identity LLC
Licensed under the One Identity Permissive Software License.
See LICENSE.txt for full terms.

Copyright notice
This software is authored and distributed by One Identity LLC. This software
is provided as an open source utility for informational and operational
purposes only. One Identity LLC does not provide support, updates, or
guarantees of any kind for this software.
Use of this software is subject to the terms of the One Identity Permissive
Software License set forth in the LICENSE.txt file accompanying this software.
#>

<#
.SYNOPSIS
    Active Roles Environment Assessment - collects environment data and generates an HTML report.

.DESCRIPTION
    Connects to the local Active Roles service, collects data across multiple categories
    (version, OS, domains, servers, dynamic groups, managed units, workflows, virtual
    attributes, script policies, policy objects, and access templates), and generates a
    self-contained interactive HTML report.

    Designed to run directly on the Active Roles server. The HTML report uses Chart.js
    (loaded from CDN) for data visualization. An internet connection is required to render
    charts; the rest of the report renders without connectivity.

    Broken rules checks for Dynamic Groups and Managed Units validate that every GUID
    referenced in membership rules still resolves to an existing AD object — adapted from
    the reference scripts Find_Broken_Dynamic_Group_Membership_Rules and
    ManagedUnitsWithBrokenRules.

.PARAMETER ARServer
    Active Roles server name or IP address. Defaults to local auto-connect.

.PARAMETER OutputPath
    Full path for the output HTML report file.
    Defaults to .\AR_Assessment_<yyyyMMdd_HHmmss>.html in the current directory.

.PARAMETER SkipBrokenRulesCheck
    Skip the broken membership rules validation for Dynamic Groups and Managed Units.
    Use this switch to speed up the script in environments with many dynamic objects.

.PARAMETER SkipUserCounts
    Skip the managed user count per domain. Use this switch to speed up report generation
    in environments with a large number of users.

.PARAMETER SqlCredential
    PSCredential for SQL Server Authentication when connecting to the Active Roles
    Configuration database (Auto Shrink check). If not provided, the script uses
    Windows Authentication (Integrated Security). Use this parameter when the AR
    database is configured with SQL Server Authentication.

.EXAMPLE
    .\Get-ARAssessmentReport.ps1
    Connects locally, collects all data, and writes the HTML report to the current directory.

.EXAMPLE
    .\Get-ARAssessmentReport.ps1 -ARServer "arsserver.domain.com" -OutputPath "C:\Reports\AR_Assessment.html"
    Connects to the specified server and saves the report to the given path.

.EXAMPLE
    .\Get-ARAssessmentReport.ps1 -SkipBrokenRulesCheck
    Runs the full assessment but skips the (potentially slow) broken rules validation.

.EXAMPLE
    .\Get-ARAssessmentReport.ps1 -SkipUserCounts
    Runs the full assessment but skips counting users per domain.

.EXAMPLE
    .\Get-ARAssessmentReport.ps1 -SqlCredential (Get-Credential)
    Prompts for SQL Server credentials and uses them for the Auto Shrink database check.

.NOTES
    Requires  : Active Roles Management Shell
    Run on    : Active Roles Server (for registry-based version detection)
    Version   : 1.0
    Author    : One Identity IDAM3 Team

    Auto Shrink Check:
        Checks if Auto Shrink is enabled on the Active Roles Configuration database.
        Uses the Publisher replication partner to determine the correct SQL Server,
        then connects via ADO.NET to query sys.databases.
        The ReplicationPartners parameter expects the result object from
        Get-ReplicationPartnersInfo containing the List of replication partners
        with RoleRaw, SQLAlias, and DatabaseName.
        Requires PowerShell running as Administrator with the AR service account
        (or an account with read access to sys.databases on the SQL Server).
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Active Roles server name or IP. Defaults to local auto-connect.")]
    [string]$ARServer,

    [Parameter(HelpMessage = "Output path for the HTML report.")]
    [string]$OutputPath = ".\AR_Assessment_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",

    [Parameter(HelpMessage = "Skip broken rules check for Dynamic Groups and Managed Units.")]
    [switch]$SkipBrokenRulesCheck,

    [Parameter(HelpMessage = "Skip managed user count per domain to speed up report generation.")]
    [switch]$SkipUserCounts,

    [Parameter(HelpMessage = "SQL Server credential for the Auto Shrink check. If omitted, Windows Authentication is used.")]
    [System.Management.Automation.PSCredential]$SqlCredential
)

#region Initialization

$ErrorActionPreference = 'Stop'
$script:LogFile = ".\logs\Get-ARAssessmentReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    $logDir = Split-Path $script:LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Add-Content -Path $script:LogFile -Value $entry -Encoding UTF8
    switch ($Level) {
        "ERROR" { Write-Host $entry -ForegroundColor Red }
        "WARN"  { Write-Host $entry -ForegroundColor Yellow }
        "DEBUG" { Write-Verbose $entry }
        default { Write-Host $entry }
    }
}

# Load Active Roles Management Shell
try {
    if (-not (Get-Module -Name ActiveRolesManagementShell -ErrorAction SilentlyContinue)) {
        Import-Module ActiveRolesManagementShell -DisableNameChecking -ErrorAction Stop
    }
    Write-Log "Active Roles Management Shell module loaded"
}
catch {
    Write-Log "Failed to load Active Roles Management Shell: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Connect to Active Roles service
try {
    $connectParams = @{ ErrorAction = 'Stop' }
    if ($ARServer) { $connectParams['Service'] = $ARServer }

    $arsConnection = Connect-QADService @connectParams
    Write-Log "Connected to Active Roles: $($arsConnection.ConnectedServer)"
}
catch {
    Write-Log "Failed to connect to Active Roles Service: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

#endregion

#region Helper Functions

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N1} GB" -f ($Bytes / 1GB) }
    elseif ($Bytes -ge 1MB) { return "{0:N1} MB" -f ($Bytes / 1MB) }
    else { return "{0:N0} KB" -f ($Bytes / 1KB) }
}

function Format-Count {
    param([int]$Value)
    if ($Value -lt 0) { return "N/A" }
    return $Value.ToString()
}

function ConvertTo-SafeHtml {
    param([string]$Text)
    if (-not $Text) { return "" }
    $Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&#39;'
}

function New-ArSqlConnection {
    <#
    .SYNOPSIS
        Opens a SqlConnection to an AR SQL alias, safely.
    .DESCRIPTION
        Builds the connection string via SqlConnectionStringBuilder (safe escaping),
        forces channel encryption, and uses SqlCredential (SecureString-backed) for
        SQL authentication instead of embedding the password in the connection string.
        Falls back to Integrated Security when no credential is provided.
    #>
    param(
        [Parameter(Mandatory)][string]$SqlServer,
        [string]$Database = 'master',
        [int]$ConnectionTimeout = 15,
        [System.Management.Automation.PSCredential]$SqlCredential
    )

    $builder = [System.Data.SqlClient.SqlConnectionStringBuilder]::new()
    $builder['Data Source']         = $SqlServer
    $builder['Initial Catalog']     = $Database
    $builder['Connect Timeout']     = $ConnectionTimeout
    $builder['Encrypt']             = $true
    $builder['TrustServerCertificate'] = $true
    $builder['Application Name']    = 'Get-ARAssessmentReport'

    if ($SqlCredential) {
        $builder['Integrated Security'] = $false
        $secure = $SqlCredential.Password.Copy()
        $secure.MakeReadOnly()
        $sqlCred = [System.Data.SqlClient.SqlCredential]::new($SqlCredential.UserName, $secure)
        $conn = [System.Data.SqlClient.SqlConnection]::new($builder.ConnectionString, $sqlCred)
    }
    else {
        $builder['Integrated Security'] = $true
        $conn = [System.Data.SqlClient.SqlConnection]::new($builder.ConnectionString)
    }

    $conn.Open()
    return $conn
}

function Test-GUIDExists {
    param([string]$Guid)
    try {
        $obj = Get-QADObject -Identity $Guid -DontUseDefaultIncludedProperties -proxy -ErrorAction Stop
        return ($null -ne $obj)
    }
    catch {
        return $false
    }
}

function Get-BrokenRulesList {
    <#
    .SYNOPSIS
        Validates GUID references inside membership condition strings.
        Adapted from Find_Broken_Dynamic_Group_Membership_Rules and ManagedUnitsWithBrokenRules.
    #>
    param(
        [Parameter(Mandatory)] $Objects,
        [string]$ConditionsAttribute,
        [string]$ObjectTypeName
    )

    $guidRegex = "^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$"
    $brokenList = @()
    $total = @($Objects).Count
    $count = 0

    foreach ($obj in $Objects) {
        $count++
        Write-Progress -Activity "Checking $ObjectTypeName broken rules" `
            -Status "$count of $total : $($obj.Name)" `
            -PercentComplete ([math]::Min(100, ($count / [math]::Max(1, $total)) * 100))

        try {
            $conditions = $obj.$ConditionsAttribute
            if (-not $conditions) { continue }

            $rules = $conditions.Split(';')
            $hasBroken = $false

            foreach ($rule in $rules) {
                $rule = $rule.Trim()
                if ($rule -match $guidRegex) {
                    if (-not (Test-GUIDExists $rule)) {
                        $hasBroken = $true
                        break
                    }
                }
            }

            if ($hasBroken) {
                $brokenList += [PSCustomObject]@{
                    Name = $obj.Name
                    DN   = $obj.DN
                }
            }
        }
        catch {
            Write-Log "Error checking broken rules for '$($obj.Name)': $($_.Exception.Message)" -Level "WARN"
        }
    }

    Write-Progress -Activity "Checking $ObjectTypeName broken rules" -Completed
    return $brokenList
}

#endregion

#region Data Collection Functions

function Get-ARVersionInfo {
    $info = [PSCustomObject]@{
        ServiceVersion   = "Unknown"
        ConnectedServer  = "Unknown"
        InstalledVersion = "Unknown"
        InstalledProduct = "One Identity Active Roles"
        InstallDate      = "N/A"
        Error            = $null
    }

    # Primary: query AR Server objects (edsARService) for version info
    try {
        $serverObjects = Get-QADObject `
            -SearchRoot 'CN=Administration Services,CN=Server Configuration,CN=Configuration' `
            -Proxy -Type edsARService `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'edsaEdmServiceComputerName', 'edsaStoredProductVersion' `
            -SizeLimit 100 -ErrorAction Stop

        if ($serverObjects) {
            $arServers = @($serverObjects)
            Write-Log "Discovered $($arServers.Count) AR service(s) via Server Configuration"
            $info | Add-Member -NotePropertyName 'DiscoveredServers' -NotePropertyValue $arServers.Count -Force

            # Prefer the server running this script. Normalize both sides:
            # AD typically returns FQDN in edsaEdmServiceComputerName, while
            # $env:COMPUTERNAME is the short name — compare short + FQDN, case-insensitive.
            $localShort = (($env:COMPUTERNAME) -split '\.', 2)[0].ToLowerInvariant()
            $localFqdn  = try {
                ([System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName).ToLowerInvariant()
            } catch { $null }

            $localServer = $arServers | Where-Object {
                $svc = if ($_.edsaEdmServiceComputerName) { ([string]$_.edsaEdmServiceComputerName).ToLowerInvariant() } else { '' }
                $obj = if ($_.Name) { ([string]$_.Name).ToLowerInvariant() } else { '' }
                $svcShort = ($svc -split '\.', 2)[0]
                $objShort = ($obj -split '\.', 2)[0]

                $svcShort -eq $localShort -or
                $objShort -eq $localShort -or
                ($localFqdn -and ($svc -eq $localFqdn -or $obj -eq $localFqdn))
            } | Select-Object -First 1

            if ($localServer) {
                Write-Log "Matched local server '$env:COMPUTERNAME' to AR service: $($localServer.edsaEdmServiceComputerName)"
            } else {
                $discovered = ($arServers | ForEach-Object {
                    if ($_.edsaEdmServiceComputerName) { $_.edsaEdmServiceComputerName } else { $_.Name }
                }) -join ', '
                Write-Log "Local server '$env:COMPUTERNAME' not found among discovered AR services ($discovered); falling back to first entry" -Level "WARN"
            }
            $sourceServer = if ($localServer) { $localServer } else { $arServers | Select-Object -First 1 }

            if ($sourceServer.edsaStoredProductVersion) {
                $info.ServiceVersion = $sourceServer.edsaStoredProductVersion
            }
            $info.ConnectedServer = if ($sourceServer.edsaEdmServiceComputerName) {
                $sourceServer.edsaEdmServiceComputerName
            } else { $sourceServer.Name }

            Write-Log "AR Service Version (Server Object): $($info.ServiceVersion) on $($info.ConnectedServer)"
        }
        else {
            Write-Log "No AR services found under CN=Administration Services,CN=Server Configuration,CN=Configuration" -Level "WARN"
        }
    }
    catch {
        Write-Log "Could not retrieve AR version from Server Objects: $($_.Exception.Message)" -Level "WARN"
        $info.Error = $_.Exception.Message
    }

    # Supplementary: Windows registry (accurate installed version + service pack)
    try {
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        foreach ($regPath in $uninstallPaths) {
            if (-not (Test-Path $regPath)) { continue }
            $arEntry = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*Active Roles*" } |
                Sort-Object -Property DisplayVersion -Descending |
                Select-Object -First 1

            if ($arEntry) {
                $info.InstalledVersion = if ($arEntry.DisplayVersion) { $arEntry.DisplayVersion } else { "N/A" }
                $info.InstalledProduct = if ($arEntry.DisplayName)    { $arEntry.DisplayName }    else { "One Identity Active Roles" }
                $info.InstallDate = if ($arEntry.InstallDate) {
                    try { [datetime]::ParseExact($arEntry.InstallDate, "yyyyMMdd", $null).ToString("yyyy-MM-dd") }
                    catch { $arEntry.InstallDate }
                } else { "N/A" }
                Write-Log "AR Installed Version (registry): $($info.InstalledVersion)"
                break
            }
        }

        # Fallback: One Identity / Quest registry key
        if ($info.InstalledVersion -eq "Unknown") {
            $oidPaths = @(
                "HKLM:\SOFTWARE\One Identity\Active Roles",
                "HKLM:\SOFTWARE\Quest Software\Active Roles Server"
            )
            foreach ($p in $oidPaths) {
                if (Test-Path $p) {
                    $regData = Get-ItemProperty $p -ErrorAction SilentlyContinue
                    if ($regData) {
                        $ver = if ($regData.Version) { $regData.Version } else { $regData.DisplayVersion }
                        if ($ver) { $info.InstalledVersion = $ver }
                        break
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Could not retrieve AR version from registry: $($_.Exception.Message)" -Level "WARN"
    }

    return $info
}

function Get-OSInfo {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        return [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            OSCaption    = $os.Caption
            OSVersion    = $os.Version
            BuildNumber  = $os.BuildNumber
            Architecture = $os.OSArchitecture
            TotalMemory  = Format-Bytes ($os.TotalVisibleMemorySize * 1KB)
            FreeMemory   = Format-Bytes ($os.FreePhysicalMemory * 1KB)
            LastBootTime = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
            Domain       = $env:USERDNSDOMAIN
            Error        = $null
        }
    }
    catch {
        Write-Log "Could not collect OS info: $($_.Exception.Message)" -Level "WARN"
        return [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            OSCaption    = "Unknown"
            OSVersion    = "N/A"
            BuildNumber  = "N/A"
            Architecture = "N/A"
            TotalMemory  = "N/A"
            FreeMemory   = "N/A"
            LastBootTime = "N/A"
            Domain       = $env:USERDNSDOMAIN
            Error        = $_.Exception.Message
        }
    }
}

function Get-ManagedDomains {
    $result = @()

    # Build a lookup of DC per domain from domainDNS objects
    $dcLookup = @{}
    try {
        $dnsDomains = Get-QADObject -Type 'domainDNS' `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'edsaLDAPServer', 'edsaDnsName' `
            -proxy -SizeLimit 0 -ErrorAction SilentlyContinue

        foreach ($dd in @($dnsDomains)) {
            $key = if ($dd.edsaDnsName) { $dd.edsaDnsName } else { $dd.Name }
            $dcLookup[$key] = if ($dd.edsaLDAPServer) { $dd.edsaLDAPServer } else { '' }
        }
        Write-Log "DC lookup built: $($dcLookup.Count) domain(s) resolved"
    }
    catch {
        Write-Log "Could not build DC lookup from domainDNS: $($_.Exception.Message)" -Level "WARN"
    }

    # Get managed domains from configuration
    try {
        $domains = Get-QADObject -Type 'edsDomainCacheConfig' `
            -SearchRoot 'CN=Managed Domains,CN=Server Configuration,CN=Configuration' `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'edsaDnsName' `
            -proxy -SizeLimit 0 -ErrorAction Stop

        foreach ($d in $domains) {
            $dnsName = if ($d.edsaDnsName) { $d.edsaDnsName } else { $d.Name }
            $dc = if ($dcLookup.ContainsKey($dnsName)) { $dcLookup[$dnsName] }
                  elseif ($dcLookup.ContainsKey($d.Name)) { $dcLookup[$d.Name] }
                  else { '' }

            # Resolve DC site from edsDomainCacheConfig using IncludeAllProperties + SearchScope Base
            $dcSite = ''
            try {
                $domainObj = Get-QADObject -SearchRoot $d.DN `
                    -Proxy -DontUseDefaultIncludedProperties -IncludedProperties 'edsvaPreferredSite' `
                    -SizeLimit 1 -SearchScope Base -ErrorAction SilentlyContinue
                if ($domainObj -and $domainObj.edsvaPreferredSite) {
                    $dcSite = $domainObj.edsvaPreferredSite
                }
            } catch { }

            $result += [PSCustomObject]@{
                Name          = ConvertTo-SafeHtml $d.Name
                DN            = ConvertTo-SafeHtml $d.DN
                LDAPServer    = $dc
                DnsName       = $dnsName
                DCSiteName    = $dcSite
            }
        }

        Write-Log "Found $($result.Count) managed domain(s)"
    }
    catch {
        Write-Log "Domain query failed: $($_.Exception.Message)" -Level "WARN"
    }

    if ($result.Count -eq 0) {
        Write-Log "Could not retrieve managed domains (0 results or query failed)" -Level "WARN"
    }
    return $result
}

function Invoke-EDMSSearch {
    # Runs an LDAP query through the Active Roles EDMS:// ADSI provider.
    # Returns a SearchResultCollection — caller must call .Dispose() when done.
    param(
        [Parameter(Mandatory)][string]$SearchRoot,
        [string]$LDAPFilter  = "(objectClass=*)",
        [string[]]$Properties = @("distinguishedName"),
        [System.DirectoryServices.SearchScope]$Scope = [System.DirectoryServices.SearchScope]::Subtree,
        [int]$PageSize        = 1000
    )
    $base     = [ADSI]"EDMS://$SearchRoot"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot  = $base
    $searcher.Filter      = $LDAPFilter
    $searcher.PageSize    = $PageSize
    $searcher.SearchScope = $Scope
    $searcher.PropertiesToLoad.Clear()
    foreach ($p in $Properties) { [void]$searcher.PropertiesToLoad.Add($p) }
    return ,$searcher.FindAll()   # comma prevents PowerShell from unrolling the SearchResultCollection
}

function Get-ManagedUserCounts {
    <#
    .SYNOPSIS
        Counts users per managed domain, excluding OUs and Managed Units
        where the "Built-in Policy - Exclude from Managed Scope" policy is linked.
    #>
    param([array]$Domains)

    $result = [PSCustomObject]@{
        TotalCount        = 0
        HybridTotal       = 0
        GmsaTotal         = 0
        ExcludedTotal     = 0
        PerDomain         = @()
        ExcludedOUs       = @()
        ExcludedMUs       = @()
    }

    # Step 1: Find the Policy Object "Built-in Policy - Exclude from Managed Scope"
    $excludedOUs = @()
    $excludedMUs = @()
    $excludedUserDNs = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    try {
        $policyObj = Get-QADObject -LdapFilter "(name=Built-in Policy - Exclude from Managed Scope)" `
            -SearchRoot 'CN=Administration,CN=Policies,CN=Configuration' `
            -DontUseDefaultIncludedProperties -IncludedProperties 'distinguishedName' `
            -proxy -SizeLimit 1 -ErrorAction Stop

        if ($policyObj) {
            $policyDN = $policyObj.DN
            Write-Log "Found 'Exclude from Managed Scope' policy: $policyDN"

            # Step 2: Find all Policy Object Links that reference this policy
            $links = Get-QADObject -Type 'edsPolicyObjectLink' `
                -SearchRoot 'CN=AP Links,CN=Configuration' `
                -proxy -IncludeAllProperties -SizeLimit 0 -ErrorAction Stop

            foreach ($link in @($links)) {
                $apoDN    = $null
                $targetDN = $null
                try { $apoDN    = $link.edsvaAPODN } catch { }
                try { $targetDN = $link.edsvaSecObjectDN } catch { }

                if ($apoDN -eq $policyDN -and $targetDN) {
                    # Managed Units live under CN=Managed Units,CN=Configuration
                    if ($targetDN -match 'CN=Managed Units,CN=Configuration') {
                        $excludedMUs += $targetDN
                    } else {
                        $excludedOUs += $targetDN
                    }
                }
            }

            Write-Log "Found $($excludedOUs.Count) OU(s) and $($excludedMUs.Count) MU(s) excluded from managed scope"

            # Step 3: Resolve effective user members of each excluded MU via EDMS
            foreach ($muDN in $excludedMUs) {
                try {
                    $muResults = Invoke-EDMSSearch -SearchRoot $muDN `
                        -LDAPFilter "(&(objectClass=user)(objectCategory=person))" `
                        -Properties @("distinguishedName")

                    $muCount = 0
                    foreach ($m in $muResults) {
                        $dn = $m.Properties["distinguishedname"][0]
                        if ($dn) { [void]$excludedUserDNs.Add($dn); $muCount++ }
                    }
                    if ($muResults) { $muResults.Dispose() }

                    Write-Log "Managed Unit '$muDN' contributed $muCount user(s) to exclusion set"
                }
                catch {
                    Write-Log "Could not enumerate members of Managed Unit '$muDN': $($_.Exception.Message)" -Level "WARN"
                }
            }
        }
        else {
            Write-Log "Policy 'Built-in Policy - Exclude from Managed Scope' not found" -Level "WARN"
        }
    }
    catch {
        Write-Log "Could not resolve excluded OUs/MUs: $($_.Exception.Message)" -Level "WARN"
    }

    $result.ExcludedOUs = $excludedOUs
    $result.ExcludedMUs = $excludedMUs

    # Step 3: Count users per domain, excluding users under the excluded OUs/MUs
    foreach ($domain in $Domains) {
        $domainName    = if ($domain.DnsName) { $domain.DnsName } else { $domain.Name }
        $domainDN      = "DC=$($domainName -replace '\.',',DC=')"
        $userCount     = 0
        $hybridCount   = 0
        $gmsaCount     = 0
        $excludedCount = 0

        # On-prem user count via EDMS
        try {
            $userResults = Invoke-EDMSSearch -SearchRoot $domainDN `
                -LDAPFilter "(&(objectClass=user)(objectCategory=person))" `
                -Properties @("distinguishedName")

            foreach ($u in $userResults) {
                $uDN = $u.Properties["distinguishedname"][0]
                $isExcluded = $false
                if ($excludedUserDNs.Contains($uDN)) {
                    $isExcluded = $true
                } else {
                    foreach ($ou in $excludedOUs) {
                        if ($uDN -like "*,$ou") { $isExcluded = $true; break }
                    }
                }
                if ($isExcluded) { $excludedCount++ } else { $userCount++ }
            }
            if ($userResults) { $userResults.Dispose() }

            Write-Log "Domain '$domainName': $userCount managed user(s), $excludedCount excluded"
        }
        catch {
            Write-Log "Could not count users for domain '$domainName': $($_.Exception.Message)" -Level "WARN"
            $userCount = -1
        }

        # Hybrid accounts (edsvaAzureObjectId populated), excluding managed scope via EDMS
        try {
            $hybridResults = Invoke-EDMSSearch -SearchRoot $domainDN `
                -LDAPFilter "(&(objectClass=user)(objectCategory=person)(edsvaAzureObjectId=*))" `
                -Properties @("distinguishedName")

            foreach ($h in $hybridResults) {
                $hDN = $h.Properties["distinguishedname"][0]
                $hexcluded = $false
                if ($excludedUserDNs.Contains($hDN)) {
                    $hexcluded = $true
                } else {
                    foreach ($ou in $excludedOUs) {
                        if ($hDN -like "*,$ou") { $hexcluded = $true; break }
                    }
                }
                if (-not $hexcluded) { $hybridCount++ }
            }
            if ($hybridResults) { $hybridResults.Dispose() }

            Write-Log "Domain '$domainName': $hybridCount hybrid account(s)"
        }
        catch {
            Write-Log "Could not count hybrid users for domain '$domainName': $($_.Exception.Message)" -Level "WARN"
        }

        # Group Managed Service Accounts (gMSA), excluding managed scope via EDMS
        try {
            $gmsaResults = Invoke-EDMSSearch -SearchRoot $domainDN `
                -LDAPFilter "(objectClass=msDS-GroupManagedServiceAccount)" `
                -Properties @("distinguishedName")

            foreach ($g in $gmsaResults) {
                $gDN = $g.Properties["distinguishedname"][0]
                $gexcluded = $false
                if ($excludedUserDNs.Contains($gDN)) {
                    $gexcluded = $true
                } else {
                    foreach ($ou in $excludedOUs) {
                        if ($gDN -like "*,$ou") { $gexcluded = $true; break }
                    }
                }
                if (-not $gexcluded) { $gmsaCount++ }
            }
            if ($gmsaResults) { $gmsaResults.Dispose() }

            Write-Log "Domain '$domainName': $gmsaCount gMSA(s)"
        }
        catch {
            Write-Log "Could not count gMSAs for domain '$domainName': $($_.Exception.Message)" -Level "WARN"
        }

        $result.PerDomain += [PSCustomObject]@{
            name     = ConvertTo-SafeHtml $domain.Name
            dns      = $domainName
            count    = $userCount
            hybrid   = $hybridCount
            onprem   = if ($userCount -ge 0) { [math]::Max(0, $userCount - $hybridCount) } else { -1 }
            gmsa     = $gmsaCount
            excluded = $excludedCount
        }
    }

    $result.TotalCount    = ($result.PerDomain | Where-Object { $_.count -ge 0 } |
        Measure-Object -Property count -Sum).Sum
    $result.HybridTotal  = ($result.PerDomain | Measure-Object -Property hybrid -Sum).Sum
    $result.GmsaTotal    = ($result.PerDomain | Measure-Object -Property gmsa -Sum).Sum
    $result.ExcludedTotal = ($result.PerDomain | Measure-Object -Property excluded -Sum).Sum

    Write-Log "Total managed users across all domains: $($result.TotalCount)"
    Write-Log "Total hybrid accounts: $($result.HybridTotal)"
    Write-Log "Total gMSA accounts: $($result.GmsaTotal)"
    Write-Log "Total users in excluded OUs/MUs: $($result.ExcludedTotal)"
    return $result
}

function Get-DomainLatency {
    param([array]$Domains)

    $results = @()

    foreach ($d in $Domains) {
        $target = if ($d.LDAPServer) { $d.LDAPServer } elseif ($d.DnsName) { $d.DnsName } else { $d.Name }
        $domainName = if ($d.DnsName) { $d.DnsName } else { $d.Name }

        $record = [PSCustomObject]@{
            domain     = ConvertTo-SafeHtml $domainName
            dc         = ConvertTo-SafeHtml $target
            avgMs      = -1
            minMs      = -1
            maxMs      = -1
            status     = 'Error'
            detail     = ''
        }

        try {
            Write-Log "Testing latency to $domainName ($target)..."
            $ping = Test-Connection -ComputerName $target -Count 4 -ErrorAction Stop

            $times = @($ping | ForEach-Object {
                if ($null -ne $_.ResponseTime) { $_.ResponseTime }
                elseif ($null -ne $_.Latency) { $_.Latency }
            })

            if ($times.Count -gt 0) {
                $avg = [math]::Round(($times | Measure-Object -Average).Average, 1)
                $min = ($times | Measure-Object -Minimum).Minimum
                $max = ($times | Measure-Object -Maximum).Maximum

                $record.avgMs  = $avg
                $record.minMs  = $min
                $record.maxMs  = $max
                $record.status = if ($avg -le 50) { 'Good' } elseif ($avg -le 150) { 'Fair' } else { 'Poor' }
                $record.detail = "$($times.Count) replies"

                Write-Log "Latency to $domainName : avg=$($avg)ms min=$($min)ms max=$($max)ms"
            }
            else {
                $record.detail = 'No response time data'
                Write-Log "Latency to $domainName : no response time data" -Level "WARN"
            }
        }
        catch {
            $record.detail = $_.Exception.Message
            Write-Log "Latency test failed for $domainName : $($_.Exception.Message)" -Level "WARN"
        }

        $results += $record
    }

    return $results
}

function Get-ARServers {
    $servers = @()

    # Primary: query AR service objects with detailed properties
    try {
        $serverObjects = Get-QADObject `
            -SearchRoot 'CN=Administration Services,CN=Server Configuration,CN=Configuration' `
            -Proxy -Type edsARService `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'edsaEdmServiceComputerName', 'edsvaConfigurationDatabase', `
                'edsaStoredProductVersion', 'edsvaMHDatabase', 'edsvaDiagnosticLoggingLevel', `
                'edsvaDiagnosticLogTurnedOn', 'edsaReplicationPartner' `
            -SizeLimit 100 -ErrorAction Stop

        foreach ($s in @($serverObjects)) {
            $partner = if ($s.edsaReplicationPartner) {
                @($s.edsaReplicationPartner) -join ', '
            } else { "" }

            # Verbose Logging: TRUE = Enabled (active), FALSE = Disabled
            $verboseLoggingRaw = $null
            try { $verboseLoggingRaw = $s.edsvaDiagnosticLogTurnedOn } catch { }
            $verboseLoggingOn = ($verboseLoggingRaw -eq $true -or $verboseLoggingRaw -eq 'True')

            # Logging Level: 2 = Verbose, 1 = Basic
            $loggingLevelRaw = $null
            try { $loggingLevelRaw = $s.edsvaDiagnosticLoggingLevel } catch { }
            $loggingType = switch ([string]$loggingLevelRaw) {
                '2'     { 'Verbose' }
                '1'     { 'Basic' }
                default { if ($loggingLevelRaw) { "Level $loggingLevelRaw" } else { 'N/A' } }
            }

            $servers += [PSCustomObject]@{
                Name               = ConvertTo-SafeHtml $s.Name
                InstanceName       = ConvertTo-SafeHtml $(if ($s.edsaEdmServiceComputerName) { $s.edsaEdmServiceComputerName } else { $s.Name })
                Version            = ConvertTo-SafeHtml $(if ($s.edsaStoredProductVersion) { $s.edsaStoredProductVersion } else { 'N/A' })
                ConfigDB           = ConvertTo-SafeHtml $(if ($s.edsvaConfigurationDatabase) { $s.edsvaConfigurationDatabase } else { 'N/A' })
                MgmtHistoryDB      = ConvertTo-SafeHtml $(if ($s.edsvaMHDatabase) { $s.edsvaMHDatabase } else { 'N/A' })
                VerboseLoggingOn   = $verboseLoggingOn
                LoggingType        = $loggingType
                ReplicationPartner = ConvertTo-SafeHtml $partner
                DN                 = $s.DN
            }
        }

        if ($servers.Count -gt 0) {
            Write-Log "Found $($servers.Count) AR service instance(s) via Administration Services"
        }
    }
    catch {
        Write-Log "Primary server query failed: $($_.Exception.Message)" -Level "WARN"
    }

    # Fallback: legacy query if primary returned nothing
    if ($servers.Count -eq 0) {
        $fallbackQueries = @(
            @{ SearchRoot = 'CN=Server Configuration,CN=Configuration'; LdapFilter = '(objectClass=*)' },
            @{ SearchRoot = 'CN=Configuration';                          LdapFilter = '(objectClass=edsServiceConfiguration)' }
        )
        foreach ($q in $fallbackQueries) {
            try {
                $serverObjects = Get-QADObject -SearchRoot $q.SearchRoot `
                    -DontUseDefaultIncludedProperties `
                    -IncludedProperties 'name', 'edsaReplicationPartner', 'description', 'objectClass' `
                    -proxy -SizeLimit 100 -ErrorAction Stop |
                    Where-Object { $_.Type -match 'eds.*[Ss]erv' -or $_.Name -match '^[A-Z].*\.' }

                foreach ($s in $serverObjects) {
                    $partner = if ($s.edsaReplicationPartner) {
                        @($s.edsaReplicationPartner) -join ', '
                    } else { "" }

                    $servers += [PSCustomObject]@{
                        Name               = ConvertTo-SafeHtml $s.Name
                        InstanceName       = ConvertTo-SafeHtml $s.Name
                        Version            = 'N/A'
                        ConfigDB           = 'N/A'
                        MgmtHistoryDB      = 'N/A'
                        VerboseLoggingOn   = $false
                        LoggingType        = 'N/A'
                        ReplicationPartner = ConvertTo-SafeHtml $partner
                        DN                 = $s.DN
                    }
                }

                if ($servers.Count -gt 0) {
                    Write-Log "Found $($servers.Count) AR server object(s) via fallback query"
                    break
                }
            }
            catch {
                Write-Log "Fallback server query at '$($q.SearchRoot)' failed: $($_.Exception.Message)" -Level "WARN"
            }
        }
    }

    $isReplication = ($servers | Where-Object { $_.ReplicationPartner -ne "" }).Count -gt 0

    # Count verbose logging enabled servers for KPI
    $verboseCount = @($servers | Where-Object { $_.VerboseLoggingOn -eq $true }).Count

    return [PSCustomObject]@{
        Servers       = $servers
        IsReplication = $isReplication
        Mode          = if ($isReplication) { "Replication" } else { "Standalone" }
        VerboseLoggingCount = $verboseCount
    }
}

function Get-ReplicationPartnersInfo {
    $result = [PSCustomObject]@{
        List  = @()
        Count = 0
        Error = $null
    }

    try {
        Write-Log "Collecting Replication Partners..."
        $replObjects = Get-QADObject `
            -SearchRoot 'CN=Configuration Databases,CN=Server Configuration,CN=Configuration' `
            -Proxy -Type edsReplicationPartner `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'edsaDatabaseName', 'edsaSQLAlias', `
                'edsaDatabaseType', 'edsaReplicationRole' `
            -SizeLimit 100 -ErrorAction Stop

        foreach ($r in @($replObjects)) {
            # Replication Role: 1 = Publisher, 2 = Subscriber, 3 = Not configured
            $roleRaw = $null
            try { $roleRaw = $r.edsaReplicationRole } catch { }
            $roleLabel = switch ([string]$roleRaw) {
                '1'     { 'Publisher' }
                '2'     { 'Subscriber' }
                '3'     { 'Not Configured' }
                default { if ($roleRaw) { "Role $roleRaw" } else { 'N/A' } }
            }

            $result.List += [PSCustomObject]@{
                Name         = ConvertTo-SafeHtml $(if ($r.Name) { $r.Name } else { 'N/A' })
                DatabaseName = ConvertTo-SafeHtml $(if ($r.edsaDatabaseName) { $r.edsaDatabaseName } else { 'N/A' })
                DatabaseType = ConvertTo-SafeHtml $(if ($r.edsaDatabaseType) { $r.edsaDatabaseType } else { 'N/A' })
                SQLAlias     = ConvertTo-SafeHtml $(if ($r.edsaSQLAlias) { $r.edsaSQLAlias } else { 'N/A' })
                RoleRaw      = [string]$roleRaw
                RoleLabel    = $roleLabel
            }
        }

        $result.Count = $result.List.Count
        Write-Log "Found $($result.Count) Replication Partner(s)"
    }
    catch {
        Write-Log "Could not collect Replication Partners: $($_.Exception.Message)" -Level "WARN"
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-MHReplicationPartnersInfo {
    $result = [PSCustomObject]@{
        List  = @()
        Count = 0
        Error = $null
    }

    try {
        Write-Log "Collecting Management History Replication Partners..."
        $replObjects = Get-QADObject `
            -SearchRoot 'CN=Management History Databases,CN=Server Configuration,CN=Configuration' `
            -Proxy -Type edsMHReplicationPartner `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'edsaDatabaseName', 'edsaSQLAlias', `
                'edsaDatabaseType', 'edsaReplicationRole' `
            -SizeLimit 100 -ErrorAction Stop

        foreach ($r in @($replObjects)) {
            $roleRaw = $null
            try { $roleRaw = $r.edsaReplicationRole } catch { }
            $roleLabel = switch ([string]$roleRaw) {
                '1'     { 'Publisher' }
                '2'     { 'Subscriber' }
                '3'     { 'Not Configured' }
                default { if ($roleRaw) { "Role $roleRaw" } else { 'N/A' } }
            }

            $result.List += [PSCustomObject]@{
                Name         = ConvertTo-SafeHtml $(if ($r.Name) { $r.Name } else { 'N/A' })
                DatabaseName = ConvertTo-SafeHtml $(if ($r.edsaDatabaseName) { $r.edsaDatabaseName } else { 'N/A' })
                DatabaseType = ConvertTo-SafeHtml $(if ($r.edsaDatabaseType) { $r.edsaDatabaseType } else { 'N/A' })
                SQLAlias     = ConvertTo-SafeHtml $(if ($r.edsaSQLAlias) { $r.edsaSQLAlias } else { 'N/A' })
                RoleRaw      = [string]$roleRaw
                RoleLabel    = $roleLabel
            }
        }

        $result.Count = $result.List.Count
        Write-Log "Found $($result.Count) MH Replication Partner(s)"
    }
    catch {
        Write-Log "Could not collect MH Replication Partners: $($_.Exception.Message)" -Level "WARN"
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-DynamicGroupsInfo {
    $result = [PSCustomObject]@{
        TotalCount   = 0
        BrokenCount  = 0
        BrokenList   = @()
        Error        = $null
        SkippedCheck = $SkipBrokenRulesCheck.IsPresent
    }

    try {
        Write-Log "Collecting Dynamic Groups..."
        $dynGroups = Get-QADGroup -Dynamic $true `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'edsaDGConditionsList' `
            -proxy -SizeLimit 0 -ErrorAction Stop

        $result.TotalCount = @($dynGroups).Count
        Write-Log "Found $($result.TotalCount) Dynamic Group(s)"

        if (-not $SkipBrokenRulesCheck -and $result.TotalCount -gt 0) {
            Write-Log "Checking Dynamic Groups for broken rules (this may take a while)..."
            $result.BrokenList = @(Get-BrokenRulesList `
                -Objects $dynGroups `
                -ConditionsAttribute 'edsaDGConditionsList' `
                -ObjectTypeName 'Dynamic Groups')
            $result.BrokenCount = $result.BrokenList.Count
            Write-Log "Dynamic Groups with broken rules: $($result.BrokenCount)"
        }
    }
    catch {
        Write-Log "Could not collect Dynamic Groups: $($_.Exception.Message)" -Level "WARN"
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-ManagedUnitsInfo {
    $result = [PSCustomObject]@{
        TotalCount   = 0
        BrokenCount  = 0
        BrokenList   = @()
        Error        = $null
        SkippedCheck = $SkipBrokenRulesCheck.IsPresent
    }

    try {
        Write-Log "Collecting Managed Units..."
        $mus = Get-QADObject -Type 'edsManagedUnit' `
            -SearchRoot 'CN=Managed Units,CN=Configuration' `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'edsaMUConditionsList' `
            -proxy -SizeLimit 0 -ErrorAction Stop

        $result.TotalCount = @($mus).Count
        Write-Log "Found $($result.TotalCount) Managed Unit(s)"

        if (-not $SkipBrokenRulesCheck -and $result.TotalCount -gt 0) {
            Write-Log "Checking Managed Units for broken rules (this may take a while)..."
            $result.BrokenList = @(Get-BrokenRulesList `
                -Objects $mus `
                -ConditionsAttribute 'edsaMUConditionsList' `
                -ObjectTypeName 'Managed Units')
            $result.BrokenCount = $result.BrokenList.Count
            Write-Log "Managed Units with broken rules: $($result.BrokenCount)"
        }
    }
    catch {
        Write-Log "Could not collect Managed Units: $($_.Exception.Message)" -Level "WARN"
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-WorkflowsInfo {
    # Collects workflow details including enabled/disabled status.
    # Excludes builtin workflows from CN=Builtin,CN=Workflow,CN=Policies,CN=Configuration.
    # The attribute edsaWorkflowIsDisabled = True means the workflow is DISABLED.
    $builtinContainer = 'CN=Builtin,CN=Workflow,CN=Policies,CN=Configuration'
    $result = [PSCustomObject]@{
        TotalCount    = 0
        EnabledCount  = 0
        DisabledCount = 0
        List          = @()
    }

    try {
        $objs = Get-QADObject -SearchRoot 'CN=Workflow,CN=Policies,CN=Configuration' `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'edsaWorkflowIsDisabled', 'distinguishedName', 'description' `
            -proxy -SizeLimit 0 -ErrorAction Stop

        foreach ($obj in @($objs)) {
            # Exclude builtin workflows
            if ($obj.DN -and $obj.DN -like "*$builtinContainer*") { continue }

            $isDisabled = $false
            try {
                $disabledVal = $obj.edsaWorkflowIsDisabled
                if ($disabledVal -eq $true -or $disabledVal -eq 'True') {
                    $isDisabled = $true
                }
            } catch { }

            $result.List += [PSCustomObject]@{
                name        = ConvertTo-SafeHtml $obj.Name
                status      = if ($isDisabled) { 'Disabled' } else { 'Enabled' }
                description = ConvertTo-SafeHtml $(if ($obj.description) { $obj.description } else { '' })
                dn          = $obj.DN
            }
        }

        $result.TotalCount    = $result.List.Count
        $result.EnabledCount  = @($result.List | Where-Object { $_.status -eq 'Enabled' }).Count
        $result.DisabledCount = @($result.List | Where-Object { $_.status -eq 'Disabled' }).Count

        Write-Log "Found $($result.TotalCount) Workflow(s) (Enabled: $($result.EnabledCount), Disabled: $($result.DisabledCount)). Excluded builtin container."
    }
    catch {
        Write-Log "Could not collect Workflow info: $($_.Exception.Message)" -Level "WARN"
    }

    return $result
}

function Get-VirtualAttributesInfo {
    $result = [PSCustomObject]@{
        TotalCount   = 0
        BuiltInCount = 0
        CustomCount  = 0
        List         = @()
        Error        = $null
    }

    try {
        $attrs = Get-QADObject -SearchRoot 'CN=Virtual Attributes,CN=Server Configuration,CN=Configuration' `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'description', 'attributeSyntax', 'edsaSystemObject' `
            -proxy -SizeLimit 0 -ErrorAction Stop

        foreach ($a in $attrs) {
            $isSystem = $false
            try {
                $sysVal = $a.edsaSystemObject
                if ($sysVal -eq $true -or $sysVal -eq 'True') {
                    $isSystem = $true
                }
            } catch { }

            $result.List += [PSCustomObject]@{
                name        = ConvertTo-SafeHtml $a.Name
                type        = if ($isSystem) { 'Built-in' } else { 'Custom' }
                syntax      = ConvertTo-SafeHtml $(if ($a.attributeSyntax) { $a.attributeSyntax } else { "N/A" })
                description = ConvertTo-SafeHtml $(if ($a.description) { $a.description } else { "" })
            }
        }

        $result.TotalCount   = $result.List.Count
        $result.BuiltInCount = @($result.List | Where-Object { $_.type -eq 'Built-in' }).Count
        $result.CustomCount  = @($result.List | Where-Object { $_.type -eq 'Custom' }).Count

        Write-Log "Found $($result.TotalCount) Virtual Attribute(s) (Built-in: $($result.BuiltInCount), Custom: $($result.CustomCount))"
    }
    catch {
        Write-Log "Could not collect Virtual Attributes: $($_.Exception.Message)" -Level "WARN"
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-ScriptPoliciesCount {
    $builtinContainer = 'CN=Builtin,CN=Script Modules,CN=Configuration'
    try {
        $objs = Get-QADObject -SearchRoot 'CN=Script Modules,CN=Configuration' `
            -DontUseDefaultIncludedProperties -proxy -SizeLimit 0 -ErrorAction Stop
        $filtered = @($objs) | Where-Object { $_.DN -notlike "*$builtinContainer*" }
        $count = $filtered.Count
        Write-Log "Found $count Script Module(s) (excluded builtin container)"
        return $count
    }
    catch {
        Write-Log "Could not collect Script Policies count: $($_.Exception.Message)" -Level "WARN"
        return -1
    }
}

function Get-PolicyObjectsInfo {
    # Collects policy object details including enabled/disabled status.
    # Excludes built-in policies by name prefix and builtin container.
    # The attribute edsaPolicyDisabled = True means the policy is DISABLED.
    $builtinContainer = 'CN=Builtin,CN=Administration,CN=Policies,CN=Configuration'
    $result = [PSCustomObject]@{
        TotalCount    = 0
        EnabledCount  = 0
        DisabledCount = 0
        List          = @()
    }

    try {
        $objs = Get-QADObject -Type 'edsPolicyObject' `
            -SearchRoot 'CN=Administration,CN=Policies,CN=Configuration' `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'edsaPolicyDisabled', 'distinguishedName', 'description' `
            -proxy -SizeLimit 0 -ErrorAction Stop

        foreach ($obj in @($objs)) {
            # Exclude built-in policies by name prefix and builtin container
            if ($obj.Name -like 'Built-in Policy -*') { continue }
            if ($obj.DN -and $obj.DN -like "*$builtinContainer*") { continue }

            $isDisabled = $false
            try {
                $disabledVal = $obj.edsaPolicyDisabled
                if ($disabledVal -eq $true -or $disabledVal -eq 'True') {
                    $isDisabled = $true
                }
            } catch { }

            $result.List += [PSCustomObject]@{
                name        = ConvertTo-SafeHtml $obj.Name
                status      = if ($isDisabled) { 'Disabled' } else { 'Enabled' }
                description = ConvertTo-SafeHtml $(if ($obj.description) { $obj.description } else { '' })
                dn          = $obj.DN
            }
        }

        $result.TotalCount    = $result.List.Count
        $result.EnabledCount  = @($result.List | Where-Object { $_.status -eq 'Enabled' }).Count
        $result.DisabledCount = @($result.List | Where-Object { $_.status -eq 'Disabled' }).Count

        Write-Log "Found $($result.TotalCount) Policy Object(s) (Enabled: $($result.EnabledCount), Disabled: $($result.DisabledCount)). Excluded built-in."
    }
    catch {
        Write-Log "Could not collect Policy Objects info: $($_.Exception.Message)" -Level "WARN"
    }

    return $result
}

function Get-OrphanPolicyLinks {
    # Detects orphan Policy Object Links where either the target object DN
    # or the Policy Object DN is null (broken reference).
    $result = [PSCustomObject]@{
        Count = 0
        List  = @()
    }

    try {
        $links = Get-QADObject -Type 'edsPolicyObjectLink' `
            -SearchRoot 'CN=AP Links,CN=Configuration' `
            -proxy -IncludeAllProperties -SizeLimit 0 -ErrorAction Stop

        foreach ($link in @($links)) {
            $targetDN = $null
            $apoDN    = $null
            try { $targetDN = $link.edsvaSecObjectDN } catch { }
            try { $apoDN    = $link.edsvaAPODN } catch { }

            $targetMissing = [string]::IsNullOrWhiteSpace($targetDN)
            $apoMissing    = [string]::IsNullOrWhiteSpace($apoDN)

            if ($targetMissing -or $apoMissing) {
                $reason = @()
                if ($targetMissing) { $reason += 'Missing target object (edsvaSecObjectDN)' }
                if ($apoMissing)    { $reason += 'Missing policy object (edsvaAPODN)' }

                $result.List += [PSCustomObject]@{
                    dn     = ConvertTo-SafeHtml $link.distinguishedName
                    reason = ConvertTo-SafeHtml ($reason -join '; ')
                }
            }
        }

        $result.Count = $result.List.Count
        Write-Log "Found $($result.Count) orphan Policy Object Link(s)."
    }
    catch {
        Write-Log "Could not collect orphan policy links: $($_.Exception.Message)" -Level "WARN"
    }

    return $result
}

function Get-AccessTemplatesInfo {
    # Collects Access Template details.
    # Uses edsaSystemObject to distinguish built-in (True) from custom (False/null).
    $paths = @(
        'CN=Access Templates,CN=Server Configuration,CN=Configuration',
        'CN=Access Templates,CN=Configuration'
    )
    $result = [PSCustomObject]@{
        TotalCount   = 0
        BuiltInCount = 0
        CustomCount  = 0
        List         = @()
    }

    foreach ($path in $paths) {
        try {
            $objs = Get-QADObject -Type 'edsAccessTemplate' -SearchRoot $path `
                -DontUseDefaultIncludedProperties `
                -IncludedProperties 'name', 'distinguishedName', 'description', 'edsaSystemObject' `
                -proxy -SizeLimit 0 -ErrorAction Stop

            foreach ($obj in @($objs)) {
                $isSystem = $false
                try {
                    $sysVal = $obj.edsaSystemObject
                    if ($sysVal -eq $true -or $sysVal -eq 'True') {
                        $isSystem = $true
                    }
                } catch { }

                $result.List += [PSCustomObject]@{
                    name        = ConvertTo-SafeHtml $obj.Name
                    type        = if ($isSystem) { 'Built-in' } else { 'Custom' }
                    description = ConvertTo-SafeHtml $(if ($obj.description) { $obj.description } else { '' })
                    dn          = $obj.DN
                }
            }

            $result.TotalCount   = $result.List.Count
            $result.BuiltInCount = @($result.List | Where-Object { $_.type -eq 'Built-in' }).Count
            $result.CustomCount  = @($result.List | Where-Object { $_.type -eq 'Custom' }).Count

            Write-Log "Found $($result.TotalCount) Access Template(s) (Built-in: $($result.BuiltInCount), Custom: $($result.CustomCount)) at '$path'"
            return $result
        }
        catch { }
    }

    Write-Log "Could not collect Access Templates info" -Level "WARN"
    return $result
}

function Get-AzureTenantsInfo {
    <#
    .SYNOPSIS
        Checks if Microsoft Entra (Azure AD) is configured in Active Roles
        and collects tenant configuration details.
    #>
    $result = [PSCustomObject]@{
        Configured = $false
        TotalCount = 0
        List       = @()
        Error      = $null
    }

    try {
        Write-Log "Collecting Azure / Microsoft Entra tenants..."
        $tenants = Get-QADObject `
            -SearchRoot "CN=Azure Tenants,CN=Azure Configuration,CN=Azure,CN=Configuration" `
            -proxy -Type edsAzureTenant `
            -DontUseDefaultIncludedProperties `
            -IncludedProperties 'name', 'edsaAzureADTenantType' `
            -SizeLimit 0 -ErrorAction Stop

        if (-not $tenants) {
            Write-Log "No Azure tenants found"
            return $result
        }

        $result.Configured = $true
        $result.TotalCount = @($tenants).Count

        foreach ($tenant in @($tenants)) {
            $tenantTypeRaw = $null
            try { $tenantTypeRaw = $tenant.edsaAzureADTenantType } catch { }
            $tenantTypeStr = [string]$tenantTypeRaw
            $tenantType = switch ($tenantTypeStr) {
                '1' { 'Non Federated Domain' }
                '2' { 'Federated Domain' }
                '3' { 'Synchronized Identity Domain' }
                default { if ($tenantTypeStr) { "Unknown ($tenantTypeStr)" } else { 'Unknown' } }
            }

            $tenantName = if ($tenant.Name) { $tenant.Name } else { 'N/A' }

            # Count objects per tenant by querying each container under
            # CN=<TenantName>,CN=Azure,CN=Configuration
            $azureBase = "CN=$tenantName,CN=Azure,CN=Configuration"
            $containerMap = @{
                users         = "CN=Azure Users,$azureBase"
                guests        = "CN=Azure Guest Users,$azureBase"
                contacts      = "CN=Azure Contacts,$azureBase"
                sharedMbx     = "CN=Shared Mailboxes,$azureBase"
                resourceMbx   = "CN=Resource mailboxes,$azureBase"
                secGroups     = "CN=Security Groups,$azureBase"
                m365Groups    = "CN=Microsoft 365 Groups,$azureBase"
                distGroups    = "CN=Distribution Groups,$azureBase"
                dynDistGroups = "CN=Dynamic Distribution Groups,$azureBase"
            }

            $counts = @{}
            foreach ($key in $containerMap.Keys) {
                $counts[$key] = 0
                try {
                    $objs = Invoke-EDMSSearch -SearchRoot $containerMap[$key] `
                        -LDAPFilter "(objectClass=*)" `
                        -Scope OneLevel `
                        -Properties @("distinguishedName")
                    $counts[$key] = $objs.Count
                    if ($objs) { $objs.Dispose() }
                    Write-Log "  $tenantName / $key = $($counts[$key]) (SearchRoot: $($containerMap[$key]))"
                }
                catch {
                    Write-Log "  $tenantName / $key = 0 (ERROR: $($_.Exception.Message))" -Level "WARN"
                }
            }

            $result.List += [PSCustomObject]@{
                name          = ConvertTo-SafeHtml $tenantName
                type          = $tenantType
                typeRaw       = $tenantTypeStr
                users         = $counts.users
                guests        = $counts.guests
                contacts      = $counts.contacts
                sharedMbx     = $counts.sharedMbx
                resourceMbx   = $counts.resourceMbx
                secGroups     = $counts.secGroups
                m365Groups    = $counts.m365Groups
                distGroups    = $counts.distGroups
                dynDistGroups = $counts.dynDistGroups
            }

            $totalObjects = ($counts.Values | Measure-Object -Sum).Sum
            Write-Log "Tenant '$tenantName': type=$tenantType users=$($counts.users) guests=$($counts.guests) contacts=$($counts.contacts) sharedMbx=$($counts.sharedMbx) resourceMbx=$($counts.resourceMbx) secGroups=$($counts.secGroups) m365Groups=$($counts.m365Groups) distGroups=$($counts.distGroups) dynDistGroups=$($counts.dynDistGroups) total=$totalObjects"
        }

        Write-Log "Found $($result.TotalCount) Azure/Entra tenant(s) (configured=$($result.Configured))"
    }
    catch {
        Write-Log "Could not collect Azure tenants: $($_.Exception.Message)" -Level "WARN"
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-OrphanATLinks {
    # Detects orphan Access Template Links where either the target object DN
    # or the trustee SID is null (broken reference).
    $result = [PSCustomObject]@{
        Count = 0
        List  = @()
    }

    try {
        $links = Get-QADObject -Type 'edsACE' `
            -SearchRoot 'CN=AT Links,CN=Configuration' `
            -proxy -IncludeAllProperties -SizeLimit 0 -ErrorAction Stop

        foreach ($link in @($links)) {
            $targetDN   = $null
            $trusteeSID = $null
            try { $targetDN   = $link.edsvaSecObjectDN } catch { }
            try { $trusteeSID = $link.edsaTrusteeSID } catch { }

            $targetMissing  = [string]::IsNullOrWhiteSpace($targetDN)
            $trusteeMissing = [string]::IsNullOrWhiteSpace($trusteeSID)

            if ($targetMissing -or $trusteeMissing) {
                $reason = @()
                if ($targetMissing)  { $reason += 'Missing target object (edsvaSecObjectDN)' }
                if ($trusteeMissing) { $reason += 'Missing trustee SID (edsaTrusteeSID)' }

                $result.List += [PSCustomObject]@{
                    dn     = ConvertTo-SafeHtml $link.distinguishedName
                    reason = ConvertTo-SafeHtml ($reason -join '; ')
                }
            }
        }

        $result.Count = $result.List.Count
        Write-Log "Found $($result.Count) orphan Access Template Link(s)."
    }
    catch {
        Write-Log "Could not collect orphan AT links: $($_.Exception.Message)" -Level "WARN"
    }

    return $result
}

function Get-AutoShrinkInfo {
    param(
        [Parameter(Mandatory)]$ReplicationPartners,
        [System.Management.Automation.PSCredential]$SqlCredential
    )

    $result = [PSCustomObject]@{
        Checked        = $false
        SqlServer      = $null
        DatabaseName   = $null
        AutoShrinkOn   = $null
        Error          = $null
    }

    try {
        if (-not $ReplicationPartners.List -or $ReplicationPartners.List.Count -eq 0) {
            Write-Log "No replication partners available for Auto Shrink check" -Level "WARN"
            $result.Error = "No replication partners available"
            return $result
        }

        # Find the Publisher (RoleRaw = '1'), fall back to first available partner
        $publisher = $ReplicationPartners.List | Where-Object { $_.RoleRaw -eq '1' } | Select-Object -First 1
        if (-not $publisher) {
            $publisher = $ReplicationPartners.List | Select-Object -First 1
            Write-Log "No Publisher found, using first available partner '$($publisher.Name)' for Auto Shrink check"
        }

        $sqlAlias = $publisher.SQLAlias
        $dbName   = $publisher.DatabaseName

        if (-not $sqlAlias -or -not $dbName -or $sqlAlias -eq 'N/A' -or $dbName -eq 'N/A') {
            Write-Log "Missing SQL alias or database name on Publisher partner '$($publisher.Name)'" -Level "WARN"
            $result.Error = "Missing SQL alias or database name on Publisher"
            return $result
        }

        $result.SqlServer    = $sqlAlias
        $result.DatabaseName = $dbName
        Write-Log "Config DB discovered from Publisher '$($publisher.Name)': $dbName on $sqlAlias"

        # Connect to SQL Server and check is_auto_shrink_on
        if ($SqlCredential) {
            Write-Log "Connecting to SQL Server using SQL Authentication (user: $($SqlCredential.UserName))"
        }
        else {
            Write-Log "Connecting to SQL Server using Windows Authentication"
        }
        $conn = New-ArSqlConnection -SqlServer $sqlAlias -SqlCredential $SqlCredential

        $query = "SELECT is_auto_shrink_on FROM sys.databases WHERE name = @dbName"
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $query
        $cmd.Parameters.Add((New-Object System.Data.SqlClient.SqlParameter("@dbName", $dbName))) | Out-Null

        $reader = $cmd.ExecuteReader()
        if ($reader.Read()) {
            $result.AutoShrinkOn = [bool]$reader["is_auto_shrink_on"]
            $result.Checked = $true
            Write-Log "Auto Shrink for '$dbName': $($result.AutoShrinkOn)"
        }
        else {
            Write-Log "Database '$dbName' not found on '$sqlAlias'" -Level "WARN"
            $result.Error = "Database not found on SQL Server"
        }
        $reader.Close()
        $conn.Close()
    }
    catch {
        Write-Log "Auto Shrink check failed: $($_.Exception.Message)" -Level "WARN"
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-AlwaysOnInfo {
    param(
        [Parameter(Mandatory)]$ReplicationPartners,
        [System.Management.Automation.PSCredential]$SqlCredential
    )

    $result = [PSCustomObject]@{
        Checked                  = $false
        AlwaysOnEnabled          = $false
        MultiSubnetFailover      = $null
        SqlServer                = $null
        DatabaseName             = $null
        Error                    = $null
    }

    try {
        if (-not $ReplicationPartners.List -or $ReplicationPartners.List.Count -eq 0) {
            Write-Log "No replication partners available for AlwaysOn check" -Level "WARN"
            $result.Error = "No replication partners available"
            return $result
        }

        # Find the Publisher (RoleRaw = '1'), fall back to first available partner
        $publisher = $ReplicationPartners.List | Where-Object { $_.RoleRaw -eq '1' } | Select-Object -First 1
        if (-not $publisher) {
            $publisher = $ReplicationPartners.List | Select-Object -First 1
            Write-Log "No Publisher found, using first available partner '$($publisher.Name)' for AlwaysOn check"
        }

        $sqlAlias = $publisher.SQLAlias
        $dbName   = $publisher.DatabaseName

        if (-not $sqlAlias -or -not $dbName -or $sqlAlias -eq 'N/A' -or $dbName -eq 'N/A') {
            Write-Log "Missing SQL alias or database name on Publisher partner '$($publisher.Name)'" -Level "WARN"
            $result.Error = "Missing SQL alias or database name on Publisher"
            return $result
        }

        $result.SqlServer    = $sqlAlias
        $result.DatabaseName = $dbName

        # Connect to SQL Server and check if AlwaysOn is enabled
        if ($SqlCredential) {
            Write-Log "AlwaysOn check: connecting to SQL Server using SQL Authentication (user: $($SqlCredential.UserName))"
        }
        else {
            Write-Log "AlwaysOn check: connecting to SQL Server using Windows Authentication"
        }

        $conn = New-ArSqlConnection -SqlServer $sqlAlias -SqlCredential $SqlCredential

        $query = "SELECT SERVERPROPERTY('IsHadrEnabled') AS IsHadrEnabled"
        $cmd = $conn.CreateCommand()
        $cmd.CommandText = $query
        $reader = $cmd.ExecuteReader()

        if ($reader.Read()) {
            $hadrValue = $reader["IsHadrEnabled"]
            $result.AlwaysOnEnabled = ($null -ne $hadrValue -and [int]$hadrValue -eq 1)
            $result.Checked = $true
            Write-Log "AlwaysOn (HADR) on '$sqlAlias': $($result.AlwaysOnEnabled)"
        }
        else {
            Write-Log "Could not retrieve HADR status from '$sqlAlias'" -Level "WARN"
            $result.Error = "Could not retrieve HADR status"
        }
        $reader.Close()
        $conn.Close()

        # If AlwaysOn is enabled, check MultiSubnetFailoverSupport via Get-ARService
        if ($result.AlwaysOnEnabled) {
            try {
                Write-Log "AlwaysOn detected, checking MultiSubnetFailoverSupport via Get-ARService..."
                $arSvc = Get-ARService -IncludeAdvancedDatabaseSettings -ErrorAction Stop
                if ($null -ne $arSvc) {
                    $msfValue = $arSvc.MultiSubnetFailoverSupport
                    $result.MultiSubnetFailover = [bool]$msfValue
                    Write-Log "MultiSubnetFailoverSupport: $($result.MultiSubnetFailover)"
                }
                else {
                    Write-Log "Get-ARService returned null" -Level "WARN"
                    $result.MultiSubnetFailover = $false
                }
            }
            catch {
                Write-Log "Could not retrieve MultiSubnetFailoverSupport: $($_.Exception.Message)" -Level "WARN"
                $result.MultiSubnetFailover = $null
                $result.Error = "AlwaysOn detected but could not check MultiSubnetFailoverSupport: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Log "AlwaysOn check failed: $($_.Exception.Message)" -Level "WARN"
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Get-ExchangePresenceInfo {
    <#
    .SYNOPSIS
        Checks for Microsoft Exchange presence by querying AD directly
        via LDAP:// and checks the PerformanceFlag registry key.
    #>
    $result = [PSCustomObject]@{
        ExchangePresent  = $false
        Organization     = $null
        Version          = 'N/A'
        MailboxDatabases = @()
        DatabaseCount    = 0
        PerformanceFlag  = $false
        Disable500VA     = $false
        Error            = $null
    }

    try {
        # Query AD directly via LDAP
        $adRootDSE = [ADSI]"LDAP://RootDSE"
        $adConfigNC = $adRootDSE.Properties["configurationNamingContext"].Value
        Write-Log "Exchange check - AD Configuration NC: $adConfigNC"

        $exchSearchRoot = [ADSI]"LDAP://CN=Microsoft Exchange,CN=Services,$adConfigNC"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = $exchSearchRoot
        $searcher.Filter = "(objectClass=msExchOrganizationContainer)"
        $searcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
        $searcher.PropertiesToLoad.AddRange(@("distinguishedName", "objectVersion", "cn"))

        $searchResult = $searcher.FindOne()
        if ($searchResult) {
            $result.ExchangePresent = $true
            $result.Organization = $searchResult.Properties["cn"][0]

            if ($searchResult.Properties.Contains("objectversion")) {
                $objVer = $searchResult.Properties["objectversion"][0]
                $result.Version = switch ($objVer) {
                    16999  { "Exchange 2019 CU12+" }
                    16998  { "Exchange 2019 CU11" }
                    16997  { "Exchange 2019 CU10" }
                    16996  { "Exchange 2019 CU9" }
                    16995  { "Exchange 2019 CU8" }
                    16994  { "Exchange 2019 CU7" }
                    16993  { "Exchange 2019 CU6" }
                    16992  { "Exchange 2019 CU5" }
                    16991  { "Exchange 2019 CU4" }
                    16990  { "Exchange 2019 CU3" }
                    16756  { "Exchange 2016 CU21+" }
                    16213  { "Exchange 2016 RTM" }
                    15332  { "Exchange 2013 SP1+" }
                    15312  { "Exchange 2013 CU1" }
                    15281  { "Exchange 2013 RTM" }
                    14734  { "Exchange 2010 SP3" }
                    14622  { "Exchange 2010 SP2" }
                    14625  { "Exchange 2010 SP1" }
                    default { "Exchange (objectVersion=$objVer)" }
                }
            }

            Write-Log "Exchange Organization found: $($result.Organization)"
            Write-Log "Exchange Version: $($result.Version)"

            # Enumerate mailbox databases
            try {
                $dbSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $dbSearcher.SearchRoot = $exchSearchRoot
                $dbSearcher.Filter = "(objectClass=msExchMDB)"
                $dbSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                $dbSearcher.PropertiesToLoad.AddRange(@("cn", "distinguishedName"))

                $dbResults = $dbSearcher.FindAll()
                foreach ($db in $dbResults) {
                    $result.MailboxDatabases += $db.Properties["cn"][0]
                }
                $dbResults.Dispose()
                $result.DatabaseCount = $result.MailboxDatabases.Count
                Write-Log "Mailbox databases: $($result.DatabaseCount) ($($result.MailboxDatabases -join ', '))"
            }
            catch {
                Write-Log "Could not enumerate mailbox databases: $($_.Exception.Message)" -Level "DEBUG"
            }

            # Check PerformanceFlag registry key (KB 4336544)
            $regPath = "HKLM:\SOFTWARE\One Identity\Active Roles\Configuration"
            try {
                if (Test-Path $regPath) {
                    $regData = Get-ItemProperty -Path $regPath -Name 'PerformanceFlag' -ErrorAction SilentlyContinue
                    if ($regData -and $regData.PerformanceFlag -eq 1) {
                        $result.PerformanceFlag = $true
                        Write-Log "PerformanceFlag = 1 (configured correctly)"
                    }
                    else {
                        Write-Log "PerformanceFlag is missing or not set to 1" -Level "WARN"
                    }
                }
                else {
                    Write-Log "Registry path not found: $regPath" -Level "WARN"
                }
            }
            catch {
                Write-Log "Could not read PerformanceFlag registry: $($_.Exception.Message)" -Level "WARN"
            }
        }
        else {
            Write-Log "No Exchange Organization found in AD"
        }
    }
    catch {
        Write-Log "Exchange presence check failed: $($_.Exception.Message)" -Level "WARN"
        $result.Error = $_.Exception.Message
    }

    # Check Disable500VA registry key (KB 4216183) - independent of Exchange
    $svcRegPath = "HKLM:\SOFTWARE\One Identity\Active Roles\Configuration\Service"
    try {
        if (Test-Path $svcRegPath) {
            $svcRegData = Get-ItemProperty -Path $svcRegPath -Name 'Disable500VA' -ErrorAction SilentlyContinue
            if ($svcRegData -and $svcRegData.Disable500VA -eq 1) {
                $result.Disable500VA = $true
                Write-Log "Disable500VA = 1 (configured correctly)"
            }
            else {
                Write-Log "Disable500VA is missing or not set to 1" -Level "WARN"
            }
        }
        else {
            Write-Log "Registry path not found: $svcRegPath" -Level "WARN"
        }
    }
    catch {
        Write-Log "Could not read Disable500VA registry: $($_.Exception.Message)" -Level "WARN"
    }

    return $result
}

#endregion

#region HTML Generation

function New-HtmlReport {
    param(
        [PSCustomObject]$ARVersion,
        [PSCustomObject]$OSInfo,
        [array]$Domains,
        [array]$DomainLatency,
        [PSCustomObject]$ManagedUserCounts,
        [PSCustomObject]$Servers,
        [PSCustomObject]$ReplicationPartners,
        [PSCustomObject]$MHReplicationPartners,
        [PSCustomObject]$DynamicGroups,
        [PSCustomObject]$ManagedUnits,
        [PSCustomObject]$Workflows,
        [PSCustomObject]$VirtualAttrs,
        [int]$ScriptPoliciesCount,
        [PSCustomObject]$PolicyObjects,
        [PSCustomObject]$OrphanPolicyLinks,
        [PSCustomObject]$AccessTemplates,
        [PSCustomObject]$OrphanATLinks,
        [PSCustomObject]$AzureTenants,
        [PSCustomObject]$ExchangeInfo,
        [PSCustomObject]$AutoShrinkInfo,
        [PSCustomObject]$AlwaysOnInfo
    )

    $reportDate    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    # Determine server mode: only Publisher (1) or Subscriber (2) indicate active replication; 3 = Not Configured
    $hasConfigRepl = @($ReplicationPartners.List | Where-Object { $_.RoleRaw -eq '1' -or $_.RoleRaw -eq '2' }).Count -gt 0
    $hasMHRepl     = @($MHReplicationPartners.List | Where-Object { $_.RoleRaw -eq '1' -or $_.RoleRaw -eq '2' }).Count -gt 0
    $hasReplication = $hasConfigRepl -or $hasMHRepl
    $serverMode    = if ($hasReplication) { "Replication" } else { "Standalone" }
    $modeBadge     = if ($serverMode -eq "Replication") { "badge-green" } else { "badge-blue" }
    $dgHealthy     = [math]::Max(0, $DynamicGroups.TotalCount - $DynamicGroups.BrokenCount)
    $muHealthy     = [math]::Max(0, $ManagedUnits.TotalCount - $ManagedUnits.BrokenCount)

    $arVersionDisplay = if ($ARVersion.InstalledVersion -ne "Unknown") {
        $ARVersion.InstalledVersion
    } elseif ($ARVersion.ServiceVersion -ne "Unknown") {
        $ARVersion.ServiceVersion
    } else { "Unknown" }

    $arProductDisplay = $ARVersion.InstalledProduct

    # -- Domain table rows (with latency) -------------------------------------
    $domainRows = ""
    # Build a latency lookup by domain name
    $latencyLookup = @{}
    foreach ($lat in $DomainLatency) {
        $latencyLookup[$lat.domain] = $lat
    }
    foreach ($d in $Domains) {
        $dName = if ($d.DnsName) { $d.DnsName } else { $d.Name }
        $siteCell = if ($d.DCSiteName) { ConvertTo-SafeHtml $d.DCSiteName } else { '<span class="muted">N/A</span>' }
        $lat = $latencyLookup[$dName]
        if ($lat) {
            $statusBadge = switch ($lat.status) {
                'Good' { 'badge-green' }
                'Fair' { 'badge-amber' }
                'Poor' { 'badge-red' }
                default { 'badge-red' }
            }
            $avgDisplay = if ($lat.avgMs -ge 0) { "$($lat.avgMs) ms" } else { 'N/A' }
            $minDisplay = if ($lat.minMs -ge 0) { "$($lat.minMs) ms" } else { 'N/A' }
            $maxDisplay = if ($lat.maxMs -ge 0) { "$($lat.maxMs) ms" } else { 'N/A' }
            $domainRows += "<tr><td>$($d.Name)</td><td>$(ConvertTo-SafeHtml $lat.dc)</td><td>$siteCell</td><td>$avgDisplay</td><td>$minDisplay</td><td>$maxDisplay</td><td><span class='badge $statusBadge'>$($lat.status)</span></td></tr>"
        }
        else {
            $domainRows += "<tr><td>$($d.Name)</td><td class='muted'>N/A</td><td>$siteCell</td><td class='muted'>N/A</td><td class='muted'>N/A</td><td class='muted'>N/A</td><td><span class='badge badge-amber'>No data</span></td></tr>"
        }
    }
    if (-not $domainRows) {
        $domainRows = '<tr><td colspan="7" class="empty-row">No domains found or unable to retrieve data</td></tr>'
    }

    # -- Server table rows ------------------------------------------------------
    $serverRows = ""
    foreach ($s in $Servers.Servers) {
        # Verbose Logging badge: TRUE = Enabled (red), FALSE = Disabled (green)
        $verboseBadgeClass = if ($s.VerboseLoggingOn) { 'badge-red' } else { 'badge-green' }
        $verboseLabel = if ($s.VerboseLoggingOn) { 'Enabled' } else { 'Disabled' }

        # Logging Type badge
        $logTypeBadge = switch ($s.LoggingType) {
            'Verbose' { '<span class="badge badge-amber">Verbose</span>' }
            'Basic'   { '<span class="badge badge-green">Basic</span>' }
            default   { "<span class='muted'>$($s.LoggingType)</span>" }
        }

        $serverRows += "<tr><td><strong>$($s.InstanceName)</strong></td><td>$($s.Version)</td><td>$($s.ConfigDB)</td><td>$($s.MgmtHistoryDB)</td><td><span class='badge $verboseBadgeClass'>$verboseLabel</span></td><td>$logTypeBadge</td></tr>"
    }
    if (-not $serverRows) {
        $serverRows = '<tr><td colspan="6" class="empty-row">No server objects found or unable to retrieve data</td></tr>'
    }

    # -- Replication Partners table rows --------------------------------------
    $replRows = ""
    foreach ($r in $ReplicationPartners.List) {
        $roleBadge = switch ($r.RoleRaw) {
            '1'     { '<span class="badge badge-blue">Publisher</span>' }
            '2'     { '<span class="badge badge-green">Subscriber</span>' }
            '0'     { '<span class="badge badge-amber">Not Configured</span>' }
            default { "<span class='muted'>$($r.RoleLabel)</span>" }
        }
        $replRows += "<tr><td><strong>$($r.Name)</strong></td><td>$($r.DatabaseName)</td><td>$($r.DatabaseType)</td><td>$($r.SQLAlias)</td><td>$roleBadge</td></tr>"
    }
    if (-not $replRows) {
        $replRows = '<tr><td colspan="5" class="empty-row">No replication partners found or unable to retrieve data</td></tr>'
    }

    # -- MH Replication Partners table rows -----------------------------------
    $mhReplRows = ""
    foreach ($r in $MHReplicationPartners.List) {
        $roleBadge = switch ($r.RoleRaw) {
            '1'     { '<span class="badge badge-blue">Publisher</span>' }
            '2'     { '<span class="badge badge-green">Subscriber</span>' }
            '0'     { '<span class="badge badge-amber">Not Configured</span>' }
            default { "<span class='muted'>$($r.RoleLabel)</span>" }
        }
        $mhReplRows += "<tr><td><strong>$($r.Name)</strong></td><td>$($r.DatabaseName)</td><td>$($r.DatabaseType)</td><td>$($r.SQLAlias)</td><td>$roleBadge</td></tr>"
    }
    if (-not $mhReplRows) {
        $mhReplRows = '<tr><td colspan="5" class="empty-row">No MH replication partners found or unable to retrieve data</td></tr>'
    }

    # -- Dynamic Groups broken rules section ------------------------------------
    if ($DynamicGroups.SkippedCheck) {
        $dgBrokenSection = '<p class="skipped-note">&#9197; Broken rules check skipped (<code>-SkipBrokenRulesCheck</code>).</p>'
    } elseif ($DynamicGroups.BrokenCount -gt 0) {
        $rows = ""
        foreach ($dg in $DynamicGroups.BrokenList) {
            $rows += "<tr><td>$(ConvertTo-SafeHtml $dg.Name)</td><td class='dn-cell'>$(ConvertTo-SafeHtml $dg.DN)</td></tr>"
        }
        $dgBrokenSection = @"
        <div class="alert-box">&#9888; <strong>$($DynamicGroups.BrokenCount) Dynamic Group(s)</strong> with broken membership rules detected</div>
        <table><thead><tr><th>Group Name</th><th>Distinguished Name</th></tr></thead><tbody>$rows</tbody></table>
"@
    } else {
        $dgBrokenSection = '<p class="ok-note">&#10003; No broken membership rules detected.</p>'
    }

    # -- Managed Units broken rules section -------------------------------------
    if ($ManagedUnits.SkippedCheck) {
        $muBrokenSection = '<p class="skipped-note">&#9197; Broken rules check skipped (<code>-SkipBrokenRulesCheck</code>).</p>'
    } elseif ($ManagedUnits.BrokenCount -gt 0) {
        $rows = ""
        foreach ($mu in $ManagedUnits.BrokenList) {
            $rows += "<tr><td>$(ConvertTo-SafeHtml $mu.Name)</td><td class='dn-cell'>$(ConvertTo-SafeHtml $mu.DN)</td></tr>"
        }
        $muBrokenSection = @"
        <div class="alert-box">&#9888; <strong>$($ManagedUnits.BrokenCount) Managed Unit(s)</strong> with broken membership rules detected</div>
        <table><thead><tr><th>Managed Unit Name</th><th>Distinguished Name</th></tr></thead><tbody>$rows</tbody></table>
"@
    } else {
        $muBrokenSection = '<p class="ok-note">&#10003; No broken membership rules detected.</p>'
    }

    # -- Managed User Counts data for chart ----------------------------------
    $userCountChartData = if ($ManagedUserCounts.PerDomain -and $ManagedUserCounts.PerDomain.Count -gt 0) {
        ConvertTo-Json @($ManagedUserCounts.PerDomain | Where-Object { $_.count -ge 0 } |
            Select-Object @{N='name';E={$_.name}}, @{N='value';E={$_.count}}) -Compress
    } else { '[]' }
    $safeTotalUsers    = [math]::Max(0, $ManagedUserCounts.TotalCount)
    $safeHybridTotal   = [math]::Max(0, $ManagedUserCounts.HybridTotal)
    $safeGmsaTotal     = [math]::Max(0, $ManagedUserCounts.GmsaTotal)
    $safeExcludedTotal = [math]::Max(0, $ManagedUserCounts.ExcludedTotal)
    $safeOnPremTotal = [math]::Max(0, $safeTotalUsers - $safeHybridTotal)

    # Cloud-only = Azure Users (all tenants) - Hybrid accounts
    $azureUsersTotal = 0
    if ($AzureTenants.List) {
        $azureUsersTotal = ($AzureTenants.List | Measure-Object -Property users -Sum).Sum
    }


    # -- Virtual Attributes data for table and chart ----------------------------
    $vaJsonData = if ($VirtualAttrs.List -and $VirtualAttrs.List.Count -gt 0) {
        ConvertTo-Json @($VirtualAttrs.List) -Compress
    } else { '[]' }
    $vaChartData = "[$($VirtualAttrs.CustomCount),$($VirtualAttrs.BuiltInCount)]"

    # -- Chart data (safe integers) ---------------------------------------------
    $dgChartData = if ($DynamicGroups.SkippedCheck -or $DynamicGroups.TotalCount -eq 0) {
        "[0,0]"
    } else { "[$dgHealthy,$($DynamicGroups.BrokenCount)]" }

    $muChartData = if ($ManagedUnits.SkippedCheck -or $ManagedUnits.TotalCount -eq 0) {
        "[0,0]"
    } else { "[$muHealthy,$($ManagedUnits.BrokenCount)]" }

    # -- Workflow data for table and chart -------------------------------------
    $wfJsonData = if ($Workflows.List -and $Workflows.List.Count -gt 0) {
        ConvertTo-Json @($Workflows.List) -Compress
    } else { '[]' }

    $wfChartData = "[$($Workflows.EnabledCount),$($Workflows.DisabledCount)]"

    # -- Orphan counts (must be computed before chart data) -----------------
    $safeOrphan = [math]::Max(0, $OrphanPolicyLinks.Count)
    $orphanBadgeClass = if ($safeOrphan -gt 0) { 'red' } else { 'green' }
    $safeOrphanAt = [math]::Max(0, $OrphanATLinks.Count)

    # -- Policy Objects data for table and chart -------------------------------
    $poJsonData = if ($PolicyObjects.List -and $PolicyObjects.List.Count -gt 0) {
        ConvertTo-Json @($PolicyObjects.List) -Compress
    } else { '[]' }
    $poChartData = "[$($PolicyObjects.EnabledCount),$($PolicyObjects.DisabledCount),$safeOrphan]"

    # -- Orphan Policy Links data for table ----------------------------------
    $orphanPoJsonData = if ($OrphanPolicyLinks.List -and $OrphanPolicyLinks.List.Count -gt 0) {
        ConvertTo-Json @($OrphanPolicyLinks.List) -Compress
    } else { '[]' }

    # -- Access Templates data for table and chart --------------------------
    $atJsonData = if ($AccessTemplates.List -and $AccessTemplates.List.Count -gt 0) {
        ConvertTo-Json @($AccessTemplates.List) -Compress
    } else { '[]' }
    $atChartData = "[$($AccessTemplates.CustomCount),$safeOrphanAt]"

    # -- Orphan Access Template Links data for table -------------------------
    $orphanAtJsonData = if ($OrphanATLinks.List -and $OrphanATLinks.List.Count -gt 0) {
        ConvertTo-Json @($OrphanATLinks.List) -Compress
    } else { '[]' }

    # -- Azure Tenants data for chart and table ----------------------------
    $azureConfigured = $AzureTenants.Configured
    $azureTenantCount = [math]::Max(0, $AzureTenants.TotalCount)
    $azureConfigBadge = if ($azureConfigured) { 'green' } else { 'slate' }
    # Static table rows for Azure tenants
    $azureTenantRows = ""
    foreach ($az in $AzureTenants.List) {
        $typeBadge = switch ($az.type) {
            'Non Federated Domain'          { '<span class="badge badge-blue">Non Federated</span>' }
            'Federated Domain'              { '<span class="badge badge-green">Federated</span>' }
            'Synchronized Identity Domain'  { '<span class="badge badge-amber">Synchronized</span>' }
            default                         { "<span class='badge badge-gray'>$($az.type)</span>" }
        }
        $azureTenantRows += "<tr><td><strong>$($az.name)</strong></td><td>$typeBadge</td><td style='text-align:right'>$($az.users)</td><td style='text-align:right'>$($az.guests)</td><td style='text-align:right'>$($az.contacts)</td><td style='text-align:right'>$($az.sharedMbx)</td><td style='text-align:right'>$($az.resourceMbx)</td><td style='text-align:right'>$($az.secGroups)</td><td style='text-align:right'>$($az.m365Groups)</td><td style='text-align:right'>$($az.distGroups)</td><td style='text-align:right'>$($az.dynDistGroups)</td></tr>"
    }
    if (-not $azureTenantRows) {
        $azureTenantRows = '<tr><td colspan="11" class="empty-row">No tenants found</td></tr>'
    }

    # -- Exchange presence data -------------------------------------------------
    $exchangePresent = $ExchangeInfo.ExchangePresent
    $exchangeBadge = if ($exchangePresent) { 'green' } else { 'slate' }
    $perfFlagOk = $ExchangeInfo.PerformanceFlag
    $disable500VA = $ExchangeInfo.Disable500VA
    $autoShrinkChecked = $AutoShrinkInfo.Checked
    $autoShrinkOn = $AutoShrinkInfo.AutoShrinkOn
    $alwaysOnChecked = $AlwaysOnInfo.Checked
    $alwaysOnEnabled = $AlwaysOnInfo.AlwaysOnEnabled
    $multiSubnetOk   = $AlwaysOnInfo.MultiSubnetFailover

    $dgBrokenBadge = if ($DynamicGroups.BrokenCount -gt 0) { "badge-red" } else { "badge-green" }
    $muBrokenBadge = if ($ManagedUnits.BrokenCount   -gt 0) { "badge-red" } else { "badge-green" }

    # -- HTML document ----------------------------------------------------------
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Active Roles Environment Assessment - $($OSInfo.ComputerName)</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#f0f2f5;color:#1a1a2e;line-height:1.5;font-size:14px}
.page{max-width:1400px;margin:0 auto;padding:24px}
/* Header */
.rpt-header{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 55%,#0f3460 100%);border-radius:16px;padding:32px 36px;margin-bottom:24px;color:#fff}
.rpt-header h1{font-size:1.75rem;font-weight:700;margin-bottom:6px;letter-spacing:-.3px}
.rpt-header .meta{display:flex;flex-wrap:wrap;gap:20px;margin-top:14px;font-size:.83rem;opacity:.85}
.rpt-header .meta span{display:flex;align-items:center;gap:6px}
.rpt-header .meta strong{opacity:1}
/* Section titles */
.sec-title{font-size:1rem;font-weight:700;color:#111827;margin:28px 0 12px;padding-bottom:8px;border-bottom:2px solid #e5e7eb;display:flex;align-items:center;gap:10px}
.sec-icon{width:22px;height:22px;display:inline-flex;align-items:center;justify-content:center;background:#2563eb;color:#fff;border-radius:5px;font-size:.68rem;font-weight:800;flex-shrink:0}
/* KPI grid */
.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:4px}
.kpi{background:#fff;border-radius:12px;padding:18px 16px;box-shadow:0 1px 3px rgba(0,0,0,.08);transition:transform .15s,box-shadow .15s}
.kpi:hover{transform:translateY(-2px);box-shadow:0 4px 14px rgba(0,0,0,.11)}
.kpi[data-section]{cursor:pointer}
.sec-title[id]{scroll-margin-top:16px}
.kpi .lbl{font-size:.72rem;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:#6b7280;margin-bottom:5px}
.kpi .val{font-size:1.85rem;font-weight:700;line-height:1}
.kpi .sub{font-size:.73rem;color:#9ca3af;margin-top:4px}
.kpi.blue .val{color:#2563eb}.kpi.green .val{color:#16a34a}.kpi.red .val{color:#dc2626}
.kpi.amber .val{color:#d97706}.kpi.purple .val{color:#7c3aed}.kpi.teal .val{color:#0d9488}
.kpi.pink .val{color:#db2777}.kpi.slate .val{color:#475569}
/* Panels */
.panel-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(400px,1fr));gap:18px;margin-bottom:4px}
.panel{background:#fff;border-radius:12px;padding:22px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.panel-full{grid-column:1/-1}
.panel h2{font-size:.92rem;font-weight:600;color:#374151;margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid #f0f0f0;display:flex;align-items:center;gap:8px}
/* Info key-value grid */
.kv{display:grid;grid-template-columns:auto 1fr;gap:3px 16px}
.kv .k{font-size:.8rem;font-weight:600;color:#6b7280;padding:4px 0;white-space:nowrap}
.kv .v{font-size:.8rem;color:#111827;padding:4px 0;word-break:break-word}
/* Tables */
table{width:100%;border-collapse:collapse;font-size:.82rem}
thead th{text-align:left;padding:9px 12px;background:#f9fafb;font-weight:600;color:#4b5563;border-bottom:2px solid #e5e7eb;white-space:nowrap}
tbody td{padding:8px 12px;border-bottom:1px solid #f3f4f6;vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:#f8fafc}
.dn-cell{font-size:.75rem;color:#6b7280;word-break:break-all}
.empty-row{text-align:center;color:#9ca3af;font-style:italic;padding:16px}
/* Badges */
.badge{display:inline-flex;align-items:center;padding:2px 10px;border-radius:9999px;font-size:.74rem;font-weight:600;line-height:1.6}
.badge-blue{background:#dbeafe;color:#1d4ed8}.badge-green{background:#dcfce7;color:#166534}
.badge-red{background:#fee2e2;color:#991b1b}.badge-amber{background:#fef3c7;color:#92400e}.badge-gray{background:#f3f4f6;color:#4b5563}
/* Type pill */
.type-pill{font-size:.73rem;background:#f3f4f6;color:#4b5563;padding:2px 8px;border-radius:4px}
/* Alert / status boxes */
.alert-box{background:#fef3c7;border:1px solid #fcd34d;border-radius:8px;padding:11px 15px;margin-bottom:14px;font-size:.83rem;color:#78350f}
.ok-note{color:#166534;font-size:.83rem;padding:10px 0;display:flex;align-items:center;gap:6px}
.skipped-note{color:#6b7280;font-size:.83rem;padding:10px 0;font-style:italic}
/* Chart wrappers */
.chart-wrap{position:relative;width:100%;height:240px}
/* Misc */
.muted{color:#9ca3af;font-style:italic}
code{background:#f3f4f6;padding:1px 5px;border-radius:4px;font-size:.82rem}
/* Footer */
.footer{text-align:center;padding:24px;font-size:.73rem;color:#9ca3af;margin-top:12px}
/* Responsive */
@media(max-width:768px){
  .page{padding:12px}.panel-grid{grid-template-columns:1fr}
  .kpi-grid{grid-template-columns:repeat(2,1fr)}.rpt-header{padding:20px}
}
@media print{
  body{background:#fff}.kpi:hover{transform:none;box-shadow:none}
  .rpt-header{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
</style>
</head>
<body>
<div class="page">

<!-- =========================== HEADER =================================== -->
<div class="rpt-header">
  <h1>Active Roles Environment Assessment</h1>
  <div class="meta">
    <span>&#128421; Server: <strong>$($OSInfo.ComputerName)</strong></span>
    <span>&#128450; Product: <strong>$arProductDisplay</strong></span>
    <span>&#128230; Version: <strong>$arVersionDisplay</strong></span>
    <span>&#128336; Generated: <strong>$reportDate</strong></span>
  </div>
</div>

<!-- =========================== SUMMARY KPIs ============================= -->
<div class="sec-title"><span class="sec-icon">KPI</span>Environment Summary</div>
<div class="kpi-grid">
  <div class="kpi blue" data-section="sec-infra" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">AR Version</div>
    <div class="val" style="font-size:1.1rem;padding-top:4px">$arVersionDisplay</div>
    <div class="sub">Active Roles</div>
  </div>
  <div class="kpi blue" data-section="sec-servers" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Server Mode</div>
    <div class="val" style="font-size:1.15rem;padding-top:4px">$serverMode</div>
    <div class="sub">$(Format-Count $Servers.Servers.Count) instance(s)</div>
  </div>
  <div class="kpi teal" data-section="sec-domains" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Managed Domains</div>
    <div class="val">$(Format-Count $Domains.Count)</div>
    <div class="sub">AD domains</div>
  </div>
$(if (-not $ManagedUserCounts.Skipped) {@"
  <div class="kpi teal" data-section="sec-domains" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Managed Users</div>
    <div class="val">$(Format-Count $safeTotalUsers)</div>
    <div class="sub">across $($Domains.Count) domain(s)</div>
  </div>
"@})
$(if (-not $AzureTenants.Skipped) {@"
  <div class="kpi $azureConfigBadge" data-section="sec-azure" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Entra Tenants</div>
    <div class="val">$(Format-Count $azureTenantCount)</div>
    <div class="sub"><span class="badge $(if($azureConfigured){'badge-green'}else{'badge-gray'})">$(if($azureConfigured){'Configured'}else{'Not Configured'})</span></div>
  </div>
"@})
  <div class="kpi $exchangeBadge" data-section="sec-exchange" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Exchange</div>
    <div class="val" style="font-size:1.1rem;padding-top:4px">$(if($exchangePresent){'Detected'}else{'Not Found'})</div>
    <div class="sub"><span class="badge $(if($exchangePresent){if($perfFlagOk){'badge-green'}else{'badge-red'}}else{'badge-gray'})">$(if($exchangePresent){if($perfFlagOk){'PerformanceFlag OK'}else{'Action Required'}}else{'N/A'})</span></div>
  </div>
  <div class="kpi $(if($disable500VA){'green'}else{'red'})" data-section="sec-disable500va" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Disable500VA</div>
    <div class="val" style="font-size:1.1rem;padding-top:4px">$(if($disable500VA){'Configured'}else{'Not Set'})</div>
    <div class="sub"><span class="badge $(if($disable500VA){'badge-green'}else{'badge-red'})">$(if($disable500VA){'Value = 1'}else{'Action Required'})</span></div>
  </div>
  <div class="kpi $(if($autoShrinkChecked){if($autoShrinkOn){'red'}else{'green'}}else{'slate'})" data-section="sec-autoshrink" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">DB Auto Shrink</div>
    <div class="val" style="font-size:1.1rem;padding-top:4px">$(if($autoShrinkChecked){if($autoShrinkOn){'Enabled'}else{'Disabled'}}else{'N/A'})</div>
    <div class="sub"><span class="badge $(if($autoShrinkChecked){if($autoShrinkOn){'badge-red'}else{'badge-green'}}else{'badge-gray'})">$(if($autoShrinkChecked){if($autoShrinkOn){'Action Required'}else{'OK'}}else{'Not Checked'})</span></div>
  </div>
  <div class="kpi $(if($alwaysOnChecked){if($alwaysOnEnabled){if($multiSubnetOk){'green'}else{'red'}}else{'slate'}}else{'slate'})" data-section="sec-alwayson" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">SQL AlwaysOn</div>
    <div class="val" style="font-size:1.1rem;padding-top:4px">$(if($alwaysOnChecked){if($alwaysOnEnabled){'Enabled'}else{'Not Enabled'}}else{'N/A'})</div>
    <div class="sub"><span class="badge $(if($alwaysOnChecked){if($alwaysOnEnabled){if($multiSubnetOk){'badge-green'}else{'badge-red'}}else{'badge-gray'}}else{'badge-gray'})">$(if($alwaysOnChecked){if($alwaysOnEnabled){if($multiSubnetOk){'MultiSubnet OK'}else{'Action Required'}}else{'N/A'}}else{'Not Checked'})</span></div>
  </div>
  <div class="kpi purple" data-section="sec-dyngroups" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Dynamic Groups</div>
    <div class="val">$(Format-Count $DynamicGroups.TotalCount)</div>
    <div class="sub"><span class="badge $dgBrokenBadge">$($DynamicGroups.BrokenCount) broken</span></div>
  </div>
  <div class="kpi purple" data-section="sec-mu" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Managed Units</div>
    <div class="val">$(Format-Count $ManagedUnits.TotalCount)</div>
    <div class="sub"><span class="badge $muBrokenBadge">$($ManagedUnits.BrokenCount) broken</span></div>
  </div>
  <div class="kpi amber" data-section="sec-workflows" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Workflows</div>
    <div class="val">$(Format-Count $Workflows.TotalCount)</div>
    <div class="sub"><span class="badge badge-green">$($Workflows.EnabledCount) enabled</span> <span class="badge badge-red">$($Workflows.DisabledCount) disabled</span></div>
  </div>
  <div class="kpi amber" data-section="sec-va" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Virtual Attrs</div>
    <div class="val">$(Format-Count $VirtualAttrs.CustomCount)</div>
    <div class="sub"><span class="badge badge-blue">custom</span></div>
  </div>
  <div class="kpi green" data-section="sec-config" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Script Policies</div>
    <div class="val">$(Format-Count $ScriptPoliciesCount)</div>
    <div class="sub">script modules</div>
  </div>
  <div class="kpi green" data-section="sec-policies" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Policy Objects</div>
    <div class="val">$(Format-Count $PolicyObjects.TotalCount)</div>
    <div class="sub"><span class="badge badge-green">$($PolicyObjects.EnabledCount) enabled</span> <span class="badge badge-red">$($PolicyObjects.DisabledCount) disabled</span></div>
  </div>
  <div class="kpi pink" data-section="sec-at" onclick="document.getElementById(this.dataset.section).scrollIntoView({behavior:'smooth'})">
    <div class="lbl">Access Templates</div>
    <div class="val">$(Format-Count $AccessTemplates.CustomCount)</div>
    <div class="sub"><span class="badge badge-blue">custom</span>$(if ($safeOrphanAt -gt 0) {" <span class='badge badge-red'>$safeOrphanAt orphan</span>"})</div>
  </div>
</div>

<!-- =========================== 01 INFRASTRUCTURE ======================== -->
<div class="sec-title" id="sec-infra"><span class="sec-icon">01</span>Infrastructure</div>
<div class="panel-grid">
  <div class="panel">
    <h2>Operating System</h2>
    <div class="kv">
      <span class="k">Hostname</span>       <span class="v">$($OSInfo.ComputerName)</span>
      <span class="k">OS Name</span>        <span class="v">$($OSInfo.OSCaption)</span>
      <span class="k">Version</span>        <span class="v">$($OSInfo.OSVersion)</span>
      <span class="k">Build Number</span>   <span class="v">$($OSInfo.BuildNumber)</span>
      <span class="k">Architecture</span>   <span class="v">$($OSInfo.Architecture)</span>
      <span class="k">Domain</span>         <span class="v">$($OSInfo.Domain)</span>
      <span class="k">Total Memory</span>   <span class="v">$($OSInfo.TotalMemory)</span>
      <span class="k">Free Memory</span>    <span class="v">$($OSInfo.FreeMemory)</span>
      <span class="k">Last Boot</span>      <span class="v">$($OSInfo.LastBootTime)</span>
    </div>
  </div>
  <div class="panel">
    <h2>Active Roles Installation</h2>
    <div class="kv">
      <span class="k">Product Name</span>      <span class="v">$arProductDisplay</span>
      <span class="k">Installed Version</span> <span class="v">$(if($ARVersion.InstalledVersion -ne 'Unknown'){$ARVersion.InstalledVersion}else{'N/A (see registry)'})</span>
      <span class="k">Service Version</span>   <span class="v">$(if($ARVersion.ServiceVersion -ne 'Unknown'){$ARVersion.ServiceVersion}else{'N/A'})</span>
      <span class="k">Connected Server</span>  <span class="v">$(if($ARVersion.ConnectedServer -ne 'Unknown'){$ARVersion.ConnectedServer}else{'N/A'})</span>
      <span class="k">Install Date</span>      <span class="v">$($ARVersion.InstallDate)</span>
    </div>
  </div>
</div>

<!-- =========================== 02 MANAGED DOMAINS ====================== -->
<div class="sec-title" id="sec-domains"><span class="sec-icon">02</span>Managed Domains</div>
<div class="panel">
  <h2>Domain Latency &nbsp;<span class="badge badge-blue">$(Format-Count $Domains.Count) domain(s)</span></h2>
  <table>
    <thead><tr><th>Domain Name</th><th>Domain Controller</th><th>DC Site</th><th>Avg</th><th>Min</th><th>Max</th><th>Status</th></tr></thead>
    <tbody>$domainRows</tbody>
  </table>
</div>
$(if ($ManagedUserCounts.Skipped) {@"
<div class="panel" style="margin-top:20px">
  <h2>Managed Users</h2>
  <p class="skipped-note">&#9197; User count skipped (<code>-SkipUserCounts</code>).</p>
</div>
"@} else {@"
<div class="panel" style="margin-top:20px">
  <h2>Managed Users &nbsp;<span class="badge badge-blue">$(Format-Count $safeTotalUsers) total</span></h2>
  <p style="font-size:.82rem;color:#6b7280;margin-bottom:14px">
    User count per domain, excluding OUs and Managed Units linked to <em>Built-in Policy &ndash; Exclude from Managed Scope</em>$(
        $exParts = @()
        if ($ManagedUserCounts.ExcludedOUs.Count -gt 0) { $exParts += "$($ManagedUserCounts.ExcludedOUs.Count) OU(s)" }
        if ($ManagedUserCounts.ExcludedMUs.Count -gt 0) { $exParts += "$($ManagedUserCounts.ExcludedMUs.Count) MU(s)" }
        if ($exParts.Count -gt 0) { " &mdash; <strong>$($exParts -join ' + ') excluded</strong>" }
    )
  </p>
  <div class="chart-wrap" style="max-height:300px"><canvas id="userCountChart"></canvas></div>
</div>
<div class="panel" style="margin-top:20px">
  <h2>Users per Domain</h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>Domain</th><th style="text-align:right">Total Users</th><th style="text-align:right">On-Prem Only</th><th style="text-align:right">Hybrid</th><th style="text-align:right">gMSA</th><th style="text-align:right">Excluded OUs Users</th></tr></thead>
    <tbody>
$(($ManagedUserCounts.PerDomain | ForEach-Object {
    $countDisplay  = if ($_.count -ge 0)  { Format-Count $_.count }  else { '<span class="muted">Error</span>' }
    $onpremDisplay = if ($_.onprem -ge 0) { Format-Count $_.onprem } else { '<span class="muted">Error</span>' }
    "      <tr><td>$($_.name)</td><td style='text-align:right;font-weight:600'>$countDisplay</td><td style='text-align:right'>$onpremDisplay</td><td style='text-align:right'>$(Format-Count $_.hybrid)</td><td style='text-align:right'>$(Format-Count $_.gmsa)</td><td style='text-align:right'>$(Format-Count $_.excluded)</td></tr>"
}) -join "`n")
    </tbody>
    <tfoot>
      <tr style="border-top:2px solid #e5e7eb;font-weight:700"><td>Subtotal (AD)</td><td style="text-align:right">$(Format-Count $safeTotalUsers)</td><td style="text-align:right">$(Format-Count $safeOnPremTotal)</td><td style="text-align:right">$(Format-Count $safeHybridTotal)</td><td style="text-align:right">$(Format-Count $safeGmsaTotal)</td><td style="text-align:right">$(Format-Count $safeExcludedTotal)</td></tr>
    </tfoot>
  </table>
  </div>
$(if ($ManagedUserCounts.ExcludedOUs.Count -gt 0) {@"
  <details style="margin-top:12px">
    <summary style="font-size:.82rem;color:#6b7280;cursor:pointer">Excluded OUs ($($ManagedUserCounts.ExcludedOUs.Count))</summary>
    <ul style="font-size:.78rem;color:#9ca3af;margin-top:6px;padding-left:18px">
$(($ManagedUserCounts.ExcludedOUs | ForEach-Object { "      <li style='word-break:break-all'>$(ConvertTo-SafeHtml $_)</li>" }) -join "`n")
    </ul>
  </details>
"@})
</div>
"@})

<!-- =========================== 2.1 MICROSOFT ENTRA TENANTS ============ -->
<div class="sec-title" id="sec-azure"><span class="sec-icon">2.1</span>Microsoft Entra ID (Azure AD)</div>
$(if ($azureConfigured) {@"
<div class="panel panel-full">
  <h2>Tenant Details &nbsp;<span class="badge badge-green">Configured</span> &nbsp;<span class="badge badge-blue">$(Format-Count $azureTenantCount) tenant(s)</span></h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>Tenant Name</th><th>Tenant Type</th><th style="text-align:right">Users</th><th style="text-align:right">Guest Users</th><th style="text-align:right">Contacts</th><th style="text-align:right">Shared Mailboxes</th><th style="text-align:right">Resource Mailboxes</th><th style="text-align:right">Security Groups</th><th style="text-align:right">M365 Groups</th><th style="text-align:right">Distribution Groups</th><th style="text-align:right">Dynamic Distribution Groups</th></tr></thead>
    <tbody>$azureTenantRows</tbody>
  </table>
  </div>
</div>
"@} elseif ($AzureTenants.Skipped) {@"
<div class="panel">
  <h2>Microsoft Entra ID</h2>
  <p class="skipped-note">&#9197; User count skipped (<code>-SkipUserCounts</code>).</p>
</div>
"@} else {@"
<div class="panel">
  <h2>Microsoft Entra ID</h2>
  <p class="skipped-note">&#10060; No Microsoft Entra (Azure AD) tenants configured in Active Roles.</p>
</div>
"@})

<!-- =========================== 2.2 EXCHANGE PRESENCE =================== -->
<div class="sec-title" id="sec-exchange"><span class="sec-icon">2.2</span>Microsoft Exchange</div>
$(if ($exchangePresent) {@"
<div class="panel panel-full">
  <h2>Exchange Details &nbsp;<span class="badge badge-green">Detected</span></h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>Organization</th><th>Version</th><th style="text-align:right">Mailbox Databases</th><th>Databases</th><th>PerformanceFlag</th></tr></thead>
    <tbody>
      <tr>
        <td><strong>$(ConvertTo-SafeHtml $ExchangeInfo.Organization)</strong></td>
        <td>$(ConvertTo-SafeHtml $ExchangeInfo.Version)</td>
        <td style="text-align:right">$($ExchangeInfo.DatabaseCount)</td>
        <td>$(ConvertTo-SafeHtml ($ExchangeInfo.MailboxDatabases -join ', '))</td>
        <td>$(if($perfFlagOk){'<span class="badge badge-green">Configured (1)</span>'}else{'<span class="badge badge-red">Not Configured</span>'})</td>
      </tr>
    </tbody>
  </table>
  </div>
$(if (-not $perfFlagOk) {@"
  <div style="margin-top:16px;padding:16px;background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;">
    <strong style="color:#92400e">&#9888; PerformanceFlag Registry Key Not Configured</strong>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      Exchange has been detected but the <code style="background:#fff;padding:2px 6px;border-radius:4px;font-weight:600">PerformanceFlag</code> DWORD registry value is not set to <strong>1</strong> at:
    </p>
    <p style="margin-top:4px;font-family:monospace;font-size:0.85rem;color:#78350f;padding-left:12px">
      HKEY_LOCAL_MACHINE\SOFTWARE\One Identity\Active Roles\Configuration
    </p>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      This registry key is required for optimal Active Roles performance when Exchange is present.
      Please refer to KB article <a href="https://support.oneidentity.com/kb/4336544/" target="_blank" rel="noopener" style="color:#1d4ed8;font-weight:600">KB 4336544</a> for configuration instructions.
    </p>
  </div>
"@})
</div>
"@} else {@"
<div class="panel">
  <h2>Microsoft Exchange</h2>
  <p class="skipped-note">No Microsoft Exchange organization detected in Active Directory.</p>
</div>
"@})

<!-- =========================== 2.3 DISABLE500VA REGISTRY CHECK ========= -->
<div class="sec-title" id="sec-disable500va"><span class="sec-icon">2.3</span>Disable500VA Registry Key</div>
$(if ($disable500VA) {@"
<div class="panel">
  <h2>Disable500VA &nbsp;<span class="badge badge-green">Configured (Value = 1)</span></h2>
  <p style="font-size:0.9rem;color:#374151">The <code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-weight:600">Disable500VA</code> DWORD registry key is correctly set to <strong>1</strong> at:</p>
  <p style="margin-top:4px;font-family:monospace;font-size:0.85rem;color:#4b5563;padding-left:12px">HKEY_LOCAL_MACHINE\SOFTWARE\One Identity\Active Roles\Configuration\Service</p>
</div>
"@} else {@"
<div class="panel">
  <h2>Disable500VA &nbsp;<span class="badge badge-red">Not Configured</span></h2>
  <div style="margin-top:8px;padding:16px;background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;">
    <strong style="color:#92400e">&#9888; Disable500VA Registry Key Not Configured</strong>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      The <code style="background:#fff;padding:2px 6px;border-radius:4px;font-weight:600">Disable500VA</code> 32-bit DWORD registry value is missing or not set to <strong>1</strong> at:
    </p>
    <p style="margin-top:4px;font-family:monospace;font-size:0.85rem;color:#78350f;padding-left:12px">
      HKEY_LOCAL_MACHINE\SOFTWARE\One Identity\Active Roles\Configuration\Service
    </p>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      This registry key should be configured for proper Active Roles operation.
      Please refer to KB article <a href="https://support.oneidentity.com/kb/4216183" target="_blank" rel="noopener" style="color:#1d4ed8;font-weight:600">KB 4216183</a> for details and configuration instructions.
    </p>
  </div>
</div>
"@})

<!-- =========================== 03 SERVER CONFIGURATION ================= -->
<div class="sec-title" id="sec-servers"><span class="sec-icon">03</span>Server Configuration</div>
<div class="panel">
  <h2>AR Service Instances &nbsp;<span class="badge $modeBadge">$serverMode</span> &nbsp;<span class="badge badge-blue">$(Format-Count $Servers.Servers.Count) instance(s)</span></h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>Instance Name</th><th>Version</th><th>Config DB</th><th>Mgmt History Database</th><th>Verbose Logging</th><th>Logging Type</th></tr></thead>
    <tbody>$serverRows</tbody>
  </table>
  </div>
</div>

<!-- =========================== 3.1 REPLICATION - CONFIG DB ============= -->
<div class="sec-title" id="sec-repl-config"><span class="sec-icon">3.1</span>Replication &mdash; Configuration DB</div>
<div class="panel">
  <h2>Configuration DB Replication Partners &nbsp;<span class="badge badge-blue">$(Format-Count $ReplicationPartners.Count) partner(s)</span></h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>Name</th><th>Database Name</th><th>Database Type</th><th>SQL Server Name</th><th>Replication Role</th></tr></thead>
    <tbody>$replRows</tbody>
  </table>
  </div>
</div>

<!-- =========================== 3.2 REPLICATION - MH DB =============== -->
<div class="sec-title" id="sec-repl-mh"><span class="sec-icon">3.2</span>Replication &mdash; Management History DB</div>
<div class="panel">
  <h2>Management History DB Replication Partners &nbsp;<span class="badge badge-blue">$(Format-Count $MHReplicationPartners.Count) partner(s)</span></h2>
  <div style="overflow-x:auto">
  <table>
    <thead><tr><th>Name</th><th>Database Name</th><th>Database Type</th><th>SQL Server Name</th><th>Replication Role</th></tr></thead>
    <tbody>$mhReplRows</tbody>
  </table>
  </div>
</div>

<!-- =========================== 3.3 AUTO SHRINK ========================= -->
<div class="sec-title" id="sec-autoshrink"><span class="sec-icon">3.3</span>Database Auto Shrink</div>
$(if ($autoShrinkChecked) {
    if ($autoShrinkOn) {@"
<div class="panel">
  <h2>Auto Shrink &nbsp;<span class="badge badge-red">Enabled</span></h2>
  <div style="margin-top:8px;padding:16px;background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;">
    <strong style="color:#92400e">&#9888; Auto Shrink is Enabled on the Configuration Database</strong>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      Database <code style="background:#fff;padding:2px 6px;border-radius:4px;font-weight:600">$($AutoShrinkInfo.DatabaseName)</code>
      on SQL Server <code style="background:#fff;padding:2px 6px;border-radius:4px;font-weight:600">$($AutoShrinkInfo.SqlServer)</code>
      has <strong>is_auto_shrink_on = 1</strong>.
    </p>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      Auto Shrink should be <strong>disabled</strong> on Active Roles databases to avoid unnecessary I/O overhead, index fragmentation, and potential performance degradation.
    </p>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      To disable, run: <code style="background:#fff;padding:2px 6px;border-radius:4px">ALTER DATABASE [$($AutoShrinkInfo.DatabaseName)] SET AUTO_SHRINK OFF</code>
    </p>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      See <a href="https://support.oneidentity.com/kb/4381874" target="_blank" rel="noopener" style="color:#2563eb">KB 4381874</a> for details and additional guidance.
    </p>
  </div>
</div>
"@} else {@"
<div class="panel">
  <h2>Auto Shrink &nbsp;<span class="badge badge-green">Disabled (OK)</span></h2>
  <p style="font-size:0.9rem;color:#374151">
    Database <code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-weight:600">$($AutoShrinkInfo.DatabaseName)</code>
    on SQL Server <code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-weight:600">$($AutoShrinkInfo.SqlServer)</code>
    has Auto Shrink correctly disabled (<strong>is_auto_shrink_on = 0</strong>).
  </p>
</div>
"@}
} else {@"
<div class="panel">
  <h2>Auto Shrink &nbsp;<span class="badge badge-gray">Not Checked</span></h2>
  <div style="margin-top:8px;padding:16px;background:#f3f4f6;border:1px solid #d1d5db;border-radius:8px;">
    <p style="color:#4b5563;font-size:0.9rem">
      Could not verify Auto Shrink status. $(if ($AutoShrinkInfo.Error) { "Error: $($AutoShrinkInfo.Error)" } else { "The Configuration DB could not be discovered or connected to." })
    </p>
  </div>
</div>
"@})

<!-- =========================== 3.4 ALWAYSON AVAILABILITY =============== -->
<div class="sec-title" id="sec-alwayson"><span class="sec-icon">3.4</span>SQL Server AlwaysOn &amp; MultiSubnetFailover</div>
$(if ($alwaysOnChecked) {
    if ($alwaysOnEnabled) {
        if ($multiSubnetOk -eq $true) {@"
<div class="panel">
  <h2>AlwaysOn &nbsp;<span class="badge badge-green">Enabled</span> &nbsp; MultiSubnetFailover &nbsp;<span class="badge badge-green">Enabled (OK)</span></h2>
  <p style="font-size:0.9rem;color:#374151">
    SQL Server <code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-weight:600">$($AlwaysOnInfo.SqlServer)</code>
    has AlwaysOn Availability Groups enabled and the Active Roles
    <strong>MultiSubnetFailoverSupport</strong> setting is correctly configured.
  </p>
</div>
"@} elseif ($multiSubnetOk -eq $false) {@"
<div class="panel">
  <h2>AlwaysOn &nbsp;<span class="badge badge-green">Enabled</span> &nbsp; MultiSubnetFailover &nbsp;<span class="badge badge-red">Not Enabled</span></h2>
  <div style="margin-top:8px;padding:16px;background:#fef3c7;border:1px solid #f59e0b;border-radius:8px;">
    <strong style="color:#92400e">&#9888; MultiSubnetFailoverSupport is Not Enabled</strong>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      SQL Server <code style="background:#fff;padding:2px 6px;border-radius:4px;font-weight:600">$($AlwaysOnInfo.SqlServer)</code>
      has AlwaysOn Availability Groups enabled, but the Active Roles
      <strong>MultiSubnetFailoverSupport</strong> setting is <strong>not enabled</strong>.
    </p>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      When using SQL Server AlwaysOn, <strong>MultiSubnetFailoverSupport</strong> should be enabled
      in Active Roles to ensure proper failover behavior and faster connection recovery across subnets.
    </p>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      To verify the current setting, run:
      <code style="background:#fff;padding:2px 6px;border-radius:4px">Get-ARService -IncludeAdvancedDatabaseSettings | fl MultiSubnetFailoverSupport</code>
    </p>
    <p style="margin-top:8px;color:#78350f;font-size:0.9rem">
      See <a href="https://support.oneidentity.com/kb/4374079" target="_blank" rel="noopener" style="color:#2563eb">KB 4374079</a> for instructions on enabling MultiSubnetFailoverSupport.
    </p>
  </div>
</div>
"@} else {@"
<div class="panel">
  <h2>AlwaysOn &nbsp;<span class="badge badge-green">Enabled</span> &nbsp; MultiSubnetFailover &nbsp;<span class="badge badge-gray">Unknown</span></h2>
  <div style="margin-top:8px;padding:16px;background:#f3f4f6;border:1px solid #d1d5db;border-radius:8px;">
    <p style="color:#4b5563;font-size:0.9rem">
      SQL Server <code style="background:#fff;padding:2px 6px;border-radius:4px;font-weight:600">$($AlwaysOnInfo.SqlServer)</code>
      has AlwaysOn Availability Groups enabled, but the MultiSubnetFailoverSupport setting
      could not be verified.$(if ($AlwaysOnInfo.Error) { " Error: $($AlwaysOnInfo.Error)" })
    </p>
    <p style="margin-top:8px;color:#4b5563;font-size:0.9rem">
      To verify manually, run:
      <code style="background:#fff;padding:2px 6px;border-radius:4px">Get-ARService -IncludeAdvancedDatabaseSettings | fl MultiSubnetFailoverSupport</code>
    </p>
    <p style="margin-top:8px;color:#4b5563;font-size:0.9rem">
      See <a href="https://support.oneidentity.com/kb/4374079" target="_blank" rel="noopener" style="color:#2563eb">KB 4374079</a> for details.
    </p>
  </div>
</div>
"@}
    } else {@"
<div class="panel">
  <h2>AlwaysOn &nbsp;<span class="badge badge-gray">Not Enabled</span></h2>
  <p style="font-size:0.9rem;color:#374151">
    SQL Server <code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-weight:600">$($AlwaysOnInfo.SqlServer)</code>
    does not have AlwaysOn Availability Groups enabled. MultiSubnetFailoverSupport check is not applicable.
  </p>
</div>
"@}
} else {@"
<div class="panel">
  <h2>AlwaysOn &nbsp;<span class="badge badge-gray">Not Checked</span></h2>
  <div style="margin-top:8px;padding:16px;background:#f3f4f6;border:1px solid #d1d5db;border-radius:8px;">
    <p style="color:#4b5563;font-size:0.9rem">
      Could not verify AlwaysOn status.$(if ($AlwaysOnInfo.Error) { " Error: $($AlwaysOnInfo.Error)" } else { " The Configuration DB could not be discovered or connected to." })
    </p>
  </div>
</div>
"@})

<!-- =========================== 04 DYNAMIC GROUPS ======================= -->
<div class="sec-title" id="sec-dyngroups"><span class="sec-icon">04</span>Dynamic Groups</div>
<div class="panel-grid">
  <div class="panel">
    <h2>Summary</h2>
    <div class="kpi-grid" style="grid-template-columns:1fr 1fr;margin-bottom:18px">
      <div class="kpi purple" style="padding:14px">
        <div class="lbl">Total</div>
        <div class="val">$(Format-Count $DynamicGroups.TotalCount)</div>
      </div>
      <div class="kpi $(if($DynamicGroups.BrokenCount -gt 0){'red'}else{'green'})" style="padding:14px">
        <div class="lbl">Broken Rules</div>
        <div class="val">$($DynamicGroups.BrokenCount)</div>
      </div>
    </div>
    <div class="chart-wrap"><canvas id="dgChart"></canvas></div>
  </div>
  <div class="panel">
    <h2>Broken Rules Details</h2>
    $dgBrokenSection
  </div>
</div>

<!-- =========================== 05 MANAGED UNITS ======================== -->
<div class="sec-title" id="sec-mu"><span class="sec-icon">05</span>Managed Units</div>
<div class="panel-grid">
  <div class="panel">
    <h2>Summary</h2>
    <div class="kpi-grid" style="grid-template-columns:1fr 1fr;margin-bottom:18px">
      <div class="kpi purple" style="padding:14px">
        <div class="lbl">Total</div>
        <div class="val">$(Format-Count $ManagedUnits.TotalCount)</div>
      </div>
      <div class="kpi $(if($ManagedUnits.BrokenCount -gt 0){'red'}else{'green'})" style="padding:14px">
        <div class="lbl">Broken Rules</div>
        <div class="val">$($ManagedUnits.BrokenCount)</div>
      </div>
    </div>
    <div class="chart-wrap"><canvas id="muChart"></canvas></div>
  </div>
  <div class="panel">
    <h2>Broken Rules Details</h2>
    $muBrokenSection
  </div>
</div>

<!-- =========================== 06 WORKFLOWS ========================== -->
<div class="sec-title" id="sec-workflows"><span class="sec-icon">06</span>Workflows</div>
<div class="panel-grid">
  <div class="panel">
    <h2>Summary</h2>
    <div class="kpi-grid" style="grid-template-columns:1fr 1fr 1fr;margin-bottom:18px">
      <div class="kpi amber" style="padding:14px">
        <div class="lbl">Total</div>
        <div class="val">$(Format-Count $Workflows.TotalCount)</div>
      </div>
      <div class="kpi green" style="padding:14px">
        <div class="lbl">Enabled</div>
        <div class="val">$($Workflows.EnabledCount)</div>
      </div>
      <div class="kpi $(if($Workflows.DisabledCount -gt 0){'red'}else{'green'})" style="padding:14px">
        <div class="lbl">Disabled</div>
        <div class="val">$($Workflows.DisabledCount)</div>
      </div>
    </div>
    <div class="chart-wrap"><canvas id="wfChart"></canvas></div>
  </div>
  <div class="panel">
    <h2>Workflow List &nbsp;<span class="badge badge-blue">$(Format-Count $Workflows.TotalCount)</span></h2>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
      <input type="text" class="search-box" id="wfSearch" placeholder="Search workflows...">
      <div style="display:flex;align-items:center;gap:8px">
        <label style="font-size:.82rem;color:#6b7280;white-space:nowrap">Show
          <select id="wfPageSize" onchange="changeWfPageSize(this.value)" style="padding:4px 8px;border:1px solid #d1d5db;border-radius:6px;font-size:.82rem;background:#fff;cursor:pointer">
            <option value="10" selected>10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </label>
        <button class="btn" onclick="exportWfCSV()">Export CSV</button>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table id="wfTable"><thead><tr id="wfTableHead"></tr></thead><tbody id="wfTableBody"></tbody></table>
    </div>
    <div class="pagination"><span id="wfPageInfo"></span><div class="pagination-btns" id="wfPagBtns"></div></div>
  </div>
</div>

<!-- =========================== 07 POLICY OBJECTS ===================== -->
<div class="sec-title" id="sec-policies"><span class="sec-icon">07</span>Policy Objects</div>
<div class="panel-grid">
  <div class="panel">
    <h2>Summary</h2>
    <div class="kpi-grid" style="grid-template-columns:1fr 1fr 1fr 1fr;margin-bottom:18px">
      <div class="kpi green" style="padding:14px">
        <div class="lbl">Total</div>
        <div class="val">$(Format-Count $PolicyObjects.TotalCount)</div>
      </div>
      <div class="kpi green" style="padding:14px">
        <div class="lbl">Enabled</div>
        <div class="val">$($PolicyObjects.EnabledCount)</div>
      </div>
      <div class="kpi $(if($PolicyObjects.DisabledCount -gt 0){'red'}else{'green'})" style="padding:14px">
        <div class="lbl">Disabled</div>
        <div class="val">$($PolicyObjects.DisabledCount)</div>
      </div>
      <div class="kpi $orphanBadgeClass" style="padding:14px">
        <div class="lbl">Orphan Links</div>
        <div class="val">$safeOrphan</div>
      </div>
    </div>
    <div class="chart-wrap"><canvas id="poChart"></canvas></div>
  </div>
  <div class="panel">
    <h2>Policy List &nbsp;<span class="badge badge-blue">$(Format-Count $PolicyObjects.TotalCount)</span></h2>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
      <input type="text" class="search-box" id="poSearch" placeholder="Search policies...">
      <div style="display:flex;align-items:center;gap:8px">
        <label style="font-size:.82rem;color:#6b7280;white-space:nowrap">Show
          <select id="poPageSize" onchange="changePoPageSize(this.value)" style="padding:4px 8px;border:1px solid #d1d5db;border-radius:6px;font-size:.82rem;background:#fff;cursor:pointer">
            <option value="10" selected>10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </label>
        <button class="btn" onclick="exportPoCSV()">Export CSV</button>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table id="poTable"><thead><tr id="poTableHead"></tr></thead><tbody id="poTableBody"></tbody></table>
    </div>
    <div class="pagination"><span id="poPageInfo"></span><div class="pagination-btns" id="poPagBtns"></div></div>
  </div>
</div>
$(if ($safeOrphan -gt 0) {@"
<div class="panel" style="margin-bottom:24px;border-left:4px solid #dc2626">
  <h2 style="color:#dc2626">Orphan Policy Object Links &nbsp;<span class="badge badge-red">$safeOrphan found</span></h2>
  <p style="font-size:.85rem;color:#6b7280;margin-bottom:12px">
    These policy links reference a missing target object or a missing policy object.
    This can occur when objects are deleted without cleaning up their policy links.
    <br><strong>Recommendation:</strong> Review and remove orphan links using PowerShell.
    See <a href="https://support.oneidentity.com/kb/4338749" target="_blank" rel="noopener" style="color:#2563eb">KB 4338749</a> for removal instructions
    and <a href="https://support.oneidentity.com/kb/4381874" target="_blank" rel="noopener" style="color:#2563eb">KB 4381874</a> for additional guidance.
  </p>
  <div style="display:flex;justify-content:flex-end;margin-bottom:12px">
    <button class="btn" onclick="exportOrphanPoCSV()">Export CSV</button>
  </div>
  <div style="overflow-x:auto">
    <table id="orphanPoTable"><thead><tr id="orphanPoTableHead"></tr></thead><tbody id="orphanPoTableBody"></tbody></table>
  </div>
  <div class="pagination"><span id="orphanPoPageInfo"></span><div class="pagination-btns" id="orphanPoPagBtns"></div></div>
</div>
"@})

<!-- =========================== 08 ACCESS TEMPLATES ===================== -->
<div class="sec-title" id="sec-at"><span class="sec-icon">08</span>Access Templates</div>
<div class="panel-grid">
  <div class="panel">
    <h2>Summary</h2>
    <div class="kpi-grid" style="grid-template-columns:1fr$(if ($safeOrphanAt -gt 0) {' 1fr'});margin-bottom:18px">
      <div class="kpi blue" style="padding:14px">
        <div class="lbl">Custom</div>
        <div class="val">$($AccessTemplates.CustomCount)</div>
      </div>
      $(if ($safeOrphanAt -gt 0) {"<div class='kpi red' style='padding:14px'><div class='lbl'>Orphan Links</div><div class='val'>$safeOrphanAt</div></div>"})
    </div>
    <div class="chart-wrap"><canvas id="atChart"></canvas></div>
  </div>
  <div class="panel">
    <h2>Custom Access Templates &nbsp;<span class="badge badge-blue">$(Format-Count $AccessTemplates.CustomCount)</span></h2>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
      <input type="text" class="search-box" id="atSearch" placeholder="Search access templates...">
      <div style="display:flex;align-items:center;gap:8px">
        <label style="font-size:.82rem;color:#6b7280;white-space:nowrap">Show
          <select id="atPageSize" onchange="changeAtPageSize(this.value)" style="padding:4px 8px;border:1px solid #d1d5db;border-radius:6px;font-size:.82rem;background:#fff;cursor:pointer">
            <option value="10" selected>10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </label>
        <button class="btn" onclick="exportAtCSV()">Export CSV</button>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table id="atTable"><thead><tr id="atTableHead"></tr></thead><tbody id="atTableBody"></tbody></table>
    </div>
    <div class="pagination"><span id="atPageInfo"></span><div class="pagination-btns" id="atPagBtns"></div></div>
  </div>
</div>
$(if ($safeOrphanAt -gt 0) {@"
<div class="panel" style="margin-bottom:24px;border-left:4px solid #dc2626">
  <h2 style="color:#dc2626">Orphan Access Template Links &nbsp;<span class="badge badge-red">$safeOrphanAt found</span></h2>
  <p style="font-size:.85rem;color:#6b7280;margin-bottom:12px">
    These Access Template links reference a missing target object or a missing trustee SID.
    This can occur when objects or security principals are deleted without cleaning up their AT links.
    <br><strong>Recommendation:</strong> Review and remove orphan links using PowerShell.
    See <a href="https://support.oneidentity.com/kb/4338749" target="_blank" rel="noopener" style="color:#2563eb">KB 4338749</a> for removal instructions
    and <a href="https://support.oneidentity.com/kb/4381874" target="_blank" rel="noopener" style="color:#2563eb">KB 4381874</a> for additional guidance.
  </p>
  <div style="display:flex;justify-content:flex-end;margin-bottom:12px">
    <button class="btn" onclick="exportOrphanAtCSV()">Export CSV</button>
  </div>
  <div style="overflow-x:auto">
    <table id="orphanAtTable"><thead><tr id="orphanAtTableHead"></tr></thead><tbody id="orphanAtTableBody"></tbody></table>
  </div>
  <div class="pagination"><span id="orphanAtPageInfo"></span><div class="pagination-btns" id="orphanAtPagBtns"></div></div>
</div>
"@})

<!-- =========================== 09 VIRTUAL ATTRIBUTES =================== -->
<div class="sec-title" id="sec-va"><span class="sec-icon">09</span>Virtual Attributes</div>
<div class="panel-grid">
  <div class="panel">
    <h2>Summary</h2>
    <div class="kpi-grid" style="grid-template-columns:1fr 1fr;margin-bottom:18px">
      <div class="kpi blue" style="padding:14px">
        <div class="lbl">Custom</div>
        <div class="val">$($VirtualAttrs.CustomCount)</div>
      </div>
      <div class="kpi green" style="padding:14px">
        <div class="lbl">Built-in</div>
        <div class="val">$($VirtualAttrs.BuiltInCount)</div>
      </div>
    </div>
    <div class="chart-wrap"><canvas id="vaChart"></canvas></div>
  </div>
  <div class="panel">
    <h2>Custom Virtual Attributes &nbsp;<span class="badge badge-blue">$(Format-Count $VirtualAttrs.CustomCount)</span></h2>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:8px">
      <input type="text" class="search-box" id="vaSearch" placeholder="Search attributes...">
      <div style="display:flex;align-items:center;gap:8px">
        <label style="font-size:.82rem;color:#6b7280;white-space:nowrap">Show
          <select id="vaPageSize" onchange="changeVaPageSize(this.value)" style="padding:4px 8px;border:1px solid #d1d5db;border-radius:6px;font-size:.82rem;background:#fff;cursor:pointer">
            <option value="10" selected>10</option>
            <option value="25">25</option>
            <option value="50">50</option>
            <option value="100">100</option>
          </select>
        </label>
        <button class="btn" onclick="exportVACSV()">Export CSV</button>
      </div>
    </div>
    <div style="overflow-x:auto">
      <table id="vaTable"><thead><tr id="vaTableHead"></tr></thead><tbody id="vaTableBody"></tbody></table>
    </div>
    <div class="pagination"><span id="vaPageInfo"></span><div class="pagination-btns" id="vaPagBtns"></div></div>
  </div>
</div>

<!-- =========================== 10 KNOWN ISSUES ========================== -->
<div class="sec-title" id="sec-config"><span class="sec-icon">10</span>Known Issues</div>
<div class="panel-grid">
  <div class="panel" style="grid-column:1/-1">
    <h2>Additional References</h2>
    <p style="margin:0;line-height:1.6;color:#374151">
      This report covers the most common health checks for Active Roles. For a comprehensive list
      of additional known issues, workarounds, and troubleshooting references, please consult the
      official One Identity Knowledge Base article:
    </p>
    <p style="margin:12px 0 0 0">
      <a href="https://support.oneidentity.com/kb/4340870" target="_blank" rel="noopener noreferrer"
         style="display:inline-block;padding:10px 16px;background:#2563eb;color:#fff;text-decoration:none;border-radius:6px;font-weight:600">
        One Identity KB 4340870 &mdash; Active Roles Known Issues &rarr;
      </a>
    </p>
    <p style="margin:12px 0 0 0;font-size:.85rem;color:#6b7280">
      Review this knowledge base periodically as One Identity publishes updates, hotfixes and
      advisories for the product.
    </p>
  </div>
</div>

<div class="footer">
  Generated by <strong>Get-ARAssessmentReport.ps1</strong> &bull;
  One Identity Active Roles &bull; $reportDate
</div>

</div><!-- /page -->

<script>
const VA_DATA = $vaJsonData;
const VA_COLUMNS = [{key:'name',label:'Attribute Name'},{key:'syntax',label:'Syntax'},{key:'description',label:'Description'}];
let vaS = {data:[],filtered:[],page:1,pageSize:10,sortCol:null,sortAsc:true};
function changeVaPageSize(v){vaS.pageSize=parseInt(v)||10;vaS.page=1;renderVATableBody()}

const WF_DATA = $wfJsonData;
const WF_COLUMNS = [{key:'name',label:'Workflow Name'},{key:'status',label:'Status'},{key:'description',label:'Description'}];
let wfS = {data:[],filtered:[],page:1,pageSize:10,sortCol:null,sortAsc:true};
function changeWfPageSize(v){wfS.pageSize=parseInt(v)||10;wfS.page=1;renderWfTableBody()}
function renderWfTableHead(){document.getElementById('wfTableHead').innerHTML=WF_COLUMNS.map((c,i)=>'<th onclick="sortWfTable('+i+')" data-col="'+i+'">'+c.label+' <span class="sort-icon">&#9650;</span></th>').join('')}
function renderWfTableBody(){const ps=wfS.pageSize;const s=(wfS.page-1)*ps;const p=wfS.filtered.slice(s,s+ps);document.getElementById('wfTableBody').innerHTML=p.map(r=>'<tr>'+WF_COLUMNS.map(c=>{let v=r[c.key]??'';if(c.key==='status'){const cls=v==='Enabled'?'badge-green':'badge-red';return'<td><span class="badge '+cls+'">'+v+'</span></td>'}return'<td>'+v+'</td>'}).join('')+'</tr>').join('');renderWfPag()}
function renderWfPag(){const ps=wfS.pageSize;const t=wfS.filtered.length;const tp=Math.ceil(t/ps);const s=(wfS.page-1)*ps+1;const e=Math.min(wfS.page*ps,t);document.getElementById('wfPageInfo').textContent=t>0?s+'-'+e+' of '+t:'No results';const b=document.getElementById('wfPagBtns');if(tp<=1){b.innerHTML='';return}let h='<button onclick="goWfPage('+(wfS.page-1)+')"'+(wfS.page===1?' disabled':'')+'>&laquo;</button>';for(let pg=Math.max(1,wfS.page-2);pg<=Math.min(tp,wfS.page+2);pg++)h+='<button class="'+(pg===wfS.page?'active':'')+'" onclick="goWfPage('+pg+')">'+pg+'</button>';h+='<button onclick="goWfPage('+(wfS.page+1)+')"'+(wfS.page===tp?' disabled':'')+'>&raquo;</button>';b.innerHTML=h}
function sortWfTable(i){const k=WF_COLUMNS[i].key;if(wfS.sortCol===i)wfS.sortAsc=!wfS.sortAsc;else{wfS.sortCol=i;wfS.sortAsc=true}wfS.filtered.sort((a,b)=>{let va=(a[k]??'').toString().toLowerCase(),vb=(b[k]??'').toString().toLowerCase();return wfS.sortAsc?va.localeCompare(vb):vb.localeCompare(va)});document.querySelectorAll('#wfTableHead th').forEach((th,j)=>{th.classList.toggle('sorted',j===i);th.querySelector('.sort-icon').innerHTML=(j===i&&!wfS.sortAsc)?'&#9660;':'&#9650;'});wfS.page=1;renderWfTableBody()}
function filterWfTable(q){q=q.toLowerCase().trim();wfS.filtered=q===''?[...wfS.data]:wfS.data.filter(r=>WF_COLUMNS.some(c=>(r[c.key]??'').toString().toLowerCase().includes(q)));wfS.page=1;renderWfTableBody()}
function goWfPage(p){const tp=Math.ceil(wfS.filtered.length/wfS.pageSize);if(p<1||p>tp)return;wfS.page=p;renderWfTableBody()}
function exportWfCSV(){const h=WF_COLUMNS.map(c=>c.label).join(',');const rows=wfS.filtered.map(r=>WF_COLUMNS.map(c=>'"'+(r[c.key]??'').toString().replace(/"/g,'""')+'"').join(','));const csv='\uFEFF'+h+'\n'+rows.join('\n');const b=new Blob([csv],{type:'text/csv;charset=utf-8;'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='workflows_'+new Date().toISOString().slice(0,10)+'.csv';a.click()}
const PO_DATA = $poJsonData;
const PO_COLUMNS = [{key:'name',label:'Policy Name'},{key:'status',label:'Status'},{key:'description',label:'Description'}];
let poS = {data:[],filtered:[],page:1,pageSize:10,sortCol:null,sortAsc:true};
function changePoPageSize(v){poS.pageSize=parseInt(v)||10;poS.page=1;renderPoTableBody()}
function renderPoTableHead(){document.getElementById('poTableHead').innerHTML=PO_COLUMNS.map((c,i)=>'<th onclick="sortPoTable('+i+')" data-col="'+i+'">'+c.label+' <span class="sort-icon">&#9650;</span></th>').join('')}
function renderPoTableBody(){const ps=poS.pageSize;const s=(poS.page-1)*ps;const p=poS.filtered.slice(s,s+ps);document.getElementById('poTableBody').innerHTML=p.map(r=>'<tr>'+PO_COLUMNS.map(c=>{let v=r[c.key]??'';if(c.key==='status'){const cls=v==='Enabled'?'badge-green':'badge-red';return'<td><span class="badge '+cls+'">'+v+'</span></td>'}return'<td>'+v+'</td>'}).join('')+'</tr>').join('');renderPoPag()}
function renderPoPag(){const ps=poS.pageSize;const t=poS.filtered.length;const tp=Math.ceil(t/ps);const s=(poS.page-1)*ps+1;const e=Math.min(poS.page*ps,t);document.getElementById('poPageInfo').textContent=t>0?s+'-'+e+' of '+t:'No results';const b=document.getElementById('poPagBtns');if(tp<=1){b.innerHTML='';return}let h='<button onclick="goPoPage('+(poS.page-1)+')"'+(poS.page===1?' disabled':'')+'>&laquo;</button>';for(let pg=Math.max(1,poS.page-2);pg<=Math.min(tp,poS.page+2);pg++)h+='<button class="'+(pg===poS.page?'active':'')+'" onclick="goPoPage('+pg+')">'+pg+'</button>';h+='<button onclick="goPoPage('+(poS.page+1)+')"'+(poS.page===tp?' disabled':'')+'>&raquo;</button>';b.innerHTML=h}
function sortPoTable(i){const k=PO_COLUMNS[i].key;if(poS.sortCol===i)poS.sortAsc=!poS.sortAsc;else{poS.sortCol=i;poS.sortAsc=true}poS.filtered.sort((a,b)=>{let va=(a[k]??'').toString().toLowerCase(),vb=(b[k]??'').toString().toLowerCase();return poS.sortAsc?va.localeCompare(vb):vb.localeCompare(va)});document.querySelectorAll('#poTableHead th').forEach((th,j)=>{th.classList.toggle('sorted',j===i);th.querySelector('.sort-icon').innerHTML=(j===i&&!poS.sortAsc)?'&#9660;':'&#9650;'});poS.page=1;renderPoTableBody()}
function filterPoTable(q){q=q.toLowerCase().trim();poS.filtered=q===''?[...poS.data]:poS.data.filter(r=>PO_COLUMNS.some(c=>(r[c.key]??'').toString().toLowerCase().includes(q)));poS.page=1;renderPoTableBody()}
function goPoPage(p){const tp=Math.ceil(poS.filtered.length/poS.pageSize);if(p<1||p>tp)return;poS.page=p;renderPoTableBody()}
function exportPoCSV(){const h=PO_COLUMNS.map(c=>c.label).join(',');const rows=poS.filtered.map(r=>PO_COLUMNS.map(c=>'"'+(r[c.key]??'').toString().replace(/"/g,'""')+'"').join(','));const csv='\uFEFF'+h+'\n'+rows.join('\n');const b=new Blob([csv],{type:'text/csv;charset=utf-8;'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='policy_objects_'+new Date().toISOString().slice(0,10)+'.csv';a.click()}
function renderVATableHead(){document.getElementById('vaTableHead').innerHTML=VA_COLUMNS.map((c,i)=>'<th onclick="sortVATable('+i+')" data-col="'+i+'">'+c.label+' <span class="sort-icon">&#9650;</span></th>').join('')}
function renderVATableBody(){const ps=vaS.pageSize;const s=(vaS.page-1)*ps;const p=vaS.filtered.slice(s,s+ps);document.getElementById('vaTableBody').innerHTML=p.map(r=>'<tr>'+VA_COLUMNS.map(c=>'<td>'+(r[c.key]??'')+'</td>').join('')+'</tr>').join('');renderVAPag()}
function renderVAPag(){const ps=vaS.pageSize;const t=vaS.filtered.length;const tp=Math.ceil(t/ps);const s=(vaS.page-1)*ps+1;const e=Math.min(vaS.page*ps,t);document.getElementById('vaPageInfo').textContent=t>0?s+'-'+e+' of '+t:'No results';const b=document.getElementById('vaPagBtns');if(tp<=1){b.innerHTML='';return}let h='<button onclick="goVAPage('+(vaS.page-1)+')"'+(vaS.page===1?' disabled':'')+'>&laquo;</button>';for(let pg=Math.max(1,vaS.page-2);pg<=Math.min(tp,vaS.page+2);pg++)h+='<button class="'+(pg===vaS.page?'active':'')+'" onclick="goVAPage('+pg+')">'+pg+'</button>';h+='<button onclick="goVAPage('+(vaS.page+1)+')"'+(vaS.page===tp?' disabled':'')+'>&raquo;</button>';b.innerHTML=h}
function sortVATable(i){const k=VA_COLUMNS[i].key;if(vaS.sortCol===i)vaS.sortAsc=!vaS.sortAsc;else{vaS.sortCol=i;vaS.sortAsc=true}vaS.filtered.sort((a,b)=>{let va=(a[k]??'').toString().toLowerCase(),vb=(b[k]??'').toString().toLowerCase();return vaS.sortAsc?va.localeCompare(vb):vb.localeCompare(va)});document.querySelectorAll('#vaTableHead th').forEach((th,j)=>{th.classList.toggle('sorted',j===i);th.querySelector('.sort-icon').innerHTML=(j===i&&!vaS.sortAsc)?'&#9660;':'&#9650;'});vaS.page=1;renderVATableBody()}
function filterVATable(q){q=q.toLowerCase().trim();vaS.filtered=q===''?[...vaS.data]:vaS.data.filter(r=>VA_COLUMNS.some(c=>(r[c.key]??'').toString().toLowerCase().includes(q)));vaS.page=1;renderVATableBody()}
function goVAPage(p){const tp=Math.ceil(vaS.filtered.length/vaS.pageSize);if(p<1||p>tp)return;vaS.page=p;renderVATableBody()}
function exportVACSV(){const h=VA_COLUMNS.map(c=>c.label).join(',');const rows=vaS.filtered.map(r=>VA_COLUMNS.map(c=>'"'+(r[c.key]??'').toString().replace(/"/g,'""')+'"').join(','));const csv='\uFEFF'+h+'\n'+rows.join('\n');const b=new Blob([csv],{type:'text/csv;charset=utf-8;'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='virtual_attributes_'+new Date().toISOString().slice(0,10)+'.csv';a.click()}
Chart.defaults.font.family = "'Segoe UI', system-ui, sans-serif";
Chart.defaults.font.size = 12;

const doughnutOpts = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: {
    legend: { position: 'bottom', labels: { boxWidth: 14, padding: 16 } }
  },
  cutout: '62%'
};

// Managed Users per Domain chart
const UC_DATA = $userCountChartData;
if (UC_DATA && UC_DATA.length > 0) {
  new Chart(document.getElementById('userCountChart'), {
    type: 'bar',
    data: {
      labels: UC_DATA.map(d => d.name || 'N/A'),
      datasets: [{
        label: 'Users',
        data: UC_DATA.map(d => d.value || 0),
        backgroundColor: ['#0d9488','#2563eb','#7c3aed','#d97706','#db2777','#16a34a','#ea580c','#6366f1'].slice(0, UC_DATA.length),
        borderRadius: 6,
        maxBarThickness: 60
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: '#f3f4f6' } },
        x: { grid: { display: false } }
      }
    }
  });
}

// Dynamic Groups chart
new Chart(document.getElementById('dgChart'), {
  type: 'doughnut',
  data: {
    labels: ['Healthy', 'Broken Rules'],
    datasets: [{ data: $dgChartData, backgroundColor: ['#16a34a','#dc2626'], borderWidth: 0 }]
  },
  options: doughnutOpts
});

// Managed Units chart
new Chart(document.getElementById('muChart'), {
  type: 'doughnut',
  data: {
    labels: ['Healthy', 'Broken Rules'],
    datasets: [{ data: $muChartData, backgroundColor: ['#16a34a','#dc2626'], borderWidth: 0 }]
  },
  options: doughnutOpts
});

// Workflows chart
new Chart(document.getElementById('wfChart'), {
  type: 'doughnut',
  data: {
    labels: ['Enabled', 'Disabled'],
    datasets: [{ data: $wfChartData, backgroundColor: ['#16a34a','#dc2626'], borderWidth: 0 }]
  },
  options: doughnutOpts
});
// Workflows interactive table
wfS.data = WF_DATA || []; wfS.filtered = [...wfS.data]; renderWfTableHead(); renderWfTableBody();
document.getElementById('wfSearch').addEventListener('input', function(e){ filterWfTable(e.target.value); });

// Policy Objects chart
new Chart(document.getElementById('poChart'), {
  type: 'doughnut',
  data: {
    labels: ['Enabled', 'Disabled', 'Orphan Links'],
    datasets: [{ data: $poChartData, backgroundColor: ['#16a34a','#d97706','#dc2626'], borderWidth: 0 }]
  },
  options: doughnutOpts
});
// Policy Objects interactive table
poS.data = PO_DATA || []; poS.filtered = [...poS.data]; renderPoTableHead(); renderPoTableBody();
document.getElementById('poSearch').addEventListener('input', function(e){ filterPoTable(e.target.value); });

// Orphan Policy Links interactive table
const ORPHAN_PO_DATA = $orphanPoJsonData;
const ORPHAN_PO_COLUMNS = [{key:'dn',label:'Distinguished Name'},{key:'reason',label:'Reason'}];
let orphanPoS = {data:[],filtered:[],page:1,pageSize:10,sortCol:null,sortAsc:true};
function renderOrphanPoTableHead(){const el=document.getElementById('orphanPoTableHead');if(!el)return;el.innerHTML=ORPHAN_PO_COLUMNS.map((c,i)=>'<th onclick="sortOrphanPoTable('+i+')" data-col="'+i+'">'+c.label+' <span class="sort-icon">&#9650;</span></th>').join('')}
function renderOrphanPoTableBody(){const el=document.getElementById('orphanPoTableBody');if(!el)return;const ps=orphanPoS.pageSize;const s=(orphanPoS.page-1)*ps;const p=orphanPoS.filtered.slice(s,s+ps);el.innerHTML=p.map(r=>'<tr>'+ORPHAN_PO_COLUMNS.map(c=>'<td style="word-break:break-all">'+(r[c.key]??'')+'</td>').join('')+'</tr>').join('');renderOrphanPoPag()}
function renderOrphanPoPag(){const el=document.getElementById('orphanPoPageInfo');if(!el)return;const ps=orphanPoS.pageSize;const t=orphanPoS.filtered.length;const tp=Math.ceil(t/ps);const s=(orphanPoS.page-1)*ps+1;const e=Math.min(orphanPoS.page*ps,t);el.textContent=t>0?s+'-'+e+' of '+t:'No results';const b=document.getElementById('orphanPoPagBtns');if(tp<=1){b.innerHTML='';return}let h='<button onclick="goOrphanPoPage('+(orphanPoS.page-1)+')"'+(orphanPoS.page===1?' disabled':'')+'>&laquo;</button>';for(let pg=Math.max(1,orphanPoS.page-2);pg<=Math.min(tp,orphanPoS.page+2);pg++)h+='<button class="'+(pg===orphanPoS.page?'active':'')+'" onclick="goOrphanPoPage('+pg+')">'+pg+'</button>';h+='<button onclick="goOrphanPoPage('+(orphanPoS.page+1)+')"'+(orphanPoS.page===tp?' disabled':'')+'>&raquo;</button>';b.innerHTML=h}
function sortOrphanPoTable(i){const k=ORPHAN_PO_COLUMNS[i].key;if(orphanPoS.sortCol===i)orphanPoS.sortAsc=!orphanPoS.sortAsc;else{orphanPoS.sortCol=i;orphanPoS.sortAsc=true}orphanPoS.filtered.sort((a,b)=>{let va=(a[k]??'').toString().toLowerCase(),vb=(b[k]??'').toString().toLowerCase();return orphanPoS.sortAsc?va.localeCompare(vb):vb.localeCompare(va)});document.querySelectorAll('#orphanPoTableHead th').forEach((th,j)=>{th.classList.toggle('sorted',j===i);th.querySelector('.sort-icon').innerHTML=(j===i&&!orphanPoS.sortAsc)?'&#9660;':'&#9650;'});orphanPoS.page=1;renderOrphanPoTableBody()}
function goOrphanPoPage(p){const tp=Math.ceil(orphanPoS.filtered.length/orphanPoS.pageSize);if(p<1||p>tp)return;orphanPoS.page=p;renderOrphanPoTableBody()}
function exportOrphanPoCSV(){const h=ORPHAN_PO_COLUMNS.map(c=>c.label).join(',');const rows=orphanPoS.filtered.map(r=>ORPHAN_PO_COLUMNS.map(c=>'"'+(r[c.key]??'').toString().replace(/"/g,'""')+'"').join(','));const csv='\uFEFF'+h+'\n'+rows.join('\n');const b=new Blob([csv],{type:'text/csv;charset=utf-8;'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='orphan_policy_links_'+new Date().toISOString().slice(0,10)+'.csv';a.click()}
if(ORPHAN_PO_DATA&&ORPHAN_PO_DATA.length>0){orphanPoS.data=ORPHAN_PO_DATA;orphanPoS.filtered=[...orphanPoS.data];renderOrphanPoTableHead();renderOrphanPoTableBody()}

// Access Templates chart and interactive table
const AT_DATA = $atJsonData;
const AT_COLUMNS = [{key:'name',label:'Template Name'},{key:'description',label:'Description'}];
let atS = {data:[],filtered:[],page:1,pageSize:10,sortCol:null,sortAsc:true};
function changeAtPageSize(v){atS.pageSize=parseInt(v)||10;atS.page=1;renderAtTableBody()}
function renderAtTableHead(){document.getElementById('atTableHead').innerHTML=AT_COLUMNS.map((c,i)=>'<th onclick="sortAtTable('+i+')" data-col="'+i+'">'+c.label+' <span class="sort-icon">&#9650;</span></th>').join('')}
function renderAtTableBody(){const ps=atS.pageSize;const s=(atS.page-1)*ps;const p=atS.filtered.slice(s,s+ps);document.getElementById('atTableBody').innerHTML=p.map(r=>'<tr>'+AT_COLUMNS.map(c=>'<td>'+(r[c.key]??'')+'</td>').join('')+'</tr>').join('');renderAtPag()}
function renderAtPag(){const ps=atS.pageSize;const t=atS.filtered.length;const tp=Math.ceil(t/ps);const s=(atS.page-1)*ps+1;const e=Math.min(atS.page*ps,t);document.getElementById('atPageInfo').textContent=t>0?s+'-'+e+' of '+t:'No results';const b=document.getElementById('atPagBtns');if(tp<=1){b.innerHTML='';return}let h='<button onclick="goAtPage('+(atS.page-1)+')"'+(atS.page===1?' disabled':'')+'>&laquo;</button>';for(let pg=Math.max(1,atS.page-2);pg<=Math.min(tp,atS.page+2);pg++)h+='<button class="'+(pg===atS.page?'active':'')+'" onclick="goAtPage('+pg+')">'+pg+'</button>';h+='<button onclick="goAtPage('+(atS.page+1)+')"'+(atS.page===tp?' disabled':'')+'>&raquo;</button>';b.innerHTML=h}
function sortAtTable(i){const k=AT_COLUMNS[i].key;if(atS.sortCol===i)atS.sortAsc=!atS.sortAsc;else{atS.sortCol=i;atS.sortAsc=true}atS.filtered.sort((a,b)=>{let va=(a[k]??'').toString().toLowerCase(),vb=(b[k]??'').toString().toLowerCase();return atS.sortAsc?va.localeCompare(vb):vb.localeCompare(va)});document.querySelectorAll('#atTableHead th').forEach((th,j)=>{th.classList.toggle('sorted',j===i);th.querySelector('.sort-icon').innerHTML=(j===i&&!atS.sortAsc)?'&#9660;':'&#9650;'});atS.page=1;renderAtTableBody()}
function filterAtTable(q){q=q.toLowerCase().trim();atS.filtered=q===''?[...atS.data]:atS.data.filter(r=>AT_COLUMNS.some(c=>(r[c.key]??'').toString().toLowerCase().includes(q)));atS.page=1;renderAtTableBody()}
function goAtPage(p){const tp=Math.ceil(atS.filtered.length/atS.pageSize);if(p<1||p>tp)return;atS.page=p;renderAtTableBody()}
function exportAtCSV(){const h=AT_COLUMNS.map(c=>c.label).join(',');const rows=atS.filtered.map(r=>AT_COLUMNS.map(c=>'"'+(r[c.key]??'').toString().replace(/"/g,'""')+'"').join(','));const csv='\uFEFF'+h+'\n'+rows.join('\n');const b=new Blob([csv],{type:'text/csv;charset=utf-8;'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='access_templates_'+new Date().toISOString().slice(0,10)+'.csv';a.click()}

// Access Templates doughnut chart
new Chart(document.getElementById('atChart'), {
  type: 'doughnut',
  data: {
    labels: ['Custom', 'Orphan Links'],
    datasets: [{ data: $atChartData, backgroundColor: ['#2563eb','#dc2626'], borderWidth: 0 }]
  },
  options: doughnutOpts
});
// Access Templates table init — show only custom templates by default
atS.data = (AT_DATA || []).filter(r => r.type === 'Custom'); atS.filtered = [...atS.data]; renderAtTableHead(); renderAtTableBody();
document.getElementById('atSearch').addEventListener('input', function(e){ filterAtTable(e.target.value); });

// Orphan Access Template Links interactive table
const ORPHAN_AT_DATA = $orphanAtJsonData;
const ORPHAN_AT_COLUMNS = [{key:'dn',label:'Distinguished Name'},{key:'reason',label:'Reason'}];
let orphanAtS = {data:[],filtered:[],page:1,pageSize:10,sortCol:null,sortAsc:true};
function renderOrphanAtTableHead(){const el=document.getElementById('orphanAtTableHead');if(!el)return;el.innerHTML=ORPHAN_AT_COLUMNS.map((c,i)=>'<th onclick="sortOrphanAtTable('+i+')" data-col="'+i+'">'+c.label+' <span class="sort-icon">&#9650;</span></th>').join('')}
function renderOrphanAtTableBody(){const el=document.getElementById('orphanAtTableBody');if(!el)return;const ps=orphanAtS.pageSize;const s=(orphanAtS.page-1)*ps;const p=orphanAtS.filtered.slice(s,s+ps);el.innerHTML=p.map(r=>'<tr>'+ORPHAN_AT_COLUMNS.map(c=>'<td style="word-break:break-all">'+(r[c.key]??'')+'</td>').join('')+'</tr>').join('');renderOrphanAtPag()}
function renderOrphanAtPag(){const el=document.getElementById('orphanAtPageInfo');if(!el)return;const ps=orphanAtS.pageSize;const t=orphanAtS.filtered.length;const tp=Math.ceil(t/ps);const s=(orphanAtS.page-1)*ps+1;const e=Math.min(orphanAtS.page*ps,t);el.textContent=t>0?s+'-'+e+' of '+t:'No results';const b=document.getElementById('orphanAtPagBtns');if(tp<=1){b.innerHTML='';return}let h='<button onclick="goOrphanAtPage('+(orphanAtS.page-1)+')"'+(orphanAtS.page===1?' disabled':'')+'>&laquo;</button>';for(let pg=Math.max(1,orphanAtS.page-2);pg<=Math.min(tp,orphanAtS.page+2);pg++)h+='<button class="'+(pg===orphanAtS.page?'active':'')+'" onclick="goOrphanAtPage('+pg+')">'+pg+'</button>';h+='<button onclick="goOrphanAtPage('+(orphanAtS.page+1)+')"'+(orphanAtS.page===tp?' disabled':'')+'>&raquo;</button>';b.innerHTML=h}
function sortOrphanAtTable(i){const k=ORPHAN_AT_COLUMNS[i].key;if(orphanAtS.sortCol===i)orphanAtS.sortAsc=!orphanAtS.sortAsc;else{orphanAtS.sortCol=i;orphanAtS.sortAsc=true}orphanAtS.filtered.sort((a,b)=>{let va=(a[k]??'').toString().toLowerCase(),vb=(b[k]??'').toString().toLowerCase();return orphanAtS.sortAsc?va.localeCompare(vb):vb.localeCompare(va)});document.querySelectorAll('#orphanAtTableHead th').forEach((th,j)=>{th.classList.toggle('sorted',j===i);th.querySelector('.sort-icon').innerHTML=(j===i&&!orphanAtS.sortAsc)?'&#9660;':'&#9650;'});orphanAtS.page=1;renderOrphanAtTableBody()}
function goOrphanAtPage(p){const tp=Math.ceil(orphanAtS.filtered.length/orphanAtS.pageSize);if(p<1||p>tp)return;orphanAtS.page=p;renderOrphanAtTableBody()}
function exportOrphanAtCSV(){const h=ORPHAN_AT_COLUMNS.map(c=>c.label).join(',');const rows=orphanAtS.filtered.map(r=>ORPHAN_AT_COLUMNS.map(c=>'"'+(r[c.key]??'').toString().replace(/"/g,'""')+'"').join(','));const csv='\uFEFF'+h+'\n'+rows.join('\n');const b=new Blob([csv],{type:'text/csv;charset=utf-8;'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='orphan_at_links_'+new Date().toISOString().slice(0,10)+'.csv';a.click()}
if(ORPHAN_AT_DATA&&ORPHAN_AT_DATA.length>0){orphanAtS.data=ORPHAN_AT_DATA;orphanAtS.filtered=[...orphanAtS.data];renderOrphanAtTableHead();renderOrphanAtTableBody()}

// Virtual Attributes doughnut chart
new Chart(document.getElementById('vaChart'), {
  type: 'doughnut',
  data: {
    labels: ['Custom', 'Built-in'],
    datasets: [{ data: $vaChartData, backgroundColor: ['#2563eb','#9ca3af'], borderWidth: 0 }]
  },
  options: doughnutOpts
});
// Virtual Attributes interactive table — show only custom
vaS.data = (VA_DATA || []).filter(r => r.type === 'Custom'); vaS.filtered = [...vaS.data]; renderVATableHead(); renderVATableBody();
document.getElementById('vaSearch').addEventListener('input', function(e){ filterVATable(e.target.value); });
</script>
</body>
</html>
"@
    return $html
}

#endregion

#region Main Execution

try {
    Write-Log "=== Active Roles Environment Assessment Starting ==="
    Write-Log "Parameters: ARServer='$ARServer'  SkipBrokenRulesCheck=$($SkipBrokenRulesCheck.IsPresent)  SkipUserCounts=$($SkipUserCounts.IsPresent)"

    # Collect OS info first (no AR connection needed)
    Write-Log "Collecting OS information..."
    $osInfo = Get-OSInfo

    # Collect AR version info (registry + ADSI RootDSE)
    Write-Log "Collecting Active Roles version..."
    $arVersion = Get-ARVersionInfo

    # Collect all AR data
    Write-Log "Collecting managed domains..."
    $domains = @(Get-ManagedDomains)

    Write-Log "Testing domain latency..."
    $domainLatency = @(Get-DomainLatency -Domains $domains)

    if (-not $SkipUserCounts) {
        Write-Log "Counting managed users per domain..."
        $userCounts = Get-ManagedUserCounts -Domains $domains
    } else {
        Write-Log "Skipping user counts (-SkipUserCounts)"
        $userCounts = [PSCustomObject]@{
            TotalCount    = 0
            HybridTotal   = 0
            GmsaTotal     = 0
            ExcludedTotal = 0
            PerDomain     = @()
            ExcludedOUs   = @()
            Skipped       = $true
        }
    }

    Write-Log "Collecting server configuration..."
    $servers = Get-ARServers

    Write-Log "Collecting replication partners..."
    $replPartners = Get-ReplicationPartnersInfo

    Write-Log "Collecting MH replication partners..."
    $mhReplPartners = Get-MHReplicationPartnersInfo

    $dynGroups    = Get-DynamicGroupsInfo
    $managedUnits = Get-ManagedUnitsInfo

    Write-Log "Collecting workflow info..."
    $wfInfo = Get-WorkflowsInfo

    Write-Log "Collecting virtual attributes..."
    $virtualAttrs = Get-VirtualAttributesInfo

    Write-Log "Collecting script policies count..."
    $scriptPols = Get-ScriptPoliciesCount

    Write-Log "Collecting policy objects info..."
    $policyObjs = Get-PolicyObjectsInfo

    Write-Log "Collecting orphan policy links..."
    $orphanPoLinks = Get-OrphanPolicyLinks

    Write-Log "Collecting access templates info..."
    $accessTmpls = Get-AccessTemplatesInfo

    Write-Log "Collecting orphan access template links..."
    $orphanAtLinks = Get-OrphanATLinks

    if (-not $SkipUserCounts) {
        Write-Log "Collecting Azure / Microsoft Entra tenants..."
        $azureTenants = Get-AzureTenantsInfo
    } else {
        Write-Log "Skipping Azure tenants collection (-SkipUserCounts)"
        $azureTenants = [PSCustomObject]@{
            Configured = $false
            TotalCount = 0
            List       = @()
            Error      = $null
            Skipped    = $true
        }
    }

    Write-Log "Checking Microsoft Exchange presence..."
    $exchangeInfo = Get-ExchangePresenceInfo

    Write-Log "Checking database Auto Shrink setting..."
    $autoShrinkParams = @{ ReplicationPartners = $replPartners }
    if ($SqlCredential) { $autoShrinkParams['SqlCredential'] = $SqlCredential }
    $autoShrinkInfo = Get-AutoShrinkInfo @autoShrinkParams

    Write-Log "Checking SQL Server AlwaysOn and MultiSubnetFailover..."
    $alwaysOnParams = @{ ReplicationPartners = $replPartners }
    if ($SqlCredential) { $alwaysOnParams['SqlCredential'] = $SqlCredential }
    $alwaysOnInfo = Get-AlwaysOnInfo @alwaysOnParams

    # Build and save the HTML report
    Write-Log "Building HTML report..."
    $html = New-HtmlReport `
        -ARVersion          $arVersion `
        -OSInfo             $osInfo `
        -Domains            $domains `
        -DomainLatency      $domainLatency `
        -ManagedUserCounts  $userCounts `
        -Servers            $servers `
        -ReplicationPartners $replPartners `
        -MHReplicationPartners $mhReplPartners `
        -DynamicGroups      $dynGroups `
        -ManagedUnits       $managedUnits `
        -Workflows          $wfInfo `
        -VirtualAttrs       $virtualAttrs `
        -ScriptPoliciesCount $scriptPols `
        -PolicyObjects       $policyObjs `
        -OrphanPolicyLinks   $orphanPoLinks `
        -AccessTemplates      $accessTmpls `
        -OrphanATLinks       $orphanAtLinks `
        -AzureTenants        $azureTenants `
        -ExchangeInfo        $exchangeInfo `
        -AutoShrinkInfo      $autoShrinkInfo `
        -AlwaysOnInfo        $alwaysOnInfo

    $html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force

    Write-Log "Assessment report saved: $OutputPath"
    Write-Host ""
    Write-Host "=== Assessment Complete ===" -ForegroundColor Green
    Write-Host "Report : $(Resolve-Path $OutputPath)" -ForegroundColor Cyan
    Write-Host "Log    : $(Resolve-Path $script:LogFile)" -ForegroundColor Cyan
    Write-Host ""
}
catch {
    Write-Log "Critical error: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "DEBUG"
    throw
}
finally {
    Disconnect-QADService -ErrorAction SilentlyContinue
    Write-Log "Disconnected from Active Roles. Script finished."
}

#endregion
