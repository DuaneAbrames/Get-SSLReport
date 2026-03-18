<#
.SYNOPSIS
Scans hosts for HTTPS certificates using Nmap and generates a CSV report.

.DESCRIPTION
This script runs Nmap with the ssl-cert NSE script against one or more
targets and parses the resulting XML output to produce a readable report
of TLS certificates discovered on the scanned hosts.

Targets may include:
    - Individual IP addresses
    - Hostnames
    - CIDR ranges
    - Multiple targets in a single invocation

By default the script scans the following common HTTPS ports:

    443, 4433, 8443, 4430

Only hosts/ports that return valid certificate data are included in the report.

Results are exported to CSV by default in the same directory as the script
using the naming format:

    SslCertReport.csv

Each row in the report includes:
    Host IP
    Hostname (if known)
    Port
    Protocol
    Certificate Common Name (CN)
    Certificate Expiration Date
    Certificate Subject
    Certificate Issuer

.PARAMETER Targets
One or more scan targets accepted by Nmap. Targets may include:

    - IPv4 or IPv6 addresses
    - DNS hostnames
    - CIDR ranges (ex: 192.168.1.0/24)
    - Multiple targets separated by spaces

.PARAMETER NmapPath
Path to the Nmap executable. Defaults to "nmap" which assumes Nmap is
available in the system PATH.

.PARAMETER CsvPath
Optional path for the CSV output file. If not specified, the report is
written to the script directory as:

    SslCertReport.csv

If the file already exists, it is overwritten.

.PARAMETER AllPorts
If specified, Nmap will scan all TCP ports (-p-) instead of only the
default HTTPS-related ports. This significantly increases scan time but
can discover certificates on non-standard ports.

.PARAMETER IpSort
If specified, sort the report by IP address (numeric order), then port,
hostname, and expiration date. By default, the report is sorted by
expiration date ascending.

.EXAMPLE
.\Get-SslCertReport.ps1 192.168.1.0/24

Scans the default HTTPS ports on the entire subnet and generates a CSV
report in the script directory.

.EXAMPLE
.\Get-SslCertReport.ps1 web01.example.com 10.10.10.25

Scans multiple targets and generates a certificate report.

.EXAMPLE
.\Get-SslCertReport.ps1 10.0.0.0/24 -AllPorts

Performs a full TCP port scan on the subnet and runs the ssl-cert script
against any discovered services.

.EXAMPLE
.\Get-SslCertReport.ps1 example.com -CsvPath C:\Reports\certs.csv

Runs the scan and saves the report to a custom CSV location.

.NOTES
Author: Duane Abrames
Requires: Nmap with the ssl-cert NSE script
Intended for: Windows PowerShell 5.1 and PowerShell 7+

Nmap: https://nmap.org

Scanning large networks or using -AllPorts may take significant time
depending on network size and host responsiveness.

.LINK
https://nmap.org/nsedoc/scripts/ssl-cert.html
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, ValueFromRemainingArguments)]
    [string[]]$Targets,

    [string]$NmapPath = "nmap",

    [string]$CsvPath,

    [switch]$AllPorts,

    [switch]$IpSort
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ScriptDirectory {
    param([string]$Path)

    if ($Path) {
        return Split-Path -Path $Path -Parent
    }

    if ($PSCommandPath) {
        return Split-Path -Path $PSCommandPath -Parent
    }

    return (Get-Location).ProviderPath
}

function Get-XmlElemValue {
    param(
        [Parameter(Mandatory)]
        [System.Xml.XmlNode]$Node,

        [Parameter(Mandatory)]
        [string]$Key
    )

    $elem = $Node.SelectSingleNode(".//elem[@key='$Key']")
    if ($null -ne $elem) {
        return $elem.InnerText
    }

    return $null
}

function Get-XmlTableKeyValue {
    param(
        [Parameter(Mandatory)]
        [System.Xml.XmlNode]$Node,

        [Parameter(Mandatory)]
        [string]$TableKey
    )

    $tableNode = $Node.SelectSingleNode("./table[@key='$TableKey']")
    if ($null -eq $tableNode) {
        return $null
    }

    $elemNodes = $tableNode.SelectNodes('./elem[@key]')
    if ($null -eq $elemNodes -or $elemNodes.Count -eq 0) {
        return $null
    }

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($elemNode in $elemNodes) {
        $key = [string]$elemNode.key
        $value = [string]$elemNode.InnerText

        if ([string]::IsNullOrWhiteSpace($key) -or [string]::IsNullOrWhiteSpace($value)) {
            continue
        }

        $parts.Add(("{0}={1}" -f $key.Trim(), $value.Trim()))
    }

    if ($parts.Count -eq 0) {
        return $null
    }

    return ($parts -join '/')
}

function Get-CommonNameFromSubject {
    param(
        [AllowNull()]
        [string]$Subject
    )

    if ([string]::IsNullOrWhiteSpace($Subject)) {
        return $null
    }

    if ($Subject -match '(?i)(?:commonName|CN)\s*=\s*([^/\r\n,]+)') {
        return $matches[1].Trim()
    }

    return $Subject.Trim()
}

function Get-HostAddress {
    param(
        [Parameter(Mandatory)]
        [System.Xml.XmlNode]$HostNode
    )

    $ipv4 = $HostNode.SelectSingleNode("./address[@addrtype='ipv4']")
    if ($null -ne $ipv4) {
        return $ipv4.addr
    }

    $ipv6 = $HostNode.SelectSingleNode("./address[@addrtype='ipv6']")
    if ($null -ne $ipv6) {
        return $ipv6.addr
    }

    $other = $HostNode.SelectSingleNode("./address")
    if ($null -ne $other) {
        return $other.addr
    }

    return $null
}

function Get-IpSortKey {
    param(
        [AllowNull()]
        [string]$Address
    )

    if ([string]::IsNullOrWhiteSpace($Address)) {
        return '9|'
    }

    try {
        $ipAddress = [System.Net.IPAddress]$Address
    }
    catch {
        return "9|$Address"
    }

    $familyPrefix = switch ($ipAddress.AddressFamily) {
        ([System.Net.Sockets.AddressFamily]::InterNetwork) { '4|' ; break }
        ([System.Net.Sockets.AddressFamily]::InterNetworkV6) { '6|' ; break }
        default { '8|' ; break }
    }

    $byteKey = ($ipAddress.GetAddressBytes() | ForEach-Object { $_.ToString('D3') }) -join '.'
    return "$familyPrefix$byteKey"
}

function Convert-ToExpirationDate {
    param(
        [AllowNull()]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return $null
    }

    try {
        return ([datetime]$Value).ToString('yyyy-MM-dd')
    }
    catch {
        if ($Value -match '^\d{4}-\d{2}-\d{2}') {
            return $matches[0]
        }

        # Preserve original text if parsing fails for locale/format reasons.
        return $Value.Trim()
    }
}

function Get-ExpirationSortKey {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return '9|'
    }

    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) {
        return '9|'
    }

    try {
        $dateValue = [datetime]$text
        return ('0|{0}' -f $dateValue.ToString('yyyyMMdd'))
    }
    catch {
        if ($text -match '^(\d{4})-(\d{2})-(\d{2})') {
            return ('0|{0}{1}{2}' -f $matches[1], $matches[2], $matches[3])
        }
    }

    return "8|$text"
}

function Get-SslCertReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Targets,

        [Parameter(Mandatory)]
        [string]$NmapPath,

        [switch]$AllPorts
    )

    $nmapArgs = @()

    if ($AllPorts) {
        $nmapArgs += '-p-'
    }
    else {
        $nmapArgs += '-p'
        $nmapArgs += '443,4433,8443,4430'
    }

    $nmapArgs += '--script'
    $nmapArgs += 'ssl-cert'
    $nmapArgs += '-oX'
    $nmapArgs += '-'
    $nmapArgs += $Targets

    Write-Verbose ("Running: {0} {1}" -f $NmapPath, ($nmapArgs -join ' '))

    $xmlText = & $NmapPath @nmapArgs 2>&1

    if ($LASTEXITCODE -ne 0) {
        throw "nmap exited with code $LASTEXITCODE.`n$($xmlText -join [Environment]::NewLine)"
    }

    $xmlString = $xmlText -join [Environment]::NewLine

    try {
        [xml]$nmapXml = $xmlString
    }
    catch {
        throw "Failed to parse nmap XML output.`n$xmlString"
    }

    $results = New-Object System.Collections.Generic.List[object]

    $hostNodes = $nmapXml.SelectNodes('/nmaprun/host')
    if ($null -eq $hostNodes -or $hostNodes.Count -eq 0) {
        return $results
    }

    foreach ($hostNode in $hostNodes) {
        $hostIp = Get-HostAddress -HostNode $hostNode
        $hostNameNode = $hostNode.SelectSingleNode('./hostnames/hostname[@name]')
        $hostName = if ($null -ne $hostNameNode) { $hostNameNode.name } else { $null }

        $portNodes = $hostNode.SelectNodes('./ports/port')
        if ($null -eq $portNodes) {
            continue
        }

        foreach ($portNode in $portNodes) {
            $stateNode = $portNode.SelectSingleNode('./state')
            $portState = if ($null -ne $stateNode) { $stateNode.state } else { $null }

            if ($portState -ne 'open') {
                continue
            }

            $scriptNode = $portNode.SelectSingleNode("./script[@id='ssl-cert']")
            if ($null -eq $scriptNode) {
                continue
            }

            $subjectRaw = Get-XmlTableKeyValue -Node $scriptNode -TableKey 'subject'
            if ([string]::IsNullOrWhiteSpace($subjectRaw)) {
                $subjectRaw = Get-XmlElemValue -Node $scriptNode -Key 'subject'
            }

            $notAfterRaw = Get-XmlElemValue -Node $scriptNode -Key 'notAfter'
            $issuerRaw = Get-XmlTableKeyValue -Node $scriptNode -TableKey 'issuer'
            if ([string]::IsNullOrWhiteSpace($issuerRaw)) {
                $issuerRaw = Get-XmlElemValue -Node $scriptNode -Key 'issuer'
            }

            $commonNameDirect = Get-XmlElemValue -Node $scriptNode -Key 'commonName'
            $commonName = if (-not [string]::IsNullOrWhiteSpace($commonNameDirect)) {
                $commonNameDirect.Trim()
            }
            else {
                Get-CommonNameFromSubject -Subject $subjectRaw
            }

            $expiration = Convert-ToExpirationDate -Value $notAfterRaw

            # Omit rows where no useful certificate data was returned
            if ([string]::IsNullOrWhiteSpace($commonName) -and [string]::IsNullOrWhiteSpace($notAfterRaw)) {
                continue
            }

            $results.Add([pscustomobject]@{
                HostIP         = $hostIp
                Hostname       = $hostName
                Port           = [int]$portNode.portid
                Protocol       = [string]$portNode.protocol
                CertificateCN  = $commonName
                ExpirationDate = $expiration
                Subject        = $subjectRaw
                Issuer         = $issuerRaw
            })
        }
    }

    return $results
}

$scriptDirectory = Get-ScriptDirectory -Path $PSCommandPath

if ([string]::IsNullOrWhiteSpace($CsvPath)) {
    $CsvPath = Join-Path $scriptDirectory "SslCertReport.csv"
}

$report = Get-SslCertReport -Targets $Targets -NmapPath $NmapPath -AllPorts:$AllPorts

if ($IpSort) {
    $sortedReport = @($report | Sort-Object `
        @{ Expression = { Get-IpSortKey -Address $_.HostIP }; Ascending = $true }, `
        @{ Expression = 'Port'; Ascending = $true }, `
        @{ Expression = 'Hostname'; Ascending = $true }, `
        @{ Expression = { Get-ExpirationSortKey -Value $_.ExpirationDate }; Ascending = $true })
}
else {
    $sortedReport = @($report | Sort-Object `
        @{ Expression = { Get-ExpirationSortKey -Value $_.ExpirationDate }; Ascending = $true }, `
        @{ Expression = { Get-IpSortKey -Address $_.HostIP }; Ascending = $true }, `
        @{ Expression = 'Port'; Ascending = $true }, `
        @{ Expression = 'Hostname'; Ascending = $true })
}

$sortedReport |
    Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Force

Write-Host "CSV written to: $CsvPath"

if (@($sortedReport).Count -eq 0) {
    Write-Warning "No certificates were returned by nmap."
}
else {
    $sortedReport | Format-Table -AutoSize
}
