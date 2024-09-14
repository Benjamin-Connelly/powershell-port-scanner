param (
    [Parameter(Position=0, Mandatory=$true)]
    [string]$Target,

    [Parameter(Position=1)]
    [string[]]$p,

    [string]$oN,
    [string]$oX,
    [string]$oG,
    [string]$oA,
    [Alias("Open")]
    [switch]$ShowOpenOnly,
    [Alias("v")]
    [switch]$VerboseOutput
)

$ErrorActionPreference = "Stop"
$VerbosePreference = "SilentlyContinue"

function Write-Log {
    param(
        [string]$Message
    )
    if ($VerboseOutput) {
        Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    }
}

Write-Log "Script started with parameters: Target=$Target, p=$p, ShowOpenOnly=$ShowOpenOnly"

try {
    function Show-Help {
        Write-Host @"
Usage: .\portscan.ps1 <target> [options]

Target:
  IP address, hostname, or subnet (e.g., 192.168.1.0/24)

Options:
  -p <ports>    Specify ports to scan (e.g., 80,443,8080 or 1-1024)
  -oN <file>    Output results in normal text format
  -oX <file>    Output results in XML format
  -oG <file>   Output results in grepable (CSV) format
  -oA <name>   Output in all formats
  -Open        Only show open ports in the results
  -v           Show verbose output
  -h, --help   Show this help message

Examples:
  .\portscan.ps1 192.168.1.1 -p 80,443,8080
  .\portscan.ps1 example.com -p 1-1024 -oN results.txt
  .\portscan.ps1 192.168.1.0/24 -p 22,80,443
"@
        exit
    }

    function Get-IPRange {
        param ([string]$Subnet)

        Write-Log "Entering Get-IPRange function with subnet: $Subnet"

        if ($Subnet -match '^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
            $ip, $cidr = $Subnet -split '/'
            $ipAddress = [System.Net.IPAddress]::Parse($ip)
            $ipBytes = $ipAddress.GetAddressBytes()
            [Array]::Reverse($ipBytes)
            $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
            $maskInt = [uint32]([Math]::Pow(2, 32) - 1) -shl (32 - [int]$cidr)
            $networkInt = $ipInt -band $maskInt
            $broadcastInt = $networkInt -bor ([uint32]::MaxValue - $maskInt)

            $startIPBytes = [BitConverter]::GetBytes([uint32]($networkInt + 1))
            [Array]::Reverse($startIPBytes)
            $startIP = [System.Net.IPAddress]::new($startIPBytes)

            $endIPBytes = [BitConverter]::GetBytes([uint32]($broadcastInt - 1))
            [Array]::Reverse($endIPBytes)
            $endIP = [System.Net.IPAddress]::new($endIPBytes)

            Write-Log "IP range obtained: StartIP=$startIP, EndIP=$endIP"
            return @{StartIP = $startIP; EndIP = $endIP}
        } elseif ($Subnet -match '^(\d{1,3}\.){3}\d{1,3}$') {
            Write-Log "Single IP address detected: $Subnet"
            return @{StartIP = [System.Net.IPAddress]::Parse($Subnet); EndIP = [System.Net.IPAddress]::Parse($Subnet)}
        } else {
            throw "Invalid subnet format. Please use CIDR notation (e.g., 192.168.1.0/24) or a single IP address."
        }
    }

    function Get-WellKnownPorts {
        Write-Log "Entering Get-WellKnownPorts function"
        $url = "https://raw.githubusercontent.com/Benjamin-Connelly/ports-list/main/all.csv"
        Write-Log "Attempting to download from $url"
        $content = Invoke-WebRequest -Uri $url -UseBasicParsing | Select-Object -ExpandProperty Content
        Write-Log "Successfully downloaded content"
        $lines = $content -split "`n"
        $portMap = @{}
        foreach ($line in $lines | Select-Object -Skip 1) {
            $parts = $line -split ',' | ForEach-Object { $_.Trim('"') }
            if ($parts.Count -ge 3 -and $parts[0] -eq "TCP") {
                if ([int]::TryParse($parts[1], [ref]$null)) {
                    $port = [int]$parts[1]
                    $service = $parts[2]
                    $portMap[$port] = $service
                }
            }
        }
        Write-Log "Processed $($portMap.Count) well-known ports"
        return $portMap
    }

    if ($args -contains "-h" -or $args -contains "--help") {
        Show-Help
    }

    Write-Log "Loading well-known ports"
    $wellKnownPorts = Get-WellKnownPorts
    Write-Log "Well-known ports loaded"

    if (-not $p) {
        $Ports = 1..1024
        Write-Log "No ports specified, using default range 1-1024"
    } else {
        $Ports = $p
        Write-Log "Ports specified: $Ports"
    }

    $parsedPorts = @()
    foreach ($portRange in $Ports) {
        if ($portRange -match "^(\d+)-(\d+)$") {
            $start = [int]$Matches[1]
            $end = [int]$Matches[2]
            $parsedPorts += $start..$end
        } elseif ($portRange -match "^\d+$") {
            $parsedPorts += [int]$portRange
        }
    }
    $parsedPorts = $parsedPorts | Select-Object -Unique | Sort-Object
    Write-Log "Parsed ports: $($parsedPorts -join ', ')"

    $results = @()

    $ipRange = Get-IPRange -Subnet $Target
    Write-Log "IP range obtained: StartIP=$($ipRange.StartIP), EndIP=$($ipRange.EndIP)"

    $startIPBytes = $ipRange.StartIP.GetAddressBytes()
    [Array]::Reverse($startIPBytes)
    $startIP = [BitConverter]::ToUInt32($startIPBytes, 0)

    $endIPBytes = $ipRange.EndIP.GetAddressBytes()
    [Array]::Reverse($endIPBytes)
    $endIP = [BitConverter]::ToUInt32($endIPBytes, 0)
    Write-Log "Start IP: $startIP, End IP: $endIP"

    $targetHosts = @()
    Write-Log "Starting to generate target hosts"
    for ($i = $startIP; $i -le $endIP; $i++) {
        $bytes = [BitConverter]::GetBytes($i)
        [Array]::Reverse($bytes)
        $currentIP = [System.Net.IPAddress]::new($bytes).ToString()
        $targetHosts += $currentIP
        Write-Log "Added host: $currentIP"
    }
    Write-Log "Total number of hosts: $($targetHosts.Count)"

    Write-Host "Starting scan of $($targetHosts.Count) host(s)"

    foreach ($targetHost in $targetHosts) {
        $ipAddress = $targetHost

        foreach ($port in $parsedPorts) {
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            try {
                $connectResult = $tcpClient.BeginConnect($ipAddress, $port, $null, $null)
                $waitResult = $connectResult.AsyncWaitHandle.WaitOne(1000, $false)
                if ($waitResult) {
                    $tcpClient.EndConnect($connectResult)
                    $status = "Open"
                } else {
                    $status = "Closed/Filtered"
                }
            } catch {
                $status = "Closed"
            } finally {
                $tcpClient.Close()
            }

            $service = if ($wellKnownPorts.ContainsKey($port)) { $wellKnownPorts[$port] } else { "Unknown" }

            $results += [PSCustomObject]@{
                Host = $ipAddress
                Port = $port
                Status = $status
                Service = $service
            }

            Write-Log "Host: ${ipAddress}, Port ${port} (${service}) is ${status}"
        }
    }

    Write-Log "Total results: $($results.Count)"

    if ($ShowOpenOnly) {
        $results = $results | Where-Object { $_.Status -eq "Open" }
    }

    $formattedResults = $results | Format-Table -AutoSize | Out-String
    $csvResults = $results | ConvertTo-Csv -NoTypeInformation

    if ($oN) {
        $formattedResults | Out-File -FilePath $oN
        Write-Log "Results saved in normal format to $oN"
    }
    if ($oX) {
        $results | Export-Clixml -Path $oX
        Write-Log "Results saved in XML format to $oX"
    }
    if ($oG) {
        $csvResults | Out-File -FilePath $oG
        Write-Log "Results saved in grepable (CSV) format to $oG"
    }
    if ($oA) {
        $baseName = $oA
        $formattedResults | Out-File -FilePath "$baseName.txt"
        $results | Export-Clixml -Path "$baseName.xml"
        $csvResults | Out-File -FilePath "$baseName.csv"
        Write-Log "Results saved in all formats to $baseName.txt, $baseName.xml, and $baseName.csv"
    }
    if (-not ($oN -or $oX -or $oG -or $oA)) {
        Write-Host "`nScan Results:"
        Write-Host $formattedResults
    }

    Write-Log "Script completed successfully"
} catch {
    Write-Log "An error occurred: $_"
    Write-Log "Stack trace: $($_.ScriptStackTrace)"
    throw
}