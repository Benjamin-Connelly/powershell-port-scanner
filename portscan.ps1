# portscan.ps1
param (
    [switch]$Common,  # Define a switch parameter for common ports
    [string]$p        # Optional parameter for specifying ports directly
)

function Write-Log {
    param(
        [string]$Message
    )
    if ($VerboseOutput) {
        Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): $Message"
    }
}

Write-Log "Script started with parameters: Target=$Target, p=$p, O=$O, Ox=$Ox, ShowOpenOnly=$ShowOpenOnly"

try {
    function Show-Help {
        Write-Host @"
Usage: .\ps2.ps1 <target> [options]

Target:
  IP address, hostname, or subnet (e.g., 192.168.1.0/24)

Options:
  -p <ports>    Specify ports to scan (e.g., 80,443,8080 or 1-1024)
  -O <file>     Output results to a file
  -Ox <file>    Output results in XML format
  -Open         Only show open ports in the results
  -v            Show verbose output
  -h, --help    Show this help message

Examples:
  .\ps2.ps1 192.168.1.1 -p 80,443,8080
  .\ps2.ps1 example.com -p 1-1024 -O results.txt
  .\ps2.ps1 192.168.1.0/24 -p 22,80,443 -Open
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
        $Ports = $p -join ','
        Write-Log "Ports specified: $Ports"
    }

    $parsedPorts = @()
    foreach ($portRange in $Ports -split ',') {
        if ($portRange -match "^(\d+)-(\d+)$") {
            $start = [int]$Matches[1]
            $end = [int]$Matches[2]
            $ports += $start..$end
        }
        elseif ($range -match '^\d+$') {
            $ports += [int]$range
        }
        else {
            Write-Log "Invalid port range format: $range"
        }
    }
    return $ports
}

function Get-WellKnownPorts {
    param([switch]$Common)

    $defaultPorts = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
    $top20Ports = "80,443,21,22,25,53,110,119,123,143,161,194,443,445,587,993,995,3306,3389,5900"

    if ($Common) {
        Write-Log "Using default well-known TCP ports"
        return Expand-PortRange -portRange $defaultPorts
    } else {
        Write-Log "Using top 20 common TCP ports"
        return Expand-PortRange -portRange $top20Ports
    }
}

function Scan-Port {
    param([string]$ip, [int]$port)
    try {
        $tcpclient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpclient.BeginConnect($ip, $port, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne(500, $false)
        if ($wait) {
            try {
                $tcpclient.EndConnect($asyncResult)
                return "Open"
            } catch {
                return "Closed"
            }
        } else {
            return "Closed"
        }
    } catch {
        Write-Log "Error scanning port $port on ${ip}: $($_.Exception.Message)"
        return "Error"
    } finally {
        if ($null -ne $tcpclient) {
            $tcpclient.Close()
        }
    }
}

try {
    $ipAddress = $args[0]  # Assuming the IP is the first argument

    if (-not $ipAddress) {
        throw "IP address not provided. Usage: .\portscan.ps1 <IP_ADDRESS> [-p <PORTS>] [-Common]"
    }

    # Initialize the port variable based on input parameters
    if ($p) {
        $portsToScan = Expand-PortRange -portRange $p
        Write-Log "Using user-specified ports: $($portsToScan -join ', ')"
    } elseif ($Common) {
        $portsToScan = Get-WellKnownPorts -Common
        Write-Log "Using default well-known TCP ports"
    } else {
        $portsToScan = Get-WellKnownPorts
        Write-Log "Using top 20 common TCP ports"
    }

    $results = @()

    foreach ($port in $portsToScan) {
        $status = Scan-Port -ip $ipAddress -port $port
        $results += [PSCustomObject]@{IPAddress = $ipAddress; Port = $port; Status = $status}
        Write-Log "Host: $ipAddress, Port $port is $status"
    }

    Write-Log "Total results: $($results.Count)"

    $formattedResults = $results | Format-Table -AutoSize | Out-String

    Write-Host "`nScan Results:"
    Write-Host $formattedResults

    Write-Log "Script completed successfully"
} catch {
    Write-Log "An error occurred: $_"
    Write-Log "Stack trace: $($_.ScriptStackTrace)"
    throw
}