# portscan.ps1
param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ipAddress,
    [switch]$Common,
    [string]$p,
    [Parameter(Mandatory=$false)]
    [switch]$Open
)

# Define the Scan-Port function at the beginning of the script
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

function Write-Log {
    param(
        [string]$Message
    )
    Write-Host $Message
}

function Expand-PortRange {
    param([string]$portRange)
    $ports = @()
    $ranges = $portRange -split '[,\s]' | Where-Object { $_ -ne '' }
    foreach ($range in $ranges) {
        $range = $range.Trim()
        if ($range -match '^(\d+)-(\d+)$') {
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

    $commonPorts = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
    $top20Ports = "80,443,21,22,25,53,110,119,123,143,161,194,443,445,587,993,995,3306,3389,5900"

    if ($Common) {
        Write-Log "Using common TCP ports"
        return Expand-PortRange -portRange $commonPorts
    } else {
        Write-Log "Using top 20 common TCP ports"
        return Expand-PortRange -portRange $top20Ports
    }
}

try {
    if (-not $ipAddress) {
        throw "IP address not provided. Usage: .\portscan.ps1 <IP_ADDRESS> [-p <PORTS>] [-Common]"
    }

    # Initialize the port variable based on input parameters
    if ($p) {
        $portsToScan = Expand-PortRange -portRange $p
        Write-Log "Using user-specified ports: $($portsToScan -join ', ')"
    } elseif ($Common) {
        $portsToScan = Get-WellKnownPorts -Common
        Write-Log "Using common TCP ports"
    } else {
        $portsToScan = Get-WellKnownPorts
        Write-Log "Using top 20 common TCP ports"
    }

    $results = @()

    foreach ($port in $portsToScan) {
        $status = Scan-Port -ip $ipAddress -port $port
        $results += [PSCustomObject]@{IPAddress = $ipAddress; Port = $port; Status = $status}
        if (-not $Open -or $status -eq "Open") {
            Write-Log "Host: $ipAddress, Port $port is $status"
        }
    }

    if ($Open) {
        $results = $results | Where-Object { $_.Status -eq "Open" }
    }

    Write-Log "Total results: $($results.Count)"

    $formattedResults = $results | Format-Table -AutoSize | Out-String

    Write-Host "`nScan Results:"
    Write-Host $formattedResults

    Write-Log "Script completed successfully"
} catch {
    Write-Log "An error occurred: $_"
    Write-Log "Stack trace: $($_.ScriptStackTrace)"
    Write-Host "An error occurred. Please check the log file for details."
    exit 1
}