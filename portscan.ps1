# portscan.ps1

param (
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ipAddressWithCIDR,
    [switch]$Common,
    [Parameter(Mandatory=$false)]
    [string[]]$p,
    [Parameter(Mandatory=$false)]
    [switch]$Open,
    [int]$Timeout = 2000,
    [int]$Threads = 100,
    [switch]$Pn,
    [switch]$sp
)

# Import CSV file with port descriptions
$portDescriptions = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Benjamin-Connelly/ports-list/main/tcp.csv" | ConvertFrom-Csv

# Function to get service name for a port
function Get-ServiceName {
    param([int]$port)
    $service = $portDescriptions | Where-Object { $_.port -eq $port -and $_.protocol -eq "TCP" } | Select-Object -First 1
    if ($service) {
        return $service.description
    } else {
        return "unknown"
    }
}

function Expand-IPRange {
    param ([string]$ipAddressWithCIDR)

    if ($ipAddressWithCIDR -notmatch '/') {
        # Single IP address
        return @([System.Net.IPAddress]::Parse($ipAddressWithCIDR))
    }

    $ipAddress, $cidrPrefix = $ipAddressWithCIDR.Split('/')
    $ip = [System.Net.IPAddress]::Parse($ipAddress)
    $cidr = [int]$cidrPrefix

    if ($cidr -eq 32) {
        # /32 CIDR, return single IP
        return @($ip)
    }

    $ipBytes = $ip.GetAddressBytes()
    [Array]::Reverse($ipBytes)
    $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)

    $maskInt = ([UInt32]::MaxValue) -shl (32 - $cidr)
    $networkInt = $ipInt -band $maskInt
    $broadcastInt = $networkInt -bor (-bnot $maskInt)

    $networkIP = [System.Net.IPAddress]([UInt32]$networkInt)
    $broadcastIP = [System.Net.IPAddress]([UInt32]$broadcastInt)

    Write-Verbose "Network ID: $networkIP"
    Write-Verbose "Broadcast IP: $broadcastIP"

    $ipRange = @()
    for ($i = $networkInt; $i -le $broadcastInt; $i++) {
        $currentIPBytes = [System.BitConverter]::GetBytes([UInt32]$i)
        [Array]::Reverse($currentIPBytes)
        $ipRange += [System.Net.IPAddress]::new($currentIPBytes)
    }

    Write-Verbose "IP Range contains $($ipRange.Count) addresses"
    return $ipRange
}

function Test-HostAlive {
    param([string]$ip)
    $ping = New-Object System.Net.NetworkInformation.Ping
    try {
        $result = $ping.Send($ip, 1000)
        return $result.Status -eq 'Success'
    } catch {
        Write-Verbose "Ping failed for $ip : $_"
        return $false
    }
}

function Scan-Port {
    param([string]$ip, [int]$port)
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try {
        Write-Verbose "Scanning $ip : $port"
        $result = $tcpClient.BeginConnect($ip, $port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne($Timeout, $false)
        if ($success) {
            $tcpClient.EndConnect($result)
            Write-Verbose "Port $port on $ip is open"
            return "Open"
        } else {
            Write-Verbose "Port $port on $ip is closed or filtered"
            return "Closed"
        }
    } catch {
        Write-Verbose "Error scanning port $port on $ip : $_"
        return "Closed"
    } finally {
        $tcpClient.Close()
    }
}

if ($p) {
    $portsToScan = $p
} elseif ($Common) {
    $portsToScan = @("7", "9", "13", "21-23", "25-26", "37", "53", "79-81", "88", "106", "110-111", "113", "119", "135", "139", "143-144", "179", "199", "389", "427", "443-445", "465", "513-515", "543-544", "548", "554", "587", "631", "646", "873", "990", "993", "995", "1025-1029", "1110", "1433", "1720", "1723", "1755", "1900", "2000-2001", "2049", "2121", "2717", "3000", "3128", "3306", "3389", "3986", "4899", "5000", "5009", "5051", "5060", "5101", "5190", "5357", "5432", "5631", "5666", "5800", "5900", "6000-6001", "6646", "7070", "8000", "8008-8009", "8080-8081", "8443", "8888", "9100", "9999-10000", "32768", "49152-49157")
} else {
    # Default ports if neither -p nor -Common is specified
    $portsToScan = @("80", "443", "22", "21", "25", "3389", "110", "143", "53",
                     "23", "445", "3306", "8080", "1433", "3389", "5900",
                     "135", "139", "8443", "1723")
}

# Expand port ranges
$expandedPorts = @()
foreach ($port in $portsToScan) {
    if ($port -match '^(\d+)-(\d+)$') {
        $start = [int]$Matches[1]
        $end = [int]$Matches[2]
        $expandedPorts += $start..$end
    } else {
        $expandedPorts += [int]$port
    }
}
$portsToScan = $expandedPorts | Sort-Object -Unique

$ipRange = Expand-IPRange $ipAddressWithCIDR

if ($sp) {
    Write-Host "Performing ping scan on IP range: $ipAddressWithCIDR"
    $pingResults = @()
    foreach ($ip in $ipRange) {
        $isAlive = Test-HostAlive -ip $ip.ToString()
        $pingResults += [PSCustomObject]@{
            IPAddress = $ip
            IsAlive = $isAlive
        }
        if ($isAlive) {
            Write-Host "Host $ip is up"
        } else {
            Write-Host "Host $ip is down"
        }
    }
    $aliveHosts = ($pingResults | Where-Object { $_.IsAlive }).Count
    Write-Host "`nPing Scan Results:"
    Write-Host "Total hosts up: $aliveHosts"
    Write-Host "Total hosts in range: $($pingResults.Count)"
    Write-Host "Script completed successfully"
    return
}

Write-Host "Scanning IP range: $ipAddressWithCIDR"
Write-Host "Ports being scanned: $($portsToScan -join ', ')"
Write-Host "Scan in progress..."

$results = @()

foreach ($ip in $ipRange) {
    $hostAlive = !$Pn
    if (!$Pn) {
        $hostAlive = Test-HostAlive -ip $ip.ToString()
        if ($hostAlive) {
            Write-Verbose "Host $ip is responding to ping"
        } else {
            Write-Verbose "Host $ip is not responding to ping"
        }
    }

    if ($hostAlive -or $Pn) {
        $openPorts = @()
        foreach ($port in $portsToScan) {
            $status = Scan-Port -ip $ip.ToString() -port $port
            if ($status -eq "Open") {
                $openPorts += $port
                Write-Host "Host: $ip, Port $port is Open"
            }
        }
        $results += [PSCustomObject]@{
            IPAddress = $ip
            OpenPorts = $openPorts
            Scanned = $true
        }
    } else {
        $results += [PSCustomObject]@{
            IPAddress = $ip
            OpenPorts = @()
            Scanned = $false
        }
    }
}

Write-Host "`nScan Results:"
if ($Open) {
    $openResults = $results | Where-Object { $_.OpenPorts.Count -gt 0 }
    if ($openResults.Count -eq 0) {
        Write-Host "No open ports found in the specified range."
    } else {
        $openResults | ForEach-Object {
            Write-Host "`nIP: $($_.IPAddress)"
            Write-Host "PORT   STATE   SERVICE"
            $_.OpenPorts | ForEach-Object {
                $serviceName = Get-ServiceName $_
                Write-Host ("{0,-6} {1,-7} {2}" -f $_, "open", $serviceName)
            }
        }
    }
    Write-Host "`nTotal hosts with open ports: $($openResults.Count)"
} else {
    $results | ForEach-Object {
        if ($_.Scanned) {
            Write-Host "`nIP: $($_.IPAddress)"
            Write-Host "PORT   STATE   SERVICE"
            $portsToScan | ForEach-Object {
                $port = $_
                $state = if ($_.OpenPorts -contains $port) { "open" } else { "closed" }
                $serviceName = Get-ServiceName $port
                Write-Host ("{0,-6} {1,-7} {2}" -f $port, $state, $serviceName)
            }
        } else {
            Write-Host "`nIP: $($_.IPAddress), Not scanned (did not respond to ping)"
        }
    }
}

$scannedHosts = ($results | Where-Object { $_.Scanned }).Count
Write-Host "`nTotal hosts scanned: $scannedHosts"
Write-Host "Total hosts in range: $($results.Count)"
Write-Host "Script completed successfully"