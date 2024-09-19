# PowerShell TCP Port Scanner

This PowerShell script provides a portable and efficient TCP port scanning tool. It allows you to scan individual hosts or subnets across multiple ports or port ranges, with options to perform a sign of life ping before scanning, or to run a ping-only scan.

## Features

- Scan individual hosts or subnets (CIDR notation supported)
- Specify individual ports or port ranges to scan
- Option to scan commonly used ports or the top 20 most commonly used ports
- Option to display only open ports (hide closed ports)
- Ping check before port scanning (sign of life ping) by default
- Option to skip sign of life ping and scan for open ports only
- Ping-only scan option to quickly check for live hosts
- Efficient asynchronous port scanning

## Usage

```powershell
.\portscan.ps1 <IPAddress> [-sp] [-Pn] [-p <ports>] [-Common] [-Open] [-Verbose]
```

### Parameters

- `IPAddress`: The IP address or hostname to scan (required)
- `-p <ports>`: Ports to scan. Can be individual ports, ranges, or a mix.
  - Examples: `-p 80,443,8080` or `-p 80-100,443,1000-2000`
  - If omitted, scans top 20 common ports by default.
- `-Common`: Scan a larger set of common ports instead of just the top 20
- `-sp`: Perform a ping scan on the IP range
- `-Pn`: Skip the ping check and scan all hosts
- `-Open`: Display only open ports in the output
- `-Verbose`: Display detailed information about the scan process

## Examples

1. Scan a single host using default top 20 ports:

   ```powershell
   .\portscan.ps1 192.168.1.1
   ```

2. Scan specific ports on a host:

   ```powershell
   .\portscan.ps1 example.com -p 80,443,22,3389
   ```

3. Scan a range of ports:

   ```powershell
   .\portscan.ps1 10.0.0.1 -p 1-1000
   ```

4. Scan common ports and show only open ports:

   ```powershell
   .\portscan.ps1 192.168.0.1 -Common -Open
   ```

## Note

This script uses asynchronous scanning for improved performance. The timeout for each port scan is set to 500 milliseconds.

## Requirements

- PowerShell 5.1 or later
