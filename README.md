# PowerShell TCP Port Scanner

This PowerShell script provides a flexible and efficient TCP port scanning tool. It allows you to scan individual hosts, subnets, and even perform scans across multiple ports or port ranges.

## Features

- Scan individual hosts or entire subnets (CIDR notation supported)
- Specify individual ports or port ranges to scan
- Save results to a file (plain text, XML, or CSV format)
- Option to display only open ports
- Fetches well-known port information for better context

## Usage

`.\ps2.ps1 <TargetHost|Subnet> [-p <ports>] [-oN <file>] [-oX <file>] [-oG <file>] [-oA <basename>] [-Open|--open]`

### Parameters

- `TargetHost|Subnet`: The IP address, hostname, or subnet (CIDR notation) to scan (required)
- `-p <ports>`: Ports to scan. Can be individual ports, ranges, or a mix.
  - Examples: `-p 80,443,8080` or `-p 80-100,443,1000-2000`
  - If omitted, scans ports 1-1024.
- `-oN <file>`: Save results in normal text format
- `-oX <file>`: Save results in XML format
- `-oG <file>`: Save results in grepable (CSV) format
- `-oA <basename>`: Save results in all major formats (normal, XML, and CSV)
- `-Open, --open`: Display only open ports in the output
- `-h`: Display the help message

## Examples

1. Scan a single host:

   ```shell
   .\ps2.ps1 8.8.8.8
   ```

2. Scan specific ports on a domain:

   ```shell
   .\ps2.ps1 example.com -p 80,443,22,3389
   ```

3. Scan a range of ports and save results to a normal text file:

   ```shell
   .\ps2.ps1 192.168.1.1 -p 1-1000 -oN results.txt
   ```

4. Scan all ports and save results in XML format:

   ```shell
   .\ps2.ps1 10.0.0.1 -p 1-65535 -oX results.xml
   ```

5. Scan a subnet, show only open ports, and save results in all formats:

   ```shell
   .\ps2.ps1 10.0.0.0/24 -p 80,443 --open -oA scan_results
   ```

## Note

This script fetches well-known port information from GitHub to provide additional context for the scanned ports.

## Requirements

- PowerShell 5.1 or later
- Internet connection (for fetching well-known port information)