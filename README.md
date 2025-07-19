# tracr

A fast DNS tracer for identifying potential dangling nameserver vulnerabilities. **tracr** performs concurrent DNS traces on subdomains and detects nameservers that return `REFUSED` or `SERVFAIL` responses, which may indicate misconfigured or abandoned DNS infrastructure.

## Features

- 🚀 **High-speed concurrent processing** - Configurable worker pools for optimal performance
- 🔍 **DNS trace analysis** - Performs `dig +trace` equivalent operations to discover nameservers
- ⚡ **Dangling nameserver detection** - Identifies `REFUSED`/`SERVFAIL` responses indicating potential vulnerabilities
- 📝 **Flexible input/output** - Reads from stdin or command line, clean output for piping
- 🎯 **Duplicate prevention** - Automatically deduplicates domains to avoid redundant work

## Installation

### From Source
Requires Go 1.19 or later:

```bash
go install github.com/cybercdh/tracr@latest
```

### From Releases
Download the latest binary from the [releases page](https://github.com/cybercdh/tracr/releases).

## Usage

### Basic Usage

```bash
# Single domain
tracr subdomain.example.com

# From stdin (pipe from other tools)
echo "test.example.com" | tracr

# From file
cat subdomains.txt | tracr

# With higher concurrency and verbose output
cat subdomains.txt | tracr -c 50 -v
```

### Integration with Other Tools

```bash
# With subfinder
subfinder -d example.com -silent | tracr

# With assetfinder  
assetfinder example.com | tracr -c 30

# With amass
amass enum -passive -d example.com | tracr

# Chain with other tools
cat domains.txt | tracr | httpx -silent
```

## Command Line Options

```
-c int    Number of concurrent workers (default: 20)
-v        Enable verbose output showing all DNS queries and results
-h        Show help information
```

## Output Formats

### Standard Output (Default)
Clean domain list suitable for piping to other tools:
```
vulnerable1.example.com
vulnerable2.example.com
```

### Verbose Output (`-v` flag)
Detailed information about the DNS tracing process:
```
[TRACE] dig subdomain.example.com +trace
[NS] subdomain.example.com -> ns1.example.com
[NS] subdomain.example.com -> ns2.example.com
[CHECK] dig example.com @ns1.example.com
[VULN] example.com (nameserver: ns1.example.com)
```

## How It Works

1. **DNS Tracing**: For each input domain, tracr performs a DNS trace (equivalent to `dig +trace`) to discover the authoritative nameservers
2. **Nameserver Extraction**: Parses the trace results to identify nameservers responsible for the domain
3. **Vulnerability Testing**: Queries each nameserver directly to check for `REFUSED` or `SERVFAIL` responses
4. **Result Reporting**: Outputs domains with potentially dangling nameservers

## What Are Dangling Nameservers?

Dangling nameservers occur when:
- A domain's nameservers are configured but no longer respond authoritatively
- The nameserver infrastructure has been decommissioned but DNS records weren't updated
- There's a misconfiguration in the DNS delegation chain

These can potentially be exploited if an attacker can register or control the abandoned nameserver infrastructure.

## Performance Tips

- **Concurrency**: Increase `-c` value for faster processing (test your system limits)
- **Input Preparation**: Remove duplicates from input to avoid unnecessary work
- **Network**: Ensure stable DNS resolution for your system

## Example Workflow

```bash
# 1. Discover subdomains
subfinder -d example.com -silent > subdomains.txt

# 2. Find potentially vulnerable nameservers
cat subdomains.txt | tracr -c 50 > vulnerable.txt

# 3. Verify the results
cat vulnerable.txt | tracr -v

# 4. Further investigation
cat vulnerable.txt | httpx -title -status-code
```

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Setup

```bash
git clone https://github.com/cybercdh/tracr.git
cd tracr
go mod tidy
go build
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before testing any domains or infrastructure they do not own.

## Related Tools

- [subfinder](https://github.com/projectdiscovery/subfinder) - Fast subdomain discovery
- [amass](https://github.com/OWASP/Amass) - Network mapping and attack surface discovery
- [httpx](https://github.com/projectdiscovery/httpx) - Fast HTTP prober
- [dig](https://linux.die.net/man/1/dig) - DNS lookup utility