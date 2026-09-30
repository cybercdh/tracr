package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/lixiangzhong/dnsutil"
	"github.com/miekg/dns"
)

// hasAtLeastTwoDots reports whether a name has at least two dots, filtering
// out TLD-only results like "com." Trailing dots are ignored so "example.com."
// counts as one dot, not two.
func hasAtLeastTwoDots(domain string) bool {
	return strings.Count(strings.TrimSuffix(domain, "."), ".") >= 1
}

// TraceIt performs a DNS trace on the input domain to discover nameservers and
// sends the discovered nameserver set to the refusals channel for testing.
func TraceIt(inputDomain string) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[TRACE] dig %s +trace\n", inputDomain)
	}

	var dig dnsutil.Dig
	responses, err := dig.Trace(inputDomain)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to trace %s: %v\n", inputDomain, err)
		}
		// Even a partial trace can carry the authority section we need.
	}

	for i, response := range responses {
		if response.Msg == nil {
			continue
		}
		// Focus on the second-to-last response, which typically holds the
		// authoritative nameservers for the domain.
		if i != len(responses)-2 {
			continue
		}

		var nameServers []string
		var targetDomain string
		for _, rr := range response.Msg.Ns {
			ns, ok := rr.(*dns.NS)
			if !ok {
				continue
			}
			targetDomain = strings.TrimSuffix(ns.Header().Name, ".")
			server := strings.TrimSuffix(ns.Ns, ".")

			// Skip records without enough depth (e.g. TLDs).
			if !hasAtLeastTwoDots(ns.Header().Name) {
				continue
			}
			if !slices.Contains(nameServers, server) {
				if verbose {
					fmt.Fprintf(os.Stderr, "[NS] %s -> %s\n", inputDomain, server)
				}
				nameServers = append(nameServers, server)
			}
		}

		if len(nameServers) > 0 {
			refusals <- Target{
				domain:    targetDomain,
				subdomain: strings.TrimSuffix(inputDomain, "."),
				servers:   nameServers,
			}
		}
	}
}

// CheckForRefusal tests nameservers to detect dangling nameserver
// vulnerabilities. Returns true if any nameserver responds REFUSED or SERVFAIL.
func CheckForRefusal(target *Target) (bool, error) {
	for _, nameServer := range target.servers {
		if verbose {
			fmt.Fprintf(os.Stderr, "[CHECK] dig %s @%s\n", target.domain, nameServer)
		}

		// A fresh Dig per nameserver: SetDNS mutates it, and reusing one across
		// servers risks carrying state between queries.
		var dig dnsutil.Dig
		dig.SetDNS(nameServer)
		message, err := dig.GetMsg(dns.TypeA, target.domain)
		if err != nil {
			if verbose {
				fmt.Fprintf(os.Stderr, "[ERROR] Query failed for %s@%s: %v\n", target.domain, nameServer, err)
			}
			continue // Try other nameservers
		}

		responseCode := dns.RcodeToString[message.MsgHdr.Rcode]
		if responseCode == "REFUSED" || responseCode == "SERVFAIL" {
			target.vulnNS = nameServer
			if verbose {
				fmt.Fprintf(os.Stderr, "[FOUND] %s nameserver %s returned %s\n", target.domain, nameServer, responseCode)
			}
			return true, nil
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "[OK] %s@%s returned %s\n", target.domain, nameServer, responseCode)
		}
	}

	return false, nil
}

// GetUserInput reads domains from stdin or a command line argument and sends
// each unique, non-blank domain to the domains channel.
func GetUserInput() error {
	seenDomains := make(map[string]bool)

	var inputReader io.Reader = os.Stdin
	if argDomain := flag.Arg(0); argDomain != "" {
		inputReader = strings.NewReader(argDomain)
	}

	scanner := bufio.NewScanner(inputReader)
	for scanner.Scan() {
		domain := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}
		if seenDomains[domain] {
			continue
		}
		seenDomains[domain] = true
		domains <- domain
	}

	return scanner.Err()
}
