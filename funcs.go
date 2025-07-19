package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/lixiangzhong/dnsutil"
	"github.com/miekg/dns"
	"golang.org/x/exp/slices"
)

// addToSeen marks a domain as already processed to prevent duplicate work
func (c *Container) addToSeen(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen[domain] = true
}

// isSeen checks if a domain has already been processed
func (c *Container) isSeen(domain string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, exists := c.seen[domain]
	return exists
}

// hasMoreThanTwoDots validates that a domain has at least two dots
// This helps filter out TLD-only results like "com." or "net."
func hasMoreThanTwoDots(domain string) bool {
	// Pattern matches: anything.something.anything (at least 3 parts)
	pattern := `(?s).*\.[^.]*\..*`
	matched, err := regexp.Match(pattern, []byte(domain))
	if err != nil {
		return false
	}
	return matched
}

// TraceIt performs a DNS trace on the input domain to discover nameservers
// Sends discovered nameserver information to the refusals channel for vulnerability testing
func TraceIt(inputDomain string) {
	if verbose {
		fmt.Printf("[TRACE] dig %s +trace\n", inputDomain)
	}

	var dig dnsutil.Dig
	responses, err := dig.Trace(inputDomain)
	if err != nil {
		if verbose {
			fmt.Printf("[ERROR] Failed to trace %s: %v\n", inputDomain, err)
		}
		return
	}

	// Process each response in the trace
	for i, response := range responses {
		var nameServers []string
		var targetDomain string

		// Focus on the second-to-last response which typically contains
		// the authoritative nameservers for the domain
		if i != len(responses)-2 {
			continue
		}

		// Extract nameserver records from the authority section
		for _, nsRecord := range response.Msg.Ns {
			fields := strings.Split(nsRecord.String(), "\t")
			if len(fields) < 5 {
				continue
			}

			recordType := fields[3]
			if recordType != "NS" {
				continue
			}

			targetDomain = fields[0]
			nameServer := fields[4]

			// Skip domains that don't have enough depth (e.g., TLDs)
			if !hasMoreThanTwoDots(targetDomain) {
				continue
			}

			// Collect unique nameservers
			if !slices.Contains(nameServers, nameServer) {
				if verbose {
					fmt.Printf("[NS] %s -> %s\n", inputDomain, nameServer)
				}
				nameServers = append(nameServers, nameServer)
			}
		}

		// If we found nameservers, create a target for vulnerability testing
		if len(nameServers) > 0 {
			target := Target{
				domain:    strings.TrimSuffix(targetDomain, "."),
				subdomain: strings.TrimSuffix(inputDomain, "."),
				servers:   nameServers,
			}
			refusals <- target
		}
	}
}

// CheckForRefusal tests nameservers to detect dangling nameserver vulnerabilities
// Returns true if any nameserver responds with REFUSED or SERVFAIL
func CheckForRefusal(target *Target) (bool, error) {
	var dig dnsutil.Dig

	for _, nameServer := range target.servers {
		if verbose {
			fmt.Printf("[CHECK] dig %s @%s\n", target.domain, nameServer)
		}

		dig.SetDNS(nameServer)
		message, err := dig.GetMsg(dns.TypeA, target.domain)
		if err != nil {
			if verbose {
				fmt.Printf("[ERROR] Query failed for %s@%s: %v\n", target.domain, nameServer, err)
			}
			continue // Try other nameservers
		}

		// Check response code for signs of dangling nameserver
		responseCode := dns.RcodeToString[message.MsgHdr.Rcode]
		if responseCode == "REFUSED" || responseCode == "SERVFAIL" {
			target.vulnNS = nameServer
			if verbose {
				fmt.Printf("[FOUND] %s nameserver %s returned %s\n", target.domain, nameServer, responseCode)
			}
			return true, nil
		}

		if verbose {
			fmt.Printf("[OK] %s@%s returned %s\n", target.domain, nameServer, responseCode)
		}
	}

	return false, nil
}

// GetUserInput reads domains from stdin or command line argument
// Sends each unique domain to the domains channel for processing
func GetUserInput() error {
	seenDomains := make(map[string]bool)

	// Determine input source: stdin or command line argument
	var inputReader io.Reader = os.Stdin

	if argDomain := flag.Arg(0); argDomain != "" {
		inputReader = strings.NewReader(argDomain)
	}

	scanner := bufio.NewScanner(inputReader)

	for scanner.Scan() {
		domain := strings.ToLower(strings.TrimSpace(scanner.Text()))

		// Skip empty lines
		if domain == "" {
			continue
		}

		// Skip domains we've already seen in this session
		if seenDomains[domain] {
			continue
		}

		seenDomains[domain] = true
		domains <- domain
	}

	return scanner.Err()
}
