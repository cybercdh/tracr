/*
tracr - DNS Tracer for Dangling Nameserver Detection

Analyzes a list of subdomains to identify potential dangling nameservers
by performing DNS traces and detecting REFUSED/SERVFAIL responses.

Usage:
  echo "subdomain.example.com" | tracr
  tracr subdomain.example.com
  cat subdomains.txt | tracr -c 50 -v
*/

package main

import (
	"flag"
	"fmt"
	"os"
	"sync"

	"github.com/gookit/color"
)

// Command-line flags
var (
	verbose     bool
	concurrency int
)

// Worker channels
var (
	domains  = make(chan string, 200)
	refusals = make(chan Target, 200)
)

func main() {
	// Parse command-line arguments
	flag.IntVar(&concurrency, "c", 20, "Number of concurrent workers (default: 20)")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output showing all attempts")
	flag.Parse()

	if concurrency < 1 {
		fmt.Fprintf(os.Stderr, "-c must be at least 1 (got %d)\n", concurrency)
		os.Exit(2)
	}

	// Initialize domain tracking container to prevent duplicate processing
	container := Container{
		seen: make(map[string]bool),
	}

	// Start trace workers - these perform DNS traces on input domains
	var traceGroup sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		traceGroup.Add(1)
		go func() {
			defer traceGroup.Done()
			for domain := range domains {
				TraceIt(domain)
			}
		}()
	}

	// Start refusal check workers - these test nameservers for vulnerabilities
	var refusalGroup sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		refusalGroup.Add(1)
		go func() {
			defer refusalGroup.Done()
			for target := range refusals {
				// Skip domains we've already processed (atomic check-and-mark)
				if !container.markSeen(target.domain) {
					if verbose {
						fmt.Fprintf(os.Stderr, "[SKIP] Already checked: %s\n", target.domain)
					}
					continue
				}

				// Test for dangling nameserver vulnerability
				isVulnerable, err := CheckForRefusal(&target)
				if err != nil {
					if verbose {
						fmt.Printf("[ERROR] Failed to check %s: %v\n", target.domain, err)
					}
					continue
				}

				if isVulnerable {
					if verbose {
						color.Green.Printf("[VULN] %s (nameserver: %s)\n", target.domain, target.vulnNS)
					} else {
						// Simple output for piping to other tools
						fmt.Println(target.domain)
					}
				}
			}
		}()
	}

	// Read domains from stdin or command line argument
	if err := GetUserInput(); err != nil {
		fmt.Fprint(os.Stderr, color.Red.Sprintf("[ERROR] Failed to read input: %v\n", err))
		os.Exit(1)
	}

	// Shutdown workers gracefully
	close(domains)
	traceGroup.Wait()

	close(refusals)
	refusalGroup.Wait()
}
