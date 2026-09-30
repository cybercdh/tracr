package main

import "sync"

// Container tracks which domains have been processed to prevent duplicates.
// Uses a mutex for thread-safe access across concurrent workers.
type Container struct {
	mu   sync.Mutex
	seen map[string]bool
}

// markSeen records domain and reports whether it was new. The check and the
// mark happen under one lock, so two workers cannot both treat the same
// domain as unseen and each go on to query its nameservers.
func (c *Container) markSeen(domain string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen[domain] {
		return false
	}
	c.seen[domain] = true
	return true
}

// Target represents a domain and its associated nameservers to be tested
// for dangling nameserver vulnerabilities.
type Target struct {
	domain    string   // The domain extracted from DNS trace (e.g., "example.com")
	subdomain string   // The original input subdomain (e.g., "sub.example.com")
	servers   []string // List of nameservers to test
	vulnNS    string   // The nameserver that returned REFUSED/SERVFAIL (if vulnerable)
}
