package tool

import (
	"fmt"
	"net"
)

// ResolveDomain performs a DNS lookup for the given domain name
// and returns the first IPv4 address found
func ResolveDomain(domain string) (string, error) {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "", fmt.Errorf("could not resolve domain %s: %v", domain, err)
	}

	// Look for the first IPv4 address
	for _, ip := range ips {
		// Check if this is an IPv4 address
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found for domain %s", domain)
}
