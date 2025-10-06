package utils

import (
	"net"
	"net/url"
	"strings"
)

// ValidateURL checks if the provided URL is valid and safe
func ValidateURL(rawURL string) error {
	if rawURL == "" {
		return ErrEmptyURL
	}

	// Parse the URL
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return ErrInvalidURL
	}

	// Check if scheme is http or https
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return ErrInvalidScheme
	}

	// Check if host is present
	if parsedURL.Host == "" {
		return ErrEmptyHost
	}

	// Extract hostname (without port)
	hostname := parsedURL.Hostname()

	// Block localhost and loopback addresses
	if isLocalhost(hostname) {
		return ErrLocalhostNotAllowed
	}

	// Block private IP addresses
	if isPrivateIP(hostname) {
		return ErrPrivateIPNotAllowed
	}

	return nil
}

// isLocalhost checks if the hostname is localhost or loopback
func isLocalhost(hostname string) bool {
	localhost := []string{"localhost", "127.0.0.1", "::1", "0.0.0.0"}
	hostname = strings.ToLower(hostname)

	for _, local := range localhost {
		if hostname == local {
			return true
		}
	}

	return false
}

// isPrivateIP checks if the hostname is a private IP address
func isPrivateIP(hostname string) bool {
	ip := net.ParseIP(hostname)
	if ip == nil {
		// Not an IP address, try to resolve it
		ips, err := net.LookupIP(hostname)
		if err != nil || len(ips) == 0 {
			return false
		}
		ip = ips[0]
	}

	// Check if IP is in private ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16", // Link-local
		"fc00::/7",        // IPv6 ULA
		"fe80::/10",       // IPv6 Link-local
	}

	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}
