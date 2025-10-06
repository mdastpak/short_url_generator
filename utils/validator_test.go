package utils

import (
	"testing"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr error
	}{
		{
			name:    "Valid HTTP URL",
			url:     "http://example.com",
			wantErr: nil,
		},
		{
			name:    "Valid HTTPS URL",
			url:     "https://www.example.com/path?query=value",
			wantErr: nil,
		},
		{
			name:    "Empty URL",
			url:     "",
			wantErr: ErrEmptyURL,
		},
		{
			name:    "Invalid URL format",
			url:     "not a url",
			wantErr: ErrInvalidURL,
		},
		{
			name:    "Invalid scheme - FTP",
			url:     "ftp://example.com",
			wantErr: ErrInvalidScheme,
		},
		{
			name:    "Invalid scheme - JavaScript",
			url:     "javascript:alert('xss')",
			wantErr: ErrInvalidScheme,
		},
		{
			name:    "Localhost - hostname",
			url:     "http://localhost:8080",
			wantErr: ErrLocalhostNotAllowed,
		},
		{
			name:    "Localhost - 127.0.0.1",
			url:     "http://127.0.0.1",
			wantErr: ErrLocalhostNotAllowed,
		},
		{
			name:    "Localhost - IPv6 loopback",
			url:     "http://[::1]",
			wantErr: ErrLocalhostNotAllowed,
		},
		{
			name:    "Private IP - 10.x.x.x",
			url:     "http://10.0.0.1",
			wantErr: ErrPrivateIPNotAllowed,
		},
		{
			name:    "Private IP - 192.168.x.x",
			url:     "http://192.168.1.1",
			wantErr: ErrPrivateIPNotAllowed,
		},
		{
			name:    "Private IP - 172.16-31.x.x",
			url:     "http://172.16.0.1",
			wantErr: ErrPrivateIPNotAllowed,
		},
		{
			name:    "Link-local IP",
			url:     "http://169.254.1.1",
			wantErr: ErrPrivateIPNotAllowed,
		},
		{
			name:    "Valid URL with path and query",
			url:     "https://github.com/user/repo?tab=readme",
			wantErr: nil,
		},
		{
			name:    "Valid URL with port",
			url:     "https://example.com:8080/api",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateURL(tt.url)
			if err != tt.wantErr {
				t.Errorf("ValidateURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsLocalhost(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{"localhost", "localhost", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"IPv6 loopback", "::1", true},
		{"0.0.0.0", "0.0.0.0", true},
		{"Localhost uppercase", "LOCALHOST", true},
		{"example.com", "example.com", false},
		{"192.168.1.1", "192.168.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLocalhost(tt.hostname); got != tt.want {
				t.Errorf("isLocalhost() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{"10.0.0.1", "10.0.0.1", true},
		{"10.255.255.254", "10.255.255.254", true},
		{"172.16.0.1", "172.16.0.1", true},
		{"172.31.255.254", "172.31.255.254", true},
		{"192.168.0.1", "192.168.0.1", true},
		{"192.168.255.254", "192.168.255.254", true},
		{"169.254.1.1", "169.254.1.1", true},
		{"8.8.8.8 (Google DNS)", "8.8.8.8", false},
		{"1.1.1.1 (Cloudflare DNS)", "1.1.1.1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPrivateIP(tt.hostname); got != tt.want {
				t.Errorf("isPrivateIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
