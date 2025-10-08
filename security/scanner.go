package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// ThreatType represents the type of security threat detected
type ThreatType string

const (
	ThreatMalware    ThreatType = "MALWARE"
	ThreatPhishing   ThreatType = "PHISHING"
	ThreatUnwanted   ThreatType = "UNWANTED_SOFTWARE"
	ThreatSocial     ThreatType = "SOCIAL_ENGINEERING"
	ThreatBlocklisted ThreatType = "BLOCKLISTED"
)

// ScanResult represents the result of a URL security scan
type ScanResult struct {
	Safe        bool         `json:"safe"`
	Threats     []ThreatType `json:"threats,omitempty"`
	Source      string       `json:"source"` // "blocklist", "safe_browsing", etc.
	ScannedAt   time.Time    `json:"scanned_at"`
	CheckedURL  string       `json:"checked_url"`
}

// URLScanner provides URL security scanning functionality
type URLScanner struct {
	safeBrowsingAPIKey string
	safeBrowsingEnabled bool
	blocklistEnabled    bool
	blocklist           []string
	httpClient          *http.Client
}

// NewURLScanner creates a new URL scanner instance
func NewURLScanner(safeBrowsingAPIKey string, blocklistEnabled bool) *URLScanner {
	return &URLScanner{
		safeBrowsingAPIKey:  safeBrowsingAPIKey,
		safeBrowsingEnabled: safeBrowsingAPIKey != "",
		blocklistEnabled:    blocklistEnabled,
		blocklist:           getDefaultBlocklist(),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// ScanURL checks if a URL is safe using available scanning methods
func (s *URLScanner) ScanURL(ctx context.Context, urlStr string) (*ScanResult, error) {
	result := &ScanResult{
		Safe:       true,
		Threats:    []ThreatType{},
		ScannedAt:  time.Now(),
		CheckedURL: urlStr,
	}

	// Check local blocklist first (fastest)
	if s.blocklistEnabled {
		if threat := s.checkBlocklist(urlStr); threat != "" {
			result.Safe = false
			result.Threats = append(result.Threats, ThreatBlocklisted)
			result.Source = "blocklist"
			log.Warn().Str("url", urlStr).Str("threat", string(threat)).Msg("URL blocked by local blocklist")
			return result, nil
		}
	}

	// Check Google Safe Browsing API if enabled
	if s.safeBrowsingEnabled {
		threats, err := s.checkSafeBrowsing(ctx, urlStr)
		if err != nil {
			log.Error().Err(err).Msg("Safe Browsing API check failed")
			// Don't fail the request, just log the error
			result.Source = "blocklist"
			return result, nil
		}

		if len(threats) > 0 {
			result.Safe = false
			result.Threats = threats
			result.Source = "safe_browsing"
			log.Warn().
				Str("url", urlStr).
				Interface("threats", threats).
				Msg("URL flagged by Safe Browsing API")
			return result, nil
		}

		result.Source = "safe_browsing"
	} else {
		result.Source = "blocklist"
	}

	return result, nil
}

// checkBlocklist checks URL against local blocklist
func (s *URLScanner) checkBlocklist(urlStr string) ThreatType {
	urlLower := strings.ToLower(urlStr)

	for _, pattern := range s.blocklist {
		if strings.Contains(urlLower, pattern) {
			return ThreatBlocklisted
		}
	}

	return ""
}

// SafeBrowsingRequest represents a Google Safe Browsing API v4 request
type SafeBrowsingRequest struct {
	Client struct {
		ClientID      string `json:"clientId"`
		ClientVersion string `json:"clientVersion"`
	} `json:"client"`
	ThreatInfo struct {
		ThreatTypes      []string `json:"threatTypes"`
		PlatformTypes    []string `json:"platformTypes"`
		ThreatEntryTypes []string `json:"threatEntryTypes"`
		ThreatEntries    []struct {
			URL string `json:"url"`
		} `json:"threatEntries"`
	} `json:"threatInfo"`
}

// SafeBrowsingResponse represents a Google Safe Browsing API v4 response
type SafeBrowsingResponse struct {
	Matches []struct {
		ThreatType      string `json:"threatType"`
		PlatformType    string `json:"platformType"`
		ThreatEntryType string `json:"threatEntryType"`
		Threat          struct {
			URL string `json:"url"`
		} `json:"threat"`
	} `json:"matches"`
}

// checkSafeBrowsing checks URL against Google Safe Browsing API
func (s *URLScanner) checkSafeBrowsing(ctx context.Context, urlStr string) ([]ThreatType, error) {
	apiURL := "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + s.safeBrowsingAPIKey

	reqBody := SafeBrowsingRequest{}
	reqBody.Client.ClientID = "short-url-generator"
	reqBody.Client.ClientVersion = "1.0.0"
	reqBody.ThreatInfo.ThreatTypes = []string{
		"MALWARE",
		"SOCIAL_ENGINEERING",
		"UNWANTED_SOFTWARE",
		"POTENTIALLY_HARMFUL_APPLICATION",
	}
	reqBody.ThreatInfo.PlatformTypes = []string{"ANY_PLATFORM"}
	reqBody.ThreatInfo.ThreatEntryTypes = []string{"URL"}
	reqBody.ThreatInfo.ThreatEntries = []struct {
		URL string `json:"url"`
	}{
		{URL: urlStr},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("safe browsing API returned non-200 status: " + resp.Status)
	}

	var sbResp SafeBrowsingResponse
	if err := json.NewDecoder(resp.Body).Decode(&sbResp); err != nil {
		return nil, err
	}

	// No matches means the URL is safe
	if len(sbResp.Matches) == 0 {
		return []ThreatType{}, nil
	}

	// Convert threat types
	threats := make([]ThreatType, 0, len(sbResp.Matches))
	for _, match := range sbResp.Matches {
		switch match.ThreatType {
		case "MALWARE":
			threats = append(threats, ThreatMalware)
		case "SOCIAL_ENGINEERING":
			threats = append(threats, ThreatPhishing)
		case "UNWANTED_SOFTWARE":
			threats = append(threats, ThreatUnwanted)
		}
	}

	return threats, nil
}

// getDefaultBlocklist returns a list of known malicious patterns
func getDefaultBlocklist() []string {
	return []string{
		// Common phishing patterns
		"bit.ly/",        // Often abused for phishing (you may want to whitelist specific patterns)
		"tinyurl.com/",   // Often abused
		"account-verify", // Common phishing pattern
		"confirm-account",
		"secure-login",
		"verify-identity",
		"suspended-account",
		"unusual-activity",
		"reset-password",
		"billing-problem",

		// Malware distribution patterns
		".exe?",
		".scr?",
		".bat?",
		".cmd?",
		".vbs?",

		// Known malicious TLDs (examples)
		".tk/",
		".ml/",
		".ga/",
		".cf/",
		".gq/",

		// Suspicious keywords
		"free-money",
		"free-bitcoin",
		"prize-winner",
		"click-here-now",
		"limited-time-offer",
	}
}

// AddToBlocklist adds a pattern to the blocklist
func (s *URLScanner) AddToBlocklist(pattern string) {
	s.blocklist = append(s.blocklist, strings.ToLower(pattern))
}

// RemoveFromBlocklist removes a pattern from the blocklist
func (s *URLScanner) RemoveFromBlocklist(pattern string) {
	pattern = strings.ToLower(pattern)
	for i, p := range s.blocklist {
		if p == pattern {
			s.blocklist = append(s.blocklist[:i], s.blocklist[i+1:]...)
			return
		}
	}
}

// GetBlocklist returns the current blocklist
func (s *URLScanner) GetBlocklist() []string {
	return s.blocklist
}
