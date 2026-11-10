package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const xbowAPIVersion = "2026-08-01"
const xbowVersion = xbowAPIVersion
const maxXBOWResponseBytes = 5 << 20

type XBOWClient struct {
	APIKey  string
	BaseURL string
	Client  *http.Client
	LogPath string
}

type Finding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Name        string `json:"name"`
	CVE         string `json:"cve"`
	CWE         string `json:"cwe"`
	Description string `json:"description"`
}

type xbowFindingLogEntry struct {
	Timestamp   string `json:"timestamp"`
	Source      string `json:"source"`
	EventID     string `json:"event_id"`
	AssetID     string `json:"asset_id"`
	Severity    string `json:"severity"`
	Name        string `json:"name"`
	CVE         string `json:"cve"`
	CWE         string `json:"cwe"`
	Description string `json:"description"`
}

func NewXBOWClient(apiKey string) *XBOWClient {
	baseURL := os.Getenv("XBOW_API_URL")
	if baseURL == "" {
		baseURL = "https://api.xbow.com/api/v1"
	}
	return &XBOWClient{
		APIKey:  apiKey,
		BaseURL: baseURL,
		Client:  &http.Client{Timeout: 15 * time.Second},
		LogPath: "security_events.log",
	}
}

// FetchAndLogFindings retrieves findings for one asset and appends them as JSONL.
func (x *XBOWClient) FetchAndLogFindings(assetID string) ([]Finding, error) {
	if strings.TrimSpace(x.APIKey) == "" {
		return nil, fmt.Errorf("XBOW API key is required")
	}
	if assetID == "" || assetID == "." || assetID == ".." {
		return nil, fmt.Errorf("invalid XBOW asset ID")
	}
	for _, r := range assetID {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || strings.ContainsRune("._~-", r)) {
			return nil, fmt.Errorf("invalid XBOW asset ID")
		}
	}
	if x.Client == nil {
		return nil, fmt.Errorf("XBOW HTTP client is not configured")
	}
	if x.BaseURL == "" {
		return nil, fmt.Errorf("XBOW API base URL is not configured")
	}

	endpoint := strings.TrimRight(x.BaseURL, "/") + "/assets/" + url.PathEscape(assetID) + "/findings"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create XBOW findings request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+x.APIKey)
	req.Header.Set("X-XBOW-API-Version", xbowAPIVersion)
	req.Header.Set("Accept", "application/json")

	resp, err := x.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch XBOW findings: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch XBOW findings: unexpected HTTP status %s", resp.Status)
	}

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxXBOWResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read XBOW findings response: %w", err)
	}
	if len(responseBody) > maxXBOWResponseBytes {
		return nil, fmt.Errorf("XBOW findings response exceeds %d bytes", maxXBOWResponseBytes)
	}

	var findings []Finding
	if err := json.Unmarshal(responseBody, &findings); err != nil {
		return nil, fmt.Errorf("decode XBOW findings response: %w", err)
	}
	if findings == nil {
		return nil, fmt.Errorf("decode XBOW findings response: expected a JSON array")
	}

	file, err := os.OpenFile(x.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return findings, fmt.Errorf("open security event log: %w", err)
	}
	for _, finding := range findings {
		entry := xbowFindingLogEntry{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Source:      "XBOW",
			EventID:     finding.ID,
			AssetID:     assetID,
			Severity:    finding.Severity,
			Name:        finding.Name,
			CVE:         finding.CVE,
			CWE:         finding.CWE,
			Description: finding.Description,
		}
		line, err := json.Marshal(entry)
		if err != nil {
			_ = file.Close()
			return findings, fmt.Errorf("encode XBOW finding for security log: %w", err)
		}
		line = append(line, '\n')
		written, err := file.Write(line)
		if err != nil {
			_ = file.Close()
			return findings, fmt.Errorf("write XBOW finding to security log: %w", err)
		}
		if written != len(line) {
			_ = file.Close()
			return findings, fmt.Errorf("write XBOW finding to security log: %w", io.ErrShortWrite)
		}
	}
	if err := file.Close(); err != nil {
		return findings, fmt.Errorf("close security event log: %w", err)
	}
	return findings, nil
}
