package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func validateXDREndpoint(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return fmt.Errorf("invalid XDR endpoint URL")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		if strings.EqualFold(host, "localhost") {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("XDR endpoint must use HTTPS (HTTP is allowed only for loopback tests)")
}

// ForwardToXDR sends a security event to an XDR endpoint using bearer-token authentication.
func ForwardToXDR(endpointURL, apiKey string, event SecurityEvent) error {
	if strings.TrimSpace(apiKey) == "" {
		return fmt.Errorf("XDR API key is required")
	}
	if err := validateXDREndpoint(endpointURL); err != nil {
		return err
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode XDR security event: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpointURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create XDR request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("send XDR security event: %w", err)
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return fmt.Errorf("read XDR response: %w", readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close XDR response: %w", closeErr)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("XDR endpoint returned unexpected HTTP status %s", resp.Status)
	}
	return nil
}
