package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxSplunkEventLineBytes = 5 << 20

type SplunkHECPayload struct {
	Time       int64           `json:"time"`
	Host       string          `json:"host"`
	Source     string          `json:"source,omitempty"`
	SourceType string          `json:"sourcetype"`
	Event      json.RawMessage `json:"event"`
}

// ShipAttackPathsToSplunk sends detailed NodeZero attack-path metadata to Splunk HEC.
func ShipAttackPathsToSplunk(paths []DetailedAttackPath) error {
	splunkURL := os.Getenv("SPLUNK_HEC_URL")
	splunkToken := os.Getenv("SPLUNK_HEC_TOKEN")
	if strings.TrimSpace(splunkURL) == "" || strings.TrimSpace(splunkToken) == "" {
		return fmt.Errorf("SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN environment variables must be set")
	}

	endpoint, err := splunkHECEndpoint(splunkURL)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}

	for _, path := range paths {
		event, err := json.Marshal(path)
		if err != nil {
			return fmt.Errorf("encode NodeZero attack path %q: %w", path.ID, err)
		}
		body, err := json.Marshal(SplunkHECPayload{
			Time:       time.Now().Unix(),
			Host:       "nodezero-scanner-01",
			Source:     "nodezero_ai_offensive",
			SourceType: "_json",
			Event:      event,
		})
		if err != nil {
			return fmt.Errorf("encode Splunk HEC payload for NodeZero attack path %q: %w", path.ID, err)
		}

		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create Splunk HEC request for NodeZero attack path %q: %w", path.ID, err)
		}
		req.Header.Set("Authorization", "Splunk "+splunkToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("send NodeZero attack path %q to Splunk HEC: %w", path.ID, err)
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read Splunk HEC response for NodeZero attack path %q: %w", path.ID, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close Splunk HEC response for NodeZero attack path %q: %w", path.ID, closeErr)
		}
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return fmt.Errorf("Splunk HEC rejected NodeZero attack path %q: unexpected HTTP status %s", path.ID, resp.Status)
		}
	}
	return nil
}

// ShipRecoveryEventsToSplunk sends recovered-file metadata to Splunk HEC.
func ShipRecoveryEventsToSplunk(events []RecoveryEvent) error {
	if len(events) == 0 {
		return nil
	}
	splunkURL := os.Getenv("SPLUNK_HEC_URL")
	splunkToken := os.Getenv("SPLUNK_HEC_TOKEN")
	if strings.TrimSpace(splunkURL) == "" || strings.TrimSpace(splunkToken) == "" {
		return fmt.Errorf("SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN environment variables must be set")
	}

	endpoint, err := splunkHECEndpoint(splunkURL)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}

	for _, recoveryEvent := range events {
		event, err := json.Marshal(recoveryEvent)
		if err != nil {
			return fmt.Errorf("encode recovered-file event at offset %d: %w", recoveryEvent.OffsetStart, err)
		}
		body, err := json.Marshal(SplunkHECPayload{
			Time:       time.Now().Unix(),
			Host:       "local-scanner-node",
			Source:     "Ovim-Gallery-Carver",
			SourceType: "_json",
			Event:      event,
		})
		if err != nil {
			return fmt.Errorf("encode Splunk HEC payload for recovered file at offset %d: %w", recoveryEvent.OffsetStart, err)
		}

		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create Splunk HEC request for recovered file at offset %d: %w", recoveryEvent.OffsetStart, err)
		}
		req.Header.Set("Authorization", "Splunk "+splunkToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("send recovered-file event at offset %d to Splunk HEC: %w", recoveryEvent.OffsetStart, err)
		}
		_, readErr := io.Copy(io.Discard, resp.Body)
		closeErr := resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read Splunk HEC response for recovered file at offset %d: %w", recoveryEvent.OffsetStart, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close Splunk HEC response for recovered file at offset %d: %w", recoveryEvent.OffsetStart, closeErr)
		}
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return fmt.Errorf("Splunk HEC rejected recovered-file event at offset %d: unexpected HTTP status %s", recoveryEvent.OffsetStart, resp.Status)
		}
	}
	return nil
}

func splunkHECEndpoint(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("invalid SPLUNK_HEC_URL")
	}
	if !strings.HasSuffix(strings.TrimRight(parsed.Path, "/"), "/services/collector") {
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/services/collector"
	}
	return parsed.String(), nil
}

// ShipLogFileToSplunk sends each JSON object in a JSONL file to Splunk HEC.
func ShipLogFileToSplunk(logPath, hecURL, hecToken string) error {
	file, err := os.Open(logPath)
	if err != nil {
		return fmt.Errorf("open security event log: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), maxSplunkEventLineBytes)
	client := &http.Client{Timeout: 10 * time.Second}

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var event map[string]json.RawMessage
		if err := json.Unmarshal(line, &event); err != nil {
			return fmt.Errorf("decode security event log line %d: %w", lineNumber, err)
		}
		if event == nil {
			return fmt.Errorf("decode security event log line %d: expected a JSON object", lineNumber)
		}

		payload := SplunkHECPayload{
			Time:       time.Now().Unix(),
			Host:       "local-scanner-node",
			SourceType: "xbow:findings:json",
			Event:      append(json.RawMessage(nil), line...),
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode Splunk HEC payload for line %d: %w", lineNumber, err)
		}

		req, err := http.NewRequest(http.MethodPost, hecURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create Splunk HEC request for line %d: %w", lineNumber, err)
		}
		req.Header.Set("Authorization", "Splunk "+hecToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("ship security event on line %d: %w", lineNumber, err)
		}
		resp.Body.Close()
		if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
			return fmt.Errorf("ship security event on line %d: unexpected HTTP status %s", lineNumber, resp.Status)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read security event log: %w", err)
	}
	return nil
}
