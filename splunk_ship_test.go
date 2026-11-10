package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShipLogFileToSplunk(t *testing.T) {
	var received []SplunkHECPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Splunk test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Splunk test-token")
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}

		var payload SplunkHECPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode HEC payload: %v", err)
			return
		}
		received = append(received, payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logPath := filepath.Join(t.TempDir(), "security_events.log")
	logData := "{\"event_id\":\"finding-1\"}\n\n{\"event_id\":\"finding-2\"}\n"
	if err := os.WriteFile(logPath, []byte(logData), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	if err := ShipLogFileToSplunk(logPath, server.URL, "test-token"); err != nil {
		t.Fatalf("ShipLogFileToSplunk() error = %v", err)
	}
	if len(received) != 2 {
		t.Fatalf("received %d events, want 2", len(received))
	}
	for i, payload := range received {
		if payload.Time == 0 || payload.Host != "local-scanner-node" ||
			payload.SourceType != "xbow:findings:json" {
			t.Errorf("payload %d metadata = %+v, want timestamp, host, and XBOW sourcetype", i, payload)
		}
	}
	if !strings.Contains(string(received[0].Event), `"finding-1"`) ||
		!strings.Contains(string(received[1].Event), `"finding-2"`) {
		t.Errorf("events = %s, %s; want finding-1 and finding-2", received[0].Event, received[1].Event)
	}
}

func TestShipLogFileToSplunkReportsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	logPath := filepath.Join(t.TempDir(), "security_events.log")
	if err := os.WriteFile(logPath, []byte("{\"event_id\":\"finding-1\"}\n"), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	err := ShipLogFileToSplunk(logPath, server.URL, "test-token")
	if err == nil || !strings.Contains(err.Error(), "503 Service Unavailable") {
		t.Fatalf("ShipLogFileToSplunk() error = %v, want HTTP status error", err)
	}
}

func TestShipLogFileToSplunkReportsMalformedLine(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "security_events.log")
	if err := os.WriteFile(logPath, []byte("{invalid}\n"), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	err := ShipLogFileToSplunk(logPath, "http://127.0.0.1:1", "test-token")
	if err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("ShipLogFileToSplunk() error = %v, want malformed line error", err)
	}
}

func TestShipAttackPathsToSplunk(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/collector" {
			t.Errorf("path = %q, want /services/collector", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Splunk test-token" {
			t.Errorf("Authorization = %q, want Splunk test-token", got)
		}

		var payload struct {
			Time       int64  `json:"time"`
			Host       string `json:"host"`
			Source     string `json:"source"`
			Sourcetype string `json:"sourcetype"`
			Event      struct {
				ID        string `json:"id"`
				Severity  string `json:"severity"`
				Timestamp string `json:"timestamp"`
			} `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode HEC payload: %v", err)
			return
		}
		if payload.Time == 0 || payload.Host != "nodezero-scanner-01" ||
			payload.Source != "nodezero_ai_offensive" || payload.Sourcetype != "_json" {
			t.Errorf("payload metadata = %+v, unexpected values", payload)
		}
		if payload.Event.ID != "path-1" || payload.Event.Severity != "High" ||
			payload.Event.Timestamp != "2026-11-05T12:00:00Z" {
			t.Errorf("event = %+v, unexpected NodeZero attack-path metadata", payload.Event)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("SPLUNK_HEC_URL", server.URL)
	t.Setenv("SPLUNK_HEC_TOKEN", "test-token")

	err := ShipAttackPathsToSplunk([]DetailedAttackPath{{
		ID:        "path-1",
		Severity:  "High",
		HostName:  "example.internal",
		Timestamp: "2026-11-05T12:00:00Z",
	}})
	if err != nil {
		t.Fatalf("ShipAttackPathsToSplunk() error = %v", err)
	}
}

func TestShipAttackPathsToSplunkReportsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	t.Setenv("SPLUNK_HEC_URL", server.URL+"/services/collector")
	t.Setenv("SPLUNK_HEC_TOKEN", "test-token")

	err := ShipAttackPathsToSplunk([]DetailedAttackPath{{ID: "path-1"}})
	if err == nil || !strings.Contains(err.Error(), "503 Service Unavailable") {
		t.Fatalf("ShipAttackPathsToSplunk() error = %v, want HTTP status error", err)
	}
}

func TestShipRecoveryEventsToSplunk(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/collector" {
			t.Errorf("path = %q, want /services/collector", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Splunk test-token" {
			t.Errorf("Authorization = %q, want Splunk test-token", got)
		}
		var payload struct {
			Time       int64  `json:"time"`
			Host       string `json:"host"`
			Source     string `json:"source"`
			SourceType string `json:"sourcetype"`
			Event      struct {
				Timestamp     string `json:"timestamp"`
				Source        string `json:"source"`
				EventType     string `json:"event_type"`
				FileType      string `json:"file_type"`
				OffsetStart   int64  `json:"offset_start"`
				FileSizeBytes int64  `json:"file_size_bytes"`
				SHA256Hash    string `json:"sha256_hash"`
			} `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode HEC payload: %v", err)
			return
		}
		if payload.Time == 0 || payload.Host != "local-scanner-node" ||
			payload.Source != "Ovim-Gallery-Carver" || payload.SourceType != "_json" {
			t.Errorf("payload metadata = %+v, unexpected values", payload)
		}
		if payload.Event.Timestamp != "2026-11-06T21:11:02Z" ||
			payload.Event.Source != "Ovim-Gallery-Carver" ||
			payload.Event.EventType != "file_recovered" ||
			payload.Event.FileType != "pdf" ||
			payload.Event.OffsetStart != 1048576 ||
			payload.Event.FileSizeBytes != 45021 ||
			payload.Event.SHA256Hash != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
			t.Errorf("recovery event = %+v, unexpected values", payload.Event)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Setenv("SPLUNK_HEC_URL", server.URL)
	t.Setenv("SPLUNK_HEC_TOKEN", "test-token")

	err := ShipRecoveryEventsToSplunk([]RecoveryEvent{{
		Timestamp:     "2026-11-06T21:11:02Z",
		Source:        "Ovim-Gallery-Carver",
		EventType:     "file_recovered",
		FileType:      "pdf",
		OffsetStart:   1048576,
		FileSizeBytes: 45021,
		SHA256Hash:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	}})
	if err != nil {
		t.Fatalf("ShipRecoveryEventsToSplunk() error = %v", err)
	}
}

func TestShipRecoveryEventsToSplunkReportsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	t.Setenv("SPLUNK_HEC_URL", server.URL)
	t.Setenv("SPLUNK_HEC_TOKEN", "test-token")

	err := ShipRecoveryEventsToSplunk([]RecoveryEvent{{OffsetStart: 12}})
	if err == nil || !strings.Contains(err.Error(), "503 Service Unavailable") {
		t.Fatalf("ShipRecoveryEventsToSplunk() error = %v, want HTTP status error", err)
	}
}

func TestShipAttackPathsToSplunkRequiresConfiguration(t *testing.T) {
	t.Setenv("SPLUNK_HEC_URL", "")
	t.Setenv("SPLUNK_HEC_TOKEN", "")

	if err := ShipAttackPathsToSplunk(nil); err == nil {
		t.Fatal("ShipAttackPathsToSplunk() error = nil, want configuration error")
	}
}
