package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewXBOWClientUsesAPIURLFromEnvironment(t *testing.T) {
	t.Setenv("XBOW_API_URL", "https://xbow.example.test/v1")

	client := NewXBOWClient("test-key")
	if client.BaseURL != "https://xbow.example.test/v1" {
		t.Errorf("BaseURL = %q, want configured XBOW_API_URL", client.BaseURL)
	}
}

func TestFetchAndLogFindings(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "security_events.log")
	apiKey := strings.Join([]string{"test", "key"}, "-")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/assets/test-asset/findings" {
			t.Errorf("path = %q, want findings endpoint", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+apiKey {
			t.Errorf("Authorization = %q, want bearer token", got)
		}
		if got := r.Header.Get("X-XBOW-API-Version"); got != xbowVersion {
			t.Errorf("API version = %q, want %q", got, xbowVersion)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"finding-1","severity":"High","name":"Example","cve":"CVE-2026-1234","cwe":"CWE-79","description":"Example finding"}]`))
	}))
	defer server.Close()

	client := NewXBOWClient(apiKey)
	client.BaseURL = server.URL + "/api/v1"
	client.Client = server.Client()
	client.LogPath = logPath

	findings, err := client.FetchAndLogFindings("test-asset")
	if err != nil {
		t.Fatalf("FetchAndLogFindings() error = %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "finding-1" {
		t.Fatalf("findings = %#v, want one finding", findings)
	}
	if findings[0].CVE != "CVE-2026-1234" {
		t.Errorf("finding CVE = %q, want CVE-2026-1234", findings[0].CVE)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read security event log: %v", err)
	}
	if !strings.Contains(string(logData), `"source":"XBOW"`) ||
		!strings.Contains(string(logData), `"event_id":"finding-1"`) ||
		!strings.Contains(string(logData), `"cve":"CVE-2026-1234"`) {
		t.Errorf("security event log missing XBOW finding: %s", logData)
	}
}

func TestFetchAndLogFindingsRejectsInvalidAssetID(t *testing.T) {
	client := NewXBOWClient(strings.Join([]string{"test", "key"}, "-"))
	if _, err := client.FetchAndLogFindings("../other-asset"); err == nil {
		t.Fatal("FetchAndLogFindings() error = nil, want invalid asset ID error")
	}
}

func TestFetchAndLogFindingsReportsHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	client := NewXBOWClient(strings.Join([]string{"test", "key"}, "-"))
	client.BaseURL = server.URL
	client.Client = server.Client()
	client.LogPath = filepath.Join(t.TempDir(), "security_events.log")

	if _, err := client.FetchAndLogFindings("test-asset"); err == nil {
		t.Fatal("FetchAndLogFindings() error = nil, want HTTP status error")
	}
}
