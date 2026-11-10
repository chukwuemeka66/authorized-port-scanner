package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFetchAndLogFindingsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET method, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-api-key" {
			t.Errorf("Authorization = %q, want bearer test-api-key", got)
		}
		if got := r.Header.Get("X-XBOW-API-Version"); got != xbowVersion {
			t.Errorf("X-XBOW-API-Version = %q, want %q", got, xbowVersion)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{
				"id": "FIND-001",
				"severity": "HIGH",
				"name": "SQL Injection",
				"cve": "CVE-2026-1234",
				"description": "Potential SQL injection vector detected in query parameter."
			}
		]`))
	}))
	defer server.Close()

	client := NewXBOWClient("test-api-key")
	client.BaseURL = server.URL
	client.Client = server.Client()
	client.LogPath = filepath.Join(t.TempDir(), "security_events.log")

	findings, err := client.FetchAndLogFindings("asset-alpha-1")
	if err != nil {
		t.Fatalf("FetchAndLogFindings() error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "FIND-001" {
		t.Errorf("finding ID = %q, want FIND-001", findings[0].ID)
	}
	if findings[0].CVE != "CVE-2026-1234" {
		t.Errorf("finding CVE = %q, want CVE-2026-1234", findings[0].CVE)
	}

	logData, err := os.ReadFile(client.LogPath)
	if err != nil {
		t.Fatalf("failed to read generated log file: %v", err)
	}
	if len(logData) == 0 {
		t.Error("expected security log file to contain data")
	}
}
