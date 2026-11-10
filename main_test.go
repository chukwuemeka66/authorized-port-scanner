package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSendLogSuccess(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}
		if got := r.Header.Get("Authorization"); got != "Splunk test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Splunk test-token")
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	}))
	defer ts.Close()

	resp, err := sendLog(ts.URL, "test-token", ts.Client(), []byte(`{"status":"test"}`))
	if err != nil {
		t.Fatalf("sendLog() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestSendLogWithoutToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want no authorization header", got)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	resp, err := sendLog(ts.URL, "", ts.Client(), []byte(`{"status":"test"}`))
	if err != nil {
		t.Fatalf("sendLog() error = %v", err)
	}
	resp.Body.Close()
}

func TestSendLogToSplunkHEC(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Splunk test-token" {
			t.Errorf("Authorization = %q, want %q", got, "Splunk test-token")
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", got)
		}

		var payload struct {
			Time       int64  `json:"time"`
			Host       string `json:"host"`
			Sourcetype string `json:"sourcetype"`
			Event      struct {
				Timestamp string `json:"timestamp"`
				EventType string `json:"event_type"`
				Status    string `json:"status"`
			} `json:"event"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode HEC payload: %v", err)
		}
		if payload.Time == 0 || payload.Host != "local-scanner-node" || payload.Sourcetype != "ovimscannerjson" {
			t.Errorf("HEC metadata = %+v, want timestamp, local-scanner-node, ovimscannerjson", payload)
		}
		if payload.Event.EventType != "SECURITY_SCAN_EVENT" || payload.Event.Status != "SUCCESS" {
			t.Errorf("event = %+v, want SECURITY_SCAN_EVENT/SUCCESS", payload.Event)
		}
		if _, err := time.Parse(time.RFC3339, payload.Event.Timestamp); err != nil {
			t.Errorf("event timestamp %q is not RFC3339: %v", payload.Event.Timestamp, err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	resp, err := SendLogToSplunkHEC(ts.URL, "test-token", "SECURITY_SCAN_EVENT", "SUCCESS")
	if err != nil {
		t.Fatalf("SendLogToSplunkHEC() error = %v", err)
	}
	resp.Body.Close()
}

func TestSecurityEventJSON(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	event := SecurityEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		EventType: "SECURITY_SCAN_EVENT",
		Status:    "SUCCESS",
	}
	after := time.Now().UTC().Add(time.Second)

	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal SecurityEvent: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("failed to decode marshaled event: %v", err)
	}

	for _, field := range []string{"timestamp", "event_type", "status"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing JSON field %q", field)
		}
	}

	if got := decoded["event_type"]; got != "SECURITY_SCAN_EVENT" {
		t.Errorf("event_type = %v, want SECURITY_SCAN_EVENT", got)
	}
	if got := decoded["status"]; got != "SUCCESS" {
		t.Errorf("status = %v, want SUCCESS", got)
	}

	parsedTimestamp, err := time.Parse(time.RFC3339, event.Timestamp)
	if err != nil {
		t.Fatalf("timestamp is not RFC3339: %v", err)
	}
	if parsedTimestamp.Before(before) || parsedTimestamp.After(after) {
		t.Errorf("timestamp %v is outside the test interval", parsedTimestamp)
	}
}
