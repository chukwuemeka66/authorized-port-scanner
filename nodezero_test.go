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

func TestFetchAndLogAttackPaths(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "security_events.log")
	apiKey := strings.Join([]string{"test", "key"}, "-")
	token := "test-token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth":
			if r.Method != http.MethodPost {
				t.Errorf("auth method = %s, want POST", r.Method)
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode auth request: %v", err)
			}
			if body["key"] != apiKey {
				t.Errorf("auth key = %q, want configured test key", body["key"])
			}
			_, _ = w.Write([]byte(`{"token":"test-token"}`))
		case "/graphql":
			if r.Header.Get("Authorization") != "Bearer "+token {
				t.Errorf("Authorization = %q, want bearer token", r.Header.Get("Authorization"))
			}
			var request GraphQLRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode GraphQL request: %v", err)
			}
			if !strings.Contains(request.Query, "attackPaths") {
				t.Errorf("GraphQL query does not request attack paths: %q", request.Query)
			}
			_, _ = w.Write([]byte(`{"data":{"attackPaths":[{"id":"path-1","severity":"High","attackPathTitle":"Example path","ipAddress":"192.0.2.10","hostName":"example.internal"}]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewNodeZeroClient()
	client.AuthURL = server.URL + "/auth"
	client.GraphQLURL = server.URL + "/graphql"
	client.APIKey = apiKey
	client.HTTPClient = server.Client()
	client.LogPath = logPath

	paths, err := client.FetchAndLogAttackPaths()
	if err != nil {
		t.Fatalf("FetchAndLogAttackPaths() error = %v", err)
	}
	if len(paths) != 1 || paths[0].ID != "path-1" {
		t.Fatalf("paths = %#v, want one attack path", paths)
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read security event log: %v", err)
	}
	if !strings.Contains(string(logData), `"source":"NodeZero"`) ||
		!strings.Contains(string(logData), `"event_id":"path-1"`) {
		t.Errorf("security event log missing NodeZero path: %s", logData)
	}
}

func TestNodeZeroRejectsInsecureNonLoopbackURL(t *testing.T) {
	if err := validateNodeZeroURL("http://example.com/v1/auth"); err == nil {
		t.Fatal("validateNodeZeroURL() error = nil, want HTTPS requirement")
	}
}

func TestValidateNodeZeroURLAllowsLoopbackHTTP(t *testing.T) {
	for _, testURL := range []string{
		"http://localhost:8080/v1/auth",
		"http://127.0.0.1:8080/v1/auth",
	} {
		if err := validateNodeZeroURL(testURL); err != nil {
			t.Errorf("validateNodeZeroURL(%q) error = %v, want loopback HTTP to be allowed", testURL, err)
		}
	}
}

func TestValidateNodeZeroURLRejectsUnsafeURLForms(t *testing.T) {
	for _, testURL := range []string{
		"",
		"https:///v1/auth",
		"https://user:pass@example.com/v1/auth",
		"https://example.com/v1/auth?key=value",
		"https://example.com/v1/auth?",
		"https://example.com/v1/auth#fragment",
		"http://[::1]:8080/v1/auth",
	} {
		if err := validateNodeZeroURL(testURL); err == nil {
			t.Errorf("validateNodeZeroURL(%q) error = nil, want rejection", testURL)
		}
	}
}

func TestNewNodeZeroClient(t *testing.T) {
	t.Setenv("H3_API_KEY", "test-key-123")

	client := NewNodeZeroClient()
	if client.APIKey != "test-key-123" {
		t.Errorf("APIKey = %q, want %q", client.APIKey, "test-key-123")
	}
	if client.LogPath != "security_events.log" {
		t.Errorf("LogPath = %q, want %q", client.LogPath, "security_events.log")
	}
}

func TestAuthenticateMock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"token": "mock-jwt-token-xyz"}`))
	}))
	defer server.Close()

	client := &NodeZeroClient{
		AuthURL:    server.URL,
		APIKey:     "dummy-key",
		HTTPClient: server.Client(),
	}

	token, err := client.Authenticate()
	if err != nil {
		t.Fatalf("Authenticate() error = %v, want nil", err)
	}
	if token != "mock-jwt-token-xyz" {
		t.Errorf("Authenticate() token = %q, want %q", token, "mock-jwt-token-xyz")
	}
}

func TestFetchDetailedAttackPathsExcludesPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth" {
			_, _ = w.Write([]byte(`{"token":"test-token"}`))
			return
		}

		var request GraphQLRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode GraphQL request: %v", err)
		}
		if strings.Contains(request.Query, "payload") {
			t.Error("GraphQL query unexpectedly requested payload data")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"attackPaths":[{"id":"path-1","severity":"High","attackPathTitle":"Example path","ipAddress":"192.0.2.10","hostName":"example.internal","timestamp":"2026-11-05T12:00:00Z"}]}}`))
	}))
	defer server.Close()

	client := NewNodeZeroClient()
	client.AuthURL = server.URL + "/auth"
	client.GraphQLURL = server.URL + "/graphql"
	client.APIKey = "test-key"
	client.HTTPClient = server.Client()

	paths, err := client.FetchDetailedAttackPaths()
	if err != nil {
		t.Fatalf("FetchDetailedAttackPaths() error = %v", err)
	}
	if len(paths) != 1 || paths[0].ID != "path-1" {
		t.Fatalf("FetchDetailedAttackPaths() = %#v, want one path", paths)
	}
	if paths[0].Timestamp != "2026-11-05T12:00:00Z" {
		t.Errorf("Timestamp = %q, want timestamp from response", paths[0].Timestamp)
	}
}

func TestFetchAndLogAttackPathsReportsGraphQLErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/auth" {
			_, _ = w.Write([]byte(`{"token":"test-token"}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"attackPaths":[]},"errors":[{"message":"query denied"}]}`))
	}))
	defer server.Close()

	client := NewNodeZeroClient()
	client.AuthURL = server.URL + "/auth"
	client.GraphQLURL = server.URL + "/graphql"
	client.APIKey = strings.Join([]string{"test", "key"}, "-")
	client.HTTPClient = server.Client()
	client.LogPath = filepath.Join(t.TempDir(), "security_events.log")

	if _, err := client.FetchAndLogAttackPaths(); err == nil {
		t.Fatal("FetchAndLogAttackPaths() error = nil, want GraphQL error")
	}
}
