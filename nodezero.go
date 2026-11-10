package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const maxNodeZeroResponseBytes = 5 << 20

const nodeZeroAttackPathsQuery = `query {
	attackPaths {
		id
		severity
		attackPathTitle
		ipAddress
		hostName
	}
}`

type NodeZeroClient struct {
	AuthURL    string
	GraphQLURL string
	APIKey     string
	HTTPClient *http.Client
	LogPath    string
}

type AuthResponse struct {
	Token string `json:"token"`
}

type AuthRequest struct {
	Key string `json:"key"`
}

type GraphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

type NodeZeroAttackPath struct {
	ID              string `json:"id"`
	Severity        string `json:"severity"`
	AttackPathTitle string `json:"attackPathTitle"`
	IPAddress       string `json:"ipAddress"`
	HostName        string `json:"hostName"`
}

type StartAssessmentResponse struct {
	AssessmentID string `json:"assessment_id"`
	Status       string `json:"status"`
}

type DetailedAttackPath struct {
	ID              string `json:"id"`
	Severity        string `json:"severity"`
	AttackPathTitle string `json:"attackPathTitle"`
	IPAddress       string `json:"ipAddress"`
	HostName        string `json:"hostName"`
	Timestamp       string `json:"timestamp"`
}

type detailedNodeZeroGraphQLResponse struct {
	Data struct {
		AttackPaths []DetailedAttackPath `json:"attackPaths"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type nodeZeroGraphQLResponse struct {
	Data struct {
		AttackPaths []NodeZeroAttackPath `json:"attackPaths"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

type nodeZeroLogEntry struct {
	Timestamp       string `json:"timestamp"`
	Source          string `json:"source"`
	EventID         string `json:"event_id"`
	Severity        string `json:"severity"`
	AttackPathTitle string `json:"attack_path_title"`
	IPAddress       string `json:"ip_address"`
	HostName        string `json:"host_name"`
}

func NewNodeZeroClient() *NodeZeroClient {
	authURL := os.Getenv("H3_AUTH_URL")
	if authURL == "" {
		authURL = "https://api.gateway.horizon3ai.com/v1/auth"
	}
	graphQLURL := os.Getenv("H3_GRAPHQL_URL")
	if graphQLURL == "" {
		graphQLURL = "https://api.gateway.horizon3ai.com/v1/graphql"
	}
	return &NodeZeroClient{
		AuthURL:    authURL,
		GraphQLURL: graphQLURL,
		APIKey:     os.Getenv("H3_API_KEY"),
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		LogPath: "security_events.log",
	}
}

func validateNodeZeroURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid NodeZero URL: %w", err)
	}
	if parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" {
		return fmt.Errorf("invalid NodeZero URL")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		if strings.EqualFold(host, "localhost") {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.Equal(net.IPv4(127, 0, 0, 1)) {
			return nil
		}
	}
	return fmt.Errorf("NodeZero URLs must use HTTPS (HTTP is allowed only for loopback tests)")
}

func (c *NodeZeroClient) postJSON(endpoint string, payload any, bearerToken string) ([]byte, error) {
	if err := validateNodeZeroURL(endpoint); err != nil {
		return nil, err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode NodeZero request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create NodeZero request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send NodeZero request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("NodeZero request returned HTTP status %s", resp.Status)
	}
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxNodeZeroResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read NodeZero response: %w", err)
	}
	if len(responseBody) > maxNodeZeroResponseBytes {
		return nil, fmt.Errorf("NodeZero response exceeds %d bytes", maxNodeZeroResponseBytes)
	}
	return responseBody, nil
}

func (c *NodeZeroClient) Authenticate() (string, error) {
	if strings.TrimSpace(c.APIKey) == "" {
		return "", fmt.Errorf("H3_API_KEY is required")
	}
	if c.HTTPClient == nil {
		return "", fmt.Errorf("NodeZero HTTP client is not configured")
	}

	responseBody, err := c.postJSON(c.AuthURL, AuthRequest{Key: c.APIKey}, "")
	if err != nil {
		return "", fmt.Errorf("authenticate with NodeZero: %w", err)
	}
	var authResponse AuthResponse
	if err := json.Unmarshal(responseBody, &authResponse); err != nil {
		return "", fmt.Errorf("decode NodeZero authentication response: %w", err)
	}
	if strings.TrimSpace(authResponse.Token) == "" {
		return "", fmt.Errorf("NodeZero authentication response did not contain a token")
	}
	return authResponse.Token, nil
}

// FetchAndLogAttackPaths reads attack paths and appends each result as JSONL.
func (c *NodeZeroClient) FetchAndLogAttackPaths() ([]NodeZeroAttackPath, error) {
	if c.HTTPClient == nil {
		return nil, fmt.Errorf("NodeZero HTTP client is not configured")
	}
	token, err := c.Authenticate()
	if err != nil {
		return nil, err
	}

	responseBody, err := c.postJSON(c.GraphQLURL, GraphQLRequest{Query: nodeZeroAttackPathsQuery}, token)
	if err != nil {
		return nil, fmt.Errorf("fetch NodeZero attack paths: %w", err)
	}
	var graphQLResponse nodeZeroGraphQLResponse
	if err := json.Unmarshal(responseBody, &graphQLResponse); err != nil {
		return nil, fmt.Errorf("decode NodeZero GraphQL response: %w", err)
	}
	if len(graphQLResponse.Errors) > 0 {
		return nil, fmt.Errorf("NodeZero GraphQL query failed: %s", graphQLResponse.Errors[0].Message)
	}
	if graphQLResponse.Data.AttackPaths == nil {
		return nil, fmt.Errorf("NodeZero GraphQL response did not contain data.attackPaths")
	}

	file, err := os.OpenFile(c.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return graphQLResponse.Data.AttackPaths, fmt.Errorf("open security event log: %w", err)
	}
	for _, path := range graphQLResponse.Data.AttackPaths {
		entry := nodeZeroLogEntry{
			Timestamp:       time.Now().UTC().Format(time.RFC3339),
			Source:          "NodeZero",
			EventID:         path.ID,
			Severity:        path.Severity,
			AttackPathTitle: path.AttackPathTitle,
			IPAddress:       path.IPAddress,
			HostName:        path.HostName,
		}
		line, err := json.Marshal(entry)
		if err != nil {
			_ = file.Close()
			return graphQLResponse.Data.AttackPaths, fmt.Errorf("encode NodeZero attack path for security log: %w", err)
		}
		line = append(line, '\n')
		written, err := file.Write(line)
		if err != nil {
			_ = file.Close()
			return graphQLResponse.Data.AttackPaths, fmt.Errorf("write NodeZero attack path to security log: %w", err)
		}
		if written != len(line) {
			_ = file.Close()
			return graphQLResponse.Data.AttackPaths, fmt.Errorf("write NodeZero attack path to security log: %w", io.ErrShortWrite)
		}
	}
	if err := file.Close(); err != nil {
		return graphQLResponse.Data.AttackPaths, fmt.Errorf("close security event log: %w", err)
	}
	return graphQLResponse.Data.AttackPaths, nil
}

// FetchDetailedAttackPaths retrieves attack path metadata without payloads.
func (c *NodeZeroClient) FetchDetailedAttackPaths() ([]DetailedAttackPath, error) {
	if c.HTTPClient == nil {
		return nil, fmt.Errorf("NodeZero HTTP client is not configured")
	}
	token, err := c.Authenticate()
	if err != nil {
		return nil, err
	}

	query := `query {
		attackPaths {
			id
			severity
			attackPathTitle
			ipAddress
			hostName
			timestamp
		}
	}`
	responseBody, err := c.postJSON(c.GraphQLURL, GraphQLRequest{Query: query}, token)
	if err != nil {
		return nil, fmt.Errorf("fetch detailed NodeZero attack paths: %w", err)
	}

	var graphQLResponse detailedNodeZeroGraphQLResponse
	if err := json.Unmarshal(responseBody, &graphQLResponse); err != nil {
		return nil, fmt.Errorf("decode detailed NodeZero GraphQL response: %w", err)
	}
	if len(graphQLResponse.Errors) > 0 {
		return nil, fmt.Errorf("NodeZero GraphQL query failed: %s", graphQLResponse.Errors[0].Message)
	}
	if graphQLResponse.Data.AttackPaths == nil {
		return nil, fmt.Errorf("NodeZero GraphQL response did not contain data.attackPaths")
	}
	return graphQLResponse.Data.AttackPaths, nil
}
