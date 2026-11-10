package main

import (
	"os"
	"testing"
)

func TestNodeZeroLiveIntegration(t *testing.T) {
	if os.Getenv("H3_LIVE_INTEGRATION") != "1" {
		t.Skip("set H3_LIVE_INTEGRATION=1 to run live NodeZero integration tests")
	}
	if os.Getenv("H3_API_KEY") == "" {
		t.Fatal("H3_API_KEY is required when H3_LIVE_INTEGRATION=1")
	}

	client := NewNodeZeroClient()
	if _, err := client.Authenticate(); err != nil {
		t.Fatalf("live NodeZero authentication failed: %v", err)
	}

	paths, err := client.FetchDetailedAttackPaths()
	if err != nil {
		t.Fatalf("fetch live NodeZero attack paths: %v", err)
	}
	t.Logf("Retrieved %d live NodeZero attack paths", len(paths))
}
