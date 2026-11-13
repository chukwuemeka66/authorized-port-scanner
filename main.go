package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

type SecurityEvent struct {
	Timestamp string `json:"timestamp"`
	EventType string `json:"event_type"`
	Status    string `json:"status"`
	Source    string `json:"source,omitempty"`
	EventID   string `json:"event_id,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Details   string `json:"details,omitempty"`
}

type hecEvent struct {
	Time       int64         `json:"time"`
	Host       string        `json:"host"`
	Sourcetype string        `json:"sourcetype"`
	Event      SecurityEvent `json:"event"`
}

// sendLog transmits a JSON payload to the Splunk HEC endpoint with retry logic and token auth.
func sendLog(target, token string, client *http.Client, payload []byte) (*http.Response, error) {
	var lastErr error

	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest(http.MethodPost, target, bytes.NewBuffer(payload))
		if err != nil {
			return nil, err
		}
		// Set required headers for Splunk HEC.
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Splunk "+token)
		}

		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		if resp != nil {
			lastErr = fmt.Errorf("unexpected response status: %s", resp.Status)
			resp.Body.Close()
		} else {
			lastErr = err
		}

		fmt.Printf("[!] Attempt %d failed. Retrying in %d seconds...\n", attempt, attempt*2)
		time.Sleep(time.Duration(attempt*2) * time.Second)
	}

	return nil, lastErr
}

// SendLogToSplunkHEC sends a security event to the Splunk HEC event endpoint.
func SendLogToSplunkHEC(splunkURL, hecToken, eventType, status string) (*http.Response, error) {
	now := time.Now().UTC()
	payload, err := json.Marshal(hecEvent{
		Time:       now.Unix(),
		Host:       "local-scanner-node",
		Sourcetype: "ovimscannerjson",
		Event: SecurityEvent{
			Timestamp: now.Format(time.RFC3339),
			EventType: eventType,
			Status:    status,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HEC payload: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	return sendLog(splunkURL, hecToken, client, payload)
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func main() {
	// 1. Define command-line flags for dynamic configuration
	targetFlag := flag.String("target", envOrDefault("SPLUNK_HEC_URL", "https://localhost:8088/services/collector"), "Splunk HEC event endpoint")
	hecTokenFlag := flag.String("token", envOrDefault("SPLUNK_HEC_TOKEN", "YOUR_SPLUNK_HEC_TOKEN"), "Splunk HEC Authorization Token")
	xbowFindingsFlag := flag.Bool("xbow-findings", false, "Fetch and log XBOW findings (requires XBOW_API_KEY and XBOW_ASSET_ID)")
	xbowAssetIDFlag := flag.String("xbow-asset-id", os.Getenv("XBOW_ASSET_ID"), "XBOW asset ID (defaults to XBOW_ASSET_ID)")
	nodeZeroPathsFlag := flag.Bool("nodezero-findings", false, "Fetch and log NodeZero attack paths (requires H3_API_KEY)")
	nodeZeroToSplunkFlag := flag.Bool("nodezero-to-splunk", false, "Fetch NodeZero attack-path metadata and send it to Splunk HEC")
	trackingServerFlag := flag.Bool("tracking-server", false, "Start a loopback-only tracking endpoint at 127.0.0.1:8080/track")
	carveImageFlag := flag.String("carve-image", "", "Scan a regular image file for recoverable files")
	carveOutputFlag := flag.String("carve-output", "", "Output directory for recovered files (must differ from image directory)")
	carveELFMaxBytesFlag := flag.Int64("carve-elf-max-bytes", defaultMaxELFSize, "Maximum bytes to carve per ELF file")
	flag.Parse()

	carveSelected := *carveImageFlag != "" || *carveOutputFlag != ""
	if carveSelected && (*carveImageFlag == "" || *carveOutputFlag == "") {
		log.Fatal("[-] -carve-image and -carve-output must be provided together")
	}
	selectedIntegrations := 0
	for _, selected := range []bool{*xbowFindingsFlag, *nodeZeroPathsFlag, *nodeZeroToSplunkFlag, *trackingServerFlag, carveSelected} {
		if selected {
			selectedIntegrations++
		}
	}
	if selectedIntegrations > 1 {
		log.Fatal("[-] Choose only one security findings integration per run")
	}

	if *xbowFindingsFlag {
		client := NewXBOWClient(os.Getenv("XBOW_API_KEY"))
		findings, err := client.FetchAndLogFindings(*xbowAssetIDFlag)
		if err != nil {
			log.Fatalf("[-] Failed to fetch XBOW findings: %v", err)
		}
		log.Printf("[+] Logged %d XBOW findings for asset %s", len(findings), *xbowAssetIDFlag)
		return
	}
	if *nodeZeroPathsFlag {
		log.Println("Initializing NodeZero security telemetry collector...")
		client := NewNodeZeroClient()
		paths, err := client.FetchAndLogAttackPaths()
		if err != nil {
			log.Fatalf("Failed to fetch and log NodeZero attack paths: %v", err)
		}
		log.Printf("Successfully processed and logged %d attack paths.", len(paths))
		return
	}
	if *nodeZeroToSplunkFlag {
		log.Println("Fetching NodeZero attack-path metadata...")
		client := NewNodeZeroClient()
		paths, err := client.FetchDetailedAttackPaths()
		if err != nil {
			log.Fatalf("[-] Failed to fetch NodeZero attack paths: %v", err)
		}
		if err := ShipAttackPathsToSplunk(paths); err != nil {
			log.Fatalf("[-] Failed to ship NodeZero attack paths to Splunk: %v", err)
		}
		log.Printf("[+] Shipped %d NodeZero attack paths to Splunk", len(paths))
		return
	}
	if *trackingServerFlag {
		log.Println("Starting tracking endpoint at http://127.0.0.1:8080/track")
		if err := http.ListenAndServe("127.0.0.1:8080", newTrackingHandler()); err != nil {
			log.Fatalf("[-] Tracking server failed: %v", err)
		}
		return
	}
	if carveSelected {
		events, carveErr := RunCarver(CarveConfig{
			ImageFilePath: *carveImageFlag,
			OutputFolder:  *carveOutputFlag,
			MaxELFSize:    *carveELFMaxBytesFlag,
		})
		shipErr := ShipRecoveryEventsToSplunk(events)
		if carveErr != nil {
			if shipErr != nil {
				log.Printf("[-] Failed to ship partial recovery metadata: %v", shipErr)
			}
			log.Fatalf("[-] File carving failed: %v", carveErr)
		}
		if shipErr != nil {
			log.Fatalf("[-] Failed to ship recovery events to Splunk: %v", shipErr)
		}
		if len(events) == 0 {
			log.Println("[+] No recoverable files found")
			return
		}
		log.Printf("[+] Recovered %d files and shipped recovery metadata", len(events))
		return
	}

	fmt.Printf("[*] Initializing log transmission to target: %s\n", *targetFlag)

	// 2. Send the security event directly to Splunk HEC with retry and backoff.
	resp, err := SendLogToSplunkHEC(*targetFlag, *hecTokenFlag, "SECURITY_SCAN_EVENT", "SUCCESS")
	if err != nil {
		log.Fatalf("[-] Failed to send log after all attempts: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("[+] Successfully sent log to Splunk. Response Status: %s\n", resp.Status)
}
