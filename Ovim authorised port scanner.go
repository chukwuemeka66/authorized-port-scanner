package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// worker picks ports from the jobs channel and tests connectivity.
func scanWorker(_ int, ports <-chan int, results chan<- string, targetHost string) {
	for port := range ports {
		address := fmt.Sprintf("%s:%d", targetHost, port)
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			results <- fmt.Sprintf("[-] Port %d: CLOSED", port)
			continue
		}
		conn.Close()
		results <- fmt.Sprintf("[+] Port %d: OPEN", port)
	}
}

// RunPortScan scans an authorized target over the requested port range.
func RunAuthorizedPortScan(targetHost string, startPort, endPort int, workerCount int) {
	ports := make(chan int, 100)
	results := make(chan string, 100)

	var wg sync.WaitGroup

	for workerID := 1; workerID <= workerCount; workerID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			scanWorker(id, ports, results, targetHost)
		}(workerID)
	}

	go func() {
		for port := startPort; port <= endPort; port++ {
			ports <- port
		}
		close(ports)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Printf("[*] Starting concurrent scan on host: %s (Ports %d-%d)\n", targetHost, startPort, endPort)
	for result := range results {
		fmt.Println(result)
	}
	fmt.Println("[*] Port scan completed.")
}
