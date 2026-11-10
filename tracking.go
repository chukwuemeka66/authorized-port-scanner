package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

func GenerateTrackingToken(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("tracking token length must be positive")
	}
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

type trackingLinkStore struct {
	mu    sync.Mutex
	links map[string]TrackingLink
}

type TrackingLink struct {
	ID         string    `json:"id"`
	TargetURL  string    `json:"target_url"`
	CreatedAt  time.Time `json:"created_at"`
	ClickCount int       `json:"click_count"`
}

var defaultTrackingLinkStore = &trackingLinkStore{links: make(map[string]TrackingLink)}

func CreateTrackingLink(targetURL string) (string, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil || !parsedURL.IsAbs() || parsedURL.Host == "" ||
		(strings.ToLower(parsedURL.Scheme) != "http" && strings.ToLower(parsedURL.Scheme) != "https") || parsedURL.User != nil {
		return "", fmt.Errorf("tracking target must be an absolute HTTP or HTTPS URL")
	}
	parsedURL.Scheme = strings.ToLower(parsedURL.Scheme)

	for {
		token, err := GenerateTrackingToken(32)
		if err != nil {
			return "", fmt.Errorf("generate tracking token: %w", err)
		}

		defaultTrackingLinkStore.mu.Lock()
		if _, exists := defaultTrackingLinkStore.links[token]; !exists {
			defaultTrackingLinkStore.links[token] = TrackingLink{
				ID:        token,
				TargetURL: parsedURL.String(),
				CreatedAt: time.Now().UTC(),
			}
			defaultTrackingLinkStore.mu.Unlock()
			return token, nil
		}
		defaultTrackingLinkStore.mu.Unlock()
	}
}

func HandleTrackClick(w http.ResponseWriter, r *http.Request) {
	handleTrackClick(defaultTrackingLinkStore, w, r)
}

func handleTrackClick(store *trackingLinkStore, w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing tracking token", http.StatusBadRequest)
		return
	}

	store.mu.Lock()
	link, exists := store.links[token]
	if exists {
		link.ClickCount++
		store.links[token] = link
	}
	store.mu.Unlock()

	if !exists {
		http.NotFound(w, r)
		return
	}

	clientIP := "unknown"
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && net.ParseIP(host) != nil {
		clientIP = host
	} else if net.ParseIP(r.RemoteAddr) != nil {
		clientIP = r.RemoteAddr
	}
	log.Printf("Tracking click token=%s ip=%s user_agent=%q timestamp=%s",
		token, clientIP, r.UserAgent(), time.Now().UTC().Format(time.RFC3339Nano))
	http.Redirect(w, r, link.TargetURL, http.StatusFound)
}

func handleTrackingRequest(w http.ResponseWriter, r *http.Request) {
	clientIP := "unknown"
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && net.ParseIP(host) != nil {
		clientIP = host
	} else if net.ParseIP(r.RemoteAddr) != nil {
		clientIP = r.RemoteAddr
	}

	log.Printf("Received tracking request from IP: %s", clientIP)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprint(w, "Access Logged"); err != nil {
		log.Printf("Failed to write tracking response: %v", err)
	}
}

func newTrackingHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/track", handleTrackingRequest)
	mux.HandleFunc("/click", HandleTrackClick)
	return mux
}
