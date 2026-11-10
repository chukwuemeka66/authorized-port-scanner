package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestRunCarverExtractsSupportedTypesAcrossBufferBoundaries(t *testing.T) {
	tests := []struct {
		extension string
		data      []byte
	}{
		{"jpg", []byte{0xFF, 0xD8, 0xFF, 0x10, 0xFF, 0xD9}},
		{"png", []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x10, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}},
		{"pdf", []byte("%PDF example %%EOF")},
		{"zip", []byte{0x50, 0x4B, 0x03, 0x04, 0x10, 0x50, 0x4B, 0x05, 0x06}},
		{"elf", []byte{0x7F, 0x45, 0x4C, 0x46, 0x10, 0x20, 0x30}},
	}

	root := t.TempDir()
	imagePath := filepath.Join(root, "image.raw")
	outputFolder := filepath.Join(root, "recovered")
	imageData := make([]byte, 0)
	offsets := make(map[string]int64)
	for _, tt := range tests {
		imageData = append(imageData, []byte{0x00, 0x11, 0x22}...)
		offsets[tt.extension] = int64(len(imageData))
		imageData = append(imageData, tt.data...)
	}
	if err := os.WriteFile(imagePath, imageData, 0600); err != nil {
		t.Fatalf("write image: %v", err)
	}

	events, err := RunCarver(CarveConfig{
		ImageFilePath: imagePath,
		OutputFolder:  outputFolder,
		BufferSize:    5,
		MaxELFSize:    32,
	})
	if err != nil {
		t.Fatalf("RunCarver() error = %v", err)
	}
	if len(events) != len(tests) {
		t.Fatalf("RunCarver() returned %d events, want %d", len(events), len(tests))
	}

	for _, tt := range tests {
		var event *RecoveryEvent
		for i := range events {
			if events[i].FileType == tt.extension {
				event = &events[i]
				break
			}
		}
		if event == nil {
			t.Fatalf("missing recovery event for %s", tt.extension)
		}
		if event.OffsetStart != offsets[tt.extension] {
			t.Errorf("%s offset = %d, want %d", tt.extension, event.OffsetStart, offsets[tt.extension])
		}

		matches, err := filepath.Glob(filepath.Join(outputFolder, "recovered_"+tt.extension+"_*.") + tt.extension)
		if err != nil {
			t.Fatalf("glob recovered %s: %v", tt.extension, err)
		}
		if len(matches) != 1 {
			t.Fatalf("found %d recovered %s files, want one", len(matches), tt.extension)
		}
		got, err := os.ReadFile(matches[0])
		if err != nil {
			t.Fatalf("read recovered %s file: %v", tt.extension, err)
		}
		if !bytes.Equal(got, tt.data) {
			t.Errorf("recovered %s data = %x, want %x", tt.extension, got, tt.data)
		}
		hash := sha256.Sum256(tt.data)
		if event.SHA256Hash != hex.EncodeToString(hash[:]) {
			t.Errorf("%s SHA256Hash = %q, want %x", tt.extension, event.SHA256Hash, hash)
		}
		if event.FileSizeBytes != int64(len(tt.data)) {
			t.Errorf("%s file size = %d, want %d", tt.extension, event.FileSizeBytes, len(tt.data))
		}
		if event.Source != "Ovim-Gallery-Carver" || event.EventType != "file_recovered" {
			t.Errorf("%s event metadata = %+v", tt.extension, *event)
		}
	}

	unchanged, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatalf("read source image: %v", err)
	}
	if !bytes.Equal(unchanged, imageData) {
		t.Fatal("RunCarver() modified the source image")
	}
}

func TestRunCarverUsesELFSizeCap(t *testing.T) {
	root := t.TempDir()
	imagePath := filepath.Join(root, "image.raw")
	outputFolder := filepath.Join(root, "recovered")
	imageData := append([]byte{0x7F, 0x45, 0x4C, 0x46}, bytes.Repeat([]byte{0x42}, 20)...)
	if err := os.WriteFile(imagePath, imageData, 0600); err != nil {
		t.Fatalf("write image: %v", err)
	}

	events, err := RunCarver(CarveConfig{ImageFilePath: imagePath, OutputFolder: outputFolder, MaxELFSize: 8})
	if err != nil {
		t.Fatalf("RunCarver() error = %v", err)
	}
	if len(events) != 1 || events[0].FileSizeBytes != 8 {
		t.Fatalf("events = %+v, want one 8-byte ELF carve", events)
	}
}

func TestRunCarverRejectsOutputInImageDirectory(t *testing.T) {
	root := t.TempDir()
	imagePath := filepath.Join(root, "image.raw")
	if err := os.WriteFile(imagePath, []byte("data"), 0600); err != nil {
		t.Fatalf("write image: %v", err)
	}

	if _, err := RunCarver(CarveConfig{ImageFilePath: imagePath, OutputFolder: root}); err == nil {
		t.Fatal("RunCarver() error = nil, want output-directory separation error")
	}
}

func TestRunCarverRejectsNonRegularInput(t *testing.T) {
	root := t.TempDir()
	if _, err := RunCarver(CarveConfig{ImageFilePath: root, OutputFolder: filepath.Join(root, "recovered")}); err == nil {
		t.Fatal("RunCarver() error = nil, want regular-file requirement")
	}
}
