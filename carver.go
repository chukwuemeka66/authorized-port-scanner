package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	defaultCarveBufferSize = 1 << 20
	maxCarveBufferSize     = 16 << 20
	defaultMaxELFSize      = 15 << 20
)

type CarveConfig struct {
	ImageFilePath string
	OutputFolder  string
	BufferSize    int64
	MaxELFSize    int64
}

type MagicNumber struct {
	Extension string
	Header    []byte
	Footer    []byte
}

type RecoveryEvent struct {
	Timestamp     string `json:"timestamp"`
	Source        string `json:"source"`
	EventType     string `json:"event_type"`
	FileType      string `json:"file_type"`
	OffsetStart   int64  `json:"offset_start"`
	FileSizeBytes int64  `json:"file_size_bytes"`
	SHA256Hash    string `json:"sha256_hash"`
}

var knownSignatures = []MagicNumber{
	{Extension: "jpg", Header: []byte{0xFF, 0xD8, 0xFF}, Footer: []byte{0xFF, 0xD9}},
	{Extension: "png", Header: []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, Footer: []byte{0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82}},
	{Extension: "pdf", Header: []byte{0x25, 0x50, 0x44, 0x46}, Footer: []byte{0x25, 0x25, 0x45, 0x4F, 0x46}},
	{Extension: "zip", Header: []byte{0x50, 0x4B, 0x03, 0x04}, Footer: []byte{0x50, 0x4B, 0x05, 0x06}},
	{Extension: "elf", Header: []byte{0x7F, 0x45, 0x4C, 0x46}},
}

// RunCarver scans a regular disk-image file without modifying it and writes
// recovered files to a separate output directory.
func RunCarver(config CarveConfig) ([]RecoveryEvent, error) {
	if config.ImageFilePath == "" || config.OutputFolder == "" {
		return nil, fmt.Errorf("image file and output folder are required")
	}
	if config.BufferSize == 0 {
		config.BufferSize = defaultCarveBufferSize
	}
	if config.BufferSize < 1 || config.BufferSize > maxCarveBufferSize {
		return nil, fmt.Errorf("buffer size must be between 1 byte and %d bytes", maxCarveBufferSize)
	}
	if config.MaxELFSize == 0 {
		config.MaxELFSize = defaultMaxELFSize
	}
	if config.MaxELFSize < 1 {
		return nil, fmt.Errorf("maximum ELF size must be positive")
	}

	imagePath, err := filepath.Abs(config.ImageFilePath)
	if err != nil {
		return nil, fmt.Errorf("resolve image path: %w", err)
	}
	image, err := os.Open(imagePath)
	if err != nil {
		return nil, fmt.Errorf("open image file: %w", err)
	}
	defer image.Close()

	imageInfo, err := image.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect image file: %w", err)
	}
	if !imageInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("image path must refer to a regular file")
	}
	imagePath, err = filepath.EvalSymlinks(imagePath)
	if err != nil {
		return nil, fmt.Errorf("resolve image file: %w", err)
	}

	outputPath, err := filepath.Abs(config.OutputFolder)
	if err != nil {
		return nil, fmt.Errorf("resolve output folder: %w", err)
	}
	if err := os.MkdirAll(outputPath, 0700); err != nil {
		return nil, fmt.Errorf("create output folder: %w", err)
	}
	outputPath, err = filepath.EvalSymlinks(outputPath)
	if err != nil {
		return nil, fmt.Errorf("resolve output folder: %w", err)
	}
	if filepath.Clean(outputPath) == filepath.Dir(imagePath) {
		return nil, fmt.Errorf("output folder must be separate from the image folder")
	}

	return carveImage(image, imageInfo.Size(), outputPath, config)
}

func carveImage(image *os.File, imageSize int64, outputFolder string, config CarveConfig) ([]RecoveryEvent, error) {
	var events []RecoveryEvent
	for _, signature := range knownSignatures {
		if signature.Footer != nil {
			carved, err := carveFooterTerminatedFiles(image, imageSize, outputFolder, signature, config.BufferSize)
			if err != nil {
				return events, err
			}
			events = append(events, carved...)
			continue
		}

		patterns := [][]byte{signature.Header}
		searchFrom := int64(0)
		for searchFrom < imageSize {
			start, _, found, err := findNextPattern(image, patterns, searchFrom, imageSize, config.BufferSize)
			if err != nil {
				return events, fmt.Errorf("scan for %s header: %w", signature.Extension, err)
			}
			if !found {
				break
			}

			end := start + config.MaxELFSize
			if end > imageSize {
				end = imageSize
			}

			event, err := writeCarvedFile(image, outputFolder, signature.Extension, start, end)
			if err != nil {
				return events, err
			}
			events = append(events, event)
			searchFrom = end
		}
	}
	return events, nil
}

func carveFooterTerminatedFiles(image *os.File, imageSize int64, outputFolder string, signature MagicNumber, bufferSize int64) ([]RecoveryEvent, error) {
	var events []RecoveryEvent
	patterns := [][]byte{signature.Header, signature.Footer}
	var pendingStart int64 = -1
	searchFrom := int64(0)

	for searchFrom < imageSize {
		offset, patternIndex, found, err := findNextPattern(image, patterns, searchFrom, imageSize, bufferSize)
		if err != nil {
			return events, fmt.Errorf("scan %s signatures: %w", signature.Extension, err)
		}
		if !found {
			break
		}
		if patternIndex == 0 {
			if pendingStart < 0 {
				pendingStart = offset
			}
		} else if pendingStart >= 0 {
			end := offset + int64(len(signature.Footer))
			event, err := writeCarvedFile(image, outputFolder, signature.Extension, pendingStart, end)
			if err != nil {
				return events, err
			}
			events = append(events, event)
			pendingStart = -1
		}
		searchFrom = offset + int64(len(patterns[patternIndex]))
	}
	return events, nil
}

func findNextPattern(image *os.File, patterns [][]byte, start, imageSize, bufferSize int64) (int64, int, bool, error) {
	maxPatternLength := 0
	for _, pattern := range patterns {
		if len(pattern) == 0 {
			return 0, 0, false, fmt.Errorf("patterns must not be empty")
		}
		if len(pattern) > maxPatternLength {
			maxPatternLength = len(pattern)
		}
	}

	buffer := make([]byte, int(bufferSize))
	var carry []byte
	offset := start
	for offset < imageSize {
		readSize := int64(len(buffer))
		if remaining := imageSize - offset; remaining < readSize {
			readSize = remaining
		}
		n, readErr := image.ReadAt(buffer[:int(readSize)], offset)
		if n > 0 {
			chunk := buffer[:n]
			combined := make([]byte, len(carry)+len(chunk))
			copy(combined, carry)
			copy(combined[len(carry):], chunk)
			bestIndex, bestPattern := -1, -1
			for i, pattern := range patterns {
				if index := bytes.Index(combined, pattern); index >= 0 && (bestIndex < 0 || index < bestIndex) {
					bestIndex, bestPattern = index, i
				}
			}
			if bestIndex >= 0 {
				return offset - int64(len(carry)) + int64(bestIndex), bestPattern, true, nil
			}

			carrySize := maxPatternLength - 1
			if carrySize > len(combined) {
				carrySize = len(combined)
			}
			carry = append(carry[:0], combined[len(combined)-carrySize:]...)
			offset += int64(n)
		}
		if readErr != nil {
			if readErr == io.EOF {
				return 0, 0, false, nil
			}
			return 0, 0, false, readErr
		}
		if n == 0 {
			return 0, 0, false, nil
		}
	}
	return 0, 0, false, nil
}

func writeCarvedFile(image *os.File, outputFolder, extension string, start, end int64) (RecoveryEvent, error) {
	size := end - start
	if size <= 0 {
		return RecoveryEvent{}, fmt.Errorf("invalid %s carve range at offset %d", extension, start)
	}
	outputPath := filepath.Join(outputFolder, fmt.Sprintf("recovered_%s_%012d.%s", extension, start, extension))
	output, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return RecoveryEvent{}, fmt.Errorf("create recovered file at offset %d: %w", start, err)
	}

	hash := sha256.New()
	reader := io.NewSectionReader(image, start, size)
	_, copyErr := io.CopyN(io.MultiWriter(output, hash), reader, size)
	closeErr := output.Close()
	if copyErr != nil {
		if removeErr := os.Remove(outputPath); removeErr != nil {
			return RecoveryEvent{}, fmt.Errorf("write recovered file at offset %d: %w (also failed to remove partial file: %v)", start, copyErr, removeErr)
		}
		return RecoveryEvent{}, fmt.Errorf("write recovered file at offset %d: %w", start, copyErr)
	}
	if closeErr != nil {
		if removeErr := os.Remove(outputPath); removeErr != nil {
			return RecoveryEvent{}, fmt.Errorf("close recovered file at offset %d: %w (also failed to remove partial file: %v)", start, closeErr, removeErr)
		}
		return RecoveryEvent{}, fmt.Errorf("close recovered file at offset %d: %w", start, closeErr)
	}

	return RecoveryEvent{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Source:        "Ovim-Gallery-Carver",
		EventType:     "file_recovered",
		FileType:      extension,
		OffsetStart:   start,
		FileSizeBytes: size,
		SHA256Hash:    hex.EncodeToString(hash.Sum(nil)),
	}, nil
}
