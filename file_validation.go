package main

import "fmt"

// ValidateJPEG checks the JPEG start and end markers. The 15 MB size guidance
// is not enforced as a hard limit.
func ValidateJPEG(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("JPEG data is too short")
	}
	if data[0] != 0xFF || data[1] != 0xD8 || data[2] != 0xFF {
		return fmt.Errorf("invalid JPEG header")
	}
	if data[len(data)-2] != 0xFF || data[len(data)-1] != 0xD9 {
		return fmt.Errorf("invalid JPEG footer")
	}
	return nil
}
