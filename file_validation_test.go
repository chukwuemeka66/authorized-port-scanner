package main

import (
	"testing"
)

func TestValidateJPEG(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "valid markers",
			data: []byte{0xFF, 0xD8, 0xFF, 0x00, 0xFF, 0xD9},
			want: true,
		},
		{
			name: "invalid header",
			data: []byte{0x00, 0xD8, 0xFF, 0x00, 0xFF, 0xD9},
		},
		{
			name: "invalid footer",
			data: []byte{0xFF, 0xD8, 0xFF, 0x00, 0xFF, 0x00},
		},
		{
			name: "too short",
			data: []byte{0xFF, 0xD8, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJPEG(tt.data)
			if (err == nil) != tt.want {
				t.Fatalf("ValidateJPEG() error = %v, want valid = %t", err, tt.want)
			}
		})
	}
}

func TestValidateJPEGAcceptsDataAbove15MBGuideline(t *testing.T) {
	data := make([]byte, 15*1024*1024+1)
	copy(data, []byte{0xFF, 0xD8, 0xFF})
	copy(data[len(data)-2:], []byte{0xFF, 0xD9})

	if err := ValidateJPEG(data); err != nil {
		t.Fatalf("ValidateJPEG() rejected data above the 15 MB guideline: %v", err)
	}
}
