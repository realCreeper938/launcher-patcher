package patcher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyPCLFallback(t *testing.T) {
	originalPCL := append([]byte("Plain Craft Launcher"), make([]byte, 32)...)
	originalPCL = append(originalPCL, []byte("A\000l\000s\000o\000 \000t\000r\000y\000 \000P\000C\000L\000 \000C\000E\000!\000")...)

	tests := []struct {
		name       string
		data       []byte
		wantKind   Kind
		recognized bool
	}{
		{
			name:       "original PCL with promotional PCL CE string",
			data:       originalPCL,
			wantKind:   KindPCL,
			recognized: true,
		},
		{
			name:       "PCL CE containing both product names",
			data:       append(append([]byte("PCL.Core"), originalPCL...), []byte("PCL.Core.App.Region")...),
			wantKind:   KindPCLCE,
			recognized: true,
		},
		{
			name:       "PCL CE marker only",
			data:       []byte("PCL CE"),
			wantKind:   KindPCLCE,
			recognized: true,
		},
		{
			name:       "unknown data",
			data:       []byte("not a launcher"),
			recognized: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kind, recognized := classifyPCLFallback(tt.data)
			if recognized != tt.recognized || kind != tt.wantKind {
				t.Fatalf("classifyPCLFallback = (%q, %v), want (%q, %v)", kind, recognized, tt.wantKind, tt.recognized)
			}
		})
	}
}

func TestPatchFileOriginalPCLIsNotPCLCE(t *testing.T) {
	data := make([]byte, 0x40)
	copy(data, "MZ")
	data = append(data, []byte("Plain Craft Launcher")...)
	data = append(data, []byte("A\x00l\x00s\x00o\x00 \x00t\x00r\x00y\x00 \x00P\x00C\x00L\x00 \x00C\x00E\x00!\x00")...)

	path := filepath.Join(t.TempDir(), "Plain Craft Launcher 2.exe")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := PatchFile(path)
	if err != nil {
		t.Fatalf("PatchFile: %v", err)
	}
	if res.Kind != KindPCL {
		t.Fatalf("Kind = %q, want %q", res.Kind, KindPCL)
	}
	if res.Changed || res.Output != "" {
		t.Fatalf("original PCL was modified: %+v", res)
	}
}
