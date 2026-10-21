package patcher

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func copySample(t *testing.T, src string) string {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	dst := filepath.Join(t.TempDir(), filepath.Base(src))
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatalf("copy sample: %v", err)
	}
	return dst
}

func fileHash(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

func TestRealPCLCE(t *testing.T) {
	src := os.Getenv("PCL_CE_SAMPLE")
	if src == "" {
		t.Skip("PCL_CE_SAMPLE is not set")
	}
	input := copySample(t, src)
	hashBefore := fileHash(t, input)

	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanPCLCE(data)
	if err != nil {
		t.Fatalf("scan sample: %v", err)
	}
	if !scan.found || len(scan.patches) == 0 {
		t.Fatal("sample does not contain the expected PCL CE restriction")
	}

	result, err := PatchFile(input)
	if err != nil {
		t.Fatalf("PatchFile: %v", err)
	}
	if result.Kind != KindPCLCE || !result.Changed || result.Output == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if fileHash(t, input) != hashBefore {
		t.Fatal("input file was modified")
	}

	out, err := os.ReadFile(result.Output)
	if err != nil {
		t.Fatal(err)
	}
	outScan, err := scanPCLCE(out)
	if err != nil {
		t.Fatalf("scan output: %v", err)
	}
	if !outScan.found || len(outScan.patches) != 0 {
		t.Fatalf("output still contains patchable code: %+v", outScan)
	}

	again, err := PatchFile(result.Output)
	if err != nil {
		t.Fatalf("PatchFile on output: %v", err)
	}
	if again.Changed {
		t.Fatalf("patched output is not idempotent: %+v", again)
	}
}

func testRealHMCL(t *testing.T, env string, wantKind Kind) {
	t.Helper()
	src := os.Getenv(env)
	if src == "" {
		t.Skipf("%s is not set", env)
	}
	input := copySample(t, src)
	hashBefore := fileHash(t, input)

	inZip, err := openAppendedZip(input)
	if err != nil {
		t.Fatalf("open sample: %v", err)
	}
	wantPrefix := inZip.prefix
	signatureBefore := readArchiveFile(t, inZip.zr, "META-INF/hmcl_signature")
	inZip.Close()

	result, err := PatchFile(input)
	if err != nil {
		t.Fatalf("PatchFile: %v", err)
	}
	if result.Kind != wantKind || !result.Changed || result.Output == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if fileHash(t, input) != hashBefore {
		t.Fatal("input file was modified")
	}

	outZip, err := openAppendedZip(result.Output)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer outZip.Close()
	if outZip.prefix != wantPrefix {
		t.Fatalf("prefix changed: %d != %d", outZip.prefix, wantPrefix)
	}
	outClass := readArchiveFile(t, outZip.zr, hmclRegionClass)
	if _, state, err := patchRegionClass(outClass); err != nil || state != regionClassAlready {
		t.Fatalf("class was not patched: state=%v err=%v", state, err)
	}
	if !bytes.Equal(signatureBefore, readArchiveFile(t, outZip.zr, "META-INF/hmcl_signature")) {
		t.Fatal("signature entry was not preserved")
	}

	again, err := PatchFile(result.Output)
	if err != nil {
		t.Fatalf("PatchFile on output: %v", err)
	}
	if again.Changed {
		t.Fatalf("patched output is not idempotent: %+v", again)
	}
}

func TestRealHMCLJar(t *testing.T) {
	testRealHMCL(t, "HMCL_JAR_SAMPLE", KindHMCLJar)
}

func TestRealHMCLExe(t *testing.T) {
	testRealHMCL(t, "HMCL_EXE_SAMPLE", KindHMCLExe)
}
