package patcher

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func writeU1(b *bytes.Buffer, value byte) {
	b.WriteByte(value)
}

func writeU2(b *bytes.Buffer, value uint16) {
	b.WriteByte(byte(value >> 8))
	b.WriteByte(byte(value))
}

func writeU4(b *bytes.Buffer, value uint32) {
	b.WriteByte(byte(value >> 24))
	b.WriteByte(byte(value >> 16))
	b.WriteByte(byte(value >> 8))
	b.WriteByte(byte(value))
}

func writeUTF8(b *bytes.Buffer, value string) {
	writeU1(b, 1)
	writeU2(b, uint16(len(value)))
	b.WriteString(value)
}

func buildTestRegionClass() []byte {
	var b bytes.Buffer
	b.Write([]byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34})
	writeU2(&b, 10)

	writeUTF8(&b, "org/jackhuang/hmcl/util/RegionUtils") // #1
	writeU1(&b, 7)                                      // #2 Class
	writeU2(&b, 1)
	writeUTF8(&b, "checkMachineIsChinaMainland") // #3
	writeUTF8(&b, "()Z")                         // #4
	writeU1(&b, 12)                              // #5 NameAndType
	writeU2(&b, 3)
	writeU2(&b, 4)
	writeU1(&b, 10) // #6 Methodref
	writeU2(&b, 2)
	writeU2(&b, 5)
	writeUTF8(&b, "<clinit>") // #7
	writeUTF8(&b, "()V")      // #8
	writeUTF8(&b, "Code")     // #9

	writeU2(&b, 0x0021) // access flags
	writeU2(&b, 2)      // this class
	writeU2(&b, 2)      // super class
	writeU2(&b, 0)      // interfaces
	writeU2(&b, 0)      // fields
	writeU2(&b, 1)      // methods

	code := []byte{0xb8, 0x00, 0x06, 0x57, 0xb1} // invokestatic #6; pop; return
	writeU2(&b, 0x0008)                          // static
	writeU2(&b, 7)                               // <clinit>
	writeU2(&b, 8)                               // ()V
	writeU2(&b, 1)                               // attributes
	writeU2(&b, 9)                               // Code
	writeU4(&b, uint32(12+len(code)))
	writeU2(&b, 1) // max_stack
	writeU2(&b, 0) // max_locals
	writeU4(&b, uint32(len(code)))
	b.Write(code)
	writeU2(&b, 0) // exception table
	writeU2(&b, 0) // code attributes
	writeU2(&b, 0) // class attributes
	return b.Bytes()
}

func TestPatchRegionClass(t *testing.T) {
	original := buildTestRegionClass()
	patched, state, err := patchRegionClass(original)
	if err != nil {
		t.Fatalf("patchRegionClass: %v", err)
	}
	if state != regionClassPatchable {
		t.Fatalf("state = %v, want patchable", state)
	}
	if len(patched) != len(original) {
		t.Fatalf("patched size %d != original %d", len(patched), len(original))
	}

	call := bytes.Index(original, []byte{0xb8, 0x00, 0x06})
	if call < 0 {
		t.Fatal("test class has no invokestatic")
	}
	want := append([]byte(nil), original...)
	want[call], want[call+1], want[call+2] = 0x03, 0x00, 0x00
	if !bytes.Equal(patched, want) {
		t.Fatal("unexpected patched class bytes")
	}
	if bytes.Equal(original, patched) {
		t.Fatal("input was modified")
	}

	again, state, err := patchRegionClass(patched)
	if err != nil {
		t.Fatalf("patchRegionClass on patched class: %v", err)
	}
	if state != regionClassAlready {
		t.Fatalf("patched state = %v, want already", state)
	}
	if !bytes.Equal(again, patched) {
		t.Fatal("already-patched class was changed")
	}
}

func writeTestJar(t *testing.T, path string, prefix []byte, class []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(prefix); err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	files := map[string][]byte{
		"META-INF/MANIFEST.MF":                 []byte("Manifest-Version: 1.0\n"),
		"META-INF/hmcl_signature":              []byte("stale-test-signature"),
		"assets/hmcl_signature_publickey.der":  []byte("public-key"),
		"org/jackhuang/hmcl/util/RegionUtils.class": class,
		"example.txt": []byte("hello"),
	}
	order := []string{
		"META-INF/MANIFEST.MF",
		"META-INF/hmcl_signature",
		"assets/hmcl_signature_publickey.der",
		"org/jackhuang/hmcl/util/RegionUtils.class",
		"example.txt",
	}
	for _, name := range order {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func readArchiveFile(t *testing.T, zr *zip.Reader, name string) []byte {
	t.Helper()
	f := findArchiveFile(zr, name)
	if f == nil {
		t.Fatalf("archive has no %s", name)
	}
	rc, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func testHMCLPatch(t *testing.T, prefix []byte, wantKind Kind) {
	t.Helper()
	dir := t.TempDir()
	ext := ".jar"
	if wantKind == KindHMCLExe {
		ext = ".exe"
	}
	input := filepath.Join(dir, "launcher"+ext)
	class := buildTestRegionClass()
	writeTestJar(t, input, prefix, class)

	before, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	result, err := PatchFile(input)
	if err != nil {
		t.Fatalf("PatchFile: %v", err)
	}
	if result.Kind != wantKind {
		t.Fatalf("kind = %q, want %q", result.Kind, wantKind)
	}
	if !result.Changed {
		t.Fatalf("changed = false, note = %q", result.Note)
	}
	if result.Output == "" {
		t.Fatal("no output path")
	}
	after, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("input file was modified")
	}

	outPrefix, err := os.ReadFile(result.Output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(outPrefix[:len(prefix)], prefix) {
		t.Fatal("native prefix was not preserved")
	}
	zs, err := openAppendedZip(result.Output)
	if err != nil {
		t.Fatalf("open output: %v", err)
	}
	defer zs.Close()
	if zs.prefix != int64(len(prefix)) {
		t.Fatalf("output prefix = %d, want %d", zs.prefix, len(prefix))
	}
	outClass := readArchiveFile(t, zs.zr, hmclRegionClass)
	if _, state, err := patchRegionClass(outClass); err != nil || state != regionClassAlready {
		t.Fatalf("output class state = %v, err = %v", state, err)
	}
	if got := string(readArchiveFile(t, zs.zr, "META-INF/hmcl_signature")); got != "stale-test-signature" {
		t.Fatalf("signature file changed: %q", got)
	}
	if got := string(readArchiveFile(t, zs.zr, "example.txt")); got != "hello" {
		t.Fatalf("other entry changed: %q", got)
	}

	second, err := PatchFile(result.Output)
	if err != nil {
		t.Fatalf("PatchFile on output: %v", err)
	}
	if second.Changed || second.Output != "" {
		t.Fatalf("output is not idempotent: %+v", second)
	}
}

func TestPatchHMCLJar(t *testing.T) {
	testHMCLPatch(t, nil, KindHMCLJar)
}

func TestPatchHMCLExe(t *testing.T) {
	prefix := make([]byte, 4096)
	prefix[0], prefix[1] = 'M', 'Z'
	testHMCLPatch(t, prefix, KindHMCLExe)
}
