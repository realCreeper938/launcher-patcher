package patcher

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"
)

func TestPlanPCL2Loader(t *testing.T) {
	loaderToken := uint32(0x0400040F)
	code := []byte{
		0x14,                         // ldnull (PanAlways)
		0x72, 0x01, 0x00, 0x00, 0x70, // ldstr "关闭下载"
		0x7e, 0xFB, 0x09, 0x00, 0x04, // cached lambda
		0x2c, 0x07,
		0x7e, 0xFB, 0x09, 0x00, 0x04,
		0x2b, 0x16,
		0x7e, 0xF9, 0x09, 0x00, 0x04,
		0xFE, 0x06, 0x67, 0x14, 0x00, 0x06, // ldftn
		0x73, 0x8D, 0x05, 0x00, 0x0A, // newobj lambda
		0x25, 0x80, 0xFB, 0x09, 0x00, 0x04,
		0x14, 0x18, 0x73, 0x8E, 0x05, 0x00, 0x0A, // ldnull; ldc.i4.2; newobj LoaderTask
		0x02, 0xFE, 0x06, 0x00, 0x00, 0x00, 0x00, // ldarg.0; ldftn OnFinish
	}

	resolver := func(token uint32) (string, bool) {
		if token == 1 {
			return pcl2DisabledLoaderName, true
		}
		return "", false
	}

	patch, already, err := planPCL2Loader(code, 1000, resolver, loaderToken)
	if err != nil {
		t.Fatalf("planPCL2Loader: %v", err)
	}
	if already {
		t.Fatal("unpatched LoaderInit reported as already patched")
	}
	if patch.offset != 1001 {
		t.Fatalf("patch offset = %d, want 1001", patch.offset)
	}
	if len(patch.new) != len(patch.old) || patch.new[0] != 0x7E || !bytes.Equal(patch.new[1:5], encodeUint32(loaderToken)) {
		t.Fatalf("unexpected replacement: %x", patch.new)
	}

	data := make([]byte, 1000+len(code))
	copy(data[1000:], code)
	patched, err := applyILPatches(data, []ilPatch{patch})
	if err != nil {
		t.Fatalf("applyILPatches: %v", err)
	}
	if _, already, err := planPCL2Loader(patched[1000:], 1000, resolver, loaderToken); err != nil || !already {
		t.Fatalf("patched LoaderInit was not recognized: already=%v err=%v", already, err)
	}
}

func TestPlanPCL2Card(t *testing.T) {
	getter := uint32(0x06000571)
	visibility := uint32(0x0A00010E)
	code := []byte{
		0x02, 0x6F, 0x71, 0x05, 0x00, 0x06, // ldarg.0; callvirt get_CardMinecraft
		0x18, 0x6F, 0x0E, 0x01, 0x00, 0x0A, // ldc.i4.2; callvirt set_Visibility
	}

	methodName := func(token uint32) (string, bool) {
		if token == getter&0xFFFFFF {
			return "get_CardMinecraft", true
		}
		return "", false
	}
	memberName := func(token uint32) (string, bool) {
		if token == visibility&0xFFFFFF {
			return "set_Visibility", true
		}
		return "", false
	}

	patch, already, err := planPCL2Card(code, 2000, methodName, memberName)
	if err != nil {
		t.Fatalf("planPCL2Card: %v", err)
	}
	if already {
		t.Fatal("collapsed card reported as already patched")
	}
	if patch.offset != 2006 || !bytes.Equal(patch.old, []byte{0x18}) || !bytes.Equal(patch.new, []byte{0x16}) {
		t.Fatalf("unexpected patch: %+v", patch)
	}

	code[6] = 0x16
	if _, already, err := planPCL2Card(code, 2000, methodName, memberName); err != nil || !already {
		t.Fatalf("visible card was not recognized: already=%v err=%v", already, err)
	}
}

func TestPCL2ScanRejectsUnknownMethod(t *testing.T) {
	code := []byte{0x14, 0x72, 0x01, 0x00, 0x00, 0x70}
	resolver := func(uint32) (string, bool) { return pcl2DisabledLoaderName, true }
	if _, _, err := planPCL2Loader(code, 0, resolver, 0x04000001); err == nil {
		t.Fatal("incomplete LoaderInit was accepted")
	}
}

func TestPCL2TokenEncoding(t *testing.T) {
	if !bytes.Equal(encodeUint32(0x0400040F), []byte{0x0F, 0x04, 0x00, 0x04}) {
		t.Fatalf("unexpected token encoding: %x", encodeUint32(0x0400040F))
	}
	var want [4]byte
	binary.LittleEndian.PutUint32(want[:], 0x0400040F)
	if !bytes.Equal(encodeUint32(0x0400040F), want[:]) {
		t.Fatal("token encoding is not little-endian")
	}
}

func TestScanPCL2HandlesGarbage(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		data := make([]byte, rng.Intn(4096))
		_, _ = rng.Read(data)
		if len(data) >= 2 {
			data[0], data[1] = 'M', 'Z'
		}
		_, _ = scanPCL2(data)
	}
}
