package patcher

import (
	"bytes"
	"testing"
)

// get_IsRestricted from PCL CE v2.15.1 (PCL.Core.dll).
var realPCLGetterIL = []byte{
	0x02, 0x28, 0x92, 0x16, 0x00, 0x06, 0x0a, 0x06, 0x2c, 0x04, 0x06,
	0x18, 0x33, 0x04, 0x17, 0x0b, 0x2b, 0x02, 0x16, 0x0b, 0x07, 0x2a,
}

func TestPlanPCLCEIL(t *testing.T) {
	method := clrMethod{code: realPCLGetterIL, offset: 1000}
	patch, already, err := planPCLCEIL(method)
	if err != nil {
		t.Fatalf("planPCLCEIL: %v", err)
	}
	if already {
		t.Fatal("unpatched method reported as already patched")
	}
	if patch.offset != 1014 {
		t.Fatalf("patch offset = %d, want 1014", patch.offset)
	}
	if !bytes.Equal(patch.old, []byte{0x17}) || !bytes.Equal(patch.new, []byte{0x16}) {
		t.Fatalf("unexpected patch: %+v", patch)
	}

	data := make([]byte, 1000+len(realPCLGetterIL))
	copy(data[1000:], realPCLGetterIL)
	patched, err := applyILPatches(data, []ilPatch{patch})
	if err != nil {
		t.Fatalf("applyILPatches: %v", err)
	}
	if patched[1014] != 0x16 {
		t.Fatalf("patched byte = 0x%02X, want 0x16", patched[1014])
	}
	if !bytes.Equal(data[1000:], realPCLGetterIL) {
		t.Fatal("input slice was modified")
	}

	again, already, err := planPCLCEIL(clrMethod{code: patched[1000:], offset: 1000})
	if err != nil {
		t.Fatalf("planPCLCEIL on patched code: %v", err)
	}
	if !already {
		t.Fatalf("patched method not recognized: %+v", again)
	}
}

func TestPlanPCLCEILFallback(t *testing.T) {
	code := []byte{0x02, 0x2a}
	patch, already, err := planPCLCEIL(clrMethod{code: code, offset: 40})
	if err != nil {
		t.Fatalf("planPCLCEIL: %v", err)
	}
	if already {
		t.Fatal("unpatched method reported as already patched")
	}
	if patch.offset != 40 || !bytes.Equal(patch.old, code) {
		t.Fatalf("unexpected patch: %+v", patch)
	}
	if patch.new[0] != 0x16 || patch.new[1] != 0x2a || len(patch.new) != len(code) {
		t.Fatalf("unexpected replacement: %x", patch.new)
	}

	if _, already, err := planPCLCEIL(clrMethod{code: []byte{0x16, 0x2a}, offset: 40}); err != nil || !already {
		t.Fatalf("whole-method false not recognized: already=%v err=%v", already, err)
	}

	if _, _, err := planPCLCEIL(clrMethod{
		code:             code,
		offset:           40,
		hasExtraSections: true,
	}); err == nil {
		t.Fatal("fallback accepted a method with exception sections")
	}
}

func TestApplyILPatchesRejectsMismatch(t *testing.T) {
	data := []byte{1, 2, 3, 4}
	_, err := applyILPatches(data, []ilPatch{{
		offset: 1,
		old:    []byte{9},
		new:    []byte{8},
	}})
	if err == nil {
		t.Fatal("mismatched original bytes were accepted")
	}
}
