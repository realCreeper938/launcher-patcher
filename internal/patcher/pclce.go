package patcher

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

var (
	pclRestrictedTrueIL = []byte{
		0x33, 0x04, 0x17, 0x0b, 0x2b, 0x02,
		0x16, 0x0b, 0x07, 0x2a,
	}
	pclRestrictedFalseIL = []byte{
		0x33, 0x04, 0x16, 0x0b, 0x2b, 0x02,
		0x16, 0x0b, 0x07, 0x2a,
	}
)

type ilPatch struct {
	offset int
	old    []byte
	new    []byte
}

type pclScan struct {
	found   bool
	patches []ilPatch
}

// scanPCLCE scans the uncompressed .NET single-file bundle for the
// RegionAssessment.get_IsRestricted method without relying on bundle offsets.
func scanPCLCE(data []byte) (pclScan, error) {
	var result pclScan
	seenOffsets := make(map[int]bool)

	for searchAt := 0; searchAt+2 <= len(data); {
		index := bytes.Index(data[searchAt:], []byte{'M', 'Z'})
		if index < 0 {
			break
		}
		base := searchAt + index
		searchAt = base + 1

		found, methods, err := findRegionMethods(data, base)
		if !found {
			continue
		}
		if err != nil {
			return result, err
		}
		result.found = true

		for _, method := range methods {
			patch, already, err := planPCLCEIL(method)
			if err != nil {
				return result, err
			}
			if already {
				continue
			}
			if seenOffsets[patch.offset] {
				continue
			}
			seenOffsets[patch.offset] = true
			result.patches = append(result.patches, patch)
		}
	}

	return result, nil
}

func planPCLCEIL(method clrMethod) (ilPatch, bool, error) {
	code := method.code
	if index := bytes.Index(code, pclRestrictedTrueIL); index >= 0 {
		return ilPatch{
			offset: method.offset + index + 2,
			old:    []byte{0x17},
			new:    []byte{0x16},
		}, false, nil
	}
	if bytes.Contains(code, pclRestrictedFalseIL) {
		return ilPatch{}, true, nil
	}
	if len(code) >= 2 && code[0] == 0x16 && code[1] == 0x2a {
		return ilPatch{}, true, nil
	}
	if method.hasExtraSections {
		return ilPatch{}, false, errors.New("get_IsRestricted 含有异常处理段，拒绝不安全的整体改写")
	}
	if len(code) < 2 {
		return ilPatch{}, false, errors.New("get_IsRestricted 方法体异常")
	}

	replacement := make([]byte, len(code))
	replacement[0] = 0x16 // ldc.i4.0
	replacement[1] = 0x2a // ret
	return ilPatch{
		offset: method.offset,
		old:    append([]byte(nil), code...),
		new:    replacement,
	}, false, nil
}

func applyILPatches(data []byte, patches []ilPatch) ([]byte, error) {
	out := append([]byte(nil), data...)
	for _, patch := range patches {
		if patch.offset < 0 || patch.offset+len(patch.old) > len(out) {
			return nil, io.ErrUnexpectedEOF
		}
		if !bytes.Equal(out[patch.offset:patch.offset+len(patch.old)], patch.old) {
			return nil, fmt.Errorf("目标字节在修补前发生了变化（偏移 0x%X）", patch.offset)
		}
		if len(patch.old) != len(patch.new) {
			return nil, errors.New("内部补丁长度不一致")
		}
		copy(out[patch.offset:patch.offset+len(patch.new)], patch.new)
	}
	return out, nil
}
