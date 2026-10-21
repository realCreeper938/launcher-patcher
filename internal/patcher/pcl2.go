package patcher

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	pcl2DisabledLoaderName = "关闭下载"
	pcl2LoaderFieldName    = "DlClientListLoader"
)

type pcl2Scan struct {
	found      bool
	restricted bool
	patches    []ilPatch
}

// scanPCL2 looks for the download gate added to PCL2 2.99.0.0. PCL CE and
// PCL2 share a namespace prefix, so this scanner is only used after the PCL CE
// scanner has rejected the file.
func scanPCL2(data []byte) (pcl2Scan, error) {
	// PCL CE also uses the PCL namespace. Its scanner runs first, but do not
	// misclassify a CE build if its region marker has been removed or renamed.
	if bytes.Contains(data, []byte("PCL.Core")) {
		return pcl2Scan{}, nil
	}
	meta, ok := loadCLRMeta(data, 0)
	if !ok {
		return pcl2Scan{}, nil
	}
	secret, ok := meta.findType("PCL", "ModSecret")
	if !ok {
		return pcl2Scan{}, nil
	}
	result := pcl2Scan{found: true}

	// Older PCL2 releases do not have this field at all. Their download pages
	// are unrestricted, so there is nothing to patch.
	if _, ok := meta.fieldOf(secret, "RestrictMcDownload"); !ok {
		return result, nil
	}
	result.restricted = true

	// ModModpack.ModpackInstall was gated as well, but the compiler removed the
	// entire install dispatch and left only a Throw. There is no reversible
	// branch to patch there, so only the two gates below are recovered.
	install, ok := meta.findType("PCL", "PageDownloadInstall")
	if !ok {
		return result, errors.New("PCL2 中未找到 PageDownloadInstall 类型")
	}
	modify, ok := meta.findType("PCL", "PageDownloadModify")
	if !ok {
		return result, errors.New("PCL2 中未找到 PageDownloadModify 类型")
	}

	loaderToken, ok := findPCL2LoaderFieldToken(meta)
	if !ok {
		return result, errors.New("PCL2 中未找到 DlClientListLoader 字段")
	}

	loaderMethod, ok := meta.methodOf(install, "LoaderInit")
	if !ok {
		return result, errors.New("PCL2 中未找到 PageDownloadInstall.LoaderInit")
	}
	loaderCode, loaderOffset, _, err := meta.methodCode(loaderMethod)
	if err != nil {
		return result, fmt.Errorf("读取 PageDownloadInstall.LoaderInit 失败: %w", err)
	}
	loaderPatch, loaderAlready, err := planPCL2Loader(loaderCode, loaderOffset, meta.userString, loaderToken)
	if err != nil {
		return result, err
	}
	if !loaderAlready {
		result.patches = append(result.patches, loaderPatch)
	}

	cardMethod, ok := meta.methodOf(modify, "LoadInstanceFinished")
	if !ok {
		return result, errors.New("PCL2 中未找到 PageDownloadModify.LoadInstanceFinished")
	}
	cardCode, cardOffset, _, err := meta.methodCode(cardMethod)
	if err != nil {
		return result, fmt.Errorf("读取 PageDownloadModify.LoadInstanceFinished 失败: %w", err)
	}
	cardPatch, cardAlready, err := planPCL2Card(cardCode, cardOffset, meta.methodName, meta.memberRefName)
	if err != nil {
		return result, err
	}
	if !cardAlready {
		result.patches = append(result.patches, cardPatch)
	}

	return result, nil
}

func findPCL2LoaderFieldToken(meta *clrMeta) (uint32, bool) {
	typeNames := [][2]string{{"PCL", "ModDownload"}}
	for _, name := range typeNames {
		owner, ok := meta.findType(name[0], name[1])
		if !ok {
			continue
		}
		field, ok := meta.fieldOf(owner, pcl2LoaderFieldName)
		if ok {
			return 0x04000000 | field.rid, true
		}
	}

	if err := meta.loadTypes(); err != nil {
		return 0, false
	}
	for i := range meta.types {
		field, ok := meta.fieldOf(&meta.types[i], pcl2LoaderFieldName)
		if ok {
			return 0x04000000 | field.rid, true
		}
	}
	return 0, false
}

// planPCL2Loader replaces the disabled LoaderTask construction in
// PageDownloadInstall.LoaderInit with the real DlClientListLoader field.
//
// The compiler folds `If RestrictMcDownload` and keeps only the disabled
// branch, so the original expression has to be replaced as a whole.
func planPCL2Loader(code []byte, codeOffset int, userString func(uint32) (string, bool), loaderToken uint32) (ilPatch, bool, error) {
	start := -1
	for i := 0; i+5 <= len(code); i++ {
		if code[i] != 0x72 {
			continue
		}
		token := binary.LittleEndian.Uint32(code[i+1 : i+5])
		if token>>24 != 0x70 {
			continue
		}
		value, ok := userString(token & 0xFFFFFF)
		if !ok || value != pcl2DisabledLoaderName {
			continue
		}
		if start >= 0 {
			return ilPatch{}, false, errors.New("PageDownloadInstall.LoaderInit 中出现了多个关闭下载占位加载器")
		}
		start = i
	}

	if start < 0 {
		if bytes.Contains(code, append([]byte{0x7e}, encodeUint32(loaderToken)...)) {
			return ilPatch{}, true, nil
		}
		return ilPatch{}, false, errors.New("PageDownloadInstall.LoaderInit 中未找到关闭下载占位加载器")
	}
	if start == 0 || code[start-1] != 0x14 {
		return ilPatch{}, false, errors.New("PageDownloadInstall.LoaderInit 的加载器参数结构异常")
	}

	end := -1
	for i := start + 1; i+3 <= len(code); i++ {
		if code[i] != 0x02 || code[i+1] != 0xfe || code[i+2] != 0x06 {
			continue
		}
		if i-7 >= start && code[i-7] == 0x14 && code[i-6] == 0x18 && code[i-5] == 0x73 {
			end = i
			break
		}
	}
	if end < 0 || end-start < 5 {
		return ilPatch{}, false, errors.New("PageDownloadInstall.LoaderInit 的加载器参数边界异常")
	}

	replacement := make([]byte, end-start)
	replacement[0] = 0x7e // ldsfld
	binary.LittleEndian.PutUint32(replacement[1:5], loaderToken)
	return ilPatch{
		offset: codeOffset + start,
		old:    append([]byte(nil), code[start:end]...),
		new:    replacement,
	}, false, nil
}

// planPCL2Card restores the Minecraft card on the version-modify page. The
// compiler turned `If(RestrictMcDownload, Collapsed, Visible)` into a constant
// Collapsed (ldc.i4.2); changing it to Visible (ldc.i4.0) is sufficient.
func planPCL2Card(code []byte, codeOffset int, methodName func(uint32) (string, bool), memberRefName func(uint32) (string, bool)) (ilPatch, bool, error) {
	for i := 0; i+12 <= len(code); i++ {
		if code[i] != 0x02 || code[i+1] != 0x6f {
			continue
		}
		methodToken := binary.LittleEndian.Uint32(code[i+2 : i+6])
		if methodToken>>24 != 0x06 {
			continue
		}
		name, ok := methodName(methodToken & 0xFFFFFF)
		if !ok || name != "get_CardMinecraft" {
			continue
		}
		if code[i+7] != 0x6f {
			continue
		}
		visToken := binary.LittleEndian.Uint32(code[i+8 : i+12])
		if visToken>>24 != 0x0a {
			continue
		}
		visName, ok := memberRefName(visToken & 0xFFFFFF)
		if !ok || visName != "set_Visibility" {
			continue
		}
		switch code[i+6] {
		case 0x18:
			return ilPatch{
				offset: codeOffset + i + 6,
				old:    []byte{0x18},
				new:    []byte{0x16},
			}, false, nil
		case 0x16:
			return ilPatch{}, true, nil
		default:
			return ilPatch{}, false, errors.New("PageDownloadModify.LoadInstanceFinished 的可见性赋值异常")
		}
	}
	return ilPatch{}, false, errors.New("PageDownloadModify.LoadInstanceFinished 中未找到 CardMinecraft 可见性赋值")
}

func encodeUint32(value uint32) []byte {
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], value)
	return out[:]
}
