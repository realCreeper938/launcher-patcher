package patcher

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Kind is the detected launcher format.
type Kind string

const (
	KindHMCLJar Kind = "HMCL jar"
	KindHMCLExe Kind = "HMCL exe"
	KindPCLCE   Kind = "PCL CE"
	KindPCL2    Kind = "PCL2"
)

// Result describes the outcome of processing one input file.
type Result struct {
	Kind    Kind
	Input   string
	Output  string
	Changed bool
	Note    string
}

// PatchFile detects and patches a launcher without modifying the input file.
func PatchFile(input string) (Result, error) {
	abs, err := filepath.Abs(input)
	if err != nil {
		return Result{}, fmt.Errorf("无法解析文件路径: %w", err)
	}

	info, err := os.Stat(abs)
	if err != nil {
		return Result{}, fmt.Errorf("无法读取文件: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Result{}, fmt.Errorf("不是普通文件: %s", abs)
	}

	if res, recognized, err := tryHMCL(abs, info.Mode()); recognized {
		return res, err
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		return Result{}, fmt.Errorf("无法读取文件: %w", err)
	}

	if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
		scan, scanErr := scanPCLCE(data)
		if scanErr != nil {
			return Result{}, fmt.Errorf("检测到 PCL CE 区域限制，但无法修补: %w", scanErr)
		}
		if scan.found {
			if len(scan.patches) == 0 {
				return Result{
					Kind:  KindPCLCE,
					Input: abs,
					Note:  "文件已经是修补后的版本，无需重复修补。",
				}, nil
			}

			patched, applyErr := applyILPatches(data, scan.patches)
			if applyErr != nil {
				return Result{}, applyErr
			}
			output, writeErr := writeBytesAtomic(abs, patched, info.Mode())
			if writeErr != nil {
				return Result{}, writeErr
			}
			return Result{
				Kind:    KindPCLCE,
				Input:   abs,
				Output:  output,
				Changed: true,
				Note:    fmt.Sprintf("已移除 PCL CE 的区域限制（%d 处）。", len(scan.patches)),
			}, nil
		}

		scan2, scan2Err := scanPCL2(data)
		if scan2Err != nil {
			return Result{}, fmt.Errorf("检测到 PCL2 的 MC 下载限制，但无法修补: %w", scan2Err)
		}
		if scan2.found {
			if !scan2.restricted {
				return Result{
					Kind:  KindPCL2,
					Input: abs,
					Note:  "该 PCL2 版本没有 MC 下载限制，文件未修改。",
				}, nil
			}
			if len(scan2.patches) == 0 {
				return Result{
					Kind:  KindPCL2,
					Input: abs,
					Note:  "文件已经是修补后的版本，无需重复修补。",
				}, nil
			}

			patched, applyErr := applyILPatches(data, scan2.patches)
			if applyErr != nil {
				return Result{}, applyErr
			}
			output, writeErr := writeBytesAtomic(abs, patched, info.Mode())
			if writeErr != nil {
				return Result{}, writeErr
			}
			return Result{
				Kind:    KindPCL2,
				Input:   abs,
				Output:  output,
				Changed: true,
				Note:    fmt.Sprintf("已移除 PCL2 的 MC 下载限制（%d 处）；2.99 的整合包安装功能（菜单/拖入/资源页）已被官方编译移除，无法恢复。", len(scan2.patches)),
			}, nil
		}

		kind, recognized := classifyPCLFallback(data)
		if recognized {
			if kind == KindPCL2 {
				return Result{
					Kind:  KindPCL2,
					Input: abs,
					Note:  "该 PCL2 版本没有同类下载限制，文件未修改。",
				}, nil
			}
			return Result{
				Kind:  KindPCLCE,
				Input: abs,
				Note:  "未检测到区域限制（可能已是修补版，或该版本尚未加入此限制）。",
			}, nil
		}

		return Result{}, errors.New("无法识别该 exe；仅支持 PCL2、PCL CE 和 HMCL")
	}

	return Result{}, errors.New("无法识别该文件；请拖入 PCL2/PCL CE 的 exe，或 HMCL 的 jar/exe")
}

func tryHMCL(path string, mode os.FileMode) (Result, bool, error) {
	zs, err := openAppendedZip(path)
	if err != nil {
		return Result{}, false, nil
	}
	defer zs.Close()

	if !isHMCLArchive(zs.zr) {
		return Result{}, false, nil
	}

	kind := KindHMCLJar
	if zs.prefix != 0 {
		kind = KindHMCLExe
	}

	res, err := patchHMCLArchive(zs, path, kind, mode)
	return res, true, err
}

func nextOutputPath(input string) (string, error) {
	dir := filepath.Dir(input)
	ext := filepath.Ext(input)
	base := strings.TrimSuffix(filepath.Base(input), ext)

	for n := 1; n <= 9999; n++ {
		suffix := "_patched"
		if n > 1 {
			suffix = fmt.Sprintf("_patched_%d", n)
		}
		candidate := filepath.Join(dir, base+suffix+ext)
		_, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			return candidate, nil
		}
		if err != nil {
			return "", fmt.Errorf("无法检查输出路径: %w", err)
		}
	}

	return "", errors.New("同名修补文件过多，请先清理旧输出")
}

func writeBytesAtomic(input string, data []byte, mode os.FileMode) (string, error) {
	output, err := nextOutputPath(input)
	if err != nil {
		return "", err
	}

	f, err := os.CreateTemp(filepath.Dir(output), ".launcher-patcher-*.tmp")
	if err != nil {
		return "", fmt.Errorf("无法创建输出文件: %w", err)
	}
	tempName := f.Name()
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = os.Remove(tempName)
		}
	}()

	if _, err := f.Write(data); err != nil {
		return "", fmt.Errorf("写入失败: %w", err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("写入失败: %w", err)
	}
	perm := mode.Perm()
	if perm == 0 {
		perm = 0o644
	}
	if err := f.Chmod(perm); err != nil {
		return "", fmt.Errorf("设置文件权限失败: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("写入失败: %w", err)
	}
	if err := os.Rename(tempName, output); err != nil {
		return "", fmt.Errorf("无法生成输出文件: %w", err)
	}
	committed = true
	return output, nil
}

// classifyPCLFallback distinguishes PCL CE from PCL2. PCL CE bundles its
// PCL.Core assembly, while PCL2 mentions "PCL CE" in promotional strings, so
// the PCL.Core marker must win over the generic product name.
func classifyPCLFallback(data []byte) (Kind, bool) {
	if bytes.Contains(data, []byte("PCL.Core")) {
		return KindPCLCE, true
	}
	if hasProductMarker(data, "Plain Craft Launcher") {
		return KindPCL2, true
	}
	if hasProductMarker(data, "PCL CE") {
		return KindPCLCE, true
	}
	return "", false
}

func hasProductMarker(data []byte, s string) bool {
	return hasUTF16ASCII(data, s) || bytes.Contains(data, []byte(s))
}

func hasUTF16ASCII(data []byte, s string) bool {
	if s == "" {
		return true
	}
	needle := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		needle = append(needle, s[i], 0)
	}
	return bytes.Contains(data, needle)
}
