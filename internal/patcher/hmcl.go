package patcher

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	hmclRegionClass = "org/jackhuang/hmcl/util/RegionUtils.class"
	hmclPublicKey   = "assets/hmcl_signature_publickey.der"
	maxClassSize    = 4 << 20
)

var (
	eocdSignature = []byte{'P', 'K', 5, 6}
	cdSignature   = []byte{'P', 'K', 1, 2}
	localSig      = []byte{'P', 'K', 3, 4}
)

type appendedZip struct {
	f      *os.File
	prefix int64
	size   int64
	zr     *zip.Reader
}

func (z *appendedZip) Close() error {
	return z.f.Close()
}

// openAppendedZip opens a plain jar or an executable with a jar suffix.
func openAppendedZip(path string) (*appendedZip, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*appendedZip, error) {
		_ = f.Close()
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	size := info.Size()
	if size < 22 {
		return fail(errors.New("zip: file too short"))
	}

	window := int64(22 + 65535)
	if window > size {
		window = size
	}
	tail := make([]byte, int(window))
	if _, err := f.ReadAt(tail, size-window); err != nil && !errors.Is(err, io.EOF) {
		return fail(err)
	}

	var (
		eocdPos    int64
		entries    uint16
		cdSize     uint32
		cdOffset   uint32
		foundEOCD  bool
		searchAt   = len(tail)
	)
	for searchAt > 0 {
		idx := bytes.LastIndex(tail[:searchAt], eocdSignature)
		if idx < 0 {
			break
		}
		searchAt = idx
		if idx+22 > len(tail) {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(tail[idx+20 : idx+22]))
		if idx+22+commentLen != len(tail) {
			continue
		}

		eocdPos = size - window + int64(idx)
		disk := binary.LittleEndian.Uint16(tail[idx+4 : idx+6])
		cdDisk := binary.LittleEndian.Uint16(tail[idx+6 : idx+8])
		entriesOnDisk := binary.LittleEndian.Uint16(tail[idx+8 : idx+10])
		entries = binary.LittleEndian.Uint16(tail[idx+10 : idx+12])
		cdSize = binary.LittleEndian.Uint32(tail[idx+12 : idx+16])
		cdOffset = binary.LittleEndian.Uint32(tail[idx+16 : idx+20])

		if disk != 0 || cdDisk != 0 || entriesOnDisk != entries || entries == 0 {
			continue
		}
		if entries == 0xffff || cdSize == 0xffffffff || cdOffset == 0xffffffff {
			return fail(errors.New("zip: zip64 is not supported"))
		}
		foundEOCD = true
		break
	}
	if !foundEOCD {
		return fail(errors.New("zip: end of central directory not found"))
	}

	cdStart := eocdPos - int64(cdSize)
	prefix := cdStart - int64(cdOffset)
	if cdSize < 4 || cdStart < 0 || prefix < 0 || prefix >= size {
		return fail(errors.New("zip: invalid central directory"))
	}

	var sig [4]byte
	if _, err := f.ReadAt(sig[:], cdStart); err != nil {
		return fail(err)
	}
	if !bytes.Equal(sig[:], cdSignature) {
		return fail(errors.New("zip: prepended data could not be located"))
	}
	if prefix > 0 {
		if _, err := f.ReadAt(sig[:], prefix); err != nil {
			return fail(err)
		}
		if !bytes.Equal(sig[:], localSig) {
			return fail(errors.New("zip: prepended data could not be located"))
		}
	}

	section := io.NewSectionReader(f, prefix, size-prefix)
	zr, err := zip.NewReader(section, size-prefix)
	if err != nil {
		return fail(err)
	}
	if len(zr.File) == 0 {
		return fail(errors.New("zip: archive is empty"))
	}

	return &appendedZip{f: f, prefix: prefix, size: size, zr: zr}, nil
}

func findArchiveFile(zr *zip.Reader, name string) *zip.File {
	for _, f := range zr.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

func isHMCLArchive(zr *zip.Reader) bool {
	if findArchiveFile(zr, hmclRegionClass) != nil {
		return true
	}
	if findArchiveFile(zr, hmclPublicKey) != nil {
		return true
	}
	manifest := findArchiveFile(zr, "META-INF/MANIFEST.MF")
	if manifest == nil || manifest.UncompressedSize64 > 64<<10 {
		return false
	}
	rc, err := manifest.Open()
	if err != nil {
		return false
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, 64<<10))
	if err != nil {
		return false
	}
	upper := strings.ToUpper(string(data))
	return strings.Contains(upper, "HMCL") || strings.Contains(upper, "ORG/JACKHUANG/HMCL")
}

func patchHMCLArchive(zs *appendedZip, input string, kind Kind, mode os.FileMode) (Result, error) {
	classFile := findArchiveFile(zs.zr, hmclRegionClass)
	if classFile == nil {
		return Result{
			Kind:  kind,
			Input: input,
			Note:  "此 HMCL 版本不含 RegionUtils 区域检查，无需修补。",
		}, nil
	}
	if classFile.UncompressedSize64 > maxClassSize {
		return Result{}, errors.New("HMCL 的 RegionUtils.class 异常过大")
	}

	rc, err := classFile.Open()
	if err != nil {
		return Result{}, fmt.Errorf("无法读取 HMCL 区域检查类: %w", err)
	}
	classBytes, readErr := io.ReadAll(io.LimitReader(rc, maxClassSize+1))
	closeErr := rc.Close()
	if readErr != nil {
		return Result{}, fmt.Errorf("无法读取 HMCL 区域检查类: %w", readErr)
	}
	if closeErr != nil {
		return Result{}, fmt.Errorf("无法读取 HMCL 区域检查类: %w", closeErr)
	}
	if len(classBytes) > maxClassSize {
		return Result{}, errors.New("HMCL 的 RegionUtils.class 异常过大")
	}

	patchedClass, state, err := patchRegionClass(classBytes)
	if err != nil {
		return Result{}, fmt.Errorf("无法解析 HMCL 的 RegionUtils.class: %w", err)
	}
	switch state {
	case regionClassAlready:
		return Result{
			Kind:  kind,
			Input: input,
			Note:  "此 HMCL 文件已经是修补后的版本，无需重复修补。",
		}, nil
	case regionClassNoCheck:
		return Result{
			Kind:  kind,
			Input: input,
			Note:  "此 HMCL 版本没有可修补的中国大陆检查，无需修补。",
		}, nil
	}

	output, err := nextOutputPath(input)
	if err != nil {
		return Result{}, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(output), ".launcher-patcher-*.tmp")
	if err != nil {
		return Result{}, fmt.Errorf("无法创建输出文件: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := io.Copy(tmp, io.NewSectionReader(zs.f, 0, zs.prefix)); err != nil {
		_ = tmp.Close()
		return Result{}, fmt.Errorf("复制启动器前缀失败: %w", err)
	}

	zw := zip.NewWriter(tmp)
	zw.SetComment(zs.zr.Comment)
	for _, entry := range zs.zr.File {
		if entry.Name == hmclRegionClass {
			header := entry.FileHeader
			header.Flags = 0
			header.CRC32 = 0
			header.CompressedSize = 0
			header.UncompressedSize = 0
			header.CompressedSize64 = 0
			header.UncompressedSize64 = 0
			header.Extra = nil
			w, err := zw.CreateHeader(&header)
			if err != nil {
				_ = zw.Close()
				_ = tmp.Close()
				return Result{}, fmt.Errorf("重建 HMCL jar 失败: %w", err)
			}
			if _, err := w.Write(patchedClass); err != nil {
				_ = zw.Close()
				_ = tmp.Close()
				return Result{}, fmt.Errorf("写入修补后的类失败: %w", err)
			}
			continue
		}
		if strings.HasSuffix(entry.Name, "/") {
			header := entry.FileHeader
			if _, err := zw.CreateHeader(&header); err != nil {
				_ = zw.Close()
				_ = tmp.Close()
				return Result{}, fmt.Errorf("重建 HMCL jar 目录条目失败: %w", err)
			}
			continue
		}
		if err := zw.Copy(entry); err != nil {
			_ = zw.Close()
			_ = tmp.Close()
			return Result{}, fmt.Errorf("复制 HMCL jar 条目失败: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		_ = tmp.Close()
		return Result{}, fmt.Errorf("生成 HMCL jar 失败: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return Result{}, fmt.Errorf("写入失败: %w", err)
	}
	perm := mode.Perm()
	if perm == 0 {
		perm = 0o644
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return Result{}, fmt.Errorf("设置文件权限失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return Result{}, fmt.Errorf("写入失败: %w", err)
	}

	if err := verifyHMCLOutput(tmpName, zs.prefix, len(zs.zr.File), patchedClass); err != nil {
		return Result{}, fmt.Errorf("修补结果校验失败: %w", err)
	}
	if err := os.Rename(tmpName, output); err != nil {
		return Result{}, fmt.Errorf("无法生成输出文件: %w", err)
	}

	return Result{
		Kind:    kind,
		Input:   input,
		Output:  output,
		Changed: true,
		Note:    "已移除 HMCL 的中国大陆下载限制。",
	}, nil
}

func verifyHMCLOutput(path string, wantPrefix int64, wantEntries int, wantClass []byte) error {
	zs, err := openAppendedZip(path)
	if err != nil {
		return err
	}
	defer zs.Close()

	if zs.prefix != wantPrefix {
		return fmt.Errorf("启动器前缀长度发生变化: %d != %d", zs.prefix, wantPrefix)
	}
	if len(zs.zr.File) != wantEntries {
		return fmt.Errorf("jar 条目数量发生变化: %d != %d", len(zs.zr.File), wantEntries)
	}

	classFile := findArchiveFile(zs.zr, hmclRegionClass)
	if classFile == nil {
		return errors.New("输出中缺少 RegionUtils.class")
	}
	rc, err := classFile.Open()
	if err != nil {
		return err
	}
	classBytes, readErr := io.ReadAll(io.LimitReader(rc, maxClassSize+1))
	closeErr := rc.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if !bytes.Equal(classBytes, wantClass) {
		return errors.New("输出中的 RegionUtils.class 与预期不一致")
	}
	return nil
}

type javaConstant struct {
	tag  byte
	a, b uint16
	text string
}

type javaClass struct {
	data       []byte
	cp         []javaConstant
	code       []byte
	codeOffset int
}

type classReader struct {
	data []byte
	off  int
}

func (r *classReader) u1() (byte, error) {
	if r.off >= len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	v := r.data[r.off]
	r.off++
	return v, nil
}

func (r *classReader) u2() (uint16, error) {
	if r.off+2 > len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.BigEndian.Uint16(r.data[r.off : r.off+2])
	r.off += 2
	return v, nil
}

func (r *classReader) u4() (uint32, error) {
	if r.off+4 > len(r.data) {
		return 0, io.ErrUnexpectedEOF
	}
	v := binary.BigEndian.Uint32(r.data[r.off : r.off+4])
	r.off += 4
	return v, nil
}

func (r *classReader) take(n int) ([]byte, error) {
	if n < 0 || r.off > len(r.data)-n {
		return nil, io.ErrUnexpectedEOF
	}
	v := r.data[r.off : r.off+n]
	r.off += n
	return v, nil
}

func (r *classReader) skip(n uint32) error {
	if uint64(n) > uint64(len(r.data)-r.off) {
		return io.ErrUnexpectedEOF
	}
	r.off += int(n)
	return nil
}

func parseJavaRegionClass(data []byte) (*javaClass, error) {
	r := &classReader{data: data}
	magic, err := r.u4()
	if err != nil {
		return nil, err
	}
	if magic != 0xcafebabe {
		return nil, errors.New("不是 Java class 文件")
	}
	if _, err := r.u2(); err != nil {
		return nil, err
	}
	if _, err := r.u2(); err != nil {
		return nil, err
	}
	cpCount, err := r.u2()
	if err != nil {
		return nil, err
	}
	if cpCount < 2 {
		return nil, errors.New("class 常量池为空")
	}

	cp := make([]javaConstant, int(cpCount))
	for i := 1; i < int(cpCount); i++ {
		slot := i
		tag, err := r.u1()
		if err != nil {
			return nil, err
		}
		entry := javaConstant{tag: tag}
		switch tag {
		case 1:
			length, err := r.u2()
			if err != nil {
				return nil, err
			}
			value, err := r.take(int(length))
			if err != nil {
				return nil, err
			}
			entry.text = string(value)
		case 3, 4:
			if err := r.skip(4); err != nil {
				return nil, err
			}
		case 5, 6:
			if err := r.skip(8); err != nil {
				return nil, err
			}
			if i+1 >= int(cpCount) {
				return nil, errors.New("class 常量池长整数索引越界")
			}
			i++
		case 7, 8, 16, 19, 20:
			value, err := r.u2()
			if err != nil {
				return nil, err
			}
			entry.a = value
		case 9, 10, 11, 12, 17, 18:
			a, err := r.u2()
			if err != nil {
				return nil, err
			}
			b, err := r.u2()
			if err != nil {
				return nil, err
			}
			entry.a, entry.b = a, b
		case 15:
			if _, err := r.u1(); err != nil {
				return nil, err
			}
			value, err := r.u2()
			if err != nil {
				return nil, err
			}
			entry.a = value
		default:
			return nil, fmt.Errorf("不支持的 class 常量池标签 %d", tag)
		}
		cp[slot] = entry
	}

	class := &javaClass{data: data, cp: cp}
	for i := 0; i < 3; i++ {
		if _, err := r.u2(); err != nil {
			return nil, err
		}
	}
	interfaces, err := r.u2()
	if err != nil {
		return nil, err
	}
	if err := r.skip(uint32(interfaces) * 2); err != nil {
		return nil, err
	}
	fields, err := r.u2()
	if err != nil {
		return nil, err
	}
	for i := 0; i < int(fields); i++ {
		if err := r.skip(6); err != nil {
			return nil, err
		}
		if err := skipClassAttributes(r); err != nil {
			return nil, err
		}
	}
	methods, err := r.u2()
	if err != nil {
		return nil, err
	}
	for i := 0; i < int(methods); i++ {
		if err := r.skip(2); err != nil {
			return nil, err
		}
		nameIndex, err := r.u2()
		if err != nil {
			return nil, err
		}
		if err := r.skip(2); err != nil {
			return nil, err
		}
		name, _ := class.utf8(nameIndex)
		attrCount, err := r.u2()
		if err != nil {
			return nil, err
		}
		for j := 0; j < int(attrCount); j++ {
			attrNameIndex, err := r.u2()
			if err != nil {
				return nil, err
			}
			attrLen, err := r.u4()
			if err != nil {
				return nil, err
			}
			if uint64(attrLen) > uint64(len(data)-r.off) {
				return nil, io.ErrUnexpectedEOF
			}
			attrStart := r.off
			attrEnd := attrStart + int(attrLen)
			if name == "<clinit>" {
				attrName, _ := class.utf8(attrNameIndex)
				if attrName == "Code" {
					code, codeOffset, err := parseCodeAttribute(data, attrStart, attrEnd)
					if err != nil {
						return nil, err
					}
					class.code = code
					class.codeOffset = codeOffset
					return class, nil
				}
			}
			r.off = attrEnd
		}
	}

	return nil, errors.New("class 中未找到 <clinit>")
}

func (c *javaClass) utf8(index uint16) (string, bool) {
	if int(index) <= 0 || int(index) >= len(c.cp) {
		return "", false
	}
	entry := c.cp[index]
	if entry.tag != 1 {
		return "", false
	}
	return entry.text, true
}

func (c *javaClass) reference(index uint16) (className, name, descriptor string, ok bool) {
	if int(index) <= 0 || int(index) >= len(c.cp) {
		return "", "", "", false
	}
	ref := c.cp[index]
	if ref.tag != 10 && ref.tag != 11 && ref.tag != 9 {
		return "", "", "", false
	}
	if int(ref.a) <= 0 || int(ref.a) >= len(c.cp) || c.cp[ref.a].tag != 7 {
		return "", "", "", false
	}
	classEntry := c.cp[ref.a]
	className, ok = c.utf8(classEntry.a)
	if !ok {
		return "", "", "", false
	}
	if int(ref.b) <= 0 || int(ref.b) >= len(c.cp) || c.cp[ref.b].tag != 12 {
		return "", "", "", false
	}
	nameType := c.cp[ref.b]
	name, ok = c.utf8(nameType.a)
	if !ok {
		return "", "", "", false
	}
	descriptor, ok = c.utf8(nameType.b)
	if !ok {
		return "", "", "", false
	}
	return className, name, descriptor, true
}

func skipClassAttributes(r *classReader) error {
	count, err := r.u2()
	if err != nil {
		return err
	}
	for i := 0; i < int(count); i++ {
		if err := r.skip(2); err != nil {
			return err
		}
		length, err := r.u4()
		if err != nil {
			return err
		}
		if err := r.skip(length); err != nil {
			return err
		}
	}
	return nil
}

func parseCodeAttribute(data []byte, start, end int) ([]byte, int, error) {
	if start < 0 || end < start || end > len(data) {
		return nil, 0, io.ErrUnexpectedEOF
	}
	r := &classReader{data: data[:end], off: start}
	if err := r.skip(4); err != nil {
		return nil, 0, err
	}
	codeLen, err := r.u4()
	if err != nil {
		return nil, 0, err
	}
	if codeLen > maxClassSize {
		return nil, 0, errors.New("class 方法体异常过大")
	}
	codeOffset := r.off
	code, err := r.take(int(codeLen))
	if err != nil {
		return nil, 0, err
	}
	return code, codeOffset, nil
}

type regionClassState int

const (
	regionClassPatchable regionClassState = iota
	regionClassAlready
	regionClassNoCheck
)

func patchRegionClass(data []byte) ([]byte, regionClassState, error) {
	class, err := parseJavaRegionClass(data)
	if err != nil {
		return nil, regionClassNoCheck, err
	}

	var callOffsets []int
	checkReferenceExists := false
	for i := 1; i < len(class.cp); i++ {
		entry := class.cp[i]
		if entry.tag != 10 && entry.tag != 11 {
			continue
		}
		_, name, desc, ok := class.reference(uint16(i))
		if ok && name == "checkMachineIsChinaMainland" && desc == "()Z" {
			checkReferenceExists = true
		}
	}

	code := class.code
	for i := 0; i+2 < len(code); i++ {
		if code[i] != 0xb8 {
			continue
		}
		index := binary.BigEndian.Uint16(code[i+1 : i+3])
		_, name, desc, ok := class.reference(index)
		if ok && name == "checkMachineIsChinaMainland" && desc == "()Z" {
			callOffsets = append(callOffsets, i)
		}
	}

	if len(callOffsets) > 1 {
		return nil, regionClassNoCheck, errors.New("RegionUtils.<clinit> 中存在多个相同的区域检查调用")
	}
	if len(callOffsets) == 0 {
		if !checkReferenceExists {
			return nil, regionClassNoCheck, nil
		}
		patchedCall := []byte{0x03, 0x00, 0x00}
		if bytes.Contains(code, patchedCall) ||
			(len(code) >= 2 && code[0] == 0x16 && code[1] == 0x2a) {
			return nil, regionClassAlready, nil
		}
		return nil, regionClassNoCheck, errors.New("RegionUtils.<clinit> 的检查调用形态不受支持")
	}

	call := callOffsets[0]
	patched := append([]byte(nil), data...)
	offset := class.codeOffset + call
	if offset < 0 || offset+3 > len(patched) {
		return nil, regionClassNoCheck, io.ErrUnexpectedEOF
	}
	patched[offset] = 0x03
	patched[offset+1] = 0x00
	patched[offset+2] = 0x00
	return patched, regionClassPatchable, nil
}
