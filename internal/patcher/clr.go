package patcher

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
)

const maxILSize = 16 << 20

type peSection struct {
	virtualAddr uint32
	virtualSize uint32
	rawPtr      uint32
	rawSize     uint32
}

type peImage struct {
	data     []byte
	base     int
	sections []peSection
}

func parseEmbeddedPE(data []byte, base int) (*peImage, bool) {
	if base < 0 || base+0x40 > len(data) || data[base] != 'M' || data[base+1] != 'Z' {
		return nil, false
	}
	lfanew := int(binary.LittleEndian.Uint32(data[base+0x3c : base+0x40]))
	if lfanew < 0x40 || lfanew > 0x10000 || base+lfanew+24 > len(data) {
		return nil, false
	}
	pe := base + lfanew
	if !bytes.Equal(data[pe:pe+4], []byte{'P', 'E', 0, 0}) {
		return nil, false
	}

	sectionCount := int(binary.LittleEndian.Uint16(data[pe+6 : pe+8]))
	optionalSize := int(binary.LittleEndian.Uint16(data[pe+20 : pe+22]))
	optional := pe + 24
	if sectionCount <= 0 || sectionCount > 96 || optionalSize < 2 || optional+optionalSize > len(data) {
		return nil, false
	}

	magic := binary.LittleEndian.Uint16(data[optional : optional+2])
	var directories, directoryCount int
	switch magic {
	case 0x10b:
		directories = optional + 96
		directoryCount = optional + 92
	case 0x20b:
		directories = optional + 112
		directoryCount = optional + 108
	default:
		return nil, false
	}
	if directoryCount+4 > optional+optionalSize {
		return nil, false
	}
	numberOfDirectories := int(binary.LittleEndian.Uint32(data[directoryCount : directoryCount+4]))
	if numberOfDirectories < 15 || directories+15*8 > optional+optionalSize {
		return nil, false
	}
	cliRVA := binary.LittleEndian.Uint32(data[directories+14*8 : directories+14*8+4])
	if cliRVA == 0 {
		return nil, false
	}

	sectionTable := optional + optionalSize
	if sectionTable+sectionCount*40 > len(data) {
		return nil, false
	}
	image := &peImage{data: data, base: base}
	for i := 0; i < sectionCount; i++ {
		off := sectionTable + i*40
		section := peSection{
			virtualSize: binary.LittleEndian.Uint32(data[off+8 : off+12]),
			virtualAddr: binary.LittleEndian.Uint32(data[off+12 : off+16]),
			rawSize:     binary.LittleEndian.Uint32(data[off+16 : off+20]),
			rawPtr:      binary.LittleEndian.Uint32(data[off+20 : off+24]),
		}
		if section.rawSize > 0 {
			end := int64(base) + int64(section.rawPtr) + int64(section.rawSize)
			if end > int64(len(data)) {
				return nil, false
			}
		}
		image.sections = append(image.sections, section)
	}

	cliOffset, ok := image.rva(cliRVA, 20)
	if !ok {
		return nil, false
	}
	flags := binary.LittleEndian.Uint32(data[cliOffset+16 : cliOffset+20])
	if flags&0x1 == 0 {
		return nil, false
	}
	return image, true
}

func (p *peImage) rva(rva uint32, size int) (int, bool) {
	if size < 0 {
		return 0, false
	}
	size64 := uint64(size)
	for _, section := range p.sections {
		span := section.virtualSize
		if section.rawSize > span {
			span = section.rawSize
		}
		start := uint64(section.virtualAddr)
		end := start + uint64(span)
		needEnd := uint64(rva) + size64
		if uint64(rva) < start || needEnd > end {
			continue
		}
		delta := uint64(rva) - start
		if delta+size64 > uint64(section.rawSize) {
			return 0, false
		}
		offset := int64(p.base) + int64(section.rawPtr) + int64(delta)
		if offset < 0 || offset+int64(size) > int64(len(p.data)) {
			return 0, false
		}
		return int(offset), true
	}
	return 0, false
}

type clrMethod struct {
	code             []byte
	offset           int
	hasExtraSections bool
}

func findRegionMethods(data []byte, base int) (bool, []clrMethod, error) {
	image, ok := parseEmbeddedPE(data, base)
	if !ok {
		return false, nil, nil
	}

	directories := 0
	// Locate the CLI header again. It is cheap and keeps parseEmbeddedPE focused.
	// The data directory offset depends on the PE optional header magic.
	pe := base + int(binary.LittleEndian.Uint32(data[base+0x3c:base+0x40]))
	optional := pe + 24
	magic := binary.LittleEndian.Uint16(data[optional : optional+2])
	if magic == 0x10b {
		directories = optional + 96
	} else {
		directories = optional + 112
	}
	cliRVA := binary.LittleEndian.Uint32(data[directories+14*8 : directories+14*8+4])
	cliOffset, ok := image.rva(cliRVA, 20)
	if !ok {
		return false, nil, nil
	}

	metadataRVA := binary.LittleEndian.Uint32(data[cliOffset+8 : cliOffset+12])
	metadataSize := binary.LittleEndian.Uint32(data[cliOffset+12 : cliOffset+16])
	if metadataRVA == 0 || metadataSize < 16 {
		return false, nil, nil
	}
	metadataOffset, ok := image.rva(metadataRVA, int(metadataSize))
	if !ok || !bytes.Equal(data[metadataOffset:metadataOffset+4], []byte("BSJB")) {
		return false, nil, nil
	}
	metadataEnd := metadataOffset + int(metadataSize)

	versionLength := int(binary.LittleEndian.Uint32(data[metadataOffset+12 : metadataOffset+16]))
	if versionLength < 0 || metadataOffset+16+versionLength+4 > metadataEnd {
		return false, nil, nil
	}
	streamPos := metadataOffset + 16 + versionLength
	streamCount := int(binary.LittleEndian.Uint16(data[streamPos+2 : streamPos+4]))
	streamPos += 4
	if streamCount <= 0 || streamCount > 64 {
		return false, nil, nil
	}

	type streamInfo struct {
		offset int
		size   int
	}
	streams := make(map[string]streamInfo, streamCount)
	for i := 0; i < streamCount; i++ {
		if streamPos+8 > metadataEnd {
			return false, nil, nil
		}
		offset := binary.LittleEndian.Uint32(data[streamPos : streamPos+4])
		size := binary.LittleEndian.Uint32(data[streamPos+4 : streamPos+8])
		streamPos += 8
		nameStart := streamPos
		for streamPos < metadataEnd && data[streamPos] != 0 {
			streamPos++
		}
		if streamPos >= metadataEnd {
			return false, nil, nil
		}
		name := string(data[nameStart:streamPos])
		streamPos++
		streamPos = (streamPos + 3) &^ 3
		if streamPos > metadataEnd {
			return false, nil, nil
		}
		absolute := int64(metadataOffset) + int64(offset)
		if offset > uint32(metadataSize) || absolute+int64(size) > int64(metadataEnd) {
			return false, nil, nil
		}
		streams[name] = streamInfo{offset: int(absolute), size: int(size)}
	}

	tableStream, ok := streams["#~"]
	if !ok {
		tableStream, ok = streams["#-"]
	}
	stringsStream, stringsOK := streams["#Strings"]
	if !ok || !stringsOK || tableStream.size < 24 || stringsStream.size < 1 {
		return false, nil, nil
	}

	table := data[tableStream.offset : tableStream.offset+tableStream.size]
	tableEnd := tableStream.offset + tableStream.size
	if binary.LittleEndian.Uint32(table[:4]) != 0 {
		return false, nil, nil
	}
	heapSizes := table[6]
	valid := binary.LittleEndian.Uint64(table[8:16])
	if bits.OnesCount64(valid) == 0 {
		return false, nil, nil
	}
	pos := 24
	var rows [64]uint32
	for i := 0; i < 64; i++ {
		if valid&(uint64(1)<<uint(i)) == 0 {
			continue
		}
		if pos+4 > len(table) {
			return false, nil, nil
		}
		rows[i] = binary.LittleEndian.Uint32(table[pos : pos+4])
		pos += 4
	}

	tableBase := tableStream.offset + pos
	stringIndex := 2
	if heapSizes&0x01 != 0 {
		stringIndex = 4
	}
	guidIndex := 2
	if heapSizes&0x02 != 0 {
		guidIndex = 4
	}
	blobIndex := 2
	if heapSizes&0x04 != 0 {
		blobIndex = 4
	}
	tableIndex := func(index int) int {
		if rows[index] >= 0x10000 {
			return 4
		}
		return 2
	}
	codedIndex := func(tagBits uint, tables ...int) int {
		var maxRows uint32
		for _, index := range tables {
			if rows[index] > maxRows {
				maxRows = rows[index]
			}
		}
		if uint64(maxRows) >= uint64(1)<<(16-tagBits) {
			return 4
		}
		return 2
	}

	resolutionScope := codedIndex(2, 0x00, 0x1a, 0x23, 0x01)
	typeDefOrRef := codedIndex(2, 0x02, 0x01, 0x1b)
	var rowSizes [7]int
	rowSizes[0] = 2 + stringIndex + 3*guidIndex
	rowSizes[1] = resolutionScope + 2*stringIndex
	rowSizes[2] = 4 + 2*stringIndex + typeDefOrRef + tableIndex(0x04) + tableIndex(0x06)
	rowSizes[3] = tableIndex(0x04)
	rowSizes[4] = 2 + stringIndex + blobIndex
	rowSizes[5] = tableIndex(0x06)
	rowSizes[6] = 4 + 2 + 2 + stringIndex + blobIndex + tableIndex(0x08)

	var tableOffsets [7]int64
	cursor := int64(tableBase)
	for i := 0; i < 7; i++ {
		tableOffsets[i] = cursor
		cursor += int64(rows[i]) * int64(rowSizes[i])
		if cursor > int64(tableEnd) {
			return false, nil, nil
		}
	}

	readID := func(offset int64, size int) (uint32, bool) {
		if offset < 0 || offset+int64(size) > int64(tableEnd) {
			return 0, false
		}
		value := data[int(offset):]
		switch size {
		case 2:
			return uint32(binary.LittleEndian.Uint16(value[:2])), true
		case 4:
			return binary.LittleEndian.Uint32(value[:4]), true
		default:
			return 0, false
		}
	}
	readString := func(index uint32) (string, bool) {
		if index == 0 {
			return "", true
		}
		if int(index) >= stringsStream.size {
			return "", false
		}
		start := stringsStream.offset + int(index)
		limit := stringsStream.offset + stringsStream.size
		end := bytes.IndexByte(data[start:limit], 0)
		if end < 0 {
			return "", false
		}
		return string(data[start : start+end]), true
	}

	type typeDefInfo struct {
		namespace  string
		name       string
		methodList uint32
	}
	typeDefCount := int(rows[0x02])
	typeDefs := make([]typeDefInfo, 0, typeDefCount)
	targetIndex := -1
	rowSize := int64(rowSizes[2])
	for i := 0; i < typeDefCount; i++ {
		rowOffset := tableOffsets[2] + int64(i)*rowSize
		if rowOffset+rowSize > int64(tableEnd) {
			if targetIndex >= 0 {
				return true, nil, io.ErrUnexpectedEOF
			}
			return false, nil, nil
		}
		nameIndex, ok := readID(rowOffset+4, stringIndex)
		if !ok {
			if targetIndex >= 0 {
				return true, nil, io.ErrUnexpectedEOF
			}
			return false, nil, nil
		}
		namespaceIndex, ok := readID(rowOffset+4+int64(stringIndex), stringIndex)
		if !ok {
			if targetIndex >= 0 {
				return true, nil, io.ErrUnexpectedEOF
			}
			return false, nil, nil
		}
		methodListOffset := rowOffset + 4 + int64(2*stringIndex) + int64(typeDefOrRef) + int64(tableIndex(0x04))
		methodList, ok := readID(methodListOffset, tableIndex(0x06))
		if !ok {
			if targetIndex >= 0 {
				return true, nil, io.ErrUnexpectedEOF
			}
			return false, nil, nil
		}
		name, nameOK := readString(nameIndex)
		namespace, namespaceOK := readString(namespaceIndex)
		if !nameOK || !namespaceOK {
			if targetIndex >= 0 {
				return true, nil, io.ErrUnexpectedEOF
			}
			return false, nil, nil
		}
		typeDefs = append(typeDefs, typeDefInfo{namespace: namespace, name: name, methodList: methodList})
		if namespace == "PCL.Core.App.Region" && name == "RegionAssessment" {
			targetIndex = i
		}
	}
	if targetIndex < 0 {
		return false, nil, nil
	}

	methodPtrCount := rows[0x05]
	methodCount := rows[0x06]
	listCount := methodCount
	if methodPtrCount > 0 {
		listCount = methodPtrCount
	}
	startList := typeDefs[targetIndex].methodList
	endList := listCount + 1
	if targetIndex+1 < len(typeDefs) {
		endList = typeDefs[targetIndex+1].methodList
	}
	if startList == 0 || startList > endList || endList > listCount+1 {
		return true, nil, errors.New("RegionAssessment 方法索引无效")
	}

	var methods []clrMethod
	for listIndex := startList; listIndex < endList; listIndex++ {
		methodRow := listIndex
		if methodPtrCount > 0 {
			pointerOffset := tableOffsets[5] + int64(listIndex-1)*int64(rowSizes[5])
			var ok bool
			methodRow, ok = readID(pointerOffset, rowSizes[5])
			if !ok || methodRow == 0 || methodRow > methodCount {
				return true, nil, errors.New("RegionAssessment 方法指针无效")
			}
		}
		if methodRow == 0 || methodRow > methodCount {
			return true, nil, errors.New("RegionAssessment 方法索引越界")
		}
		methodOffset := tableOffsets[6] + int64(methodRow-1)*int64(rowSizes[6])
		if methodOffset+int64(rowSizes[6]) > int64(tableEnd) {
			return true, nil, io.ErrUnexpectedEOF
		}
		methodNameIndex, ok := readID(methodOffset+8, stringIndex)
		if !ok {
			return true, nil, io.ErrUnexpectedEOF
		}
		methodName, ok := readString(methodNameIndex)
		if !ok {
			return true, nil, io.ErrUnexpectedEOF
		}
		if methodName != "get_IsRestricted" {
			continue
		}
		methodRVA := binary.LittleEndian.Uint32(data[int(methodOffset) : int(methodOffset)+4])
		if methodRVA == 0 {
			return true, nil, errors.New("RegionAssessment.get_IsRestricted 没有方法体")
		}
		bodyOffset, ok := image.rva(methodRVA, 1)
		if !ok {
			return true, nil, errors.New("无法定位 RegionAssessment.get_IsRestricted 方法体")
		}
		code, codeOffset, hasExtra, err := parseILBody(data, bodyOffset)
		if err != nil {
			return true, nil, err
		}
		methods = append(methods, clrMethod{code: code, offset: codeOffset, hasExtraSections: hasExtra})
	}
	if len(methods) == 0 {
		return true, nil, errors.New("RegionAssessment 中未找到 get_IsRestricted")
	}
	return true, methods, nil
}

func parseILBody(data []byte, offset int) ([]byte, int, bool, error) {
	if offset < 0 || offset >= len(data) {
		return nil, 0, false, io.ErrUnexpectedEOF
	}
	first := data[offset]
	switch first & 0x3 {
	case 0x2:
		codeSize := int(first >> 2)
		codeOffset := offset + 1
		if codeOffset+codeSize > len(data) {
			return nil, 0, false, io.ErrUnexpectedEOF
		}
		return data[codeOffset : codeOffset+codeSize], codeOffset, false, nil
	case 0x3:
		if offset+12 > len(data) {
			return nil, 0, false, io.ErrUnexpectedEOF
		}
		flagsAndSize := binary.LittleEndian.Uint16(data[offset : offset+2])
		headerSize := int(flagsAndSize>>12) * 4
		if headerSize < 12 || headerSize > 1024 {
			return nil, 0, false, fmt.Errorf("无效的 IL 方法头大小 %d", headerSize)
		}
		codeSize := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		if codeSize > maxILSize {
			return nil, 0, false, errors.New("IL 方法体异常过大")
		}
		codeOffset := offset + headerSize
		if codeOffset > len(data) || uint64(codeOffset)+uint64(codeSize) > uint64(len(data)) {
			return nil, 0, false, io.ErrUnexpectedEOF
		}
		hasExtra := flagsAndSize&0x0008 != 0
		return data[codeOffset : codeOffset+int(codeSize)], codeOffset, hasExtra, nil
	default:
		return nil, 0, false, errors.New("无效的 IL 方法头")
	}
}
