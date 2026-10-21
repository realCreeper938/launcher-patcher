package patcher

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"unicode/utf16"
)

// clrStream describes one metadata heap (or the table stream) inside a PE image.
type clrStream struct {
	offset int
	size   int
}

// clrMeta is a small, read-only ECMA-335 metadata reader. It only exposes the
// tables needed to locate methods and fields by name; offsets are never assumed.
type clrMeta struct {
	data           []byte
	image          *peImage
	metadataOffset int
	metadataEnd    int

	streams map[string]clrStream

	tableBase  int
	tableEnd   int
	rows       [64]uint32
	tableStart [64]int

	heapSizes  byte
	stringSize int
	guidSize   int
	blobSize   int

	types       []clrType
	typesLoaded bool
}

type clrType struct {
	rid         uint32
	namespace   string
	name        string
	fieldStart  uint32
	fieldEnd    uint32
	methodStart uint32
	methodEnd   uint32
}

type clrMethodDef struct {
	rid     uint32
	rva     uint32
	name    string
	params  int
	sigBlob []byte
}

type clrFieldDef struct {
	rid   uint32
	flags uint16
	name  string
}

func loadCLRMeta(data []byte, base int) (*clrMeta, bool) {
	image, ok := parseEmbeddedPE(data, base)
	if !ok {
		return nil, false
	}

	pe := base + int(binary.LittleEndian.Uint32(data[base+0x3c:base+0x40]))
	optional := pe + 24
	magic := binary.LittleEndian.Uint16(data[optional : optional+2])
	directories := optional + 112
	if magic == 0x10b {
		directories = optional + 96
	}
	cliRVA := binary.LittleEndian.Uint32(data[directories+14*8 : directories+14*8+4])
	cliOffset, ok := image.rva(cliRVA, 20)
	if !ok {
		return nil, false
	}

	metadataRVA := binary.LittleEndian.Uint32(data[cliOffset+8 : cliOffset+12])
	metadataSize := binary.LittleEndian.Uint32(data[cliOffset+12 : cliOffset+16])
	if metadataRVA == 0 || metadataSize < 32 {
		return nil, false
	}
	metadataOffset, ok := image.rva(metadataRVA, int(metadataSize))
	if !ok || !bytes.Equal(data[metadataOffset:metadataOffset+4], []byte("BSJB")) {
		return nil, false
	}
	metadataEnd := metadataOffset + int(metadataSize)

	versionLength := int(binary.LittleEndian.Uint32(data[metadataOffset+12 : metadataOffset+16]))
	if versionLength < 0 || metadataOffset+16+versionLength+4 > metadataEnd {
		return nil, false
	}
	streamPos := (metadataOffset + 16 + versionLength + 3) &^ 3
	if streamPos < 0 || streamPos+4 > metadataEnd {
		return nil, false
	}
	streamCount := int(binary.LittleEndian.Uint16(data[streamPos+2 : streamPos+4]))
	streamPos += 4
	if streamCount <= 0 || streamCount > 64 || streamPos > metadataEnd {
		return nil, false
	}

	streams := make(map[string]clrStream, streamCount)
	for i := 0; i < streamCount; i++ {
		if streamPos+8 > metadataEnd {
			return nil, false
		}
		offset := binary.LittleEndian.Uint32(data[streamPos : streamPos+4])
		size := binary.LittleEndian.Uint32(data[streamPos+4 : streamPos+8])
		streamPos += 8
		nameStart := streamPos
		for streamPos < metadataEnd && data[streamPos] != 0 {
			streamPos++
		}
		if streamPos >= metadataEnd {
			return nil, false
		}
		name := string(data[nameStart:streamPos])
		streamPos++
		streamPos = (streamPos + 3) &^ 3
		if streamPos > metadataEnd {
			return nil, false
		}
		absolute := int64(metadataOffset) + int64(offset)
		if offset > uint32(metadataSize) || absolute+int64(size) > int64(metadataEnd) {
			return nil, false
		}
		streams[name] = clrStream{offset: int(absolute), size: int(size)}
	}

	tableStream, ok := streams["#~"]
	if !ok {
		tableStream, ok = streams["#-"]
	}
	stringsStream, stringsOK := streams["#Strings"]
	_, usOK := streams["#US"]
	if !ok || !stringsOK || !usOK || tableStream.size < 24 || stringsStream.size < 1 {
		return nil, false
	}

	table := data[tableStream.offset : tableStream.offset+tableStream.size]
	tableEnd := tableStream.offset + tableStream.size
	if binary.LittleEndian.Uint32(table[:4]) != 0 {
		return nil, false
	}
	heapSizes := table[6]
	valid := binary.LittleEndian.Uint64(table[8:16])
	if valid == 0 {
		return nil, false
	}

	meta := &clrMeta{
		data:           data,
		image:          image,
		metadataOffset: metadataOffset,
		metadataEnd:    metadataEnd,
		streams:        streams,
		tableEnd:       tableEnd,
		heapSizes:      heapSizes,
		stringSize:     2,
		guidSize:       2,
		blobSize:       2,
	}
	if heapSizes&0x01 != 0 {
		meta.stringSize = 4
	}
	if heapSizes&0x02 != 0 {
		meta.guidSize = 4
	}
	if heapSizes&0x04 != 0 {
		meta.blobSize = 4
	}

	pos := 24
	for i := 0; i < 64; i++ {
		if valid&(uint64(1)<<uint(i)) == 0 {
			continue
		}
		if pos+4 > len(table) {
			return nil, false
		}
		meta.rows[i] = binary.LittleEndian.Uint32(table[pos : pos+4])
		pos += 4
	}
	if anyRowsBeyondKnown(meta.rows) {
		return nil, false
	}
	meta.tableBase = tableStream.offset + pos

	cursor := meta.tableBase
	for i := 0; i < 64; i++ {
		meta.tableStart[i] = cursor
		if meta.rows[i] == 0 {
			continue
		}
		size := meta.tableRowSize(i)
		if size <= 0 {
			return nil, false
		}
		cursor += int(meta.rows[i]) * size
		if cursor > tableEnd {
			return nil, false
		}
	}
	return meta, true
}

func anyRowsBeyondKnown(rows [64]uint32) bool {
	for i := 45; i < 64; i++ {
		if rows[i] != 0 {
			return true
		}
	}
	return false
}

func (m *clrMeta) indexSize(table int) int {
	if m.rows[table] >= 0x10000 {
		return 4
	}
	return 2
}

func (m *clrMeta) codedSize(tagBits uint, tables ...int) int {
	var maxRows uint32
	for _, table := range tables {
		if m.rows[table] > maxRows {
			maxRows = m.rows[table]
		}
	}
	if uint64(maxRows) >= uint64(1)<<(16-tagBits) {
		return 4
	}
	return 2
}

func (m *clrMeta) tableRowSize(table int) int {
	s := m.indexSize
	c := m.codedSize
	switch table {
	case 0:
		return 2 + m.stringSize + 3*m.guidSize
	case 1:
		return c(2, 0, 26, 35, 1) + 2*m.stringSize
	case 2:
		return 4 + 2*m.stringSize + c(2, 2, 1, 27) + s(4) + s(6)
	case 3:
		return s(4)
	case 4:
		return 2 + m.stringSize + m.blobSize
	case 5:
		return s(6)
	case 6:
		return 4 + 2 + 2 + m.stringSize + m.blobSize + s(8)
	case 7:
		return s(8)
	case 8:
		return 2 + 2 + m.stringSize
	case 9:
		return s(2) + c(2, 2, 1, 27)
	case 10:
		return c(3, 2, 1, 26, 6, 27) + m.stringSize + m.blobSize
	case 11:
		return 1 + 1 + c(2, 4, 8, 23) + m.blobSize
	case 12:
		return c(5, 6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 43, 44) + c(3, 6, 10) + m.blobSize
	case 13:
		return c(1, 4, 8) + m.blobSize
	case 14:
		return 2 + c(2, 2, 6, 32) + m.blobSize
	case 15:
		return 2 + 4 + s(2)
	case 16:
		return 4 + s(4)
	case 17:
		return m.blobSize
	case 18:
		return s(2) + s(20)
	case 19:
		return s(20)
	case 20:
		return 2 + m.stringSize + c(2, 2, 1, 27)
	case 21:
		return s(2) + s(23)
	case 22:
		return s(23)
	case 23:
		return 2 + m.stringSize + m.blobSize
	case 24:
		return 2 + s(6) + c(1, 20, 23)
	case 25:
		return s(2) + c(1, 6, 10) + c(1, 6, 10)
	case 26:
		return m.stringSize
	case 27:
		return m.blobSize
	case 28:
		return 2 + c(1, 4, 6) + m.stringSize + s(26)
	case 29:
		return 4 + s(4)
	case 30, 31:
		return 4
	case 32:
		return 4 + 2 + 2 + 2 + 2 + 4 + m.blobSize + 2*m.stringSize
	case 33:
		return 4
	case 34:
		return 12
	case 35:
		return 2 + 2 + 2 + 2 + 4 + m.blobSize + 2*m.stringSize + m.blobSize
	case 36:
		return 4 + s(35)
	case 37:
		return 12 + s(35)
	case 38:
		return 4 + m.stringSize + m.blobSize
	case 39:
		return 4 + 4 + 2*m.stringSize + c(2, 38, 35, 39)
	case 40:
		return 4 + 4 + m.stringSize + c(2, 38, 35, 39)
	case 41:
		return 2 * s(2)
	case 42:
		return 2 + 2 + c(1, 2, 6) + m.stringSize
	case 43:
		return c(1, 6, 10) + m.blobSize
	case 44:
		return s(42) + c(2, 2, 1, 27)
	default:
		return 0
	}
}

func (m *clrMeta) readID(offset, size int) (uint32, bool) {
	if offset < 0 || size <= 0 || offset+size > m.tableEnd {
		return 0, false
	}
	value := m.data[offset:]
	if size == 2 {
		return uint32(binary.LittleEndian.Uint16(value[:2])), true
	}
	if size == 4 {
		return binary.LittleEndian.Uint32(value[:4]), true
	}
	return 0, false
}

func (m *clrMeta) readString(index uint32) (string, bool) {
	stream := m.streams["#Strings"]
	if index == 0 {
		return "", true
	}
	if int(index) >= stream.size {
		return "", false
	}
	start := stream.offset + int(index)
	limit := stream.offset + stream.size
	end := bytes.IndexByte(m.data[start:limit], 0)
	if end < 0 {
		return "", false
	}
	return string(m.data[start : start+end]), true
}

func (m *clrMeta) blobAt(index uint32) ([]byte, bool) {
	stream := m.streams["#Blob"]
	if int(index) >= stream.size {
		return nil, false
	}
	length, pos, ok := readCLRCompressed(m.data, stream.offset+int(index))
	if !ok {
		return nil, false
	}
	start := pos
	end := start + int(length)
	if end > stream.offset+stream.size {
		return nil, false
	}
	return m.data[start:end], true
}

func (m *clrMeta) userString(index uint32) (string, bool) {
	stream := m.streams["#US"]
	if int(index) >= stream.size {
		return "", false
	}
	length, pos, ok := readCLRCompressed(m.data, stream.offset+int(index))
	if !ok {
		return "", false
	}
	if length == 0 {
		return "", true
	}
	start := pos
	end := start + int(length)
	if end > stream.offset+stream.size || end <= start {
		return "", false
	}
	payload := m.data[start:end]
	// The trailing byte is a flag, not part of the UTF-16 payload.
	payload = payload[:len(payload)-1]
	if len(payload)%2 != 0 {
		payload = payload[:len(payload)-1]
	}
	units := make([]uint16, len(payload)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(payload[2*i:])
	}
	return string(utf16.Decode(units)), true
}

func readCLRCompressed(data []byte, pos int) (uint32, int, bool) {
	if pos < 0 || pos >= len(data) {
		return 0, 0, false
	}
	b := data[pos]
	switch {
	case b < 0x80:
		return uint32(b), pos + 1, true
	case b < 0xC0:
		if pos+1 >= len(data) {
			return 0, 0, false
		}
		return uint32(b&0x3f)<<8 | uint32(data[pos+1]), pos + 2, true
	case b < 0xE0:
		if pos+3 >= len(data) {
			return 0, 0, false
		}
		return uint32(b&0x1f)<<24 | uint32(data[pos+1])<<16 | uint32(data[pos+2])<<8 | uint32(data[pos+3]), pos + 4, true
	default:
		return 0, 0, false
	}
}

func (m *clrMeta) rowOffset(table int, rid uint32) (int, bool) {
	if rid == 0 || int(rid) > int(m.rows[table]) {
		return 0, false
	}
	size := m.tableRowSize(table)
	if size <= 0 {
		return 0, false
	}
	offset := m.tableStart[table] + int(rid-1)*size
	if offset+size > m.tableEnd {
		return 0, false
	}
	return offset, true
}

func (m *clrMeta) loadTypes() error {
	if m.typesLoaded {
		return nil
	}
	m.typesLoaded = true

	count := int(m.rows[2])
	if count == 0 {
		return errors.New("CLR 元数据中没有类型")
	}
	types := make([]clrType, 0, count)
	rowSize := m.tableRowSize(2)
	strSize := m.stringSize
	typeDefOrRef := m.codedSize(2, 2, 1, 27)
	fieldIndex := m.indexSize(4)
	methodIndex := m.indexSize(6)
	for i := 0; i < count; i++ {
		offset := m.tableStart[2] + i*rowSize
		if offset+rowSize > m.tableEnd {
			return io.ErrUnexpectedEOF
		}
		nameIndex, ok := m.readID(offset+4, strSize)
		if !ok {
			return io.ErrUnexpectedEOF
		}
		namespaceIndex, ok := m.readID(offset+4+strSize, strSize)
		if !ok {
			return io.ErrUnexpectedEOF
		}
		fieldListIndex := offset + 4 + 2*strSize + typeDefOrRef
		fieldStart, ok := m.readID(fieldListIndex, fieldIndex)
		if !ok {
			return io.ErrUnexpectedEOF
		}
		methodStart, ok := m.readID(fieldListIndex+fieldIndex, methodIndex)
		if !ok {
			return io.ErrUnexpectedEOF
		}
		name, ok := m.readString(nameIndex)
		if !ok {
			return io.ErrUnexpectedEOF
		}
		namespace, ok := m.readString(namespaceIndex)
		if !ok {
			return io.ErrUnexpectedEOF
		}
		types = append(types, clrType{
			rid:         uint32(i + 1),
			namespace:   namespace,
			name:        name,
			fieldStart:  fieldStart,
			methodStart: methodStart,
		})
	}

	fieldLimit := m.rows[4] + 1
	methodLimit := m.rows[6] + 1
	for i := range types {
		fieldEnd := fieldLimit
		methodEnd := methodLimit
		if i+1 < len(types) {
			fieldEnd = types[i+1].fieldStart
			methodEnd = types[i+1].methodStart
		}
		if types[i].fieldStart == 0 || types[i].fieldStart > fieldEnd || fieldEnd > fieldLimit {
			return errors.New("CLR 字段列表索引无效")
		}
		if types[i].methodStart == 0 || types[i].methodStart > methodEnd || methodEnd > methodLimit {
			return errors.New("CLR 方法列表索引无效")
		}
		types[i].fieldEnd = fieldEnd
		types[i].methodEnd = methodEnd
	}
	m.types = types
	return nil
}

func (m *clrMeta) findType(namespace, name string) (*clrType, bool) {
	if err := m.loadTypes(); err != nil {
		return nil, false
	}
	for i := range m.types {
		if m.types[i].namespace == namespace && m.types[i].name == name {
			return &m.types[i], true
		}
	}
	return nil, false
}

func (m *clrMeta) methodOf(owner *clrType, name string) (*clrMethodDef, bool) {
	strSize := m.stringSize
	for rid := owner.methodStart; rid < owner.methodEnd; rid++ {
		offset, ok := m.rowOffset(6, rid)
		if !ok {
			return nil, false
		}
		nameIndex, ok := m.readID(offset+8, strSize)
		if !ok {
			return nil, false
		}
		methodName, ok := m.readString(nameIndex)
		if !ok {
			return nil, false
		}
		if methodName != name {
			continue
		}
		rva := binary.LittleEndian.Uint32(m.data[offset : offset+4])
		sigIndex, ok := m.readID(offset+8+strSize, m.blobSize)
		if !ok {
			return nil, false
		}
		sig, ok := m.blobAt(sigIndex)
		if !ok {
			return nil, false
		}
		params, _ := methodParamCount(sig)
		return &clrMethodDef{rid: rid, rva: rva, name: methodName, params: params, sigBlob: sig}, true
	}
	return nil, false
}

func (m *clrMeta) fieldOf(owner *clrType, name string) (*clrFieldDef, bool) {
	strSize := m.stringSize
	for rid := owner.fieldStart; rid < owner.fieldEnd; rid++ {
		offset, ok := m.rowOffset(4, rid)
		if !ok {
			return nil, false
		}
		flags := binary.LittleEndian.Uint16(m.data[offset : offset+2])
		nameIndex, ok := m.readID(offset+2, strSize)
		if !ok {
			return nil, false
		}
		fieldName, ok := m.readString(nameIndex)
		if !ok {
			return nil, false
		}
		if fieldName == name {
			return &clrFieldDef{rid: rid, flags: flags, name: fieldName}, true
		}
	}
	return nil, false
}

func (m *clrMeta) methodName(rid uint32) (string, bool) {
	offset, ok := m.rowOffset(6, rid)
	if !ok {
		return "", false
	}
	nameIndex, ok := m.readID(offset+8, m.stringSize)
	if !ok {
		return "", false
	}
	return m.readString(nameIndex)
}

func (m *clrMeta) memberRefName(rid uint32) (string, bool) {
	offset, ok := m.rowOffset(10, rid)
	if !ok {
		return "", false
	}
	classSize := m.codedSize(3, 2, 1, 26, 6, 27)
	nameIndex, ok := m.readID(offset+classSize, m.stringSize)
	if !ok {
		return "", false
	}
	return m.readString(nameIndex)
}

func methodParamCount(sig []byte) (int, bool) {
	if len(sig) == 0 {
		return 0, false
	}
	pos := 0
	convention := sig[pos]
	pos++
	if convention&0x10 != 0 {
		_, next, ok := readCLRCompressed(sig, pos)
		if !ok {
			return 0, false
		}
		pos = next
	}
	count, _, ok := readCLRCompressed(sig, pos)
	if !ok {
		return 0, false
	}
	return int(count), true
}

func (m *clrMeta) methodCode(method *clrMethodDef) ([]byte, int, bool, error) {
	if method == nil || method.rva == 0 {
		return nil, 0, false, errors.New("方法没有方法体")
	}
	bodyOffset, ok := m.image.rva(method.rva, 1)
	if !ok {
		return nil, 0, false, errors.New("无法定位方法体")
	}
	code, codeOffset, hasExtra, err := parseILBody(m.data, bodyOffset)
	if err != nil {
		return nil, 0, false, err
	}
	return code, codeOffset, hasExtra, nil
}
