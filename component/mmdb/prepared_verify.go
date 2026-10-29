package mmdb

import (
	"bytes"
	"errors"
	"math/big"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

const (
	preparedMaxMetadata     = 128 << 10
	preparedMaxRecordValues = 65536
	preparedMaxRecordBytes  = 1 << 20
)

var preparedMarker = []byte("\xab\xcd\xefMaxMind.com")

// Reader.Verify explicitly imposes stronger flat-layout requirements than
// MMDB: every sequential top-level data value must be indexed by the tree.
// MMDB permits shared targets and targets inside another record, and optional
// description metadata. Validate the reachable graph instead, with the pinned
// reader's own decoder. Never re-encode or change the original resource bytes.
// Format: https://maxmind.github.io/MaxMind-DB/
func openPreparedReader(buffer []byte) (reader *maxminddb.Reader, err error) {
	defer func() {
		if recover() != nil {
			if reader != nil {
				_ = reader.Close()
			}
			reader, err = nil, errors.New("invalid prepared MMDB")
		}
	}()
	marker := bytes.LastIndex(buffer, preparedMarker)
	if marker < 0 {
		return nil, errors.New("invalid prepared MMDB metadata")
	}
	metadataBytes := buffer[marker+len(preparedMarker):]
	if len(metadataBytes) == 0 || len(metadataBytes) > preparedMaxMetadata {
		return nil, errors.New("invalid prepared MMDB metadata bounds")
	}
	// Decode untrusted metadata through the pinned deserializer first. A small
	// fixed reader exposes it as data, avoiding reflection's container allocation
	// before operation/byte budgets have checked shared-pointer expansion.
	metadataReader, err := metadataDecoder(metadataBytes)
	if err != nil {
		return nil, err
	}
	defer metadataReader.Close()
	metadataBudget := preparedBudget{values: 8192, bytes: preparedMaxMetadata}
	visitor := preparedVisitor{data: metadataBytes, budget: &metadataBudget}
	if err = metadataReader.Decode(0, &visitor); err != nil || visitor.root != 'm' {
		return nil, errors.New("invalid prepared MMDB metadata record")
	}
	var metadata maxminddb.Metadata
	if err = metadataReader.Decode(0, &metadata); err != nil {
		return nil, errors.New("invalid prepared MMDB metadata fields")
	}
	if metadata.BinaryFormatMajorVersion != 2 || metadata.BinaryFormatMinorVersion != 0 || metadata.DatabaseType == "" || (metadata.IPVersion != 4 && metadata.IPVersion != 6) || (metadata.RecordSize != 24 && metadata.RecordSize != 28 && metadata.RecordSize != 32) || metadata.NodeCount == 0 {
		return nil, errors.New("unsupported prepared MMDB metadata")
	}
	nodeBytes := metadata.RecordSize / 4
	if metadata.NodeCount > uint(marker)/nodeBytes {
		return nil, errors.New("invalid prepared MMDB node count")
	}
	treeSize := uint64(metadata.NodeCount) * uint64(nodeBytes)
	if treeSize+16 > uint64(marker) {
		return nil, errors.New("invalid prepared MMDB search tree bounds")
	}
	for _, value := range buffer[treeSize : treeSize+16] {
		if value != 0 {
			return nil, errors.New("invalid prepared MMDB separator")
		}
	}
	reader, err = maxminddb.FromBytes(buffer)
	if err != nil {
		return nil, errors.New("invalid prepared MMDB reader")
	}
	verifier := preparedTree{
		reader: reader, tree: buffer[:treeSize], data: buffer[treeSize+16 : marker],
		heights: make([]uint8, metadata.NodeCount), records: map[uint32]bool{},
	}
	_, err = verifier.node(0, 0)
	if err != nil {
		_ = reader.Close()
		reader = nil
	}
	return reader, err
}

// A known metadata section permits the original decoder to inspect an
// arbitrary, bounded metadata value. This temporary reader never reaches
// routing or publication and never changes the original bytes/metadata.
func metadataDecoder(data []byte) (*maxminddb.Reader, error) {
	buffer := append([]byte{0, 0, 17, 0, 0, 17}, make([]byte, 16)...)
	buffer = append(buffer, data...)
	buffer = append(buffer, preparedMarker...)
	buffer = append(buffer, 0xe6)
	str := func(value string) { buffer = append(buffer, byte(0x40|len(value))); buffer = append(buffer, value...) }
	number := func(key string, value byte) { str(key); buffer = append(buffer, 0xc1, value) }
	number("node_count", 1)
	number("record_size", 24)
	number("ip_version", 4)
	number("binary_format_major_version", 2)
	number("binary_format_minor_version", 0)
	str("database_type")
	str("prepared-metadata")
	return maxminddb.FromBytes(buffer)
}

type preparedTree struct {
	reader  *maxminddb.Reader
	tree    []byte
	data    []byte
	heights []uint8 // 0 unvisited, 255 active; otherwise longest remaining depth.
	records map[uint32]bool
}

func (v *preparedTree) node(pointer uint32, depth uint) (uint8, error) {
	count := uint32(v.reader.Metadata.NodeCount)
	if pointer == count {
		return 0, nil
	}
	if pointer > count {
		if pointer < count+16 {
			return 0, errors.New("invalid prepared MMDB data pointer")
		}
		offset := pointer - count - 16
		if uint64(offset) >= uint64(len(v.data)) {
			return 0, errors.New("invalid prepared MMDB data pointer bounds")
		}
		if v.records[offset] {
			return 0, nil
		}
		budget := preparedBudget{values: preparedMaxRecordValues, bytes: preparedMaxRecordBytes}
		visitor := preparedVisitor{data: v.data, budget: &budget}
		if err := v.reader.Decode(uintptr(offset), &visitor); err != nil {
			return 0, errors.New("invalid prepared MMDB reachable record")
		}
		if err := verifyPreparedRecord(v.reader, uintptr(offset), &visitor); err != nil {
			return 0, err
		}
		v.records[offset] = true
		return 0, nil
	}
	width := uint(32)
	if v.reader.Metadata.IPVersion == 6 {
		width = 128
	}
	if depth >= width || v.heights[pointer] == 255 {
		return 0, errors.New("invalid prepared MMDB tree depth or cycle")
	}
	if height := v.heights[pointer]; height > 0 {
		if uint(height)+depth > width {
			return 0, errors.New("invalid prepared MMDB tree depth")
		}
		return height, nil
	}
	v.heights[pointer] = 255
	offset := int(pointer) * int(v.reader.Metadata.RecordSize/4)
	left, right := preparedNode(v.tree[offset:], v.reader.Metadata.RecordSize)
	a, err := v.node(left, depth+1)
	if err != nil {
		return 0, err
	}
	b, err := v.node(right, depth+1)
	if err != nil {
		return 0, err
	}
	if b > a {
		a = b
	}
	if uint(a)+1+depth > width {
		return 0, errors.New("invalid prepared MMDB tree depth")
	}
	v.heights[pointer] = a + 1
	return a + 1, nil
}

func preparedNode(data []byte, size uint) (uint32, uint32) {
	three := func(b []byte) uint32 { return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]) }
	switch size {
	case 24:
		return three(data), three(data[3:])
	case 28:
		return uint32(data[3]&0xf0)<<20 | three(data), uint32(data[3]&0x0f)<<24 | three(data[4:])
	default:
		return uint32(data[0])<<24 | three(data[1:]), uint32(data[4])<<24 | three(data[5:])
	}
}

func verifyPreparedRecord(reader *maxminddb.Reader, offset uintptr, visitor *preparedVisitor) error {
	var result any
	switch reader.Metadata.DatabaseType {
	case "sing-geoip":
		if visitor.root != 's' {
			return errors.New("invalid prepared country record")
		}
		return nil
	case "Meta-geoip0":
		if visitor.root != 's' && (visitor.root != 'a' || !visitor.flatStrings) {
			return errors.New("invalid prepared country record")
		}
		return nil
	case "GeoLite2-Country", "GeoIP2-Country", "DBIP-Country-Lite (compat=GeoLite2-Country)":
		result = &geoip2Country{}
	case "GeoLite2-ASN", "DBIP-ASN-Lite (compat=GeoLite2-ASN)":
		result = &GeoLite2{}
	case "ipinfo generic_asn_free.mmdb":
		var value IPInfo
		if err := reader.Decode(offset, &value); err != nil || !strings.HasPrefix(value.ASN, "AS") {
			return errors.New("invalid prepared ASN record")
		}
		return nil
	default:
		return errors.New("unsupported prepared database type")
	}
	if visitor.root != 'm' || reader.Decode(offset, result) != nil {
		return errors.New("invalid prepared reachable record type")
	}
	return nil
}

type preparedBudget struct{ values, bytes int }
type preparedVisitor struct {
	data                        []byte
	budget                      *preparedBudget
	values, decodedBytes, depth int
	root                        byte
	flatStrings                 bool
}

// The original decoder calls ShouldSkip before each value and dereference.
// Do not skip: every reachable field must decode. Bounded callbacks prevent a
// tiny shared-pointer DAG from expanding into huge reflection allocations.
func (v *preparedVisitor) ShouldSkip(offset uintptr) (bool, error) {
	v.values++
	v.budget.values--
	if v.values > preparedMaxRecordValues || v.budget.values < 0 || offset >= uintptr(len(v.data)) {
		return false, errors.New("prepared MMDB decode budget exceeded")
	}
	return false, nil
}
func (v *preparedVisitor) value(kind byte, size int) error {
	if v.root == 0 {
		v.root, v.flatStrings = kind, true
	} else if v.root == 'a' && (kind != 's' || v.depth != 1) {
		v.flatStrings = false
	}
	v.decodedBytes += size
	v.budget.bytes -= size
	if v.decodedBytes > preparedMaxRecordBytes || v.budget.bytes < 0 {
		return errors.New("prepared MMDB decoded byte budget exceeded")
	}
	return nil
}
func (v *preparedVisitor) container(kind byte, size uint) error {
	if size > 4096 || v.depth >= 64 {
		return errors.New("prepared MMDB container budget exceeded")
	}
	if err := v.value(kind, 0); err != nil {
		return err
	}
	v.depth++
	return nil
}
func (v *preparedVisitor) StartSlice(size uint) error { return v.container('a', size) }
func (v *preparedVisitor) StartMap(size uint) error   { return v.container('m', size) }
func (v *preparedVisitor) End() error                 { v.depth--; return nil }
func (v *preparedVisitor) String(value string) error  { return v.value('s', len(value)) }
func (v *preparedVisitor) Bytes(value []byte) error   { return v.value('b', len(value)) }
func (v *preparedVisitor) Float64(float64) error      { return v.value('n', 8) }
func (v *preparedVisitor) Float32(float32) error      { return v.value('n', 4) }
func (v *preparedVisitor) Uint16(uint16) error        { return v.value('n', 2) }
func (v *preparedVisitor) Uint32(uint32) error        { return v.value('n', 4) }
func (v *preparedVisitor) Int32(int32) error          { return v.value('n', 4) }
func (v *preparedVisitor) Uint64(uint64) error        { return v.value('n', 8) }
func (v *preparedVisitor) Uint128(*big.Int) error     { return v.value('n', 16) }
func (v *preparedVisitor) Bool(bool) error            { return v.value('n', 1) }
