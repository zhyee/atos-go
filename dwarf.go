package atos

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

type DwarfArange struct {
	CUOffset        uint64 // offset to .debug_info
	SegmentSelector uint64 // usually is 0 for modern system
	LowPC           uint64
	HighPC          uint64
}

func ParseDebugAranges(br *bytesReader, byteOrders ...binary.ByteOrder) ([]*DwarfArange, error) {
	if br == nil {
		return nil, fmt.Errorf("unable to parse a nil __debug_aranges reader")
	}
	if len(byteOrders) > 1 {
		return nil, fmt.Errorf("expected at most one byte order, got %d", len(byteOrders))
	}

	var byteOrder binary.ByteOrder
	if len(byteOrders) == 1 {
		byteOrder = byteOrders[0]
		if byteOrder == nil {
			return nil, fmt.Errorf("unable to parse __debug_aranges with a nil byte order")
		}
	}

	var aranges []*DwarfArange
	for br.Len() > 0 {
		setStart := br.Offset()
		if br.Len() < 4 {
			return aranges, fmt.Errorf("truncated __debug_aranges initial length at offset 0x%x", setStart)
		}
		if byteOrder == nil {
			var err error
			byteOrder, err = inferArangesByteOrder(br.data, setStart)
			if err != nil {
				return aranges, err
			}
		}

		initialLengthBytes, _ := br.Bytes(4)
		initialLength := byteOrder.Uint32(initialLengthBytes)
		lengthFieldSize := 4
		offsetSize := 4
		var unitLength uint64
		switch {
		case initialLength == 0xffffffff:
			lengthFieldSize = 12
			offsetSize = 8
			lengthBytes, err := readArangesBytes(br, 8, len(br.data))
			if err != nil {
				return aranges, fmt.Errorf("truncated DWARF64 initial length at offset 0x%x: %w", setStart, err)
			}
			unitLength = byteOrder.Uint64(lengthBytes)
		case initialLength >= 0xfffffff0:
			return aranges, fmt.Errorf("reserved DWARF initial length 0x%x at offset 0x%x", initialLength, setStart)
		default:
			unitLength = uint64(initialLength)
		}
		if unitLength == 0 {
			return aranges, fmt.Errorf("zero-length address range table at offset 0x%x", setStart)
		}

		contentStart := br.Offset()
		if unitLength > uint64(len(br.data)-contentStart) {
			return aranges, fmt.Errorf(
				"address range table at offset 0x%x has length 0x%x exceeding the remaining section size 0x%x",
				setStart, unitLength, len(br.data)-contentStart,
			)
		}
		setEnd := contentStart + int(unitLength)

		versionBytes, err := readArangesBytes(br, 2, setEnd)
		if err != nil {
			return aranges, fmt.Errorf("unable to read address range version at offset 0x%x: %w", setStart, err)
		}
		version := byteOrder.Uint16(versionBytes)
		if version != 2 {
			return aranges, fmt.Errorf("unsupported __debug_aranges version %d at offset 0x%x", version, setStart)
		}

		debugInfoOffset, err := readArangesUint(br, offsetSize, byteOrder, setEnd)
		if err != nil {
			return aranges, fmt.Errorf("unable to read debug_info offset at 0x%x: %w", setStart, err)
		}
		addressSizeByte, err := readArangesBytes(br, 1, setEnd)
		if err != nil {
			return aranges, fmt.Errorf("unable to read address size at 0x%x: %w", setStart, err)
		}
		segmentSizeByte, err := readArangesBytes(br, 1, setEnd)
		if err != nil {
			return aranges, fmt.Errorf("unable to read segment selector size at 0x%x: %w", setStart, err)
		}
		addressSize := int(addressSizeByte[0])
		segmentSize := int(segmentSizeByte[0])
		if !supportedArangesUintSize(addressSize, false) {
			return aranges, fmt.Errorf("unsupported address size %d at offset 0x%x", addressSize, setStart)
		}
		if !supportedArangesUintSize(segmentSize, true) {
			return aranges, fmt.Errorf("unsupported segment selector size %d at offset 0x%x", segmentSize, setStart)
		}

		tupleSize := segmentSize + addressSize*2
		fullLength := lengthFieldSize + int(unitLength)
		if fullLength%tupleSize != 0 {
			return aranges, fmt.Errorf(
				"address range table at offset 0x%x has size 0x%x not aligned to tuple size 0x%x",
				setStart, fullLength, tupleSize,
			)
		}
		headerSize := br.Offset() - setStart
		padding := (tupleSize - headerSize%tupleSize) % tupleSize
		if padding > setEnd-br.Offset() {
			return aranges, fmt.Errorf("address range table at offset 0x%x is too short for header padding", setStart)
		}
		if _, err := br.Skip(padding); err != nil {
			return aranges, fmt.Errorf("unable to skip address range header padding at 0x%x: %w", setStart, err)
		}
		if setEnd-br.Offset() < tupleSize {
			return aranges, fmt.Errorf("address range table at offset 0x%x has no room for a terminating tuple", setStart)
		}

		terminated := false
		for br.Offset() < setEnd {
			entryOffset := br.Offset()
			segment, err := readArangesUint(br, segmentSize, byteOrder, setEnd)
			if err != nil {
				return aranges, fmt.Errorf("unable to read segment selector at 0x%x: %w", entryOffset, err)
			}
			address, err := readArangesUint(br, addressSize, byteOrder, setEnd)
			if err != nil {
				return aranges, fmt.Errorf("unable to read range address at 0x%x: %w", entryOffset, err)
			}
			length, err := readArangesUint(br, addressSize, byteOrder, setEnd)
			if err != nil {
				return aranges, fmt.Errorf("unable to read range length at 0x%x: %w", entryOffset, err)
			}

			if segment == 0 && address == 0 && length == 0 {
				if br.Offset() != setEnd {
					return aranges, fmt.Errorf("premature terminating tuple at offset 0x%x", entryOffset)
				}
				terminated = true
				break
			}
			if length == 0 {
				return aranges, fmt.Errorf("zero-length address range at offset 0x%x", entryOffset)
			}
			if address > ^uint64(0)-length {
				return aranges, fmt.Errorf("address range overflows at offset 0x%x", entryOffset)
			}
			aranges = append(aranges, &DwarfArange{
				CUOffset:        debugInfoOffset,
				SegmentSelector: segment,
				LowPC:           address,
				HighPC:          address + length,
			})
		}
		if !terminated {
			return aranges, fmt.Errorf("address range table at offset 0x%x is not terminated by a null tuple", setStart)
		}
	}

	sortDwarfAranges(aranges)

	return aranges, nil
}

func sortDwarfAranges(aranges []*DwarfArange) {
	sort.SliceStable(aranges, func(i, j int) bool {
		if aranges[i].SegmentSelector != aranges[j].SegmentSelector {
			return aranges[i].SegmentSelector < aranges[j].SegmentSelector
		}
		if aranges[i].LowPC != aranges[j].LowPC {
			return aranges[i].LowPC < aranges[j].LowPC
		}
		if aranges[i].HighPC != aranges[j].HighPC {
			return aranges[i].HighPC < aranges[j].HighPC
		}
		return aranges[i].CUOffset < aranges[j].CUOffset
	})
}

func inferArangesByteOrder(data []byte, setStart int) (binary.ByteOrder, error) {
	if setStart < 0 || setStart+4 > len(data) {
		return nil, fmt.Errorf("truncated __debug_aranges initial length at offset 0x%x", setStart)
	}
	versionOffset := setStart + 4
	if data[setStart] == 0xff && data[setStart+1] == 0xff && data[setStart+2] == 0xff && data[setStart+3] == 0xff {
		versionOffset += 8
	}
	if versionOffset+2 > len(data) {
		return nil, fmt.Errorf("truncated __debug_aranges version at offset 0x%x", setStart)
	}
	switch {
	case data[versionOffset] == 2 && data[versionOffset+1] == 0:
		return binary.LittleEndian, nil
	case data[versionOffset] == 0 && data[versionOffset+1] == 2:
		return binary.BigEndian, nil
	default:
		return nil, fmt.Errorf("unable to infer __debug_aranges byte order at offset 0x%x", setStart)
	}
}

func supportedArangesUintSize(size int, allowZero bool) bool {
	if allowZero && size == 0 {
		return true
	}
	return size >= 1 && size <= 8
}

func readArangesBytes(br *bytesReader, size, setEnd int) ([]byte, error) {
	if size < 0 || br.Offset() > setEnd || size > setEnd-br.Offset() {
		return nil, io.ErrUnexpectedEOF
	}
	return br.Bytes(size)
}

func readArangesUint(br *bytesReader, size int, byteOrder binary.ByteOrder, setEnd int) (uint64, error) {
	if size == 0 {
		return 0, nil
	}
	b, err := readArangesBytes(br, size, setEnd)
	if err != nil {
		return 0, err
	}
	switch size {
	case 1:
		return uint64(b[0]), nil
	case 2:
		return uint64(byteOrder.Uint16(b)), nil
	case 4:
		return uint64(byteOrder.Uint32(b)), nil
	case 8:
		return byteOrder.Uint64(b), nil
	default:
		var padded [8]byte
		var probe [2]byte
		byteOrder.PutUint16(probe[:], 0x0102)
		switch probe {
		case [2]byte{0x02, 0x01}:
			copy(padded[:], b)
		case [2]byte{0x01, 0x02}:
			copy(padded[len(padded)-len(b):], b)
		default:
			return 0, fmt.Errorf("unsupported byte order %q", byteOrder.String())
		}
		return byteOrder.Uint64(padded[:]), nil
	}
}

// GetCUBodyOffset gets the .debug_info CU body offset by the CU header offset
func GetCUBodyOffset(cuOffset uint64, debugInfoReader *bytesReader) (int, error) {
	r := debugInfoReader
	if _, err := r.Seek(int64(cuOffset), io.SeekStart); err != nil {
		return 0, fmt.Errorf("unable to seek to offset: %w", err)
	}
	isDWARF64 := false
	first4B, err := r.Bytes(4)
	if err != nil {
		return 0, fmt.Errorf("unable to read the CU first 4 bytes: %w", err)
	}
	if first4B[0] == 0xff && first4B[1] == 0xff && first4B[2] == 0xff && first4B[3] == 0xff {
		_, err = r.Skip(8) // 64-bit data length
		if err != nil {
			return 0, fmt.Errorf("unable to read the CU 8 length bytes: %w", err)
		}
		isDWARF64 = true
	}

	verBytes, err := r.Bytes(2)
	if err != nil {
		return 0, fmt.Errorf("unable to read the CU 2 version bytes: %w", err)
	}

	var bytesOrder binary.ByteOrder = binary.LittleEndian
	if verBytes[0] == 0 {
		bytesOrder = binary.BigEndian
	}

	version := bytesOrder.Uint16(verBytes)

	if version < 2 || version > 5 {
		return 0, fmt.Errorf("unsupported DWARF version: %d", version)
	}

	var (
		unitType  uint8
		skipBytes int
	)

	if version >= 5 {
		unitType, err = r.ReadByte() // DWARF 5 unit type
		if err != nil {
			return 0, fmt.Errorf("unable to read the DWARF type: %w", err)
		}
		// address size
		skipBytes++
	}

	// Abbrev offset
	if isDWARF64 {
		skipBytes += 8
	} else {
		skipBytes += 4
	}

	if version < 5 {
		// address size
		skipBytes++
	}

	switch unitType {
	case 0x04, 0x05:
		// unit ID
		skipBytes += 8
	case 0x02, 0x06:
		// type signature
		skipBytes += 8

		// type offset
		if isDWARF64 {
			skipBytes += 8
		} else {
			skipBytes += 4
		}
	}

	if _, err = r.Skip(skipBytes); err != nil {
		return 0, fmt.Errorf("unable to skip the CU %d bytes: %w", skipBytes, err)
	}

	return r.Offset(), nil
}
