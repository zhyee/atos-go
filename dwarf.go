package atos

import (
	"encoding/binary"
	"errors"
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

func ParseDebugAranges(br *bytesReader) ([]*DwarfArange, error) {
	if br.Len() < 6 {
		return nil, errors.New("a DWARF CU is at least 6 bytes long")
	}

	var (
		aranges             []*DwarfArange
		isDWARF64           bool
		byteOrder           binary.ByteOrder
		bodyLength          uint64
		version             uint16
		debugInfoOffset     uint64
		addressSize         int
		segmentSelectorSize int
	)

	for br.Len() > 0 {
		startOffset := br.Offset()
		isDWARF64 = false

		unitLen, err := br.Bytes(4)
		if err != nil {
			return aranges, err
		}

		if unitLen[0] == 0xff && unitLen[1] == 0xff && unitLen[2] == 0xff && unitLen[3] == 0xff {
			isDWARF64 = true
			unitLen, err = br.Bytes(8)
			if err != nil {
				return aranges, err
			}
		}

		versionBytes, err := br.Bytes(2) // 2 bytes version
		if err != nil {
			return aranges, err
		}
		if versionBytes[0] > 0 {
			byteOrder = binary.LittleEndian
		} else {
			byteOrder = binary.BigEndian
		}

		if isDWARF64 {
			bodyLength = byteOrder.Uint64(unitLen)
		} else {
			bodyLength = uint64(byteOrder.Uint32(unitLen))
		}

		if bodyLength == 0 {
			continue // current unit is finish
		}

		version = byteOrder.Uint16(versionBytes)
		if version != 2 {
			return aranges, fmt.Errorf("only support DWARF __debug_aranges version 2 now, but got %d", version)
		}

		if isDWARF64 {
			debugOff, err := br.Bytes(8)
			if err != nil {
				return aranges, err
			}
			debugInfoOffset = byteOrder.Uint64(debugOff)
		} else {
			debugOff, err := br.Bytes(4)
			if err != nil {
				return aranges, err
			}
			debugInfoOffset = uint64(byteOrder.Uint32(debugOff))
		}
		addSize, err := br.ReadByte()
		if err != nil {
			return aranges, err
		}
		addressSize = int(addSize)

		selectorSize, err := br.ReadByte()
		if err != nil {
			return aranges, err
		}
		segmentSelectorSize = int(selectorSize)

		tupleSize := segmentSelectorSize + addressSize*2

		// padding to multi of tupleSize
		if remain := (br.Offset() - startOffset) % tupleSize; remain != 0 {
			if _, err = br.Skip(tupleSize - remain); err != nil {
				return aranges, err
			}
		}

		for {
			var segment, address, length uint64
			if segmentSelectorSize > 0 {
				ss, err := br.Bytes(segmentSelectorSize)
				if err != nil {
					return aranges, err
				}
				switch segmentSelectorSize {
				case 1:
					segment = uint64(ss[0])
				case 2:
					segment = uint64(byteOrder.Uint16(ss))
				case 4:
					segment = uint64(byteOrder.Uint32(ss))
				case 8:
					segment = byteOrder.Uint64(ss)
				}
			}
			addr, err := br.Bytes(addressSize * 2)
			if err != nil {
				return aranges, err
			}
			if addressSize == 4 {
				address = uint64(byteOrder.Uint32(addr[:4]))
				length = uint64(byteOrder.Uint32(addr[4:]))
			} else {
				address = byteOrder.Uint64(addr[:8])
				length = byteOrder.Uint64(addr[8:])
			}

			if segment == 0 && address == 0 && length == 0 {
				break // mark current CU is ended
			}

			aranges = append(aranges, &DwarfArange{
				CUOffset:        debugInfoOffset,
				SegmentSelector: segment,
				LowPC:           address,
				HighPC:          address + length,
			})
		}
	}

	sort.Slice(aranges, func(i, j int) bool {
		return aranges[i].LowPC < aranges[j].LowPC
	})

	return aranges, nil
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
		_, err = r.Skip(8) // 64 bit data length
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
