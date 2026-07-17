package atos

import (
	"encoding/binary"
	"math"
	"reflect"
	"strings"
	"testing"
)

type arangeTestDescriptor struct {
	segment uint64
	address uint64
	length  uint64
}

func TestParseDebugArangesFormats(t *testing.T) {
	littleEndianData := append(
		encodeArangeSet(binary.LittleEndian, false, 0x11223344, 8, 0, []arangeTestDescriptor{
			{address: 0x2000, length: 0x20},
			{address: 0x1000, length: 0x10},
		}),
		encodeArangeSet(binary.LittleEndian, false, 0x55667788, 4, 0, []arangeTestDescriptor{
			{address: 0x3000, length: 0x30},
		})...,
	)
	ranges, err := ParseDebugAranges(newBytesReader(littleEndianData), binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	want := []*DwarfArange{
		{CUOffset: 0x11223344, LowPC: 0x1000, HighPC: 0x1010},
		{CUOffset: 0x11223344, LowPC: 0x2000, HighPC: 0x2020},
		{CUOffset: 0x55667788, LowPC: 0x3000, HighPC: 0x3030},
	}
	if !reflect.DeepEqual(ranges, want) {
		t.Fatalf("ranges = %#v, want %#v", ranges, want)
	}

	bigEndianData := encodeArangeSet(binary.BigEndian, true, 0x0102030405060708, 4, 2, []arangeTestDescriptor{
		{segment: 7, address: 0x12345678, length: 0x100},
	})
	// Omitting the explicit byte order exercises the backwards-compatible
	// version-2 byte-order inference path.
	ranges, err = ParseDebugAranges(newBytesReader(bigEndianData))
	if err != nil {
		t.Fatal(err)
	}
	want = []*DwarfArange{
		{CUOffset: 0x0102030405060708, SegmentSelector: 7, LowPC: 0x12345678, HighPC: 0x12345778},
	}
	if !reflect.DeepEqual(ranges, want) {
		t.Fatalf("ranges = %#v, want %#v", ranges, want)
	}

	oddWidthData := encodeArangeSet(binary.LittleEndian, false, 0x1234, 3, 1, []arangeTestDescriptor{
		{segment: 3, address: 0x123456, length: 0x20},
	})
	ranges, err = ParseDebugAranges(newBytesReader(oddWidthData), binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	want = []*DwarfArange{
		{CUOffset: 0x1234, SegmentSelector: 3, LowPC: 0x123456, HighPC: 0x123476},
	}
	if !reflect.DeepEqual(ranges, want) {
		t.Fatalf("ranges = %#v, want %#v", ranges, want)
	}
}

func TestParseDebugArangesRejectsMalformedData(t *testing.T) {
	valid := encodeArangeSet(binary.LittleEndian, false, 0x100, 8, 0, []arangeTestDescriptor{
		{address: 0x1000, length: 0x20},
	})
	tests := []struct {
		name    string
		data    func() []byte
		wantErr string
	}{
		{
			name: "truncated initial length",
			data: func() []byte {
				return []byte{1, 2, 3}
			},
			wantErr: "truncated __debug_aranges initial length",
		},
		{
			name: "reserved initial length",
			data: func() []byte {
				data := cloneBytes(valid)
				binary.LittleEndian.PutUint32(data[:4], 0xfffffff0)
				return data
			},
			wantErr: "reserved DWARF initial length",
		},
		{
			name: "declared length exceeds section",
			data: func() []byte {
				data := cloneBytes(valid)
				binary.LittleEndian.PutUint32(data[:4], uint32(len(data)+100))
				return data
			},
			wantErr: "exceeding the remaining section size",
		},
		{
			name: "unsupported address size",
			data: func() []byte {
				data := cloneBytes(valid)
				data[10] = 9
				return data
			},
			wantErr: "unsupported address size 9",
		},
		{
			name: "missing terminator",
			data: func() []byte {
				data := cloneBytes(valid[:len(valid)-16])
				binary.LittleEndian.PutUint32(data[:4], uint32(len(data)-4))
				return data
			},
			wantErr: "not terminated by a null tuple",
		},
		{
			name: "premature terminator",
			data: func() []byte {
				data := cloneBytes(valid)
				for i := 16; i < 32; i++ {
					data[i] = 0
				}
				return data
			},
			wantErr: "premature terminating tuple",
		},
		{
			name: "zero length descriptor",
			data: func() []byte {
				data := cloneBytes(valid)
				for i := 24; i < 32; i++ {
					data[i] = 0
				}
				return data
			},
			wantErr: "zero-length address range",
		},
		{
			name: "range overflow",
			data: func() []byte {
				return encodeArangeSet(binary.LittleEndian, false, 0x100, 8, 0, []arangeTestDescriptor{
					{address: math.MaxUint64 - 1, length: 4},
				})
			},
			wantErr: "address range overflows",
		},
		{
			name: "misaligned set length",
			data: func() []byte {
				data := cloneBytes(valid)
				binary.LittleEndian.PutUint32(data[:4], uint32(len(data)-5))
				return data
			},
			wantErr: "not aligned to tuple size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDebugAranges(newBytesReader(tt.data()), binary.LittleEndian)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestParseDebugArangesFixtures(t *testing.T) {
	tests := []struct {
		name      string
		file      string
		arch      Arch
		wantCount int
		wantFirst [2]uint64
		wantCUOff uint64
	}{
		{
			name:      "App",
			file:      testDSYM,
			arch:      ArchARM64,
			wantCount: 101,
			wantFirst: [2]uint64{0x100003978, 0x100003e28},
			wantCUOff: 0xd293d,
		},
		{
			name:      "AFNetworking",
			file:      "testdata/AFNetworking.framework.dSYM/Contents/Resources/DWARF/AFNetworking",
			arch:      ArchARM64,
			wantCount: 15,
		},
		{
			name:      "a.out",
			file:      "testdata/a.out.dSYM/Contents/Resources/DWARF/a.out",
			arch:      ArchARM64,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mf, err := OpenMachO(tt.file, tt.arch)
			if err != nil {
				t.Fatal(err)
			}
			defer mf.Close()

			var data []byte
			for _, section := range mf.Sections {
				if section.Name == "__debug_aranges" || section.Name == "__zdebug_aranges" {
					data, err = sectionData(section)
					if err != nil {
						t.Fatal(err)
					}
					break
				}
			}
			if len(data) == 0 {
				t.Fatal("fixture has no debug_aranges data")
			}
			ranges, err := ParseDebugAranges(newBytesReader(data), mf.ByteOrder)
			if err != nil {
				t.Fatal(err)
			}
			if len(ranges) != tt.wantCount {
				t.Fatalf("range count = %d, want %d", len(ranges), tt.wantCount)
			}
			if tt.wantFirst != [2]uint64{} {
				first := ranges[0]
				if first.LowPC != tt.wantFirst[0] || first.HighPC != tt.wantFirst[1] || first.CUOffset != tt.wantCUOff {
					t.Fatalf("first range = %#v, want CU 0x%x [0x%x, 0x%x)", first, tt.wantCUOff, tt.wantFirst[0], tt.wantFirst[1])
				}
			}
		})
	}
}

func encodeArangeSet(
	byteOrder binary.ByteOrder,
	dwarf64 bool,
	cuOffset uint64,
	addressSize int,
	segmentSize int,
	descriptors []arangeTestDescriptor,
) []byte {
	lengthFieldSize := 4
	offsetSize := 4
	if dwarf64 {
		lengthFieldSize = 12
		offsetSize = 8
	}
	data := make([]byte, lengthFieldSize)
	if dwarf64 {
		for i := 0; i < 4; i++ {
			data[i] = 0xff
		}
	}
	data = appendArangeUint(data, 2, 2, byteOrder)
	data = appendArangeUint(data, cuOffset, offsetSize, byteOrder)
	data = append(data, byte(addressSize), byte(segmentSize))

	tupleSize := segmentSize + addressSize*2
	for len(data)%tupleSize != 0 {
		data = append(data, 0xff)
	}
	for _, descriptor := range descriptors {
		data = appendArangeUint(data, descriptor.segment, segmentSize, byteOrder)
		data = appendArangeUint(data, descriptor.address, addressSize, byteOrder)
		data = appendArangeUint(data, descriptor.length, addressSize, byteOrder)
	}
	data = appendArangeUint(data, 0, segmentSize, byteOrder)
	data = appendArangeUint(data, 0, addressSize, byteOrder)
	data = appendArangeUint(data, 0, addressSize, byteOrder)

	unitLength := uint64(len(data) - lengthFieldSize)
	if dwarf64 {
		byteOrder.PutUint64(data[4:12], unitLength)
	} else {
		byteOrder.PutUint32(data[:4], uint32(unitLength))
	}
	return data
}

func appendArangeUint(dst []byte, value uint64, size int, byteOrder binary.ByteOrder) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, size)...)
	switch size {
	case 0:
	case 1:
		dst[start] = byte(value)
	case 2:
		byteOrder.PutUint16(dst[start:], uint16(value))
	case 4:
		byteOrder.PutUint32(dst[start:], uint32(value))
	case 8:
		byteOrder.PutUint64(dst[start:], value)
	default:
		var encoded [8]byte
		byteOrder.PutUint64(encoded[:], value)
		var probe [2]byte
		byteOrder.PutUint16(probe[:], 0x0102)
		if probe == [2]byte{0x02, 0x01} {
			copy(dst[start:], encoded[:size])
		} else {
			copy(dst[start:], encoded[len(encoded)-size:])
		}
	}
	return dst
}

func cloneBytes(data []byte) []byte {
	return append([]byte(nil), data...)
}
