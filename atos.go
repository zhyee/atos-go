package atos

import (
	"bytes"
	"compress/zlib"
	"debug/dwarf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"go.uber.org/zap"
)

const cpuArch64 = 0x01000000

// Log is the internal logger, the default is a no-op one,
// replace it with your custom *zap.SugaredLogger like below to enable it
//
// Log = zap.New(zapcore.NewCore(
// zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
// os.Stderr,
// zapcore.DebugLevel)).Sugar()
var Log = zap.NewNop().Sugar()

// Mach-O fat-arch cpu subtype definitions, see: https://llvm.org/doxygen/BinaryFormat_2MachO_8h_source.html for details
const (
	CpuSubTypeI386All  = 0x03
	CpuSubTypeX8664All = 0x03
	CpuSubTypeX8664H   = 0x08 // Intel Haswell

	CpuSubTypeArmAll = 0x00
	CpuSubTypeArmV6  = 0x06
	CpuSubTypeArmV7  = 0x09
	CpuSubTypeArmV7s = 0x0b

	CpuSubTypeArm64All = 0x00
	CpuSubTypeArm64V8  = 0x01
	CpuSubTypeArm64E   = 0x02 // Apple Silicon only
)

type SubProgram struct {
	PCRanges [][2]uint64
	Name     string
}

type Arch struct {
	Cpu    macho.Cpu
	SubCpu uint32
}

var (
	ArchI386   = Arch{Cpu: macho.Cpu386, SubCpu: CpuSubTypeI386All}
	ArchX64    = Arch{Cpu: macho.CpuAmd64, SubCpu: CpuSubTypeX8664All}
	ArchX64h   = Arch{Cpu: macho.CpuAmd64, SubCpu: CpuSubTypeX8664H}
	ArchARM    = Arch{Cpu: macho.CpuArm, SubCpu: CpuSubTypeArmAll}
	ArchARMv6  = Arch{Cpu: macho.CpuArm, SubCpu: CpuSubTypeArmV6}
	ArchARMv7  = Arch{Cpu: macho.CpuArm, SubCpu: CpuSubTypeArmV7}
	ArchARMv7s = Arch{Cpu: macho.CpuArm, SubCpu: CpuSubTypeArmV7s}
	ArchARM64  = Arch{Cpu: macho.CpuArm64, SubCpu: CpuSubTypeArm64All}
	ArchARM64e = Arch{Cpu: macho.CpuArm64, SubCpu: CpuSubTypeArm64E}
)

var archSet = map[string]Arch{
	"i386":    ArchI386,
	"x86":     ArchI386,
	"x86_64":  ArchX64,
	"amd64":   ArchX64,
	"x64":     ArchX64,
	"x86_64h": ArchX64h,
	"arm":     ArchARM,
	"armv6":   ArchARMv6,
	"armv7":   ArchARMv7,
	"armv7s":  ArchARMv7s,
	"arm64":   ArchARM64,
	"arm64e":  ArchARM64e,
}

func ParseArch(arch string) (Arch, error) {
	arch = strings.ToLower(strings.TrimSpace(arch))
	if ac, ok := archSet[arch]; ok {
		return ac, nil
	}
	return Arch{}, fmt.Errorf("unsupported architecture: %s", arch)
}

type Symbol struct {
	Func string
	Line *dwarf.LineEntry
}

type MachFile struct {
	r  io.ReaderAt
	ff *macho.FatFile
	*macho.File
	vmAddr       uint64
	loadSlide    uint64
	debugAranges []*DwarfArange
	symbolTable  []*macho.Symbol
	dwarf        *dwarf.Data
	dwarfReader  *dwarf.Reader
}

func OpenMachO(file string, arch Arch) (*MachFile, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %v", file, err)
	}
	mf, err := Parse(f, arch)
	if err != nil {
		defer f.Close()
		return nil, fmt.Errorf("unable to parse Mach-O file [%s]: %w", file, err)
	}
	_ = mf.parseDebugAranges()
	for _, load := range mf.Loads {
		if s, ok := load.(*macho.Segment); ok && s.Name == "__TEXT" {
			mf.vmAddr = s.Addr // parse __TEXT vmaddr
			break
		}
	}
	mf.symbolTable = make([]*macho.Symbol, len(mf.Symtab.Syms))
	for i := range mf.Symtab.Syms {
		mf.symbolTable[i] = &mf.Symtab.Syms[i]
	}
	sort.Slice(mf.symbolTable, func(i, j int) bool {
		return mf.symbolTable[i].Value >= mf.symbolTable[j].Value // descending sort
	})
	dwarfData, err := mf.DWARF()
	if err != nil {
		_ = mf.Close()
		return nil, fmt.Errorf("unable to parse DWARF debug info: %w", err)
	}
	mf.dwarf = dwarfData
	mf.dwarfReader = dwarfData.Reader()
	return mf, nil
}

func Parse(r io.ReaderAt, arch Arch) (*MachFile, error) {
	magic := make([]byte, 4)
	if _, err := r.ReadAt(magic, 0); err != nil {
		return nil, fmt.Errorf("atosgo: unable to read Macho magic: %w", err)
	}
	magicBe := binary.BigEndian.Uint32(magic)
	magicLe := binary.LittleEndian.Uint32(magic)

	if magicBe == macho.MagicFat {
		ff, err := macho.NewFatFile(r)
		if err != nil {
			return nil, fmt.Errorf("invalid Fat Mach-O file: %w", err)
		}
		for _, fa := range ff.Arches {
			if fa.Cpu == arch.Cpu && fa.SubCpu == arch.SubCpu {
				return &MachFile{
					r:    r,
					ff:   ff,
					File: fa.File,
				}, nil
			}
		}
		defer ff.Close()
		return nil, fmt.Errorf("the expected arch [%s:%d] not found in Mach-O file", arch.Cpu, arch.SubCpu)
	} else if magicBe == macho.Magic32 || magicBe == macho.Magic64 || magicLe == macho.Magic32 || magicLe == macho.Magic64 {
		f, err := macho.NewFile(r)
		if err != nil {
			return nil, fmt.Errorf("invalid Mach-O file: %w", err)
		}
		if f.Cpu != arch.Cpu || f.SubCpu != arch.SubCpu {
			defer f.Close()
			return nil, fmt.Errorf("the expected arch [%s:%d] not match with the Mach-O file [%s:%d]",
				arch.Cpu, arch.SubCpu, f.Cpu, f.SubCpu)
		}
		return &MachFile{
			r:    r,
			File: f,
		}, nil
	}

	return nil, fmt.Errorf("invalid Mach-O magic: 0x%x", magicBe)
}

func (f *MachFile) VMAddr() uint64 {
	return f.vmAddr
}

func (f *MachFile) LoadSlide() uint64 {
	return f.loadSlide
}

func (f *MachFile) Close() error {
	if f.File != nil {
		if err := f.File.Close(); err != nil {
			return fmt.Errorf("unable to close Mach-O file: %w", err)
		}
	}
	if f.ff != nil {
		if err := f.ff.Close(); err != nil {
			return fmt.Errorf("unable to close fat Mach-O file: %w", err)
		}
	}
	if f.r != nil {
		if c, ok := f.r.(io.Closer); ok {
			if err := c.Close(); err != nil {
				return fmt.Errorf("unable to close os file: %w", err)
			}
		}
	}
	return nil
}

// parseDebugAranges parse __debug_aranges or __zdebug_aranges
func (f *MachFile) parseDebugAranges() error {
	for _, section := range f.File.Sections {
		if section.Name == "__debug_aranges" || section.Name == "__zdebug_aranges" {
			b, err := sectionData(section)
			if err != nil {
				return err
			}
			aranges, err := ParseDebugAranges(newBytesReader(b))
			if err != nil {
				return fmt.Errorf("unable to parse _debug_aranges: %w", err)
			}
			f.debugAranges = append(f.debugAranges, aranges...)
		}
	}
	if len(f.debugAranges) > 0 {
		sort.Slice(f.debugAranges, func(i, j int) bool {
			return f.debugAranges[i].LowPC < f.debugAranges[j].LowPC
		})
	}
	return nil
}

func (f *MachFile) SetLoadAddress(lAddr uint64) {
	f.loadSlide = lAddr - f.vmAddr
}

func (f *MachFile) LoadAddress() uint64 {
	return f.vmAddr + f.loadSlide
}

func (f *MachFile) SetLoadSlide(loadSlide uint64) {
	f.loadSlide = loadSlide
}

func (f *MachFile) Atos(pc uint64) (*Symbol, error) {
	vmAddr := pc - f.loadSlide
	entry, err := f.LocateCUEntry(vmAddr)
	if err != nil {
		return nil, err
	}
	if entry.Tag != dwarf.TagCompileUnit {
		return nil, fmt.Errorf("expect a compile unit entry but got %s", entry.Tag.String())
	}
	lReader, err := f.dwarf.LineReader(entry)
	if err != nil {
		return nil, fmt.Errorf("unable to init the line table's reader: %w", err)
	}
	var le dwarf.LineEntry
	if err = lReader.SeekPC(vmAddr, &le); err != nil {
		return nil, fmt.Errorf("unable to locate line entry: %w", err)
	}

	//name, err := f.ResolveNameFromSymTab(trueAddr)
	//if err == nil {
	//	return &Symbol{
	//		Func: name,
	//		Line: &le,
	//	}, nil
	//}

	var ranges [][2]uint64
	for {
		entry, err = f.dwarfReader.Next()
		if entry == nil && err == nil {
			break // EOF
		}
		if err != nil {
			return nil, fmt.Errorf("unable to fetch CU Subprogram entry: %w", err)
		}
		if entry.Tag == dwarf.TagCompileUnit || entry.Tag == dwarf.TagPartialUnit { // Got next CU or PU
			return nil, fmt.Errorf("unable to find the target subprogram entry cause current CU has reached the end")
		}
		if entry.Tag == dwarf.TagSubprogram {
			ranges, err = f.dwarf.Ranges(entry)
			if err != nil {
				return nil, fmt.Errorf("unable to parse subprogram ranges: %w", err)
			}
			for _, addrRange := range ranges {
				if addrRange[0] <= vmAddr && addrRange[1] >= vmAddr {
					funcName, _ := entry.Val(dwarf.AttrName).(string)
					// TODO: handle inlined function
					//inlined := entry.Val(dwarf.AttrInline)
					return &Symbol{
						Func: funcName,
						Line: &le,
					}, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("unable to find subprogram entry")
}

func (f *MachFile) FastLocateCUEntry(addr uint64) (*dwarf.Entry, error) {
	if len(f.debugAranges) == 0 {
		return nil, fmt.Errorf("no debug aranges available")
	}
	idx, found := sort.Find(len(f.debugAranges), func(i int) int {
		if f.debugAranges[i].LowPC <= addr && f.debugAranges[i].HighPC >= addr {
			return 0
		}
		if f.debugAranges[i].LowPC > addr {
			return -1
		}
		return 1
	})
	if found {
		cuHeaderOff := f.debugAranges[idx].CUOffset
		for _, section := range f.Sections {
			if section.Name == "__debug_info" || section.Name == "__zdebug_info" {
				secData, err := sectionData(section)
				if err != nil {
					return nil, fmt.Errorf("unable to parse __debug_info in DWARF: %w", err)
				}
				cuBodyOff, err := GetCUBodyOffset(cuHeaderOff, newBytesReader(secData))
				if err != nil {
					return nil, fmt.Errorf("unable to locate CU by CU offset: %w", err)
				}
				f.dwarfReader.Seek(dwarf.Offset(cuBodyOff))
				return f.dwarfReader.Next()
			}
		}
	}
	return nil, fmt.Errorf("unable to locate CU via __debug_arrages section cause the target PC is not in any PC ranges")
}

func (f *MachFile) LocateCUEntry(addr uint64) (*dwarf.Entry, error) {
	if len(f.debugAranges) > 0 {
		entry, err := f.FastLocateCUEntry(addr)
		if err == nil {
			return entry, nil
		}
		Log.Debugf("unable to seek CU for addr [0x%x] via __debug_aranges(reason: %v), try to iterate all CUs", addr, err)
	}
	return f.dwarfReader.SeekPC(addr)
}

func (f *MachFile) ResolveNameFromSymTab(addr uint64) (string, error) {
	idx := sort.Search(len(f.symbolTable), func(i int) bool {
		return f.symbolTable[i].Value <= addr
	})
	if idx >= len(f.symbolTable) {
		return "", fmt.Errorf("no symbol table entry for addr 0x%x", addr)
	}
	symbol := f.symbolTable[idx]
	if f.Sections[symbol.Sect-1].Seg != "__TEXT" || f.Sections[symbol.Sect-1].Name != "__text" {
		return "", fmt.Errorf("symbol table entry for addr 0x%x is not in __TEXT,__text section", addr)
	}
	if symbol.Type&0x0e != 0x0e {
		return "", fmt.Errorf("symbol table entry for addr 0x%x is not N_SECT type", addr)
	}
	return symbol.Name, nil
}

func sectionData(s *macho.Section) ([]byte, error) {
	b, err := s.Data()
	if err != nil && uint64(len(b)) < s.Size {
		return nil, fmt.Errorf("unable to read Mach-O section data: %w", err)
	}

	if len(b) >= 12 && string(b[:4]) == "ZLIB" {
		secLen := binary.BigEndian.Uint64(b[4:12])
		secData := make([]byte, secLen)
		r, err := zlib.NewReader(bytes.NewReader(b[12:]))
		if err != nil {
			return nil, err
		}
		defer r.Close()
		if _, err = io.ReadFull(r, secData); err != nil {
			return nil, fmt.Errorf("unable to read gzipped section data: %w", err)
		}
		b = secData
	}
	return b, nil
}
