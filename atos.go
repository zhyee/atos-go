package atos

import (
	"bytes"
	"compress/zlib"
	"debug/dwarf"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"go.uber.org/zap"
)

const cpuArch64 = 0x01000000

// Log is the internal logger, the default is a no-op one,
// replace it with your custom *zap.SugaredLogger like below to enable it
//
// logger := zap.New(zapcore.NewCore(
// zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
// os.Stderr,
// zapcore.DebugLevel)).Sugar()
// SetLogger(logger)
var Log = zap.NewNop().Sugar()

// Mach-O fat-arch cpu subtype definitions, see https://llvm.org/doxygen/BinaryFormat_2MachO_8h_source.html for details.
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
	// Offset is the byte offset from the beginning of Func.
	Offset uint64
	// Line is nil when the binary has no line table entry for the address.
	Line *dwarf.LineEntry
}

type SymbolicationResult struct {
	Symbol *Symbol
	Err    error
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
	dwarfIndex   dwarfIndexState
}

func OpenMachO(file string, arch Arch) (*MachFile, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, fmt.Errorf("unable to open file %s: %v", file, err)
	}
	mf, err := parseArch(f, arch)
	if err != nil {
		defer f.Close()
		return nil, fmt.Errorf("unable to parse Mach-O file [%s]: %w", file, err)
	}
	for _, load := range mf.Loads {
		if s, ok := load.(*macho.Segment); ok && s.Name == "__TEXT" {
			mf.vmAddr = s.Addr // parse __TEXT vmaddr
			break
		}
	}
	if mf.Symtab != nil {
		for i := range mf.Symtab.Syms {
			symbol := &mf.Symtab.Syms[i]
			if mf.isTextSymbol(symbol) {
				mf.symbolTable = append(mf.symbolTable, symbol)
			}
		}
	}
	sort.SliceStable(mf.symbolTable, func(i, j int) bool {
		return mf.symbolTable[i].Value > mf.symbolTable[j].Value // descending sort
	})
	dwarfData, err := mf.DWARF()
	if err != nil {
		if len(mf.symbolTable) == 0 {
			_ = mf.Close()
			return nil, fmt.Errorf("unable to parse DWARF debug info: %w", err)
		}
		Log.Debugf("unable to parse DWARF debug info, falling back to the symbol table: %v", err)
		return mf, nil
	}
	mf.dwarf = dwarfData
	return mf, nil
}

func SetLogger(l *zap.SugaredLogger) {
	Log = l
}

func parseArch(r io.ReaderAt, arch Arch) (*MachFile, error) {
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
			aranges, err := ParseDebugAranges(newBytesReader(b), f.ByteOrder)
			if err != nil {
				return fmt.Errorf("unable to parse _debug_aranges: %w", err)
			}
			f.debugAranges = append(f.debugAranges, aranges...)
		}
	}
	if len(f.debugAranges) > 0 {
		sortDwarfAranges(f.debugAranges)
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

func (f *MachFile) UnslideAddress(pc uint64) (uint64, error) {
	if pc < f.loadSlide {
		return 0, fmt.Errorf("PC 0x%x is below load slide 0x%x", pc, f.loadSlide)
	}
	return pc - f.loadSlide, nil
}

func (f *MachFile) ContainsVMAddress(addr uint64) bool {
	for _, load := range f.Loads {
		if segment, ok := load.(*macho.Segment); ok && containsAddress(segment.Addr, segment.Memsz, addr) {
			return true
		}
	}
	return false
}

func (f *MachFile) Atos(pc uint64) (*Symbol, error) {
	frames, err := f.symbolicateFrames(pc, false)
	if err != nil {
		return nil, err
	}
	return frames[len(frames)-1], nil
}

// AtosInlineFrames symbolizes PC and returns inline frames from the innermost
// inlined call to the concrete outer function, matching atos -inlineFrames.
func (f *MachFile) AtosInlineFrames(pc uint64) ([]*Symbol, error) {
	return f.symbolicateFrames(pc, true)
}

func (f *MachFile) symbolicateFrames(pc uint64, includeInlineFrames bool) ([]*Symbol, error) {
	vmAddr, err := f.UnslideAddress(pc)
	if err != nil {
		return nil, err
	}

	var (
		funcName  string
		funcLowPC uint64
		line      *dwarf.LineEntry
		cu        *compileUnitIndex
		dwarfErr  error
	)
	index, err := f.dwarfIndex.get(f.dwarf)
	if err != nil {
		dwarfErr = err
	} else if compileUnit, ok := index.compileUnits.find(vmAddr); ok {
		cu = compileUnit
		if err := cu.ensure(f.dwarf); err != nil {
			dwarfErr = err
		} else {
			if function, ok := cu.functions.find(vmAddr); ok {
				funcName = displayFunctionName(function.names.linkage, function.names.fallback)
				funcLowPC = function.lowPC
			}
			if lineEntry, ok := cu.lines.find(vmAddr); ok {
				line = &lineEntry
			}
		}
	}

	var frames []*Symbol
	outerLine := line
	if cu != nil && dwarfErr == nil {
		if inline, ok := cu.findInline(vmAddr); ok {
			currentLine := cloneLineEntry(line)
			for current := inline; current != nil; current = current.parent {
				if includeInlineFrames {
					name := displayFunctionName(current.names.linkage, current.names.fallback)
					if name != "" {
						frames = append(frames, &Symbol{Func: name, Line: currentLine})
					}
				}
				currentLine = cu.callSiteLine(current, vmAddr)
			}
			outerLine = currentLine
		}
	}

	if funcName == "" {
		if symbol, err := f.resolveSymbolFromSymTab(vmAddr); err == nil {
			funcName = displayFunctionName(normalizeMachOSymbolName(symbol.Name), "")
			funcLowPC = symbol.Value
		}
	}
	if funcName == "" {
		if len(frames) > 0 {
			return frames, nil
		}
		if dwarfErr != nil {
			return nil, fmt.Errorf("unable to symbolize PC 0x%x: %w", pc, dwarfErr)
		}
		return nil, fmt.Errorf("unable to find subprogram entry for PC 0x%x", pc)
	}

	frames = append(frames, &Symbol{Func: funcName, Offset: vmAddr - funcLowPC, Line: outerLine})
	return frames, nil
}

func cloneLineEntry(line *dwarf.LineEntry) *dwarf.LineEntry {
	if line == nil {
		return nil
	}
	cloned := *line
	return &cloned
}

// AtosMany symbolizes PCs in input order. Each result carries its own error so
// one unknown address does not discard successful symbolications.
func (f *MachFile) AtosMany(pcs []uint64) []SymbolicationResult {
	results := make([]SymbolicationResult, len(pcs))
	for i, pc := range pcs {
		results[i].Symbol, results[i].Err = f.Atos(pc)
	}
	return results
}

func (f *MachFile) FastLocateCUEntry(addr uint64) (*dwarf.Entry, error) {
	index, err := f.dwarfIndex.get(f.dwarf)
	if err != nil {
		return nil, err
	}
	if cu, ok := index.compileUnits.find(addr); ok {
		return cu.entry, nil
	}
	return nil, fmt.Errorf("no compile unit entry for address 0x%x", addr)
}

func (f *MachFile) LocateCUEntry(addr uint64) (*dwarf.Entry, error) {
	return f.FastLocateCUEntry(addr)
}

func (f *MachFile) ResolveNameFromSymTab(addr uint64) (string, error) {
	symbol, err := f.resolveSymbolFromSymTab(addr)
	if err != nil {
		return "", err
	}
	return symbol.Name, nil
}

func (f *MachFile) resolveSymbolFromSymTab(addr uint64) (*macho.Symbol, error) {
	idx := sort.Search(len(f.symbolTable), func(i int) bool {
		return f.symbolTable[i].Value <= addr
	})
	if idx >= len(f.symbolTable) {
		return nil, fmt.Errorf("no symbol table entry for addr 0x%x", addr)
	}
	symbol := f.symbolTable[idx]
	if !f.isTextSymbol(symbol) {
		return nil, fmt.Errorf("symbol table entry for addr 0x%x is not in __TEXT,__text", addr)
	}
	section, ok := f.textSectionForSymbol(symbol)
	if !ok || !containsAddress(section.Addr, section.Size, addr) {
		return nil, fmt.Errorf("symbol table entry for addr 0x%x is not in __TEXT,__text", addr)
	}
	return symbol, nil
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

func (f *MachFile) isTextSymbol(symbol *macho.Symbol) bool {
	section, ok := f.textSectionForSymbol(symbol)
	return ok && containsAddress(section.Addr, section.Size, symbol.Value)
}

func (f *MachFile) textSectionForSymbol(symbol *macho.Symbol) (*macho.Section, bool) {
	if symbol == nil || symbol.Type&0xe0 != 0 || symbol.Type&0x0e != 0x0e {
		return nil, false
	}
	sectionIndex := int(symbol.Sect) - 1
	if sectionIndex < 0 || sectionIndex >= len(f.Sections) {
		return nil, false
	}
	section := f.Sections[sectionIndex]
	return section, section.Seg == "__TEXT" && section.Name == "__text"
}

func containsAddress(start, size, addr uint64) bool {
	return addr >= start && addr-start < size
}

func normalizeMachOSymbolName(name string) string {
	if strings.HasPrefix(name, "_") {
		return name[1:]
	}
	return name
}

func AtosARM64(symbolFile, loadAddress string, addresses []string, fullPath bool) ([]string, error) {
	return Atos(ArchARM64, symbolFile, loadAddress, addresses, fullPath)
}

func Atos(arch Arch, symbolFile, loadAddress string, addresses []string, fullPath bool) ([]string, error) {
	mf, err := OpenMachO(symbolFile, arch)
	if err != nil {
		return nil, fmt.Errorf("parse Mach-O file: %w", err)
	}
	defer mf.Close()

	loadAt, err := strconv.ParseUint(PrependHexSign(loadAddress), 0, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid load address [%s]: %w", loadAddress, err)
	}
	mf.SetLoadAddress(loadAt)
	symbols := make([]string, 0, len(addresses))
	binaryName := filepath.Base(symbolFile)
	var errs []error
	for _, addr := range addresses {
		pc, err := strconv.ParseUint(PrependHexSign(addr), 0, 64)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid address [%s]: %w", addr, err))
			symbols = append(symbols, addr)
			continue
		}
		symbol, err := mf.Atos(pc)
		if err != nil {
			errs = append(errs, fmt.Errorf("unable to symbolize address [%s]: %w", addr, err))
			symbols = append(symbols, addr)
			continue
		}
		symbols = append(symbols, FormatSymbol(symbol, binaryName, fullPath))
	}
	return symbols, errors.Join(errs...)
}
