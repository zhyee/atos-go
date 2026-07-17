package atos

import (
	"debug/dwarf"
	"fmt"
	"io"
	"sort"
	"sync"
)

const attrMIPSLinkageName dwarf.Attr = 0x2007

type pcRange[T any] struct {
	low   uint64
	high  uint64
	value T
}

type pcRangeIndex[T any] struct {
	ranges  []pcRange[T]
	maxHigh []uint64
}

func newPCRangeIndex[T any](ranges []pcRange[T]) pcRangeIndex[T] {
	valid := ranges[:0]
	for _, addrRange := range ranges {
		if addrRange.low < addrRange.high {
			valid = append(valid, addrRange)
		}
	}
	ranges = valid

	sort.SliceStable(ranges, func(i, j int) bool {
		if ranges[i].low == ranges[j].low {
			return ranges[i].high < ranges[j].high
		}
		return ranges[i].low < ranges[j].low
	})

	maxHigh := make([]uint64, len(ranges))
	var high uint64
	for i := range ranges {
		if ranges[i].high > high {
			high = ranges[i].high
		}
		maxHigh[i] = high
	}

	return pcRangeIndex[T]{
		ranges:  ranges,
		maxHigh: maxHigh,
	}
}

func (idx *pcRangeIndex[T]) find(addr uint64) (T, bool) {
	var zero T
	end := sort.Search(len(idx.ranges), func(i int) bool {
		return idx.ranges[i].low > addr
	})

	var (
		best     T
		bestSize uint64
		found    bool
	)
	for i := end - 1; i >= 0; i-- {
		if idx.maxHigh[i] <= addr {
			break
		}
		addrRange := idx.ranges[i]
		if addrRange.low <= addr && addr < addrRange.high {
			size := addrRange.high - addrRange.low
			if !found || size < bestSize {
				best = addrRange.value
				bestSize = size
				found = true
			}
		}
	}
	if !found {
		return zero, false
	}
	return best, true
}

type dwarfIndexState struct {
	once  sync.Once
	index *dwarfIndex
	err   error
}

func (s *dwarfIndexState) get(data *dwarf.Data) (*dwarfIndex, error) {
	s.once.Do(func() {
		s.index, s.err = buildDwarfIndex(data)
	})
	return s.index, s.err
}

type dwarfIndex struct {
	compileUnits pcRangeIndex[*compileUnitIndex]
}

type compileUnitIndex struct {
	entry *dwarf.Entry

	once      sync.Once
	err       error
	functions pcRangeIndex[functionRecord]
	inlines   pcRangeIndex[*inlineRecord]
	lines     pcRangeIndex[dwarf.LineEntry]
	files     []*dwarf.LineFile
}

type functionNames struct {
	linkage  string
	fallback string
}

type functionRecord struct {
	names functionNames
	lowPC uint64
}

type inlineRecord struct {
	names      functionNames
	parent     *inlineRecord
	depth      int
	callFile   int
	callLine   int
	callColumn int
}

type dieContext struct {
	inline *inlineRecord
}

func buildDwarfIndex(data *dwarf.Data) (*dwarfIndex, error) {
	if data == nil {
		return nil, fmt.Errorf("no DWARF debug info available")
	}

	reader := data.Reader()
	var ranges []pcRange[*compileUnitIndex]
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, fmt.Errorf("unable to read DWARF compile units: %w", err)
		}
		if entry == nil {
			break
		}
		if entry.Tag != dwarf.TagCompileUnit && entry.Tag != dwarf.TagPartialUnit {
			if entry.Children {
				reader.SkipChildren()
			}
			continue
		}

		cu := &compileUnitIndex{entry: entry}
		pcRanges, err := data.Ranges(entry)
		if err != nil {
			return nil, fmt.Errorf("unable to parse compile unit ranges at offset 0x%x: %w", entry.Offset, err)
		}
		for _, addrRange := range pcRanges {
			ranges = append(ranges, pcRange[*compileUnitIndex]{
				low:   addrRange[0],
				high:  addrRange[1],
				value: cu,
			})
		}
		reader.SkipChildren()
	}

	return &dwarfIndex{compileUnits: newPCRangeIndex(ranges)}, nil
}

func (cu *compileUnitIndex) ensure(data *dwarf.Data) error {
	cu.once.Do(func() {
		cu.err = cu.build(data)
	})
	return cu.err
}

func (cu *compileUnitIndex) build(data *dwarf.Data) error {
	reader := data.Reader()
	reader.Seek(cu.entry.Offset)
	root, err := reader.Next()
	if err != nil {
		return fmt.Errorf("unable to read compile unit at offset 0x%x: %w", cu.entry.Offset, err)
	}
	if root == nil || (root.Tag != dwarf.TagCompileUnit && root.Tag != dwarf.TagPartialUnit) {
		return fmt.Errorf("invalid compile unit at offset 0x%x", cu.entry.Offset)
	}

	nameCache := make(map[dwarf.Offset]functionNames)
	var (
		functions    []pcRange[functionRecord]
		inlineRanges []pcRange[*inlineRecord]
		contexts     []dieContext
	)
	for {
		entry, err := reader.Next()
		if err != nil {
			return fmt.Errorf("unable to read entries in compile unit at offset 0x%x: %w", cu.entry.Offset, err)
		}
		if entry == nil || entry.Tag == dwarf.TagCompileUnit || entry.Tag == dwarf.TagPartialUnit {
			break
		}
		if entry.Tag == 0 {
			if len(contexts) > 0 {
				contexts = contexts[:len(contexts)-1]
			}
			continue
		}

		var parentInline *inlineRecord
		if len(contexts) > 0 {
			parentInline = contexts[len(contexts)-1].inline
		}
		currentInline := parentInline

		switch entry.Tag {
		case dwarf.TagSubprogram:
			pcRanges, err := data.Ranges(entry)
			if err != nil {
				return fmt.Errorf("unable to parse subprogram ranges at offset 0x%x: %w", entry.Offset, err)
			}
			if len(pcRanges) > 0 {
				functionLowPC := pcRanges[0][0]
				for _, addrRange := range pcRanges[1:] {
					if addrRange[0] < functionLowPC {
						functionLowPC = addrRange[0]
					}
				}
				names, err := resolveDIEName(data, cu.entry, entry, nameCache, make(map[dwarf.Offset]bool))
				if err != nil {
					return fmt.Errorf("unable to resolve subprogram name at offset 0x%x: %w", entry.Offset, err)
				}
				for _, addrRange := range pcRanges {
					functions = append(functions, pcRange[functionRecord]{
						low:  addrRange[0],
						high: addrRange[1],
						value: functionRecord{
							names: names,
							lowPC: functionLowPC,
						},
					})
				}
			}

		case dwarf.TagInlinedSubroutine:
			names, err := resolveDIEName(data, cu.entry, entry, nameCache, make(map[dwarf.Offset]bool))
			if err != nil {
				return fmt.Errorf("unable to resolve inlined subroutine name at offset 0x%x: %w", entry.Offset, err)
			}
			inline := &inlineRecord{
				names:      names,
				parent:     parentInline,
				depth:      1,
				callFile:   dwarfInt(entry.Val(dwarf.AttrCallFile)),
				callLine:   dwarfInt(entry.Val(dwarf.AttrCallLine)),
				callColumn: dwarfInt(entry.Val(dwarf.AttrCallColumn)),
			}
			if parentInline != nil {
				inline.depth = parentInline.depth + 1
			}
			pcRanges, err := data.Ranges(entry)
			if err != nil {
				return fmt.Errorf("unable to parse inlined subroutine ranges at offset 0x%x: %w", entry.Offset, err)
			}
			for _, addrRange := range pcRanges {
				inlineRanges = append(inlineRanges, pcRange[*inlineRecord]{
					low:   addrRange[0],
					high:  addrRange[1],
					value: inline,
				})
			}
			currentInline = inline
		}

		if entry.Children {
			contexts = append(contexts, dieContext{inline: currentInline})
		}
	}
	cu.functions = newPCRangeIndex(functions)
	cu.inlines = newPCRangeIndex(inlineRanges)

	lines, files, err := buildLineIndex(data, cu.entry)
	if err != nil {
		Log.Debugf("unable to index line table for compile unit at offset 0x%x: %v", cu.entry.Offset, err)
		return nil
	}
	cu.lines = lines
	cu.files = files
	return nil
}

func buildLineIndex(data *dwarf.Data, cu *dwarf.Entry) (pcRangeIndex[dwarf.LineEntry], []*dwarf.LineFile, error) {
	if cu.Tag != dwarf.TagCompileUnit {
		return pcRangeIndex[dwarf.LineEntry]{}, nil, nil
	}
	reader, err := data.LineReader(cu)
	if err != nil {
		return pcRangeIndex[dwarf.LineEntry]{}, nil, err
	}
	if reader == nil {
		return pcRangeIndex[dwarf.LineEntry]{}, nil, nil
	}

	var (
		ranges   []pcRange[dwarf.LineEntry]
		previous dwarf.LineEntry
		havePrev bool
	)
	for {
		var current dwarf.LineEntry
		err := reader.Next(&current)
		if err != nil {
			if err == io.EOF {
				break
			}
			return pcRangeIndex[dwarf.LineEntry]{}, nil, err
		}
		if havePrev && !previous.EndSequence && previous.Address < current.Address {
			ranges = append(ranges, pcRange[dwarf.LineEntry]{
				low:   previous.Address,
				high:  current.Address,
				value: previous,
			})
		}
		previous = current
		havePrev = true
	}
	files := append([]*dwarf.LineFile(nil), reader.Files()...)
	return newPCRangeIndex(ranges), files, nil
}

func (cu *compileUnitIndex) findInline(addr uint64) (*inlineRecord, bool) {
	end := sort.Search(len(cu.inlines.ranges), func(i int) bool {
		return cu.inlines.ranges[i].low > addr
	})
	var (
		best     *inlineRecord
		bestSize uint64
	)
	for i := end - 1; i >= 0; i-- {
		if cu.inlines.maxHigh[i] <= addr {
			break
		}
		addrRange := cu.inlines.ranges[i]
		if addrRange.low <= addr && addr < addrRange.high {
			size := addrRange.high - addrRange.low
			if best == nil || addrRange.value.depth > best.depth ||
				(addrRange.value.depth == best.depth && size < bestSize) {
				best = addrRange.value
				bestSize = size
			}
		}
	}
	return best, best != nil
}

func (cu *compileUnitIndex) callSiteLine(inline *inlineRecord, addr uint64) *dwarf.LineEntry {
	if inline == nil || inline.callFile <= 0 || inline.callFile >= len(cu.files) {
		return nil
	}
	return &dwarf.LineEntry{
		Address: addr,
		File:    cu.files[inline.callFile],
		Line:    inline.callLine,
		Column:  inline.callColumn,
	}
}

func dwarfInt(value any) int {
	switch value := value.(type) {
	case int:
		return value
	case int8:
		return int(value)
	case int16:
		return int(value)
	case int32:
		return int(value)
	case int64:
		return int(value)
	case uint:
		return int(value)
	case uint8:
		return int(value)
	case uint16:
		return int(value)
	case uint32:
		return int(value)
	case uint64:
		return int(value)
	default:
		return 0
	}
}

func resolveDIEName(
	data *dwarf.Data,
	cu *dwarf.Entry,
	entry *dwarf.Entry,
	cache map[dwarf.Offset]functionNames,
	visiting map[dwarf.Offset]bool,
) (functionNames, error) {
	if names, ok := cache[entry.Offset]; ok {
		return names, nil
	}
	if visiting[entry.Offset] {
		return functionNames{}, fmt.Errorf("cyclic DWARF name reference at offset 0x%x", entry.Offset)
	}
	visiting[entry.Offset] = true
	defer delete(visiting, entry.Offset)

	names := functionNames{}
	names.fallback, _ = entry.Val(dwarf.AttrName).(string)
	names.linkage, _ = entry.Val(dwarf.AttrLinkageName).(string)
	if names.linkage == "" {
		names.linkage, _ = entry.Val(attrMIPSLinkageName).(string)
	}

	for _, attr := range []dwarf.Attr{dwarf.AttrAbstractOrigin, dwarf.AttrSpecification} {
		if names.linkage != "" && names.fallback != "" {
			break
		}
		offset, ok := entry.Val(attr).(dwarf.Offset)
		if !ok {
			continue
		}
		target, err := readDIEAt(data, cu, offset)
		if err != nil {
			return functionNames{}, err
		}
		targetNames, err := resolveDIEName(data, cu, target, cache, visiting)
		if err != nil {
			return functionNames{}, err
		}
		if names.linkage == "" {
			names.linkage = targetNames.linkage
		}
		if names.fallback == "" {
			names.fallback = targetNames.fallback
		}
	}

	cache[entry.Offset] = names
	return names, nil
}

func readDIEAt(data *dwarf.Data, cu *dwarf.Entry, offset dwarf.Offset) (*dwarf.Entry, error) {
	reader := data.Reader()
	reader.Seek(cu.Offset)
	if _, err := reader.Next(); err != nil {
		return nil, err
	}
	reader.Seek(offset)
	entry, err := reader.Next()
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("no DWARF entry at offset 0x%x", offset)
	}
	return entry, nil
}
