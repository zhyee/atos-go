package atos

import (
	"bytes"
	"debug/dwarf"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const (
	testDSYM        = "testdata/App.app.dSYM/Contents/Resources/DWARF/App"
	testLoadAddress = uint64(0x104480000)
)

func openTestMachFile(t *testing.T) *MachFile {
	t.Helper()
	mf, err := OpenMachO(testDSYM, ArchARM64)
	if err != nil {
		t.Fatal(err)
	}
	mf.SetLoadAddress(testLoadAddress)
	t.Cleanup(func() {
		if err := mf.Close(); err != nil {
			t.Errorf("close Mach-O: %v", err)
		}
	})
	return mf
}

func TestReadStruct(t *testing.T) {

	type st struct {
		Num  uint32
		Char byte
		B    bool
		U16  uint16
	}

	var tt st

	f := bytes.NewReader([]byte{0, 0, 0, 42, 'x', 1, 0x12, 0x34})

	if err := binary.Read(f, binary.BigEndian, &tt); err != nil {
		t.Fatal(err)
	}
	if tt.Num != 42 || tt.Char != 'x' || !tt.B || tt.U16 != 0x1234 {
		t.Fatalf("unexpected decoded struct: %#v", tt)
	}
}

func TestSymbolTable(t *testing.T) {
	mf := openTestMachFile(t)

	addr := uint64(0x0000000104486ef0) - mf.loadSlide

	symbolName, err := mf.ResolveNameFromSymTab(addr)
	if err != nil {
		t.Fatal(err)
	}
	const want = "___35-[Crasher throwUncaughtNSException]_block_invoke_2"
	if symbolName != want {
		t.Fatalf("symbol name = %q, want %q", symbolName, want)
	}
}

func TestAtos(t *testing.T) {
	mf := openTestMachFile(t)

	symbol, err := mf.Atos(0x104486ef0)
	if err != nil {
		t.Fatal(err)
	}
	const want = "__35-[Crasher throwUncaughtNSException]_block_invoke_2"
	if symbol.Func != want {
		t.Fatalf("function name = %q, want %q", symbol.Func, want)
	}
	if symbol.Offset != 0x48 {
		t.Fatalf("function offset = 0x%x, want 0x48", symbol.Offset)
	}
	if symbol.Line == nil || symbol.Line.File == nil || !strings.HasSuffix(symbol.Line.File.Name, "/Crasher.mm") {
		t.Fatalf("unexpected line entry: %#v", symbol.Line)
	}
}

func TestAtosBoundariesAndReferencedNames(t *testing.T) {
	mf := openTestMachFile(t)
	tests := []struct {
		name string
		pc   uint64
		want string
	}{
		{name: "function boundary", pc: 0x104486f1c, want: "-[Crasher dereferenceBadPointer]"},
		{name: "compile unit boundary", pc: 0x104486cd4, want: "MyException::what() const"},
		{name: "specification", pc: 0x104486cd5, want: "MyException::what() const"},
		{name: "abstract origin chain", pc: 0x104487a91, want: "MyException::~MyException()"},
		{name: "swift abstract origin", pc: 0x10448c6dd, want: expectedSwiftTestName()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			symbol, err := mf.Atos(tt.pc)
			if err != nil {
				t.Fatal(err)
			}
			if symbol.Func != tt.want {
				t.Fatalf("function name = %q, want %q", symbol.Func, tt.want)
			}
		})
	}
}

func TestAtosUsesOuterInlineCallSite(t *testing.T) {
	mf := openTestMachFile(t)
	for _, tt := range []struct {
		pc       uint64
		file     string
		line     int
		function string
	}{
		{pc: 0x104487a50, file: "Crasher.mm", line: 288, function: "__36-[Crasher throwUncaughtCPPException]_block_invoke"},
		{pc: 0x10448c708, file: "PrintHookTest.swift", line: 12, function: expectedSwiftTestName()},
	} {
		symbol, err := mf.Atos(tt.pc)
		if err != nil {
			t.Fatal(err)
		}
		assertSymbol(t, symbol, tt.function, tt.file, tt.line)
	}
}

func TestAtosInlineFrames(t *testing.T) {
	mf := openTestMachFile(t)
	frames, err := mf.AtosInlineFrames(0x104487a50)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		function string
		file     string
		line     int
	}{
		{function: "MyException::MyException()", file: "Crasher.mm", line: 11},
		{function: "MyException::MyException()", file: "Crasher.mm", line: 11},
		{function: "MyCPPClass::throwAnException()", file: "Crasher.mm", line: 28},
		{function: "__36-[Crasher throwUncaughtCPPException]_block_invoke", file: "Crasher.mm", line: 288},
	}
	if len(frames) != len(want) {
		t.Fatalf("frame count = %d, want %d", len(frames), len(want))
	}
	for i := range want {
		assertSymbol(t, frames[i], want[i].function, want[i].file, want[i].line)
	}
}

func TestAtosInlineFramesMatchMacOS(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS atos comparison")
	}
	atosPath, err := exec.LookPath("atos")
	if err != nil {
		t.Skip("macOS atos is unavailable")
	}

	mf := openTestMachFile(t)
	for _, pc := range []uint64{0x104487a50, 0x10448c708, 0x104486ef0} {
		output, err := exec.Command(
			atosPath,
			"-arch", "arm64",
			"-o", testDSYM,
			"-l", fmt.Sprintf("0x%x", testLoadAddress),
			"-inlineFrames",
			"-d", "",
			fmt.Sprintf("0x%x", pc),
		).Output()
		if err != nil {
			t.Fatalf("run macOS atos for 0x%x: %v", pc, err)
		}
		want := strings.Split(strings.TrimSpace(string(output)), "\n")

		frames, err := mf.AtosInlineFrames(pc)
		if err != nil {
			t.Fatalf("AtosInlineFrames(0x%x): %v", pc, err)
		}
		got := make([]string, len(frames))
		for i, frame := range frames {
			got[i] = formatTestSymbol(frame)
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("AtosInlineFrames(0x%x):\n got %q\nwant %q", pc, got, want)
		}
	}
}

func TestAtosDoesNotUseSymbolOutsideTextSection(t *testing.T) {
	mf := openTestMachFile(t)
	if _, err := mf.Atos(testLoadAddress); err == nil {
		t.Fatal("address before __text unexpectedly resolved")
	}
}

func TestAtosSymbolTableFallbackMatchesAtos(t *testing.T) {
	textSection := &macho.Section{SectionHeader: macho.SectionHeader{
		Name: "__text",
		Seg:  "__TEXT",
		Addr: 0x100,
		Size: 0x100,
	}}
	mf := &MachFile{
		File: &macho.File{Sections: []*macho.Section{textSection}},
		symbolTable: []*macho.Symbol{
			{Name: "__ZNK11MyException4whatEv", Type: 0x0e, Sect: 1, Value: 0x120},
		},
	}

	symbol, err := mf.Atos(0x125)
	if err != nil {
		t.Fatal(err)
	}
	if symbol.Func != "MyException::what() const" {
		t.Fatalf("function name = %q, want %q", symbol.Func, "MyException::what() const")
	}
	if symbol.Offset != 5 {
		t.Fatalf("function offset = %d, want 5", symbol.Offset)
	}
	if symbol.Line != nil {
		t.Fatalf("line entry = %#v, want nil", symbol.Line)
	}
}

func TestAtosMatchesMacOSFunctionNames(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS atos comparison")
	}
	atosPath, err := exec.LookPath("atos")
	if err != nil {
		t.Skip("macOS atos is unavailable")
	}

	pcs := []uint64{0x104486ef0, 0x104486cd4, 0x104487a91, 0x10448c6dd}
	args := []string{"-arch", "arm64", "-o", testDSYM, "-l", fmt.Sprintf("0x%x", testLoadAddress)}
	for _, pc := range pcs {
		args = append(args, fmt.Sprintf("0x%x", pc))
	}
	output, err := exec.Command(atosPath, args...).Output()
	if err != nil {
		t.Fatalf("run macOS atos: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != len(pcs) {
		t.Fatalf("macOS atos returned %d lines, want %d", len(lines), len(pcs))
	}

	mf := openTestMachFile(t)
	for i, pc := range pcs {
		symbol, err := mf.Atos(pc)
		if err != nil {
			t.Fatalf("Atos(0x%x): %v", pc, err)
		}
		want, _, ok := strings.Cut(lines[i], " (in ")
		if !ok {
			t.Fatalf("unexpected macOS atos output %q", lines[i])
		}
		if symbol.Func != want {
			t.Errorf("Atos(0x%x) function = %q, macOS atos = %q", pc, symbol.Func, want)
		}
	}
}

func TestAtosMany(t *testing.T) {
	mf := openTestMachFile(t)
	results := mf.AtosMany([]uint64{0x104486ef0, 1, 0x104486f1c})
	if len(results) != 3 {
		t.Fatalf("result count = %d, want 3", len(results))
	}
	if results[0].Err != nil || results[0].Symbol.Func != "__35-[Crasher throwUncaughtNSException]_block_invoke_2" {
		t.Fatalf("unexpected first result: %#v", results[0])
	}
	if results[1].Err == nil {
		t.Fatal("invalid PC unexpectedly succeeded")
	}
	if results[2].Err != nil || results[2].Symbol.Func != "-[Crasher dereferenceBadPointer]" {
		t.Fatalf("unexpected third result: %#v", results[2])
	}
}

func TestAtosARM64(t *testing.T) {
	symbols, err := AtosARM64(testDSYM, "0x104480000", []string{"0x104486ef0", "0x104486f1c"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, symbol := range symbols {
		t.Log(symbol)
	}
}

func TestPCRangeIndexUsesHalfOpenRanges(t *testing.T) {
	index := newPCRangeIndex([]pcRange[string]{
		{low: 10, high: 20, value: "first"},
		{low: 20, high: 30, value: "second"},
		{low: 22, high: 25, value: "nested"},
	})
	for _, tt := range []struct {
		addr  uint64
		value string
		ok    bool
	}{
		{addr: 19, value: "first", ok: true},
		{addr: 20, value: "second", ok: true},
		{addr: 23, value: "nested", ok: true},
		{addr: 30, ok: false},
	} {
		value, ok := index.find(tt.addr)
		if value != tt.value || ok != tt.ok {
			t.Errorf("find(%d) = (%q, %t), want (%q, %t)", tt.addr, value, ok, tt.value, tt.ok)
		}
	}
}

func TestAtosConcurrent(t *testing.T) {
	mf := openTestMachFile(t)
	tests := []struct {
		pc   uint64
		want string
	}{
		{pc: 0x104486ef0, want: "__35-[Crasher throwUncaughtNSException]_block_invoke_2"},
		{pc: 0x104486f1c, want: "-[Crasher dereferenceBadPointer]"},
		{pc: 0x104486cd5, want: "MyException::what() const"},
		{pc: 0x10448c6dd, want: expectedSwiftTestName()},
	}

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for iteration := 0; iteration < 25; iteration++ {
				for _, tt := range tests {
					symbol, err := mf.Atos(tt.pc)
					if err != nil {
						errs <- err
						return
					}
					if symbol.Func != tt.want {
						errs <- fmt.Errorf("PC 0x%x resolved to %q, want %q", tt.pc, symbol.Func, tt.want)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func expectedSwiftTestName() string {
	return displayFunctionName("$s3App13PrintHookTestC4showyyF", "show")
}

func assertSymbol(t *testing.T, symbol *Symbol, function, file string, line int) {
	t.Helper()
	if symbol.Func != function {
		t.Errorf("function = %q, want %q", symbol.Func, function)
	}
	if symbol.Line == nil || symbol.Line.File == nil {
		t.Fatalf("line entry = %#v, want %s:%d", symbol.Line, file, line)
	}
	if got := pathBase(symbol.Line.File.Name); got != file || symbol.Line.Line != line {
		t.Errorf("location = %s:%d, want %s:%d", got, symbol.Line.Line, file, line)
	}
}

func formatTestSymbol(symbol *Symbol) string {
	if symbol.Line == nil || symbol.Line.File == nil {
		return fmt.Sprintf("%s (in App) + %d", symbol.Func, symbol.Offset)
	}
	return fmt.Sprintf("%s (in App) (%s:%d)", symbol.Func, pathBase(symbol.Line.File.Name), symbol.Line.Line)
}

func pathBase(file string) string {
	if index := strings.LastIndexAny(file, "/\\"); index >= 0 {
		return file[index+1:]
	}
	return file
}

func BenchmarkAtos(b *testing.B) {
	mf, err := OpenMachO(testDSYM, ArchARM64)
	if err != nil {
		b.Fatal(err)
	}
	defer mf.Close()
	mf.SetLoadAddress(testLoadAddress)
	if _, err := mf.Atos(0x104486ef0); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := mf.Atos(0x104486ef0); err != nil {
			b.Fatal(err)
		}
	}
}

func Test3(t *testing.T) {
	//f, err := macho.Open("testdata/a.out.dSYM/Contents/Resources/DWARF/a.out")
	f, err := OpenMachO("testdata/App.app.dSYM/Contents/Resources/DWARF/App", ArchARM64)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	//addr := 0x0000000104486ef0 - (0x104480000 - 0x100000000)

	t.Log("CPU: ", f.Cpu, ", Type: ", f.Type, ", command count: ", f.Ncmd,
		", size of command: ", f.Cmdsz, ", flags: ", f.Flags)

	for _, load := range f.Loads {
		switch x := load.(type) {
		case *macho.Segment:
			if x.Cmd == macho.LoadCmdSegment {
				t.Logf("segment32 load, name: %s, vmaddr: 0x%x, vmsize: 0x%x, sections count: %d",
					x.Name, x.Addr, x.Memsz, x.Nsect)
			} else {
				t.Logf("segment64 load, name: %s, vmaddr: 0x%x, vmsize: 0x%x, sections count: %d",
					x.Name, x.Addr, x.Memsz, x.Nsect)
			}
		}
	}

	data, err := f.DWARF()
	if err != nil {
		t.Fatal(err)
	}

	r := data.Reader()
	for {
		entry, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		if entry == nil {
			break
		}

		t.Log("entry tag: ", entry.Tag,
			", is CU: ", dwarf.TagCompileUnit == entry.Tag, ", is SubProgram: ", dwarf.TagSubprogram == entry.Tag)

		ranges, err := data.Ranges(entry)
		if err != nil {
			t.Fatal(err)
		}

		for _, uint64s := range ranges {
			t.Logf("PC low: 0x%x, PC high: 0x%x", uint64s[0], uint64s[1])
		}

		if len(ranges) > 0 {
			t.Log("-----------------------------------------")
		}

		if entry.Tag == dwarf.TagCompileUnit {
			lr, err := data.LineReader(entry)
			if err != nil {
				t.Fatal(err)
			}

			//lr.SeekPC()

			var en dwarf.LineEntry
			for {
				if err = lr.Next(&en); err != nil {
					if errors.Is(err, io.EOF) {
						break
					}
					t.Fatal(err)
				}

				t.Log("Addr: ", en.Address, "file: ", en.File.Name, "line: ", en.Line, "column: ", en.Column)
			}
			//lf := lr.Files()
			//for _, file := range lf {
			//	t.Logf("file: %+#v", file)
			//}
		} else if entry.Tag == dwarf.TagSubprogram {
			for _, field := range entry.Field {
				t.Log("FIELD:   ", field.Attr, ": ", field.Val, ", class: ", field.Class)
			}
		}

		//t.Log("entry offset: ", entry.Offset, ", entry tag: ", entry.Tag.GoString(), ", entry fields count: ", len(entry.Field))
		//
		//for _, field := range entry.Field {
		//	t.Log("attr: ", field.Attr.GoString())
		//	t.Log("val: ", field.Val)
		//	t.Log("class: ", field.Class.GoString())
		//	t.Log()
		//}
		//t.Log()
	}
}
