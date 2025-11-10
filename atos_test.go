package atos

import (
	"debug/dwarf"
	"debug/macho"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
)

func TestReadStruct(t *testing.T) {

	type st struct {
		Num  uint32
		Char byte
		B    bool
		U16  uint16
	}

	var tt st

	f, err := os.Open("testdata/struct.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := binary.Read(f, binary.BigEndian, &tt); err != nil {
		t.Fatal(err)
	}

	t.Logf("0x%x, char: %s, bool: %t, u16: 0x%x", tt.Num, string(tt.Char), tt.B, tt.U16)

}

func TestSymbolTable(t *testing.T) {
	mf, err := OpenMachO("testdata/App.app.dSYM/Contents/Resources/DWARF/App", "arm64")
	if err != nil {
		t.Fatal(err)
	}

	defer mf.Close()

	mf.SetLoadAddress(0x104480000)

	addr := uint64(0x0000000104486ef0) - mf.loadSlide
	t.Logf("addr: 0x%x\n", addr) // addr: 0x100006ef0

	//for _, symbol := range mf.symbolTable {
	//	t.Logf("symbol name: %s, addr: 0x%x", symbol.Name, symbol.Value)
	//}

	symbolName, err := mf.ResolveNameFromSymTab(addr)
	if err != nil {
		t.Fatal(err)
	}

	//t.Logf("symbol: 0x%x\n", 0x100006ea8+mf.loadSlide) // 0x104486ea8
	// name: ___35-[Crasher throwUncaughtNSException]_block_invoke_2, addr: 0x100006ea8, section: __text
	t.Log(symbolName)
}

func TestAtos(t *testing.T) {
	//f, err := Open("testdata/AFNetworking.framework.dSYM/Contents/Resources/DWARF/AFNetworking", "arm64")
	mf, err := OpenMachO("testdata/App.app.dSYM/Contents/Resources/DWARF/App", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	defer mf.Close()

	if mf.vmAddr != 0x100000000 {
		t.Fatalf("vmaddr expect 0x100000000, but got 0x%x, ", mf.vmAddr)
	}

	mf.SetLoadAddress(0x104480000) // set ASLR slide
	//or mf.SetLoadSlide(0x104480000 - mf.vmAddr)

	symbol, err := mf.Atos(0x0000000104486ef0, false)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("func name: %s, source file: %s, at line: %d ",
		symbol.Func, symbol.Line.File.Name, symbol.Line.Line)

}

func Test3(t *testing.T) {
	//f, err := macho.Open("testdata/a.out.dSYM/Contents/Resources/DWARF/a.out")
	f, err := OpenMachO("testdata/App.app.dSYM/Contents/Resources/DWARF/App", "arm64")
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
