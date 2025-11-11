# atos-go
Atos-go is a Mach-O symbolication tool implemented in Go, similar to macOS's atos

# Install
```shell
go install github.com/zhyee/atos-go/cmd/gatos@latest
```

# Usage
```text
gatos [-o executable/dSYM] [-f file-of-input-addresses] [-s slide | -l loadAddress | -textExecAddress addr | -offset] [-arch architecture] [-printHeader] [-fullPath] [-d delimiter] [address ...]

        -d/--delimiter     delimiter when outputting inline frames. Defaults to newline.
        --fullPath         show full path to source file
        --offset           treat all following addresses as offsets into the binary
```
Issue command `gatos --help` for details.

for example:
```shell
$ gatos -o testdata/App.app.dSYM/Contents/Resources/DWARF/App -l 0x104480000 -arch arm64 --fullPath 0x0000000104486ef0 0x0000000104489940
$ __35-[Crasher throwUncaughtNSException]_block_invoke_2 (in App) (/Users/hulilei/Desktop/ft-sdk-ios/App/Crasher.mm:0)
$ main (in App) (/Users/hulilei/Desktop/ft-sdk-ios/App/main.m:18)
```

# Used as a library
```shell
go get github.com/zhyee/atos-go
```

```go
package main

import (
	"log"

	"github.com/zhyee/atos-go"
)

func main() {
	mf, err := atos.OpenMachO("./testdata/App.app.dSYM/Contents/Resources/DWARF/App", atos.ArchARM64)
	if err != nil {
		log.Fatalf("unable to open Mach-O binary: %v", err)
	}

	defer mf.Close()

	mf.SetLoadAddress(0x104480000)

	for _, addr := range []uint64{0x0000000104486ef0, 0x0000000104489940} {
		symbol, err := mf.Atos(addr)
		if err != nil {
			log.Fatalf("unable to symbolize PC [0x%x]: %v", addr, err)
		}
		log.Printf("addr: 0x%x, func: %s, file: %s, line: %d",
			addr, symbol.Func, symbol.Line.File.Name, symbol.Line.Line)
	}
}
```

# Todo
- Resolve inlined function.
- Add parsing cache support.
