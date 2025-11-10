package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/zhyee/atos-go"
)

const usageMsg = `Usage: %s [-o executable/dSYM] [-f file-of-input-addresses] [-s slide | -l loadAddress | -textExecAddress addr | -offset] [-arch architecture] [-printHeader] [-fullPath] [-inlineFrames] [-d delimiter] [address ...]

        -d/--delimiter     delimiter when outputting inline frames. Defaults to newline.
        --fullPath         show full path to source file
        -i/--inlineFrames  display inlined functions
        --offset           treat all following addresses as offsets into the binary
`

var (
	usage  = fmt.Sprintf(usageMsg, os.Args[0])
	stderr = log.New(os.Stderr, "", 0)
)

func showUsage() {
	stderr.Println(usage)
}

func popErrAndUsage(format string, v ...any) {
	stderr.Println(fmt.Sprintf(format, v...) + "\n")
	showUsage()
	os.Exit(1)
}

func printf(format string, v ...any) {
	_, err := fmt.Fprintf(os.Stdout, format, v...)
	if err != nil {
		panic(err)
	}
}

func prependHexSign(addr string) string {
	if !strings.HasPrefix(addr, "0x") && !strings.HasPrefix(addr, "0X") {
		addr = "0x" + addr
	}
	return addr
}

func main() {
	flagSet := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	help := flagSet.Bool("h", false, "show this help")
	helpLong := flagSet.Bool("help", false, "show this help")
	bin := flagSet.String("o", "", `The path to a binary image file or dSYM in which to look up symbols`)
	arch := flagSet.String("arch", "arm64", `The particular architecture of a binary image file in which to look up symbols`)
	loadAddr := flagSet.String("l", "", `The load address of the binary image.  This value is always assumed to be in hex, even without a "0x" prefix.  The input addresses are assumed to be in a binary image with that load address.  Load addresses for binary images can be found in the Binary Images: section at the bottom of crash, sample, leaks, and malloc_history reports`)
	textExecAddress := flag.String("textExecAddress", "", `Should be used instead of load address with kernel-space binary images on arm64(e) devices.  This value is always assumed to be in hex, even without a "0x" prefix.
             The input addresses are assumed to be in a binary image with that text exec address. In kernel panic report the text exec address can be found in "Kernel text exec base" line, or for kexts in "Kernel Extensions in backtrace:" section.`)
	slide := flagSet.String("s", "", `The slide value of the binary image -- this is the difference between the load address of a binary image, and the address at which the binary image was built.  This slide value is subtracted from the input addresses.  It is usually easier to directly specify the load address with the -l argument than to manually calculate a slide value`)
	isOffset := flagSet.Bool("offset", false, `Treat all given addresses as offsets into the binary. Only one of the following options can be used at a time: -s , -l , -textExecAddress or -offset`)
	fullPath := flagSet.Bool("fullPath", false, `Print the full path of the source files`)
	inline := flagSet.Bool("i", false, `Display inlined symbols`)
	inlineLong := flagSet.Bool("inlineFrames", false, `Display inlined symbols`)
	delimiter := flagSet.String("d", "\n", `Delimiter when outputting inline frames. Defaults to newline`)
	_ = flagSet.Parse(os.Args[1:])
	addresses := flagSet.Args()

	// TODO: handle inlined function
	_ = inline
	_ = inlineLong

	if *help || *helpLong {
		showUsage()
		return
	}

	var (
		err                            error
		lAddr, kernelLoadAt, loadSlide uint64
	)

	addrParams := 0
	if *loadAddr != "" {
		lAddr, err = strconv.ParseUint(prependHexSign(*loadAddr), 0, 64)
		if err != nil {
			popErrAndUsage("invalid load address: %v", err)
		}
		addrParams++
	}
	if *textExecAddress != "" {
		kernelLoadAt, err = strconv.ParseUint(prependHexSign(*textExecAddress), 0, 64)
		if err != nil {
			popErrAndUsage("invalid text exec address: %v", err)
		}
		addrParams++
	}
	if *slide != "" {
		loadSlide, err = strconv.ParseUint(*slide, 0, 64)
		if err != nil {
			popErrAndUsage("invalid slide value: %v", err)
		}
		addrParams++
	}
	if *isOffset {
		addrParams++
	}

	if addrParams > 1 {
		popErrAndUsage(`only one of "-s , -l , -textExecAddress or -offset" can be used at a time`)
	}

	if *bin == "" {
		popErrAndUsage("no executable or dSYM file specified")
	}

	ac, err := atos.ParseArch(*arch)
	if err != nil {
		popErrAndUsage("invalid architecture [%s]: %v", *arch, err)
	}

	binaryFile := filepath.Base(*bin)
	mf, err := atos.OpenMachO(*bin, ac)
	if err != nil {
		popErrAndUsage("unable to open the executable or dSYM file: %v", err)
	}
	defer mf.Close()

	if lAddr > 0 {
		mf.SetLoadAddress(lAddr)
	}

	if kernelLoadAt > 0 {
		mf.SetLoadAddress(kernelLoadAt)
	}

	if loadSlide > 0 {
		mf.SetLoadSlide(loadSlide)
	}

	var vmAddr uint64
	for _, addr := range addresses {
		if *isOffset {
			vmAddr, err = strconv.ParseUint(addr, 0, 64)
			if err != nil {
				fmt.Printf("invalid address offset [%s]: %v", addr, err)
			}
			vmAddr += mf.VMAddr()
		} else {
			vmAddr, err = strconv.ParseUint(prependHexSign(addr), 0, 64)
			if err != nil {
				printf("invalid address [%s]: %v\n", addr, err)
				continue
			}
			vmAddr -= mf.LoadSlide()
		}
		symbol, err := mf.Atos(vmAddr)
		if err != nil {
			printf("invalid address [%s]: %v\n", addr, err)
			continue
		}
		filename := symbol.Line.File.Name
		if !(*fullPath) {
			filename = path.Base(filename)
		}
		printf("%s (in %s) (%s:%d)%s", symbol.Func, binaryFile, filename, symbol.Line.Line, *delimiter)
	}
}
