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
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const usageMsg = `Usage: %s [-o executable/dSYM] [-f file-of-input-addresses] [-s slide | -l loadAddress | -textExecAddress addr | -offset] [-arch architecture] [-printHeader] [-fullPath] [-inlineFrames] [-d delimiter] [address ...]`

var (
	usage   = fmt.Sprintf(usageMsg, os.Args[0]) + "\n"
	logger  = log.New(os.Stderr, "", 0)
	flagSet *flag.FlagSet
)

func showUsage() {
	logger.Println(usage)
	flagSet.PrintDefaults()
}

func popErr(format string, args ...interface{}) {
	logger.Println(fmt.Sprintf(format, args...))
	os.Exit(1)
}

func popErrAndUsage(format string, v ...any) {
	logger.Println(fmt.Sprintf(format, v...) + "\n")
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
	flagSet = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flagSet.SetOutput(logger.Writer())

	help := flagSet.Bool("h", false, "show this help")
	debug := flagSet.Bool("debug", false, "enable debug logging")
	helpLong := flagSet.Bool("help", false, "show this help")
	bin := flagSet.String("o", "", `The path to a binary image file or dSYM in which to look up symbols`)
	arch := flagSet.String("arch", "arm64", `The particular architecture of a binary image file in which to look up symbols`)
	loadAddr := flagSet.String("l", "", `The load address of the binary image.  This value is always assumed to be in hex, even without a "0x" prefix.  The input addresses are assumed to be in a binary image with that load address.  Load addresses for binary images can be found in the Binary Images: section at the bottom of crash, sample, leaks, and malloc_history reports`)
	textExecAddress := flag.String("textExecAddress", "", `Should be used instead of load address with kernel-space binary images on arm64(e) devices.  This value is always assumed to be in hex, even without a "0x" prefix.
             The input addresses are assumed to be in a binary image with that text exec address. In kernel panic report the text exec address can be found in "Kernel text exec base" line, or for kexts in "Kernel Extensions in backtrace:" section. This value is always assumed to be in hex, even without a "0x" prefix`)
	slide := flagSet.String("s", "", `The slide value of the binary image -- this is the difference between the load address of a binary image, and the address at which the binary image was built.  This slide value is subtracted from the input addresses.  It is usually easier to directly specify the load address with the -l argument than to manually calculate a slide value. This value is always assumed to be in hex, even without a "0x" prefix`)
	isOffset := flagSet.Bool("offset", false, `Treat all given addresses as offsets into the binary. Only one of the following options can be used at a time: -s , -l , -textExecAddress or -offset`)
	fullPath := flagSet.Bool("fullPath", false, `Print the full path of the source files`)
	inline := flagSet.Bool("i", false, `Display inlined symbols, not yet implemented`)
	inlineLong := flagSet.Bool("inlineFrames", false, `Display inlined symbols, not yet implemented`)
	delimiter := flagSet.String("d", "\n", `Delimiter when outputting inline frames. Defaults to newline`)
	_ = flagSet.Parse(os.Args[1:])
	addresses := flagSet.Args()

	// TODO: show inlined function
	_ = inline
	_ = inlineLong

	if *help || *helpLong {
		showUsage()
		return
	}

	if *debug {
		atos.Log = zap.New(zapcore.NewCore(
			zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
			zapcore.AddSync(logger.Writer()),
			zapcore.DebugLevel)).Sugar()
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
		loadSlide, err = strconv.ParseUint(prependHexSign(*slide), 0, 64)
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
		atos.Log.Debugf("unable to parse architecture [%q]: %v", *arch, err)
		popErr("Unknown architecture [%s]", *arch)
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

	var pc uint64
	for _, addr := range addresses {
		if *isOffset {
			offset, err := strconv.ParseUint(prependHexSign(addr), 0, 64)
			if err != nil {
				atos.Log.Debugf("invalid address offset [%s]: %v", addr, err)
				fmt.Printf("%s%s", addr, *delimiter)
				continue
			}
			pc = mf.LoadAddress() + offset
		} else {
			pc, err = strconv.ParseUint(prependHexSign(addr), 0, 64)
			if err != nil {
				atos.Log.Debugf("invalid address [%s]: %v", addr, err)
				fmt.Printf("%s%s", addr, *delimiter)
				continue
			}
		}
		symbol, err := mf.Atos(pc)
		if err != nil {
			atos.Log.Debugf("unable to symbolize PC [%s]: %v", addr, err)
			fmt.Printf("%s%s", addr, *delimiter)
			continue
		}
		filename := symbol.Line.File.Name
		if !(*fullPath) {
			filename = path.Base(filename)
		}
		printf("%s (in %s) (%s:%d)%s", symbol.Func, binaryFile, filename, symbol.Line.Line, *delimiter)
	}
}
