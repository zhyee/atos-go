package main

import (
	"debug/macho"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	atos "github.com/zhyee/atos-go"
)

func TestReadAddressFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "addresses.txt")
	if err := os.WriteFile(file, []byte("0x1000\n  2000\t0X3000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	addresses, err := readAddressFile(file)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"0x1000", "2000", "0X3000"}
	if !reflect.DeepEqual(addresses, want) {
		t.Fatalf("addresses = %#v, want %#v", addresses, want)
	}
}

func TestFormatVMAddress(t *testing.T) {
	if got := formatVMAddress(&atos.MachFile{File: &macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic64}}}, 1); got != "0x0000000000000001" {
		t.Fatalf("64-bit address = %q", got)
	}
	if got := formatVMAddress(&atos.MachFile{File: &macho.File{FileHeader: macho.FileHeader{Magic: macho.Magic32}}}, 1); got != "0x00000001" {
		t.Fatalf("32-bit address = %q", got)
	}
}
