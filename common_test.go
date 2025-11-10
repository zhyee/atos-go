package atos

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestBytesReader(t *testing.T) {
	testBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	br := newBytesReader(testBytes)
	b, err := br.ReadByte()
	if err != nil {
		t.Fatal(err)
	}
	if b != 0x01 {
		t.Fatalf("ReadByte returned wrong byte")
	}
	if br.Offset() != 1 {
		t.Fatalf("ReadByte returned wrong offset")
	}

	buf, err := br.Bytes(4)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(buf, testBytes[1:5]) != 0 {
		t.Fatalf("ReadByte returned wrong bytes")
	}
	if br.Offset() != 5 {
		t.Fatalf("ReadByte returned wrong offset")
	}

	n, err := br.Skip(3)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("ReadByte returned wrong length")
	}
	if br.Offset() != 8 {
		t.Fatalf("ReadByte returned wrong offset")
	}

	_, err = br.ReadByte()
	if !errors.Is(err, io.EOF) {
		t.Fatalf("expect EOF, got %T", err)
	}

	if _, err = br.Seek(-1, io.SeekCurrent); err != nil {
		t.Fatal(err)
	}
	b, err = br.ReadByte()
	if err != nil {
		t.Fatal(err)
	}
	if b != 0x08 {
		t.Fatalf("ReadByte returned wrong byte")
	}

	if _, err = br.Seek(4, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	all, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(all, testBytes[4:]) != 0 {
		t.Fatalf("ReadByte returned wrong bytes")
	}
}
