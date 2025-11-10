package atos

import (
	"fmt"
	"io"
)

type bytesReader struct {
	data   []byte
	offset int // next read position or the length of bytes which has been read.
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

// Len denotes the length of the unread bytes
func (r *bytesReader) Len() int {
	return len(r.data) - r.offset
}

func (r *bytesReader) Offset() int {
	return r.offset
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}

func (r *bytesReader) ReadByte() (b byte, err error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	b = r.data[r.offset]
	r.offset++
	return b, nil
}

func (r *bytesReader) Skip(n int) (int, error) {
	if r.offset+n > len(r.data) {
		n = len(r.data) - r.offset
		r.offset = len(r.data)
		return n, io.ErrUnexpectedEOF
	}
	r.offset += n
	return n, nil
}

func (r *bytesReader) Bytes(n int) ([]byte, error) {
	if r.offset+n > len(r.data) {
		b := r.data[r.offset:]
		r.offset = len(r.data)
		return b, io.ErrUnexpectedEOF
	}
	b := r.data[r.offset : r.offset+n]
	r.offset += n
	return b, nil
}

func (r *bytesReader) Seek(offset int64, whence int) (int64, error) {
	var newOff int64
	switch whence {
	case io.SeekStart:
		newOff = offset
	case io.SeekCurrent:
		newOff = int64(r.offset) + offset
	case io.SeekEnd:
		newOff = int64(len(r.data)) + offset
	default:
		return int64(r.offset), fmt.Errorf("invalid seek whence: %d", whence)
	}
	if newOff < 0 {
		return 0, fmt.Errorf("resolved seek offset invalid: %d", offset)
	}
	r.offset = int(newOff)
	return newOff, nil
}
