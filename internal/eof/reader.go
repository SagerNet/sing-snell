package eof

import (
	"errors"
	"io"
)

type UnexpectedReader struct {
	io.Reader
}

func (r UnexpectedReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	return n, Unexpected(err)
}

func (r UnexpectedReader) Upstream() any {
	return r.Reader
}

func Unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
