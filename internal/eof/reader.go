package eof

import (
	"errors"
	"io"
	"sync/atomic"
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

type TrackingReader struct {
	io.Reader
	reached atomic.Bool
}

func (r *TrackingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		r.reached.Store(true)
	}
	return n, err
}

func (r *TrackingReader) Reached() bool {
	return r.reached.Load()
}

func (r *TrackingReader) Upstream() any {
	return r.Reader
}

func Unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
