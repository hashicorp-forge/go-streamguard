/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2023 HashiCorp Inc.
 */

package lite

import (
	"bytes"
	"context"
	"errors"
	"io"
)

// stagedReadWriter allows packets to be staged for Read() or Write()
// using incomingWrite() and outgoingRead(), respectively.
type stagedReadWriter struct {
	incomingChan chan []byte
	outgoingChan chan []byte

	closedCtx context.Context
	closeFunc context.CancelFunc
}

func newStagedReadWriter() *stagedReadWriter {
	closedCtx, closeFunc := context.WithCancel(context.Background())
	return &stagedReadWriter{
		incomingChan: make(chan []byte, 16),
		outgoingChan: make(chan []byte, 16),
		closedCtx:    closedCtx,
		closeFunc:    closeFunc,
	}
}

// outgoingRead reads bytes that were written with Write.
func (d *stagedReadWriter) outgoingRead(p []byte) (int, error) {
	var data []byte
	select {
	case <-d.closedCtx.Done():
		return 0, d.closedCtx.Err()
	case data = <-d.outgoingChan:
	}

	b := bytes.NewBuffer(data)
	n, err := b.Read(p)
	if n < len(data) {
		go func() {
			d.outgoingChan <- data[n:]
		}()
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return n, err
}

// incomingWrite writes bytes that will be read with Read.
func (d *stagedReadWriter) incomingWrite(p []byte) (n int, err error) {
	pCopy := make([]byte, len(p), len(p))
	copy(pCopy, p)

	select {
	case <-d.closedCtx.Done():
		return 0, d.closedCtx.Err()
	case d.incomingChan <- pCopy:
	default:
	}
	return len(p), nil
}

// Read reads bytes that were staged with incomingWrite
func (d *stagedReadWriter) Read(p []byte) (int, error) {
	var data []byte
	select {
	case <-d.closedCtx.Done():
		return 0, d.closedCtx.Err()
	case data = <-d.incomingChan:
	}

	b := bytes.NewBuffer(data)
	n, err := b.Read(p)
	if n < len(data) {
		go func() {
			d.incomingChan <- data[n:]
		}()
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return n, err
}

// Write writes bytes that will be read by outgoingRead
func (d *stagedReadWriter) Write(p []byte) (n int, err error) {
	pCopy := make([]byte, len(p), len(p))
	copy(pCopy, p)

	select {
	case <-d.closedCtx.Done():
		return 0, d.closedCtx.Err()
	case d.outgoingChan <- pCopy:
	default:
	}
	return len(p), nil
}

func (d *stagedReadWriter) Close() error {
	d.closeFunc()
	return nil
}

var _ io.ReadWriteCloser = (*stagedReadWriter)(nil)
