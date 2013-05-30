package assembly

import (
	"errors"
	"io"
)

// NewReaderStream returns a new ReaderStream object.
// If lossErrors is true, this stream will return ReaderStreamDataLoss
// errors from its Read function whenever it determines data has been lost.
// Otherwise, it will only ever return an io.EOF error.
func NewReaderStream(lossErrors bool) ReaderStream {
	r := ReaderStream{
		reassembled: make(chan []Reassembly),
		done:        make(chan bool),
		lossErrors:  lossErrors,
	}
	<-r.done // Grab first done thing.
	return r
}

// ReaderStream implements both assembly.Stream and io.Reader.  You can use it
// as a building block to make simple, easy stream handlers.
//
// IMPORTANT:  If you use a ReaderStream, you MUST read ALL BYTES from it,
// quickly.  Not reading available bytes will block TCP stream reassembly.
type ReaderStream struct {
	reassembled  chan []Reassembly
	done         chan bool
	current      []Reassembly
	closed       bool
	lossErrors   bool
	lossReported bool
}

// Reassembled implements assembly.Stream's Reassembled function.
func (r *ReaderStream) Reassembled(reassembly []Reassembly) {
	r.reassembled <- reassembly
	<-r.done
}

// ReassemblyComplete implements assembly.Stream's ReassemblyComplete function.
func (r *ReaderStream) ReassemblyComplete() {
	close(r.reassembled)
	close(r.done)
}

func (r *ReaderStream) stripEmpty() {
	for len(r.current) > 0 && len(r.current[0].Bytes) == 0 {
		r.current = r.current[:len(r.current)-1]
		r.lossReported = false
	}
}

// DataLost is returned by the ReaderStream's Read function when it encounters
// a Reassembly with the Skip bit set.
var DataLost error = errors.New("lost data")

// Read implements io.Reader's Read function.
// Given a byte slice, it will either copy a non-zero number of bytes into
// that slice and return the number of bytes and a nil error, or it will
// leave slice p as is and return 0, io.EOF.
func (r *ReaderStream) Read(p []byte) (int, error) {
	var ok bool
	r.stripEmpty()
	for !r.closed && len(r.current) == 0 {
		r.done <- true
		if r.current, ok = <-r.reassembled; ok {
			r.stripEmpty()
		} else {
			r.closed = true
		}
	}
	if len(r.current) > 0 {
		current := &r.current[0]
		if r.lossErrors && !r.lossReported && current.Skip {
			r.lossReported = true
			return 0, DataLost
		}
		length := copy(p, current.Bytes)
		current.Bytes = current.Bytes[length:]
		return length, nil
	}
	return 0, io.EOF
}
