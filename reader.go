package assembly

import (
	"errors"
	"io"
)

var discardBytes [4096]byte
var discardBuffer = discardBytes[:]

// DiscardBytesToFirstError will read in all bytes up to the first error
// reported by the given reader, then return the number of bytes discarded
// and the error encountered.
func DiscardBytesToFirstError(r io.Reader) (discarded int, err error) {
	for {
		n, e := r.Read(discardBuffer)
		discarded += n
		if e != nil {
			return discarded, e
		}
	}
}

// DiscardBytesToEOF will read in all bytes from a Reader until it
// encounters an io.EOF, then return the number of bytes.  Be careful
// of this... if used on a Reader that returns a non-io.EOF error
// consistently, this will loop forever discarding that error while
// it waits for an EOF.
func DiscardBytesToEOF(r io.Reader) (discarded int) {
	for {
		n, e := DiscardBytesToFirstError(r)
		discarded += n
		if e == io.EOF {
			return
		}
	}
}

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

// Close implements io.Closer's Close function, making ReaderStream a
// io.ReadCloser.  It discards all remaining bytes in the reassembly in a
// manner that's safe for the assembler (IE: it doesn't block).
func (r *ReaderStream) Close() error {
	r.current = nil
	r.closed = true
	for {
		r.done <- true
		if _, ok := <-r.reassembled; !ok {
			return nil
		}
	}
}
