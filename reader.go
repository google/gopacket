package assembly

import (
	"io"
)

func NewReaderStream() *ReaderStream {
	r := &ReaderStream{
		reassembled: make(chan []Reassembly),
		done:        make(chan bool),
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
	key         Key
	reassembled chan []Reassembly
	done        chan bool
	current     []Reassembly
	closed      bool
}

// Reassembled implements assembly.Stream's Reassembled function.
func (r *ReaderStream) Reassembled(reassembly []Reassembly) {
	r.reassembled <- reassembly
	<-r.done
}

func (r *ReaderStream) ReassemblyComplete() {
	close(r.reassembled)
	close(r.done)
}

func (r *ReaderStream) stripEmpty() {
	for len(r.current) > 0 && len(r.current[0].Bytes) == 0 {
		r.current = r.current[:len(r.current)-1]
	}
}

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
		length := copy(p, r.current[0].Bytes)
		r.current[0].Bytes = r.current[0].Bytes[length:]
		return length, nil
	}
	return 0, io.EOF
}
