package reader

import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"fmt"
	"github.com/gconnell/assembly"
	"io"
	"net"
	"testing"
)

var netFlow gopacket.Flow

func init() {
	netFlow, _ = gopacket.FlowFromEndpoints(
		layers.NewIPEndpoint(net.IP{1, 2, 3, 4}),
		layers.NewIPEndpoint(net.IP{5, 6, 7, 8}))
}

type readReturn struct {
	data []byte
	err  error
}
type readSequence struct {
	in   []layers.TCP
	want []readReturn
}
type testReaderFactory struct {
	lossErrors bool
	readSize   int
	ReaderStream
	output chan []byte
}

func (t *testReaderFactory) New(a, b gopacket.Flow) assembly.Stream {
	return &t.ReaderStream
}

func testReadSequence(t *testing.T, lossErrors bool, readSize int, seq readSequence) {
	f := &testReaderFactory{ReaderStream: NewReaderStream()}
	f.ReaderStream.LossErrors = lossErrors
	p := assembly.NewStreamPool(f)
	a := assembly.NewAssembler(p)
	buf := make([]byte, readSize)
	go func() {
		for i, test := range seq.in {
			t.Log("Assembling", i)
			a.Assemble(netFlow, &test)
			t.Log("Assembly done")
		}
	}()
	for i, test := range seq.want {
		t.Log("Waiting for read", i)
		n, err := f.Read(buf[:])
		t.Log("Got read")
		if n != len(test.data) {
			t.Errorf("test %d want %d bytes, got %d bytes", i, len(test.data), n)
		} else if err != test.err {
			t.Errorf("test %d want err %v, got err %v", i, test.err, err)
		} else if !bytes.Equal(buf[:n], test.data) {
			t.Errorf("test %d\nwant: %v\n got: %v\n", i, test.data, buf[:n])
		}
	}
	t.Log("All done reads")
}

func TestRead(t *testing.T) {
	testReadSequence(t, false, 10, readSequence{
		in: []layers.TCP{
			{
				SYN:       true,
				SrcPort:   1,
				DstPort:   2,
				Seq:       1000,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
			},
			{
				FIN:     true,
				SrcPort: 1,
				DstPort: 2,
				Seq:     1004,
			},
		},
		want: []readReturn{
			{data: []byte{1, 2, 3}},
			{err: io.EOF},
		},
	})
}

func TestReadSmallChunks(t *testing.T) {
	testReadSequence(t, false, 2, readSequence{
		in: []layers.TCP{
			{
				SYN:       true,
				SrcPort:   1,
				DstPort:   2,
				Seq:       1000,
				BaseLayer: layers.BaseLayer{Payload: []byte{1, 2, 3}},
			},
			{
				FIN:     true,
				SrcPort: 1,
				DstPort: 2,
				Seq:     1004,
			},
		},
		want: []readReturn{
			{data: []byte{1, 2}},
			{data: []byte{3}},
			{err: io.EOF},
		},
	})
}

func ExampleDiscardBytesToEOF() {
	b := bytes.NewBuffer([]byte{1, 2, 3, 4, 5})
	fmt.Println(DiscardBytesToEOF(b))
	// Output:
	// 5
}
