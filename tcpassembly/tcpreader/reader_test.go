// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package tcpreader

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
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
type readInputWithTimestamp struct {
	tcp       layers.TCP
	timestamp time.Time
}
type readReturnWithTimestamp struct {
	readReturn
	timestamp time.Time
}
type readSequenceWithTimestamp struct {
	in   []readInputWithTimestamp
	want []readReturnWithTimestamp
}

func (t *testReaderFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	return &t.ReaderStream
}

func testReadSequence(t *testing.T, lossErrors bool, readSize int, seq readSequence) {
	f := &testReaderFactory{ReaderStream: NewReaderStream()}
	f.ReaderStream.LossErrors = lossErrors
	p := tcpassembly.NewStreamPool(f)
	a := tcpassembly.NewAssembler(p)
	buf := make([]byte, readSize)
	go func() {
		for i, test := range seq.in {
			fmt.Println("Assembling", i)
			a.Assemble(netFlow, &test)
			fmt.Println("Assembly done")
		}
	}()
	for i, test := range seq.want {
		fmt.Println("Waiting for read", i)
		n, err := f.Read(buf[:])
		fmt.Println("Got read")
		if n != len(test.data) {
			t.Errorf("test %d want %d bytes, got %d bytes", i, len(test.data), n)
		} else if err != test.err {
			t.Errorf("test %d want err %v, got err %v", i, test.err, err)
		} else if !bytes.Equal(buf[:n], test.data) {
			t.Errorf("test %d\nwant: %v\n got: %v\n", i, test.data, buf[:n])
		}
	}
	fmt.Println("All done reads")
}

func testReadFullSequenceWithTimestamp(t *testing.T, lossErrors bool, seq readSequenceWithTimestamp) {
	f := &testReaderFactory{ReaderStream: NewReaderStream()}
	f.ReaderStream.LossErrors = lossErrors
	p := tcpassembly.NewStreamPool(f)
	a := tcpassembly.NewAssembler(p)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		for i, test := range seq.in {
			fmt.Println("Assembling", i)
			a.AssembleWithTimestamp(netFlow, &test.tcp, test.timestamp)
			fmt.Println("Assembly done")
		}
		wg.Done()
	}()
	for i, test := range seq.want {
		buf := make([]byte, len(test.data))
		fmt.Println("Waiting for read", i)
		n, err := io.ReadFull(f, buf)
		fmt.Println("Got read")
		if n != len(test.data) {
			t.Errorf("test %d want %d bytes, got %d bytes", i, len(test.data), n)
		} else if err != test.err {
			t.Errorf("test %d want err %v, got err %v", i, test.err, err)
		} else if !bytes.Equal(buf[:n], test.data) {
			t.Errorf("test %d\nwant: %v\n got: %v\n", i, test.data, buf[:n])
		} else if f.Seen() != test.timestamp {
			t.Errorf("test %d\nwant: %v\n got: %v\n", i, test.timestamp, f.Seen())
		}
	}
	fmt.Println("All done reads, testing for EOF")
	buf := make([]byte, 1)
	n, err := io.ReadFull(f, buf)
	if n != 0 {
		t.Errorf("test EOF want 0 bytes, got %d bytes", n)
	} else if err != io.EOF {
		t.Errorf("test EOF want err io.EOF, got err %v", err)
	} else if !f.Seen().IsZero() {
		t.Errorf("test EOF want 0 got %v", f.Seen())
	}
	wg.Wait()
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

func TestReadTimestamps(t *testing.T) {
	t0 := time.Now()
	t1 := t0.Add(1 * time.Millisecond)
	t2 := t0.Add(2 * time.Millisecond)
	testReadFullSequenceWithTimestamp(t, false, readSequenceWithTimestamp{
		in: []readInputWithTimestamp{
			{
				tcp: layers.TCP{
					SYN:       true,
					SrcPort:   1,
					DstPort:   2,
					Seq:       1000,
					BaseLayer: layers.BaseLayer{Payload: []byte{1, 2}},
				},
				timestamp: t0,
			},
			{
				tcp: layers.TCP{
					SrcPort:   1,
					DstPort:   2,
					Seq:       1003,
					BaseLayer: layers.BaseLayer{Payload: []byte{3, 4}},
				},
				timestamp: t1,
			},
			{
				tcp: layers.TCP{
					SrcPort:   1,
					DstPort:   2,
					Seq:       1005,
					BaseLayer: layers.BaseLayer{Payload: []byte{5, 6}},
				},
				timestamp: t2,
			},
			{
				tcp: layers.TCP{
					FIN:     true,
					SrcPort: 1,
					DstPort: 2,
					Seq:     1007,
				},
			},
		},
		want: []readReturnWithTimestamp{
			{readReturn: readReturn{data: []byte{1}}, timestamp: t0},
			{readReturn: readReturn{data: []byte{2}}, timestamp: t0},
			{readReturn: readReturn{data: []byte{3}}, timestamp: t1},
			{readReturn: readReturn{data: []byte{4, 5}}, timestamp: t2},
			{readReturn: readReturn{data: []byte{6}}, timestamp: t2},
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
