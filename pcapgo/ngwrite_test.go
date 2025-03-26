// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcapgo

import (
	"bufio"
	"bytes"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestNgWriteSimple(t *testing.T) {
	buffer := &bytes.Buffer{}

	w, err := NewNgWriter(buffer, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal("Opening file failed with: ", err)
	}
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Unix(0, 0).UTC(),
		Length:         len(ngPacketSource[0]),
		CaptureLength:  len(ngPacketSource[0]),
		InterfaceIndex: 0,
	}
	err = w.WritePacket(ci, ngPacketSource[0])
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	err = w.Flush()
	if err != nil {
		t.Fatal("Couldn't flush buffer", err)
	}

	interf := DefaultNgInterface
	interf.LinkType = layers.LinkTypeEthernet

	test := ngFileReadTest{
		testContents: bytes.NewReader(buffer.Bytes()),
		linkType:     layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: DefaultNgWriterOptions.SectionInfo,
				ifaces: []NgInterface{
					interf,
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci:   ci,
			},
		},
	}

	ngRunFileReadTest(test, "", false, t)
}

func TestNgWriteComplex(t *testing.T) {
	test := ngFileReadTest{
		linkType: layers.LinkTypeEthernet,
		sections: []ngFileReadTestSection{
			{
				sectionInfo: NgSectionInfo{
					Comment: "A test",
				},
				ifaces: []NgInterface{
					{
						Name:                "in0",
						Comment:             "test0",
						Description:         "some test interface",
						LinkType:            layers.LinkTypeEthernet,
						TimestampResolution: 3,
						Statistics: NgInterfaceStatistics{
							LastUpdate:      time.Unix(1519128000, 195312500).UTC(),
							StartTime:       time.Unix(1519128000-100, 195312500).UTC(),
							EndTime:         time.Unix(1519128000, 195312500).UTC(),
							PacketsReceived: 100,
							PacketsDropped:  1,
						},
					},
					{
						Name:            "null0",
						Description:     "some test interface",
						Filter:          "none",
						OS:              "not needed",
						LinkType:        layers.LinkTypeEthernet,
						TimestampOffset: 100,
						Statistics: NgInterfaceStatistics{
							LastUpdate: time.Unix(1519128000, 195312500).UTC(),
						},
					},
				},
			},
		},
		packets: []ngFileReadTestPacket{
			{
				data: ngPacketSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-900, 195312500).UTC(),
					Length:         len(ngPacketSource[0]),
					CaptureLength:  len(ngPacketSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[4],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-800, 195312500).UTC(),
					Length:         len(ngPacketSource[4]),
					CaptureLength:  len(ngPacketSource[4]),
					InterfaceIndex: 1,
				},
			},
			{
				data: ngPacketSource[1],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-500, 195312500).UTC(),
					Length:         len(ngPacketSource[1]),
					CaptureLength:  len(ngPacketSource[1]),
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[2][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-300, 195312500).UTC(),
					Length:         len(ngPacketSource[2]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: ngPacketSource[3],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-200, 195312500).UTC(),
					Length:         len(ngPacketSource[3]),
					CaptureLength:  len(ngPacketSource[3]),
					InterfaceIndex: 0,
				},
			},
		},
	}

	buffer := &bytes.Buffer{}

	options := NgWriterOptions{
		SectionInfo: test.sections[0].sectionInfo,
	}

	w, err := NewNgWriterInterface(buffer, test.sections[0].ifaces[0], options)
	if err != nil {
		t.Fatal("Opening file failed with: ", err)
	}

	packets := test.packets
	err = w.WritePacket(packets[0].ci, packets[0].data)
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	id, err := w.AddInterface(test.sections[0].ifaces[1])
	if err != nil {
		t.Fatal("Couldn't add interface", err)
	}
	if id != 1 {
		t.Fatalf("Expected interface id 1, but got %d", id)
	}
	err = w.WritePacket(packets[1].ci, packets[1].data)
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	err = w.WriteInterfaceStats(1, test.sections[0].ifaces[1].Statistics)
	if err != nil {
		t.Fatal("Couldn't write interface stats", err)
	}
	err = w.WritePacket(packets[2].ci, packets[2].data)
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	err = w.WritePacket(packets[3].ci, packets[3].data)
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	err = w.WritePacket(packets[4].ci, packets[4].data)
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	err = w.WriteInterfaceStats(0, test.sections[0].ifaces[0].Statistics)
	if err != nil {
		t.Fatal("Couldn't write interface stats", err)
	}

	err = w.Flush()
	if err != nil {
		t.Fatal("Couldn't flush buffer", err)
	}

	// writer fixes resolution to 9
	test.sections[0].ifaces[0].TimestampResolution = 9
	test.sections[0].ifaces[1].TimestampResolution = 9

	// compensate for offset on interface 1
	test.sections[0].ifaces[1].Statistics.LastUpdate = test.sections[0].ifaces[1].Statistics.LastUpdate.Add(100 * time.Second)
	test.packets[1].ci.Timestamp = test.packets[1].ci.Timestamp.Add(100 * time.Second)

	test.testContents = bytes.NewReader(buffer.Bytes())

	ngRunFileReadTest(test, "", false, t)
}

func TestWriteTLSKeyLog(t *testing.T) {
	// Create a buffer to capture the output
	buffer := new(bytes.Buffer)

	// Create a new NgWriter with the buffer
	w := &NgWriter{
		w: bufio.NewWriter(buffer),
	}

	// Call the WriteTLSKeyLog function with some test data
	kl := []byte("test key log!")
	w.WriteTLSKeyLog(kl)

	// Flush the buffer and capture the result
	w.Flush()
	result := buffer.Bytes()

	if len(result) != 36 {
		t.Fatalf("Expected 36 bytes, got %d", len(result))
	}
	if !bytes.Equal(result[0:4], []byte{0x0A, 0x00, 0x00, 0x00}) {
		t.Fatalf("Unexpected block type %x", result[0:4])
	}
	if !bytes.Equal(result[4:8], []byte{36, 0, 0, 0}) {
		t.Fatalf("Unexpected value in 1st length field %v", result[4:8])
	}
	if !bytes.Equal(result[8:12], []byte{0x4b, 0x53, 0x4c, 0x54}) {
		t.Fatalf("Unexpected key log format %x", result[8:12])
	}
	if !bytes.Equal(result[12:16], []byte{13, 0, 0, 0}) {
		t.Fatalf("Unexpected value in key log length field %x", result[12:16])
	}
	if !bytes.Equal(result[16:29], []byte("test key log!")) {
		t.Fatalf(`Unexpected key log data "%s"`, result[16:29])
	}
	if !bytes.Equal(result[29:32], []byte{0, 0, 0}) {
		t.Fatalf("Expected zero-padding, got %x", result[29:32])
	}
	if !bytes.Equal(result[32:36], []byte{36, 0, 0, 0}) {
		t.Fatalf("Unexpected value in 2nd length field %v", result[32:36])
	}
}

func TestWriteCustomBlock(t *testing.T) {
	// Create a buffer to capture the output
	buffer := new(bytes.Buffer)

	// Create a new NgWriter with the buffer
	w := &NgWriter{
		w: bufio.NewWriter(buffer),
	}

	// Write a custom block
	blockType := uint32(0xDEADBEEF)
	body := []byte("test body")
	w.WriteCustomBlock(blockType, body)

	// Flush the buffer and capture the result
	w.Flush()
	result := buffer.Bytes()

	if len(result) != 24 {
		t.Fatalf("Expected 24 bytes, got %d", len(result))
	}
	if !bytes.Equal(result[0:4], []byte{0xEF, 0xBE, 0xAD, 0xDE}) {
		t.Fatalf("Unexpected block type %x", result[0:4])
	}
	if !bytes.Equal(result[4:8], []byte{24, 0, 0, 0}) {
		t.Fatalf("Unexpected value in 1st length field %v", result[4:8])
	}
	if !bytes.Equal(result[8:17], []byte("test body")) {
		t.Fatalf(`Unexpected body "%s"`, result[8:17])
	}
	if !bytes.Equal(result[17:20], []byte{0, 0, 0}) {
		t.Fatalf("Expected zero-padding, got %x", result[17:20])
	}
	if !bytes.Equal(result[20:24], []byte{24, 0, 0, 0}) {
		t.Fatalf("Unexpected value in 2nd length field %v", result[20:24])
	}
}

func TestWriteCustomBlock_EmptyBody(t *testing.T) {
	// Create a buffer to capture the output
	buffer := new(bytes.Buffer)

	// Create a new NgWriter with the buffer
	w := &NgWriter{
		w: bufio.NewWriter(buffer),
	}

	// Write a custom block with an empty body
	blockType := uint32(0xABADFACE)
	w.WriteCustomBlock(blockType, nil)

	// Flush the buffer and capture the result
	w.Flush()
	result := buffer.Bytes()

	if len(result) != 12 {
		t.Fatalf("Expected 16 bytes, got %d", len(result))
	}
	if !bytes.Equal(result[0:4], []byte{0xCE, 0xFA, 0xAD, 0xAB}) {
		t.Fatalf("Unexpected block type %x", result[0:4])
	}
	if !bytes.Equal(result[4:8], []byte{12, 0, 0, 0}) {
		t.Fatalf("Unexpected value in 1st length field %v", result[4:8])
	}
	if !bytes.Equal(result[8:12], []byte{12, 0, 0, 0}) {
		t.Fatalf("Unexpected value in 2nd length field %v", result[12:16])
	}
}

type ngDevNull struct{}

func (w *ngDevNull) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func BenchmarkNgWritePacket(b *testing.B) {
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(0x01020304, 0xAA*1000),
		Length:        0xABCD,
		CaptureLength: 10,
	}
	data := []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	w, err := NewNgWriter(&ngDevNull{}, layers.LinkTypeEthernet)
	if err != nil {
		b.Fatal("Failed creating writer:", err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w.WritePacket(ci, data)
	}
}
