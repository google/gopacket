// Copyright 2018 The GoPacket Authors. All rights reserved.

package pcapnggo

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestPcapngWriteSimple(t *testing.T) {
	buffer := &bytes.Buffer{}

	w, err := NewWriter(buffer, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal("Opening file failed with: ", err)
	}
	ci := gopacket.CaptureInfo{
		Timestamp:      time.Unix(0, 0).UTC(),
		Length:         len(packetSource[0]),
		CaptureLength:  len(packetSource[0]),
		InterfaceIndex: 0,
	}
	err = w.WritePacket(ci, packetSource[0])
	if err != nil {
		t.Fatal("Couldn't write packet", err)
	}
	err = w.Flush()
	if err != nil {
		t.Fatal("Couldn't flush buffer", err)
	}

	interf := DefaultInterface
	interf.LinkType = layers.LinkTypeEthernet

	test := fileReadTest{
		testContents: bytes.NewReader(buffer.Bytes()),
		linkType:     layers.LinkTypeEthernet,
		sections: []fileReadTestSection{
			{
				sectionInfo: DefaultWriterOptions.SectionInfo,
				ifaces: []Interface{
					interf,
				},
			},
		},
		packets: []fileReadTestPacket{
			{
				data: packetSource[0],
				ci:   ci,
			},
		},
	}

	runFileReadTest(test, "", false, t)
}

func TestPcapngWriteComplex(t *testing.T) {
	test := fileReadTest{
		linkType: layers.LinkTypeEthernet,
		sections: []fileReadTestSection{
			{
				sectionInfo: SectionInfo{
					Comment: "A test",
				},
				ifaces: []Interface{
					{
						Name:                "in0",
						Comment:             "test0",
						Description:         "some test interface",
						LinkType:            layers.LinkTypeEthernet,
						TimestampResolution: 3,
						Statistics: InterfaceStatistics{
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
						Statistics: InterfaceStatistics{
							LastUpdate: time.Unix(1519128000, 195312500).UTC(),
						},
					},
				},
			},
		},
		packets: []fileReadTestPacket{
			{
				data: packetSource[0],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-900, 195312500).UTC(),
					Length:         len(packetSource[0]),
					CaptureLength:  len(packetSource[0]),
					InterfaceIndex: 0,
				},
			},
			{
				data: packetSource[4],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-800, 195312500).UTC(),
					Length:         len(packetSource[4]),
					CaptureLength:  len(packetSource[4]),
					InterfaceIndex: 1,
				},
			},
			{
				data: packetSource[1],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-500, 195312500).UTC(),
					Length:         len(packetSource[1]),
					CaptureLength:  len(packetSource[1]),
					InterfaceIndex: 0,
				},
			},
			{
				data: packetSource[2][:96],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-300, 195312500).UTC(),
					Length:         len(packetSource[2]),
					CaptureLength:  96,
					InterfaceIndex: 0,
				},
			},
			{
				data: packetSource[3],
				ci: gopacket.CaptureInfo{
					Timestamp:      time.Unix(1519128000-200, 195312500).UTC(),
					Length:         len(packetSource[3]),
					CaptureLength:  len(packetSource[3]),
					InterfaceIndex: 0,
				},
			},
		},
	}

	buffer := &bytes.Buffer{}

	options := WriterOptions{
		SectionInfo: test.sections[0].sectionInfo,
	}

	w, err := NewWriterInterface(buffer, test.sections[0].ifaces[0], options)
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

	runFileReadTest(test, "", false, t)
}

type devNull struct{}

func (w *devNull) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func BenchmarkWritePacket(b *testing.B) {
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Unix(0x01020304, 0xAA*1000),
		Length:        0xABCD,
		CaptureLength: 10,
	}
	data := []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}
	w, err := NewWriter(&devNull{}, layers.LinkTypeEthernet)
	if err != nil {
		b.Fatal("Failed creating writer:", err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w.WritePacket(ci, data)
	}
}
