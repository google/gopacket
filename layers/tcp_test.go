// Copyright 2016, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"reflect"
	"testing"

	"github.com/google/gopacket"
)

func TestTCPOptionKindString(t *testing.T) {
	testData := []struct {
		o *TCPOption
		s string
	}{
		{&TCPOption{
			OptionType:   TCPOptionKindNop,
			OptionLength: 1,
		},
			"TCPOption(NOP:)"},
		{&TCPOption{
			OptionType:   TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{0x12, 0x34},
		},
			"TCPOption(MSS:4660 0x1234)"},
		{&TCPOption{
			OptionType:   TCPOptionKindTimestamps,
			OptionLength: 10,
			OptionData:   []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01},
		},
			"TCPOption(Timestamps:2/1 0x0000000200000001)"},
		{&TCPOption{
			OptionType:   TCPOptionKindMultipathTCP,
			OptionLength: 4,
			OptionMPTCPMpCapable: &MPCapable{
				Version: 1,
			},
		},
			"MPTCPOption(MP_CAPABLE Version 1)"}}

	for _, tc := range testData {
		if s := tc.o.String(); s != tc.s {
			t.Errorf("expected %#v string to be %s, got %s", tc.o, tc.s, s)
		}
	}
}

func TestTCPSerializePadding(t *testing.T) {
	tcp := &TCP{}
	tcp.Options = append(tcp.Options, TCPOption{
		OptionType:   TCPOptionKindNop,
		OptionLength: 1,
	})
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, tcp)
	if err != nil {
		t.Fatal(err)
	}
	if len(buf.Bytes())%4 != 0 {
		t.Errorf("TCP data of len %d not padding to 32 bit boundary", len(buf.Bytes()))
	}
}

// testPacketTCPOptionDecode is the packet:
//   16:17:26.239051 IP 192.168.0.1.12345 > 192.168.0.2.54321: Flags [S], seq 3735928559:3735928563, win 0, options [mss 8192,mpcapable,eol], length 8
//   	0x0000:  0000 0000 0001 0000  0000 0001 0800 4500  ..............E.
//   	0x0010:  0038 0000 0000 8006  0000 c0a8 0001 c0a8  .8..............
//   	0x0020:  0002 3039 d431 dead  beef 0000 0000 8002  ..09.1..........
//   	0x0030:  0000 0000 0000 0204  2000 1e04 0100 0000  ........ .......
//   	0x0040:  0000 5465 7374                            ..Test
var testPacketTCPOptionDecode = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x80, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x00, 0x01, 0xC0, 0xA8,
	0x00, 0x02, 0x30, 0x39, 0xD4, 0x31, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x20, 0x00, 0x1E, 0x04, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x54, 0x65, 0x73, 0x74,
}

func TestPacketTCPOptionDecode(t *testing.T) {
	p := gopacket.NewPacket(testPacketTCPOptionDecode, LinkTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	tcp := p.Layer(LayerTypeTCP).(*TCP)
	if tcp == nil {
		t.Error("Expected TCP layer, but got none")
	}

	expected := []TCPOption{
		{
			OptionType:   TCPOptionKindMSS,
			OptionLength: 4,
			OptionData:   []byte{32, 00},
		},
		{
			OptionType:   TCPOptionKindMultipathTCP,
			OptionLength: 4,
			OptionMPTCPMpCapable: &MPCapable{
				Version: 1,
			},
		},
		{
			OptionType:   TCPOptionKindEndList,
			OptionLength: 1,
		},
	}

	if !reflect.DeepEqual(expected, tcp.Options) {
		t.Errorf("expected options to be %#v, but got %#v", expected, tcp.Options)
	}
}
