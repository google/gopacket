// Copyright 2014, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"github.com/google/gopacket"
	"net"
	"reflect"
	"testing"
)

func TestSerializeIPv6HeaderTLVOptions(t *testing.T) {
	//RFC 2460 Appendix B
	/*
	   Example 3

	   A Hop-by-Hop or Destination Options header containing both options X
	   and Y from Examples 1 and 2 would have one of the two following
	   formats, depending on which option appeared first:

	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  Next Header  | Hdr Ext Len=3 | Option Type=X |Opt Data Len=12|
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                         4-octet field                         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                                                               |
	   +                         8-octet field                         +
	   |                                                               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | PadN Option=1 |Opt Data Len=1 |       0       | Option Type=Y |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |Opt Data Len=7 | 1-octet field |         2-octet field         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                         4-octet field                         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | PadN Option=1 |Opt Data Len=2 |       0       |       0       |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/

	opt1 := &IPv6HeaderTLVOptionUnknown{}
	opt1.Type = 0x1e
	opt1.Value = []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}
	opt1.Alignment = [2]uint8{8, 2}

	opt2 := &IPv6HeaderTLVOptionUnknown{}
	opt2.Type = 0x3e
	opt2.Value = []byte{0x11, 0x22, 0x22, 0x44, 0x44, 0x44, 0x44}
	opt2.Alignment = [2]uint8{4, 3}

	// Check that Align(Align(X)) == Align(X)
	hopopt1 := []IPv6HeaderTLVOption{opt1, opt2}
	IPv6AlignHeaderTLVOptions(&hopopt1)
	hopopt2 := []IPv6HeaderTLVOption{}
	for i := range hopopt1 {
		hopopt2 = append(hopopt2, hopopt1[i])
	}
	IPv6AlignHeaderTLVOptions(&hopopt2)
	if !reflect.DeepEqual(hopopt1, hopopt2) {
		t.Errorf("Align(Align(X)) != Align(X):\n%#v != %#v\n\n", hopopt1, hopopt2)
	}

	buf := gopacket.NewSerializeBuffer()
	serializeIPv6HeaderTLVOptions(buf, []IPv6HeaderTLVOption{opt1, opt2}, true)
	got := buf.Bytes()
	want := []byte{0x1e, 0x0c, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x01, 0x01, 0x00, 0x3e, 0x07, 0x11, 0x22, 0x22, 0x44, 0x44, 0x44, 0x44, 0x01, 0x02, 0x00, 0x00}

	if !bytes.Equal(got, want) {
		t.Errorf("IPv6HeaderTLVOption serialize (X,Y) failed:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
	}

	/*
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |  Next Header  | Hdr Ext Len=3 | Pad1 Option=0 | Option Type=Y |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |Opt Data Len=7 | 1-octet field |         2-octet field         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                         4-octet field                         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   | PadN Option=1 |Opt Data Len=4 |       0       |       0       |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |       0       |       0       | Option Type=X |Opt Data Len=12|
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                         4-octet field                         |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                                                               |
	   +                         8-octet field                         +
	   |                                                               |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	*/

	buf.Clear()
	serializeIPv6HeaderTLVOptions(buf, []IPv6HeaderTLVOption{opt2, opt1}, true)
	got = buf.Bytes()
	want = []byte{0x00, 0x3e, 0x07, 0x11, 0x22, 0x22, 0x44, 0x44, 0x44, 0x44, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x0c, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb}

	if !bytes.Equal(got, want) {
		t.Errorf("IPv6HeaderTLVOption serialize (Y,X) failed:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
	}
}

var testPacketIPv6HopByHop0 = []byte{
	0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3b, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
}

func TestPacketIPv6HopByHop0Serialize(t *testing.T) {
	var serialize []gopacket.SerializableLayer = make([]gopacket.SerializableLayer, 0, 2)
	var err error

	ip6 := &IPv6{}
	ip6.Version = 6
	ip6.NextHeader = IPProtocolIPv6HopByHop
	ip6.HopLimit = 64
	ip6.SrcIP = net.ParseIP("2001:db8::1")
	ip6.DstIP = net.ParseIP("2001:db8::2")
	serialize = append(serialize, ip6)

	tlv := IPv6HeaderTLVOptionPad(6)
	hop := &IPv6HopByHop{}
	hop.Options = append(hop.Options, tlv)
	hop.NextHeader = IPProtocolNoNextHeader
	serialize = append(serialize, hop)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		t.Fatalf("%s\n\n", err)
	}

	got := buf.Bytes()
	want := testPacketIPv6HopByHop0
	if !bytes.Equal(got, want) {
		t.Errorf("IPv6HopByHop serialize failed:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
	}
}

func TestPacketIPv6HopByHop0Decode(t *testing.T) {
	ip6 := &IPv6{
		BaseLayer: BaseLayer{
			Contents: []byte{
				0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			},
			Payload: []byte{0x3b, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00},
		},
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		Length:       8,
		NextHeader:   IPProtocolIPv6HopByHop,
		HopLimit:     64,
		SrcIP:        net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstIP: net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
	}
	hop := &IPv6HopByHop{}
	hop.ipv6ExtensionBase = ipv6ExtensionBase{
		BaseLayer: BaseLayer{
			Contents: []byte{0x3b, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00},
			Payload:  []byte{},
		},
		NextHeader:   IPProtocolNoNextHeader,
		HeaderLength: uint8(0),
		ActualLength: 8,
	}
	opt := IPv6HeaderTLVOptionPad(6)
	hop.Options = append(hop.Options, opt)

	p := gopacket.NewPacket(testPacketIPv6HopByHop0, LinkTypeRaw, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet: %s\n\n", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeIPv6, LayerTypeIPv6HopByHop}, t)

	if got, ok := p.Layer(LayerTypeIPv6).(*IPv6); ok {
		want := ip6
		if !reflect.DeepEqual(got, want) {
			t.Errorf("IPv6 packet processing failed:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
		}
	} else {
		t.Errorf("No IPv6 layer type found in packet\n\n")
	}
	if got, ok := p.Layer(LayerTypeIPv6HopByHop).(*IPv6HopByHop); ok {
		want := hop
		if !reflect.DeepEqual(got, want) {
			t.Errorf("IPv6HopByHop packet processing failed:\ngot\n%#v\n\nwant:\n%#v\n\n", got, want)
		}
	} else {
		t.Errorf("No IPv6HopByHop layer type found in packet\n\n")
	}
}

// testPacketIPv6Destination0 is the packet:
//   12:40:14.429409595 IP6 2001:db8::1 > 2001:db8::2: DSTOPT no next header
//   	0x0000:  6000 0000 0008 3c40 2001 0db8 0000 0000  `.....<@........
//   	0x0010:  0000 0000 0000 0001 2001 0db8 0000 0000  ................
//   	0x0020:  0000 0000 0000 0002 3b00 0104 0000 0000  ........;.......
var testPacketIPv6Destination0 = []byte{
	0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3c, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3b, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
}

func TestPacketIPv6Destination0Serialize(t *testing.T) {
	var serialize []gopacket.SerializableLayer = make([]gopacket.SerializableLayer, 0, 2)
	var err error

	ip6 := &IPv6{}
	ip6.Version = 6
	ip6.NextHeader = IPProtocolIPv6Destination
	ip6.HopLimit = 64
	ip6.SrcIP = net.ParseIP("2001:db8::1")
	ip6.DstIP = net.ParseIP("2001:db8::2")
	serialize = append(serialize, ip6)

	tlv := IPv6HeaderTLVOptionPad(6)
	dst := &IPv6Destination{}
	dst.Options = append(dst.Options, tlv)
	dst.NextHeader = IPProtocolNoNextHeader
	serialize = append(serialize, dst)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		t.Fatalf("%s\n\n", err)
	}

	got := buf.Bytes()
	want := testPacketIPv6Destination0
	if !bytes.Equal(got, want) {
		t.Errorf("IPv6Destination serialize failed:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
	}
}

func TestPacketIPv6Destination0Decode(t *testing.T) {
	ip6 := &IPv6{
		BaseLayer: BaseLayer{
			Contents: []byte{
				0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3c, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			},
			Payload: []byte{0x3b, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00},
		},
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		Length:       8,
		NextHeader:   IPProtocolIPv6Destination,
		HopLimit:     64,
		SrcIP:        net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstIP: net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
	}

	hop := &IPv6Destination{}
	hop.BaseLayer = BaseLayer{
		Contents: []byte{0x3b, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00},
		Payload:  []byte{},
	}
	hop.NextHeader = IPProtocolNoNextHeader
	hop.HeaderLength = uint8(0)
	hop.ActualLength = 8
	opt := IPv6HeaderTLVOptionPad(6)
	hop.Options = append(hop.Options, opt)

	p := gopacket.NewPacket(testPacketIPv6Destination0, LinkTypeRaw, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet:%s\n\n", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeIPv6, LayerTypeIPv6Destination}, t)

	if got, ok := p.Layer(LayerTypeIPv6).(*IPv6); ok {
		want := ip6
		if !reflect.DeepEqual(got, want) {
			t.Errorf("IPv6 packet processing failed:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
		}
	} else {
		t.Errorf("No IPv6 layer type found in packet\n\n")
	}
	if got, ok := p.Layer(LayerTypeIPv6Destination).(*IPv6Destination); ok {
		want := hop
		if !reflect.DeepEqual(got, want) {
			t.Errorf("IPv6Destination packet processing failed:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
		}
	} else {
		t.Errorf("No IPv6Destination layer type found in packet\n\n")
	}
}

var testPacketIPv6JumbogramHeader = []byte{
	0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3b, 0x00, 0xc2, 0x04, 0x00, 0x01, 0x00, 0x08,
}

func TestIPv6JumbogramSerialize(t *testing.T) {
	var serialize []gopacket.SerializableLayer = make([]gopacket.SerializableLayer, 0, 2)
	var err error

	ip6 := &IPv6{}
	ip6.Version = 6
	ip6.NextHeader = IPProtocolIPv6HopByHop
	ip6.HopLimit = 64
	ip6.SrcIP = net.ParseIP("2001:db8::1")
	ip6.DstIP = net.ParseIP("2001:db8::2")
	serialize = append(serialize, ip6)

	hop := &IPv6HopByHop{}
	hop.NextHeader = IPProtocolNoNextHeader
	serialize = append(serialize, hop)

	payload := make([]byte, ipv6MaxPayloadLength+1)
	for i := range payload {
		payload[i] = 0xfe
	}
	serialize = append(serialize, gopacket.Payload(payload))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		t.Fatalf("%s\n\n", err)
	}

	got := buf.Bytes()
	w := new(bytes.Buffer)
	w.Write(testPacketIPv6JumbogramHeader)
	w.Write(payload)
	want := w.Bytes()

	if !bytes.Equal(got, want) {
		t.Errorf("IPv6 Jumbogram serialize failed:\ngot:\n%v\n\nwant:\n%v\n\n",
			gopacket.LongBytesString(got), gopacket.LongBytesString(want))
	}

}

func TestIPv6JumbogramDecode(t *testing.T) {
	payload := make([]byte, ipv6MaxPayloadLength+1)
	for i := range payload {
		payload[i] = 0xfe
	}

	ip6 := &IPv6{
		BaseLayer: BaseLayer{
			Contents: []byte{
				0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			},
		},
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		Length:       0,
		NextHeader:   IPProtocolIPv6HopByHop,
		HopLimit:     64,
		SrcIP:        net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstIP: net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
	}
	buf := new(bytes.Buffer)
	buf.Write([]byte{0x3b, 0x00, 0xc2, 0x04, 0x00, 0x01, 0x00, 0x08})
	buf.Write(payload)
	ip6.Payload = buf.Bytes()

	hop := &IPv6HopByHop{}
	hop.Contents = []byte{0x3b, 0x00, 0xc2, 0x04, 0x00, 0x01, 0x00, 0x08}
	hop.Payload = payload
	hop.NextHeader = IPProtocolNoNextHeader
	hop.HeaderLength = uint8(0)
	hop.ActualLength = 8
	opt := IPv6HeaderTLVOptionJumbo(len(hop.Contents) + ipv6MaxPayloadLength + 1)
	hop.Options = append(hop.Options, opt)

	pkt := new(bytes.Buffer)
	pkt.Write(testPacketIPv6JumbogramHeader)
	pkt.Write(payload)

	p := gopacket.NewPacket(pkt.Bytes(), LinkTypeRaw, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Errorf("Failed to decode packet: %s\n\n", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeIPv6, LayerTypeIPv6HopByHop, gopacket.LayerTypePayload}, t)

	if got, ok := p.Layer(LayerTypeIPv6).(*IPv6); ok {
		want := ip6
		if !reflect.DeepEqual(got, want) {
			t.Errorf("IPv6 packet processing failed:\ngot:\n%v\n\nwant:\n%v\n\n",
				gopacket.LayerGoString(got), gopacket.LayerGoString(want))
		}
	} else {
		t.Errorf("No IPv6 layer type found in packet\n\n")
	}

	if got, ok := p.Layer(LayerTypeIPv6HopByHop).(*IPv6HopByHop); ok {
		want := hop
		if !reflect.DeepEqual(got, want) {
			t.Errorf("IPv6HopByHop packet processing failed:\ngot:\n%v\n\nwant:\n%v\n\n",
				gopacket.LayerGoString(got), gopacket.LayerGoString(want))
		}
	} else {
		t.Errorf("No IPv6HopByHop layer type found in packet\n\n")
	}

	if got, ok := p.Layer(gopacket.LayerTypePayload).(*gopacket.Payload); ok {
		want := (*gopacket.Payload)(&payload)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Payload packet processing failed:\ngot:\n%v\n\nwant:\n%v\n\n",
				gopacket.LayerGoString(got), gopacket.LayerGoString(want))
		}
	} else {
		t.Errorf("No Payload layer type found in packet\n\n")
	}
}

// testPacketIPv6RoutingType0 is the packet:
//   12:40:14.429409595 IP6 2001:db8::1 > 2001:db8::2: srcrt (len=4, type=0, segleft=2, [0]2001:db8::3, [1]2001:db8::4) no next header
//   	0x0000:  6000 0000 0028 2b40 2001 0db8 0000 0000  `....(+@........
//   	0x0010:  0000 0000 0000 0001 2001 0db8 0000 0000  ................
//   	0x0020:  0000 0000 0000 0004 3b04 0002 0000 0000  ........;.......
//   	0x0030:  2001 0db8 0000 0000 0000 0000 0000 0003  ................
//   	0x0040:  2001 0db8 0000 0000 0000 0000 0000 0004  ................
var testPacketIPv6RoutingType0 = []byte{
	0x60, 0x00, 0x00, 0x00, 0x00, 0x28, 0x2b, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x3b, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
}

func TestPacketIPv6RoutingType0Serialize(t *testing.T) {
	var serialize []gopacket.SerializableLayer = make([]gopacket.SerializableLayer, 0, 2)
	var err error

	ip6 := &IPv6{}
	ip6.Version = 6
	ip6.NextHeader = IPProtocolIPv6Routing
	ip6.HopLimit = 64
	ip6.SrcIP = net.ParseIP("2001:db8::1")
	ip6.DstIP = net.ParseIP("2001:db8::2")
	serialize = append(serialize, ip6)

	rt0 := &IPv6RoutingType0{}
	rt0.NextHeader = IPProtocolNoNextHeader
	rt0.SegmentsLeft = 2
	rt0.SourceRoutingIPs = append(rt0.SourceRoutingIPs, net.ParseIP("2001:db8::3"))
	rt0.SourceRoutingIPs = append(rt0.SourceRoutingIPs, net.ParseIP("2001:db8::4"))
	serialize = append(serialize, rt0)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true}
	err = gopacket.SerializeLayers(buf, opts, serialize...)
	if err != nil {
		t.Fatal(err)
	}

	got := buf.Bytes()
	want := testPacketIPv6RoutingType0
	if !reflect.DeepEqual(got, want) {
		t.Errorf("IPv6RoutingType0 serialize failed:\ngot:\n%#v\n\nwant:\n%#v\n\n", got, want)
	}
}

func TestPacketIPv6RoutingType0Decode(t *testing.T) {
	ip6 := &IPv6{
		BaseLayer: BaseLayer{
			Contents: []byte{
				0x60, 0x00, 0x00, 0x00, 0x00, 0x28, 0x2b, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
			},
			Payload: []byte{0x3b, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
		},
		Version:      6,
		TrafficClass: 0,
		FlowLabel:    0,
		Length:       40,
		NextHeader:   IPProtocolIPv6Routing,
		HopLimit:     64,
		SrcIP:        net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		DstIP: net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
		RoutingDstIP: net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
	}

	rt0 := &IPv6RoutingType0{}
	rt0.BaseLayer = BaseLayer{
		Contents: []byte{0x3b, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
			0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
			0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
		Payload: []byte{},
	}
	rt0.NextHeader = IPProtocolNoNextHeader
	rt0.HeaderLength = uint8(4)
	rt0.ActualLength = 40
	rt0.RoutingType = 0
	rt0.SegmentsLeft = 2
	rt0.Reserved = []byte{0x00, 0x00, 0x00, 0x00}
	rt0.SourceRoutingIPs = append(rt0.SourceRoutingIPs, net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03})
	rt0.SourceRoutingIPs = append(rt0.SourceRoutingIPs, net.IP{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04})

	p := gopacket.NewPacket(testPacketIPv6RoutingType0, LinkTypeRaw, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeIPv6, LayerTypeIPv6Routing}, t)

	if got, ok := p.Layer(LayerTypeIPv6).(*IPv6); ok {
		want := ip6
		if !reflect.DeepEqual(got, want) {
			t.Errorf("IPv6 packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No IPv6 layer type found in packet")
	}
	if got, ok := p.Layer(LayerTypeIPv6Routing).(*IPv6RoutingType0); ok {
		want := rt0
		if !reflect.DeepEqual(got, want) {
			t.Errorf("IPv6RoutingType0 packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	} else {
		t.Error("No IPv6routing layer type found in packet")
	}
}
