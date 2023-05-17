// Copyright 2014, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"net"
	"reflect"
	"testing"

	"github.com/niklaskb/gopacket"
)

// Generator: python layers/test_creator.py --layerType=LayerTypeRadioTap --linkType=LinkTypeIEEE80211Radio --name=Dot11%s ~/Downloads/mesh.pcap
// http://wiki.wireshark.org/SampleCaptures#Sample_Captures

// testPacketDot11CtrlCTS is the packet:
//   09:28:41.830560 20604983us tsft short preamble 24.0 Mb/s 5240 MHz 11a -79dB signal -92dB noise antenna 1 Clear-To-Send RA:d8:a2:5e:97:61:c1
//   	0x0000:  0000 1900 6f08 0000 3768 3a01 0000 0000  ....o...7h:.....
//   	0x0010:  1230 7814 4001 b1a4 01c4 0094 00d8 a25e  .0x.@..........^
//   	0x0020:  9761 c136 5095 8e                        .a.6P..

var testPacketDot11CtrlCTS = []byte{
	0x00, 0x00, 0x19, 0x00, 0x6f, 0x08, 0x00, 0x00, 0x37, 0x68, 0x3a, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x12, 0x30, 0x78, 0x14, 0x40, 0x01, 0xb1, 0xa4, 0x01, 0xc4, 0x00, 0x94, 0x00, 0xd8, 0xa2, 0x5e,
	0x97, 0x61, 0xc1, 0x36, 0x50, 0x95, 0x8e,
}

func TestPacketDot11CtrlCTS(t *testing.T) {
	p := gopacket.NewPacket(testPacketDot11CtrlCTS, LinkTypeIEEE80211Radio, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11}, t)

	if got, ok := p.Layer(LayerTypeRadioTap).(*RadioTap); ok {
		want := &RadioTap{
			BaseLayer: BaseLayer{
				Contents: []uint8{0x0, 0x0, 0x19, 0x0, 0x6f, 0x8, 0x0, 0x0, 0x37, 0x68, 0x3a, 0x1, 0x0, 0x0, 0x0, 0x0, 0x12, 0x30, 0x78, 0x14, 0x40, 0x1, 0xb1, 0xa4, 0x1},
				Payload:  []uint8{0xc4, 0x0, 0x94, 0x0, 0xd8, 0xa2, 0x5e, 0x97, 0x61, 0xc1, 0x36, 0x50, 0x95, 0x8e},
			},
			Version:          0x0,
			Length:           0x19,
			Present:          0x86f,
			TSFT:             0x13a6837,
			Flags:            0x12,
			Rate:             0x30,
			ChannelFrequency: 0x1478,
			ChannelFlags:     0x140,
			FHSS:             0x0,
			DBMAntennaSignal: -79,
			DBMAntennaNoise:  -92,
			LockQuality:      0x0,
			TxAttenuation:    0x0,
			DBTxAttenuation:  0x0,
			DBMTxPower:       0,
			Antenna:          1,
			DBAntennaSignal:  0x0,
			DBAntennaNoise:   0x0,
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("RadioTap packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	}

	if got, ok := p.Layer(LayerTypeDot11).(*Dot11); ok {
		if !got.ChecksumValid() {
			t.Errorf("Dot11 packet processing failed:\nchecksum failed. got  :\n%#v\n\n", got)
		}

		want := &Dot11{
			BaseLayer: BaseLayer{
				Contents: []uint8{0xc4, 0x0, 0x94, 0x0, 0xd8, 0xa2, 0x5e, 0x97, 0x61, 0xc1},
				Payload:  []uint8{},
			},
			Type:       Dot11TypeCtrlCTS,
			Proto:      0x0,
			Flags:      0x0,
			DurationID: 0x94,
			Address1:   net.HardwareAddr{0xd8, 0xa2, 0x5e, 0x97, 0x61, 0xc1}, // check
			Address2:   net.HardwareAddr(nil),
			Address3:   net.HardwareAddr(nil),
			Address4:   net.HardwareAddr(nil),
			Checksum:   0x8e955036,
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("Dot11 packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	}
}

func BenchmarkDecodePacketDot11CtrlCTS(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketDot11CtrlCTS, LinkTypeIEEE80211Radio, gopacket.NoCopy)
	}
}

// testPacketDot11MgmtBeacon is the packet:
//   15:44:56.531833 6.0 Mb/s 2412 MHz 11g -81dB signal antenna 5 Beacon (Wi2) [6.0* 9.0 12.0* 18.0 24.0* 36.0 48.0 54.0 Mbit] ESS CH: 1
//   	0x0000:  0000 1200 2e48 0000 100c 6c09 c000 af05  .....H....l.....
//   	0x0010:  0000 8000 0000 ffff ffff ffff c08a de01  ................
//   	0x0020:  11b8 c08a de01 11b8 f097 80f1 30bc 1300  ............0...
//   	0x0030:  0000 6400 2104 0003 5769 3201 088c 1298  ..d.!...Wi2.....
//   	0x0040:  24b0 4860 6c03 0101 0504 0001 0000 2a01  $.H`l.........*.
//   	0x0050:  00dd 1800 50f2 0201 0181 0007 a400 0023  ....P..........#
//   	0x0060:  a400 0042 435e 0062 322f 00dd 1e00 904c  ...BC^.b2/.....L
//   	0x0070:  338c 011b ffff 0000 0000 0000 0000 0000  3...............
//   	0x0080:  1000 0000 0000 0000 0000 002d 1a8c 011b  ...........-....
//   	0x0090:  ffff 0000 0000 0000 0000 0000 1000 0000  ................
//   	0x00a0:  0000 0000 0000 00dd 1a00 904c 3401 0000  ...........L4...
//   	0x00b0:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x00c0:  0000 003d 1601 0000 0000 0000 0000 0000  ...=............
//   	0x00d0:  0000 0000 0000 0000 0000 007f 0400 0000  ................
//   	0x00e0:  00dd 0800 1392 0100 0185 0094 0b90 15    ...............
var testPacketDot11MgmtBeacon = []byte{
	0x00, 0x00, 0x12, 0x00, 0x2e, 0x48, 0x00, 0x00, 0x10, 0x0c, 0x6c, 0x09, 0xc0, 0x00, 0xaf, 0x05,
	0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x8a, 0xde, 0x01,
	0x11, 0xb8, 0xc0, 0x8a, 0xde, 0x01, 0x11, 0xb8, 0xf0, 0x97, 0x80, 0xf1, 0x30, 0xbc, 0x13, 0x00,
	0x00, 0x00, 0x64, 0x00, 0x21, 0x04, 0x00, 0x03, 0x57, 0x69, 0x32, 0x01, 0x08, 0x8c, 0x12, 0x98,
	0x24, 0xb0, 0x48, 0x60, 0x6c, 0x03, 0x01, 0x01, 0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x2a, 0x01,
	0x00, 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x81, 0x00, 0x07, 0xa4, 0x00, 0x00, 0x23,
	0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00, 0xdd, 0x1e, 0x00, 0x90, 0x4c,
	0x33, 0x8c, 0x01, 0x1b, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x1a, 0x8c, 0x01, 0x1b,
	0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0x1a, 0x00, 0x90, 0x4c, 0x34, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x3d, 0x16, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x04, 0x00, 0x00, 0x00,
	0x00, 0xdd, 0x08, 0x00, 0x13, 0x92, 0x01, 0x00, 0x01, 0x85, 0x00, 0x94, 0x0b, 0x90, 0x15,
}

func TestPacketDot11MgmtBeacon(t *testing.T) {
	p := gopacket.NewPacket(testPacketDot11MgmtBeacon, LinkTypeIEEE80211Radio, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	expectedLayers := []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11, LayerTypeDot11MgmtBeacon}
	for i := 0; i < 12; i++ {
		expectedLayers = append(expectedLayers, LayerTypeDot11InformationElement)
	}
	checkLayers(p, expectedLayers, t)

	if p.Layer(LayerTypeDot11).(*Dot11).SequenceNumber != 2431 {
		t.Error("dot11 invalid sequence number")
	}
	if p.Layer(LayerTypeDot11).(*Dot11).FragmentNumber != 0 {
		t.Error("dot11 invalid fragment number")
	}
	if _, ok := p.Layer(LayerTypeDot11MgmtBeacon).(*Dot11MgmtBeacon); !ok {
		t.Errorf("dot11 management beacon frame was expected")
	}
}

func BenchmarkDecodePacketDot11MgmtBeacon(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketDot11MgmtBeacon, LinkTypeIEEE80211Radio, gopacket.NoCopy)
	}
}

// testPacketDot11DataQOSData is the packet:
//   06:14:27.838634 638790765us tsft short preamble 54.0 Mb/s -51dB signal -96dB noise antenna 2 5180 MHz 11a CF +QoS ARP, Request who-has 140.180.51.68 tell 169.254.247.0, length 28
//   	0x0000:  0000 2000 6708 0400 6d2c 1326 0000 0000  ....g...m,.&....
//   	0x0010:  226c cda0 0200 0000 4001 0000 3c14 2411  "l......@...<.$.
//   	0x0020:  8801 2c00 0603 7f07 a016 0019 e3d3 5352  ..,...........SR
//   	0x0030:  ffff ffff ffff 5064 0000 50aa aaaa 0300  ......Pd..P.....
//   	0x0040:  0000 0806 0001 0800 0604 0001 0019 e3d3  ................
//   	0x0050:  5352 a9fe f700 0000 0000 0000 8cb4 3344  SR............3D
var testPacketDot11DataQOSData = []byte{
	0x00, 0x00, 0x20, 0x00, 0x67, 0x08, 0x04, 0x00, 0x6d, 0x2c, 0x13, 0x26, 0x00, 0x00, 0x00, 0x00,
	0x22, 0x6c, 0xcd, 0xa0, 0x02, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3c, 0x14, 0x24, 0x11,
	0x88, 0x01, 0x2c, 0x00, 0x06, 0x03, 0x7f, 0x07, 0xa0, 0x16, 0x00, 0x19, 0xe3, 0xd3, 0x53, 0x52,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x50, 0x64, 0x00, 0x00, 0x50, 0xaa, 0xaa, 0xaa, 0x03, 0x00,
	0x00, 0x00, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x19, 0xe3, 0xd3,
	0x53, 0x52, 0xa9, 0xfe, 0xf7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8c, 0xb4, 0x33, 0x44,
}

func TestPacketDot11DataQOSData(t *testing.T) {
	p := gopacket.NewPacket(testPacketDot11DataQOSData, LinkTypeIEEE80211Radio, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11, LayerTypeDot11DataQOSData, LayerTypeDot11Data, LayerTypeLLC, LayerTypeSNAP, LayerTypeARP}, t)

	if got, ok := p.Layer(LayerTypeARP).(*ARP); ok {
		want := &ARP{BaseLayer: BaseLayer{
			Contents: []uint8{0x0, 0x1, 0x8, 0x0, 0x6, 0x4, 0x0, 0x1, 0x0, 0x19, 0xe3, 0xd3, 0x53, 0x52, 0xa9, 0xfe, 0xf7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x8c, 0xb4, 0x33, 0x44},
			Payload:  []uint8{},
		},
			AddrType:          0x1,
			Protocol:          0x800,
			HwAddressSize:     0x6,
			ProtAddressSize:   0x4,
			Operation:         0x1,
			SourceHwAddress:   []uint8{0x0, 0x19, 0xe3, 0xd3, 0x53, 0x52},
			SourceProtAddress: []uint8{0xa9, 0xfe, 0xf7, 0x0},
			DstHwAddress:      []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			DstProtAddress:    []uint8{0x8c, 0xb4, 0x33, 0x44},
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("ARP packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	}
}
func BenchmarkDecodePacketDot11DataQOSData(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketDot11DataQOSData, LinkTypeIEEE80211Radio, gopacket.NoCopy)
	}
}

// testPacketDot11MgmtAction is the packet:
//   15:54:43.236460 1.0 Mb/s 2412 MHz 11b -67dB signal antenna 5 Action (8e:3a:e3:44:ac:c6): Spectrum Management Act#4
//   	0x0000:  0000 1200 2e48 0000 1002 6c09 a000 bd05  .....H....l.....
//   	0x0010:  0000 d000 0000 ffff ffff ffff 8e3a e344  .............:.D
//   	0x0020:  acc6 8e3a e344 acc6 001b 0004 2503 0001  ...:.D......%...
//   	0x0030:  0055 39f0 33                             .U9.3
var testPacketDot11MgmtAction = []byte{
	0x00, 0x00, 0x12, 0x00, 0x2e, 0x48, 0x00, 0x00, 0x10, 0x02, 0x6c, 0x09, 0xa0, 0x00, 0xbd, 0x05,
	0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x8e, 0x3a, 0xe3, 0x44,
	0xac, 0xc6, 0x8e, 0x3a, 0xe3, 0x44, 0xac, 0xc6, 0x00, 0x1b, 0x00, 0x04, 0x25, 0x03, 0x00, 0x01,
	0x00, 0x55, 0x39, 0xf0, 0x33,
}

func TestPacketDot11MgmtAction(t *testing.T) {
	p := gopacket.NewPacket(testPacketDot11MgmtAction, LinkTypeIEEE80211Radio, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11, LayerTypeDot11MgmtAction}, t)
	if got, ok := p.Layer(LayerTypeDot11).(*Dot11); !ok {
		t.Errorf("dot11 frame was not parsed")
	} else if !got.ChecksumValid() {
		t.Errorf("Dot11 packet processing failed: checksum failed")
	}
	if got, ok := p.Layer(LayerTypeDot11MgmtAction).(*Dot11MgmtAction); !ok {
		t.Errorf("management action frame was not parsed")
	} else if got.Contents[0] != 0 {
		t.Errorf("action category was not spectrum management")
	}
}

func BenchmarkDecodePacketDot11MgmtAction(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketDot11MgmtAction, LinkTypeIEEE80211Radio, gopacket.NoCopy)
	}
}

// testPacketDot11CtrlAck is the packet:
//   06:14:27.838669 638758038us tsft short preamble 24.0 Mb/s -39dB signal -96dB noise antenna 2 5180 MHz 11a Acknowledgment RA:00:19:e3:d3:53:52
//   	0x0000:  0000 2000 6708 0400 96ac 1226 0000 0000  ....g......&....
//   	0x0010:  2230 d9a0 0200 0000 4001 0000 3c14 2411  "0......@...<.$.
//   	0x0020:  d400 0000 0019 e3d3 5352 46e9 7687       ........SRF.v.
var testPacketDot11CtrlAck = []byte{
	0x00, 0x00, 0x20, 0x00, 0x67, 0x08, 0x04, 0x00, 0x96, 0xac, 0x12, 0x26, 0x00, 0x00, 0x00, 0x00,
	0x32, 0x30, 0xd9, 0xa0, 0x02, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3c, 0x14, 0x24, 0x11,
	0xd4, 0x00, 0x00, 0x00, 0x00, 0x19, 0xe3, 0xd3, 0x53, 0x52, 0x46, 0xe9, 0x76, 0x87,
}

func TestPacketDot11CtrlAck(t *testing.T) {
	p := gopacket.NewPacket(testPacketDot11CtrlAck, LinkTypeIEEE80211Radio, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11}, t)

	if got, ok := p.Layer(LayerTypeDot11).(*Dot11); ok {
		if !got.ChecksumValid() {
			t.Errorf("Dot11 packet processing failed:\nchecksum failed. got  :\n%#v\n\n", got)
		}
	}

	if got, ok := p.Layer(LayerTypeDot11).(*Dot11); ok {
		if !got.ChecksumValid() {
			t.Errorf("Dot11 packet processing failed:\nchecksum failed. got  :\n%#v\n\n", got)
		}
		want := &Dot11{
			BaseLayer: BaseLayer{
				Contents: []uint8{0xd4, 0x0, 0x0, 0x0, 0x0, 0x19, 0xe3, 0xd3, 0x53, 0x52},
				Payload:  []uint8{},
			},
			Type:       Dot11TypeCtrlAck,
			Proto:      0x0,
			Flags:      0x0,
			DurationID: 0x0,
			Address1:   net.HardwareAddr{0x0, 0x19, 0xe3, 0xd3, 0x53, 0x52},
			Address2:   net.HardwareAddr(nil),
			Address3:   net.HardwareAddr(nil),
			Address4:   net.HardwareAddr(nil),
			Checksum:   0x8776e946,
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Dot11 packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	}
}
func BenchmarkDecodePacketDot11CtrlAck(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketDot11CtrlAck, LinkTypeIEEE80211Radio, gopacket.NoCopy)
	}
}

// testPacketDot11DataARP is the packet:
//   06:14:11.512316 622463798us tsft short preamble 6.0 Mb/s -39dB signal -96dB noise antenna 2 5180 MHz 11a ARP, Request who-has 67.8.14.54 tell 169.254.247.0, length 28
//   	0x0000:  0000 2000 6708 0400 360b 1a25 0000 0000  ....g...6..%....
//   	0x0010:  220c d9a0 0200 0000 4001 0000 3c14 2411  ".......@...<.$.
//   	0x0020:  0802 0000 ffff ffff ffff 0603 7f07 a016  ................
//   	0x0030:  0019 e3d3 5352 e07f aaaa 0300 0000 0806  ....SR..........
//   	0x0040:  0001 0800 0604 0001 0019 e3d3 5352 a9fe  ............SR..
//   	0x0050:  f700 0000 0000 0000 4308 0e36            ........C..6
var testPacketDot11DataARP = []byte{
	0x00, 0x00, 0x20, 0x00, 0x67, 0x08, 0x04, 0x00, 0x36, 0x0b, 0x1a, 0x25, 0x00, 0x00, 0x00, 0x00,
	0x22, 0x0c, 0xd9, 0xa0, 0x02, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3c, 0x14, 0x24, 0x11,
	0x08, 0x02, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x06, 0x03, 0x7f, 0x07, 0xa0, 0x16,
	0x00, 0x19, 0xe3, 0xd3, 0x53, 0x52, 0xe0, 0x7f, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x06,
	0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0x00, 0x19, 0xe3, 0xd3, 0x53, 0x52, 0xa9, 0xfe,
	0xf7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x43, 0x08, 0x0e, 0x36,
}

func TestPacketDot11DataARP(t *testing.T) {
	p := gopacket.NewPacket(testPacketDot11DataARP, LinkTypeIEEE80211Radio, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11, LayerTypeDot11Data, LayerTypeLLC, LayerTypeSNAP, LayerTypeARP}, t)

	if got, ok := p.Layer(LayerTypeARP).(*ARP); ok {
		want := &ARP{
			BaseLayer: BaseLayer{
				Contents: []uint8{0x0, 0x1, 0x8, 0x0, 0x6, 0x4, 0x0, 0x1, 0x0, 0x19, 0xe3, 0xd3, 0x53, 0x52, 0xa9, 0xfe, 0xf7, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x43, 0x8, 0xe, 0x36},
				Payload:  []uint8{},
			},
			AddrType:          0x1,
			Protocol:          0x800,
			HwAddressSize:     0x6,
			ProtAddressSize:   0x4,
			Operation:         0x1,
			SourceHwAddress:   []uint8{0x0, 0x19, 0xe3, 0xd3, 0x53, 0x52},
			SourceProtAddress: []uint8{0xa9, 0xfe, 0xf7, 0x0},
			DstHwAddress:      []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
			DstProtAddress:    []uint8{0x43, 0x8, 0xe, 0x36},
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("ARP packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", got, want)
		}
	}
}

func BenchmarkDecodePacketDot11DataARP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketDot11DataARP, LinkTypeIEEE80211Radio, gopacket.NoCopy)
	}
}

// testPacketDot11DataIP is the packet:
//   06:14:21.388622 632340487us tsft short preamble 6.0 Mb/s -40dB signal -96dB noise antenna 1 5180 MHz 11a IP 0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 00:19:e3:d3:53:52, length 300
//   	0x0000:  0000 2000 6708 0400 07c0 b025 0000 0000  ....g......%....
//   	0x0010:  220c d8a0 0100 0000 4001 0000 3c14 2411  ".......@...<.$.
//   	0x0020:  0802 0000 ffff ffff ffff 0603 7f07 a016  ................
//   	0x0030:  0019 e3d3 5352 4095 aaaa 0300 0000 0800  ....SR@.........
//   	0x0040:  4500 0148 c514 0000 ff11 f590 0000 0000  E..H............
//   	0x0050:  ffff ffff 0044 0043 0134 2b39 0101 0600  .....D.C.4+9....
//   	0x0060:  131f 8c43 003c 0000 0000 0000 0000 0000  ...C.<..........
//   	0x0070:  0000 0000 0000 0000 0019 e3d3 5352 0000  ............SR..
//   	0x0080:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x0090:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x00a0:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x00b0:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x00c0:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x00d0:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x00e0:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x00f0:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x0100:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x0110:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x0120:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x0130:  0000 0000 0000 0000 0000 0000 0000 0000  ................
//   	0x0140:  0000 0000 0000 0000 6382 5363 3501 0137  ........c.Sc5..7
//   	0x0150:  0a01 0306 0f77 5ffc 2c2e 2f39 0205 dc3d  .....w_.,./9...=
//   	0x0160:  0701 0019 e3d3 5352 3304 0076 a700 0c0b  ......SR3..v....
//   	0x0170:  4d61 6369 6e74 6f73 682d 34ff 0000 0000  Macintosh-4.....
//   	0x0180:  0000 0000 0000 0000                      ........
var testPacketDot11DataIP = []byte{
	0x00, 0x00, 0x20, 0x00, 0x67, 0x08, 0x04, 0x00, 0x07, 0xc0, 0xb0, 0x25, 0x00, 0x00, 0x00, 0x00,
	0x22, 0x0c, 0xd8, 0xa0, 0x01, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3c, 0x14, 0x24, 0x11,
	0x08, 0x02, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x06, 0x03, 0x7f, 0x07, 0xa0, 0x16,
	0x00, 0x19, 0xe3, 0xd3, 0x53, 0x52, 0x40, 0x95, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00,
	0x45, 0x00, 0x01, 0x48, 0xc5, 0x14, 0x00, 0x00, 0xff, 0x11, 0xf5, 0x90, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff, 0x00, 0x44, 0x00, 0x43, 0x01, 0x34, 0x2b, 0x39, 0x01, 0x01, 0x06, 0x00,
	0x13, 0x1f, 0x8c, 0x43, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0xe3, 0xd3, 0x53, 0x52, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x01, 0x37,
	0x0a, 0x01, 0x03, 0x06, 0x0f, 0x77, 0x5f, 0xfc, 0x2c, 0x2e, 0x2f, 0x39, 0x02, 0x05, 0xdc, 0x3d,
	0x07, 0x01, 0x00, 0x19, 0xe3, 0xd3, 0x53, 0x52, 0x33, 0x04, 0x00, 0x76, 0xa7, 0x00, 0x0c, 0x0b,
	0x4d, 0x61, 0x63, 0x69, 0x6e, 0x74, 0x6f, 0x73, 0x68, 0x2d, 0x34, 0xff, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestPacketDot11DataIP(t *testing.T) {
	p := gopacket.NewPacket(testPacketDot11DataIP, LinkTypeIEEE80211Radio, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11, LayerTypeDot11Data, LayerTypeLLC, LayerTypeSNAP, LayerTypeIPv4, LayerTypeUDP, LayerTypeDHCPv4}, t)
}
func BenchmarkDecodePacketDot11DataIP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketDot11DataIP, LinkTypeIEEE80211Radio, gopacket.NoCopy)
	}
}

// Encrypted

/// testPacketP6196 is the packet:
//   09:28:41.830631 20605036us tsft wep -69dB signal -92dB noise antenna 1 5240 MHz 11a ht/40- 162.0 Mb/s MCS 12 40 MHz lon GI mixed BCC FEC [bit 20] CF +QoS Data IV:50a9 Pad 20 KeyID 0
//   	0x0000:  0000 3000 6b08 1c00 6c68 3a01 0000 0000  ..0.k...lh:.....
//   	0x0010:  1400 7814 4001 bba4 0160 0e1a 4001 0400  ..x.@....`..@...
//   	0x0020:  7814 3022 1f01 0cff b10d 0000 0400 0000  x.0"............
//   	0x0030:  8841 2c00 0025 9c42 c262 d8a2 5e97 61c1  .A,..%.B.b..^.a.
//   	0x0040:  0025 9c42 c25f 10db 0000 a950 0020 0000  .%.B._.....P....
//   	0x0050:  0000 f8ab a97e 3fbd d6e1 785b 0040 5f15  .....~?...x[.@_.
//   	0x0060:  7123 8711 bd1f ffb9 e5b3 84bb ec2a 0a90  q#...........*..
//   	0x0070:  d0a0 1a6f 9033 1083 5179 a0da f833 3a00  ...o.3..Qy...3:.
//   	0x0080:  5471 f596 539b 1823 a33c 4908 545c 266a  Tq..S..#.<I.T\&j
//   	0x0090:  8540 515a 1da9 c49e a85a fbf7 de09 7f9c  .@QZ.....Z......
//   	0x00a0:  6f35 0b8b 6831 2c10 43dc 8983 b1d9 dd29  o5..h1,.C......)
//   	0x00b0:  7395 65b9 4b43 b391 16ec 4201 86c9 ca    s.e.KC....B....
var testPacketP6196 = []byte{
	0x00, 0x00, 0x30, 0x00, 0x6b, 0x08, 0x1c, 0x00, 0x6c, 0x68, 0x3a, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x14, 0x00, 0x78, 0x14, 0x40, 0x01, 0xbb, 0xa4, 0x01, 0x60, 0x0e, 0x1a, 0x40, 0x01, 0x04, 0x00,
	0x78, 0x14, 0x30, 0x22, 0x1f, 0x01, 0x0c, 0xff, 0xb1, 0x0d, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
	0x88, 0x41, 0x2c, 0x00, 0x00, 0x25, 0x9c, 0x42, 0xc2, 0x62, 0xd8, 0xa2, 0x5e, 0x97, 0x61, 0xc1,
	0x00, 0x25, 0x9c, 0x42, 0xc2, 0x5f, 0x10, 0xdb, 0x00, 0x00, 0xa9, 0x50, 0x00, 0x20, 0x00, 0x00,
	0x00, 0x00, 0xf8, 0xab, 0xa9, 0x7e, 0x3f, 0xbd, 0xd6, 0xe1, 0x78, 0x5b, 0x00, 0x40, 0x5f, 0x15,
	0x71, 0x23, 0x87, 0x11, 0xbd, 0x1f, 0xff, 0xb9, 0xe5, 0xb3, 0x84, 0xbb, 0xec, 0x2a, 0x0a, 0x90,
	0xd0, 0xa0, 0x1a, 0x6f, 0x90, 0x33, 0x10, 0x83, 0x51, 0x79, 0xa0, 0xda, 0xf8, 0x33, 0x3a, 0x00,
	0x54, 0x71, 0xf5, 0x96, 0x53, 0x9b, 0x18, 0x23, 0xa3, 0x3c, 0x49, 0x08, 0x54, 0x5c, 0x26, 0x6a,
	0x85, 0x40, 0x51, 0x5a, 0x1d, 0xa9, 0xc4, 0x9e, 0xa8, 0x5a, 0xfb, 0xf7, 0xde, 0x09, 0x7f, 0x9c,
	0x6f, 0x35, 0x0b, 0x8b, 0x68, 0x31, 0x2c, 0x10, 0x43, 0xdc, 0x89, 0x83, 0xb1, 0xd9, 0xdd, 0x29,
	0x73, 0x95, 0x65, 0xb9, 0x4b, 0x43, 0xb3, 0x91, 0x16, 0xec, 0x42, 0x01, 0x86, 0xc9, 0xca,
}

func TestPacketP6196(t *testing.T) {
	p := gopacket.NewPacket(testPacketP6196, LinkTypeIEEE80211Radio, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}

	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11, LayerTypeDot11DataQOSData, LayerTypeDot11WEP}, t)
}

func BenchmarkDecodePacketP6196(b *testing.B) {
	for i := 0; i < b.N; i++ {
		gopacket.NewPacket(testPacketP6196, LinkTypeIEEE80211Radio, gopacket.NoCopy)
	}
}

// testPacketDot11HTControl is the packet:
// 0000   00 00 26 00 2b 48 20 00 bf 70 06 02 00 00 00 00   ..&.+H .¿p......
// 0010   40 00 78 14 40 01 b8 00 00 00 44 00 00 01 73 00   @.x.@.¸...D...s.
// 0020   00 00 00 00 00 00 88 c9 30 14 01 02 03 04 05 06   .......É0.ò.Jòs}
// 0030   11 12 13 14 15 16 21 22 23 24 25 26 c0 bd 00 14   .öP.6:M 2.Á7À½..
// 0040   0e 28 00 a8 06 01 00 04 e6 73 b3 4a 24 3e 19 ea   .(.¨....æs³J$>.ê
// 0050   2a b7 1f 3c c7 89 2b 22 e2 2b 28 6c 69 aa 0a ee   *·.<Ç.+"â+(liª.î
// 0060   1e bc 2d 2a 00 35 68 39 ad 6f 29 52 38 07 ae cf   .¼-*.5h9.o)R8.®Ï
// 0070   03 e7 0d 53 8b 3c 12 28 52 05 cc 70 be c7 68 5e   .ç.S.<.(R.Ìp¾Çh^
// 0080   5f b1 06 f4 73 22 63 ef 77 41 7b 86               _±.ôs"cïwA{.
var testPacketDot11HTControl = []byte{
	0x00, 0x00, 0x26, 0x00, 0x2b, 0x48, 0x20, 0x00, 0xbf, 0x70, 0x06, 0x02, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x78, 0x14, 0x40, 0x01, 0xb8, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x01, 0x73, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xc9, 0x30, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0xc0, 0xbd, 0x00, 0x14,
	0x0e, 0x28, 0x00, 0xa8, 0x06, 0x01, 0x00, 0x04, 0xe6, 0x73, 0xb3, 0x4a, 0x24, 0x3e, 0x19, 0xea,
	0x2a, 0xb7, 0x1f, 0x3c, 0xc7, 0x89, 0x2b, 0x22, 0xe2, 0x2b, 0x28, 0x6c, 0x69, 0xaa, 0x0a, 0xee,
	0x1e, 0xbc, 0x2d, 0x2a, 0x00, 0x35, 0x68, 0x39, 0xad, 0x6f, 0x29, 0x52, 0x38, 0x07, 0xae, 0xcf,
	0x03, 0xe7, 0x0d, 0x53, 0x8b, 0x3c, 0x12, 0x28, 0x52, 0x05, 0xcc, 0x70, 0xbe, 0xc7, 0x68, 0x5e,
	0x5f, 0xb1, 0x06, 0xf4, 0x73, 0x22, 0x63, 0xef, 0x77, 0x41, 0x7b, 0x86,
}

var mfb = uint8(20)

var wantHTControl = Dot11HTControl{
	ACConstraint: false,
	RDGMorePPDU:  true,
	HT: &Dot11HTControlHT{
		LinkAdapationControl: &Dot11LinkAdapationControl{
			TRQ:  true,
			MRQ:  true,
			MSI:  1,
			MFSI: 0,
			ASEL: nil,
			MFB:  &mfb,
		},
		CalibrationPosition: 0,
		CalibrationSequence: 0,
		CSISteering:         0,
		NDPAnnouncement:     false,
		DEI:                 true,
	},
}

func TestPacketDot11HTControl(t *testing.T) {
	p := gopacket.NewPacket(testPacketDot11HTControl, LinkTypeIEEE80211Radio, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}

	checkLayers(p, []gopacket.LayerType{LayerTypeRadioTap, LayerTypeDot11, LayerTypeDot11DataQOSData, LayerTypeDot11WEP}, t)

	ld11 := p.Layer(LayerTypeDot11)
	if dot11, ok := ld11.(*Dot11); ok {
		if dot11.HTControl == nil {
			t.Fatal("Packet didn't contain HTControl")
		}
		if !reflect.DeepEqual(*dot11.HTControl, wantHTControl) {
			t.Errorf("Dot11 packet processing failed:\ngot  :\n%#v\n\nwant :\n%#v\n\n", dot11.HTControl, wantHTControl)
		}
	}
}

func TestInformationElement(t *testing.T) {
	bin := []byte{
		0, 0,
		0, 2, 1, 3,
		221, 5, 1, 2, 3, 4, 5,
	}
	pkt := gopacket.NewPacket(bin, LayerTypeDot11InformationElement, gopacket.NoCopy)

	buf := gopacket.NewSerializeBuffer()
	var sLayers []gopacket.SerializableLayer
	for _, l := range pkt.Layers() {
		sLayers = append(sLayers, l.(*Dot11InformationElement))
	}
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, sLayers...); err != nil {
		t.Error(err.Error())
	}
	if !bytes.Equal(bin, buf.Bytes()) {
		t.Error("build failed")
	}
}
