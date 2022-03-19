// Copyright 2021 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
package layers

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/google/gopacket"
)

var testPacketSTPRDATA = []byte{
	0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x01, 0xAA, 0xBB, 0xCC,
	0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0xAA,
	0xBB, 0xCC, 0x00, 0x01, 0x00, 0x80, 0x01, 0x00, 0x00, 0x14,
	0x00, 0x02, 0x00, 0x0F, 0x00,
}

// real stp packet data with the following value :
// {
// 	ProtocolID: 0,
// 	Version: 0,
// 	Type: 0,
// 	TCA: false,
//  TC: true,
// 	RooteID : {
// 		Priority: 32768,
// 		SysID: 1,
// 		HwAddr: aa bb cc 00 01 00
// 	},
// 	Cost: 0,
// 	BridgeID: {
// 		Priority: 32768,
// 		SysID: 1,
// 		HwAddr: aa bb cc 00 01 00
// 	},
// 	PortID : 0x8001,
// 	MessageAge: 0,
// 	MaxAge: 5120,
// 	HelloTime: 512, // we must divide by 256 to have the value in seconds
// 	FDelay : 3840,
// }

//   00 00 00 00 01 80 01 AA  BB CC 00 01 00 00 00 00  ................
//   00 80 01 AA BB CC 00 01  00 80 01 00 00 14 00 02  ................
//   00 0F 00                                          ...

func TestPacketSTPNilRdata(t *testing.T) {
	p := gopacket.NewPacket(testPacketSTPRDATA, LayerTypeSTP, testDecodeOptions)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeSTP}, t)
}

// test decoding stp layer on real packet data
func TestDecodeSTPRData(t *testing.T) {
	p := gopacket.NewPacket(testPacketSTPRDATA, LayerTypeSTP, testDecodeOptions)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	expectedSTP := &STP{
		ProtocolID: 0,
		Version:    0,
		Type:       0,
		TCA:        false,
		TC:         true,
		RouteID: STPSwitchID{
			Priority: 32768,
			SysID:    1,
			HwAddr:   net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x01, 0x00},
		},
		Cost: 0,
		BridgeID: STPSwitchID{
			Priority: 32768,
			SysID:    1,
			HwAddr:   net.HardwareAddr{0xaa, 0xbb, 0xcc, 0x00, 0x01, 0x00},
		},
		PortID:     0x8001,
		MessageAge: 0,
		MaxAge:     5120,
		HelloTime:  512, // we must divide by 256 to have the value in seconds
		FDelay:     3840,
	}

	decodedSTP := p.Layer(LayerTypeSTP).(*STP)
	decodedSTP.BaseLayer = BaseLayer{}

	if !reflect.DeepEqual(expectedSTP, decodedSTP) {
		t.Error("Expect ", expectedSTP, "actual ", decodedSTP)
	}

}

// test harness to ensure the stp layer can be encoded/decoded properly
// return error if decoded data not match.
func testEncodeDecodeSTP(stp *STP) error {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		// ComputeChecksums: true,
		// FixLengths:       true,
	}
	expectedSTP := stp

	err := stp.SerializeTo(buf, opts)
	if err != nil {
		return err
	}

	newSTP := &STP{}
	err = newSTP.DecodeFromBytes(buf.Bytes(), gopacket.NilDecodeFeedback)
	if err != nil {
		return err
	}
	newSTP.BaseLayer = BaseLayer{}

	if !reflect.DeepEqual(expectedSTP, newSTP) {
		return fmt.Errorf("Expect %v actual %v", expectedSTP, newSTP)
	}
	return nil

}

// Test to ensure what has been encode can be decoded
func TestEncodeDecodeSTP(t *testing.T) {
	STPs := []*STP{
		&STP{
			ProtocolID: 0,
			Version:    0,
			Type:       0,
			RouteID: STPSwitchID{
				Priority: 32768,
				SysID:    1,
				HwAddr:   net.HardwareAddr{0x64, 0x5a, 0x04, 0xaf, 0x33, 0xdc},
			},
			Cost: 0,
			BridgeID: STPSwitchID{
				Priority: 32768,
				SysID:    1,
				HwAddr:   net.HardwareAddr{0x64, 0x5a, 0x04, 0xaf, 0x33, 0xdc},
			},
			PortID:     0x8001,
			MessageAge: 0,
			MaxAge:     20 * 256,
			HelloTime:  2 * 256,
			FDelay:     15 * 256,
		},
		&STP{
			ProtocolID: 0,
			Version:    0,
			Type:       0,
			RouteID: STPSwitchID{
				Priority: 32768,
				SysID:    1,
				HwAddr:   net.HardwareAddr{0x64, 0x5a, 0x04, 0xaf, 0x33, 0xdc},
			},
			TC:   true,
			TCA:  true,
			Cost: 0,
			BridgeID: STPSwitchID{
				Priority: 32768,
				SysID:    1,
				HwAddr:   net.HardwareAddr{0x64, 0x5a, 0x04, 0xaf, 0x33, 0xdc},
			},
			PortID:     0x8001,
			MessageAge: 0,
			MaxAge:     20 * 256,
			HelloTime:  2 * 256,
			FDelay:     15 * 256,
		},
	}

	for i, curTest := range STPs {
		err := testEncodeDecodeSTP(curTest)
		if err != nil {
			t.Error("Error with item ", i, " with error message :", err)
		}
	}
}
