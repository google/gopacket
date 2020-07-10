// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/google/gopacket"
)

func init() {
	opts.DecodeStreamsAsDatagrams = true
}

// Pulled from a modbus test data dump at https://github.com/automayt/ICS-pcap
// 10.0.0.9	10.0.0.3	Modbus/TCP	66	   Query: Trans:     1; Unit:  10, Func:   1: Read Coils
var testPacketModbusReadCoils = []byte{
	0x00, 0x02, 0xb3, 0xce, 0x70, 0x51, 0x00, 0x50, 0x04, 0x93, 0x70, 0x67, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x34, 0x03, 0xab, 0x40, 0x00, 0x80, 0x06, 0xe3, 0x0d, 0x0a, 0x00, 0x00, 0x09, 0x0a, 0x00,
	0x00, 0x03, 0x0c, 0x0a, 0x01, 0xf6, 0x48, 0x3c, 0xbe, 0x92, 0x7a, 0x8a, 0xa5, 0x21, 0x50, 0x18,
	0xfa, 0xe6, 0x62, 0x47, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x0a, 0x01, 0x00, 0x02,
	0x00, 0x02,
}

func TestModbusReadCoilRequest(t *testing.T) {
	p := gopacket.NewPacket(testPacketModbusReadCoils, LinkTypeEthernet, opts)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode modbus packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeModbus}, t)

	if got, ok := p.Layer(LayerTypeModbus).(*Modbus); ok {
		want := &Modbus{
			BaseLayer: BaseLayer{
				Contents: []uint8{0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x0a, 0x01, 0x00, 0x02, 0x00, 0x02},
				Payload:  []uint8{},
			},
			MBAP: MBAP{
				TransactionID: 1,
				ProtocolID:    0,
				Length:        6,
				UnitID:        10,
			},
			FunctionCode: 0x01,
			ReqResp:      []byte{0x00, 0x02, 0x00, 0x02},
		}
		if !reflect.DeepEqual(got, want) {
			t.Error("Modbus Exception packet does not match")
		}
	} else {
		t.Error("Failed to get modbus layer")
	}
}

// Pulled from a modbus test data dump at https://github.com/automayt/ICS-pcap
// 10.0.0.3	10.0.0.57	Modbus/TCP	63	Response: Trans:     0; Unit:  10, Func:   8: Diagnostics. Exception returned
// 0000   00 20 78 00 62 0d 00 02 b3 ce 70 51 08 00 45 00  . x.b.....pQ..E.
// 0010   00 31 ff e5 40 00 80 06 e6 a5 0a 00 00 03 0a 00  .1..@...........
// 0020   00 39 01 f6 0a 12 70 f1 ad 1b 61 97 f1 8f 50 18  .9....p...a...P.
// 0030   ff f3 08 cd 00 00 00 00 00 00 00 03 0a 88 0b     ...............
var testPacketModbusExceptionResponse = []byte{
	0x00, 0x20, 0x78, 0x00, 0x62, 0x0d, 0x00, 0x02, 0xb3, 0xce, 0x70, 0x51, 0x08, 0x00, 0x45, 0x00,
	0x00, 0x31, 0xff, 0xe5, 0x40, 0x00, 0x80, 0x06, 0xe6, 0xa5, 0x0a, 0x00, 0x00, 0x03, 0x0a, 0x00,
	0x00, 0x39, 0x01, 0xf6, 0x0a, 0x12, 0x70, 0xf1, 0xad, 0x1b, 0x61, 0x97, 0xf1, 0x8f, 0x50, 0x18,
	0xff, 0xf3, 0x08, 0xcd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0a, 0x88, 0x0b,
}

func TestModbusExceptionResponse(t *testing.T) {
	p := gopacket.NewPacket(testPacketModbusExceptionResponse, LinkTypeEthernet, opts)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode modbus exception packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeTCP, LayerTypeModbus}, t)

	if got, ok := p.Layer(LayerTypeModbus).(*Modbus); ok {
		want := &Modbus{
			BaseLayer: BaseLayer{
				Contents: []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x0a, 0x88, 0x0b},
				Payload:  []uint8{},
			},
			MBAP: MBAP{
				TransactionID: 0,
				ProtocolID:    0,
				Length:        3,
				UnitID:        10,
			},
			FunctionCode: 0x8,
			Exception:    true,
			ReqResp:      []uint8{0x0b},
		}
		if !reflect.DeepEqual(got, want) {
			fmt.Println(got)
			fmt.Println(want)
			t.Fatal("Modbus Exception packet does not match")
		}
	} else {
		t.Error("Failed to get modbus layer")
	}
}
