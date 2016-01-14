// Copyright 2012, Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"testing"

	"github.com/google/gopacket"
)

func loadOFPv14(openflowpacket []byte, t *testing.T) *OFPv14 {
	p := gopacket.NewPacket(openflowpacket, LayerTypeOFP, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeOFP, LayerTypeOFPv14}, t)

	ofpL := p.Layer(LayerTypeOFPv14)
	if ofpL == nil {
		t.Error("No Openflow v1.4 Layer found")
	}

	ofp, ok := ofpL.(*OFPv14)
	if !ok {
		return nil
	}
	return ofp
}

var testOFPv14HelloRequest = []byte{
	0x05,       // openflow version
	0x00,       // message hello
	0x00, 0x18, // message len = 24
	0x00, 0x00, 0x00, 0x00, // transaction id
	0x00, 0x01, // hello element
	0x00, 0x08, // element len = 8
	0x00, 0x00, 0x00, 0x10, // first bitmap
	0x00, 0xff, // element foo
	0x00, 0x08, // element len = 8
	0xff, 0xee, 0xee, 0xdd, // element payload
}

func TestOFPv14PacketHelloRequest(t *testing.T) {
	loadOFPv14(testOFPv14HelloRequest, t)
}
