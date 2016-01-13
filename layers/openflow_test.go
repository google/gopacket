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

func loadOpenflow(openflowpacket []byte, t *testing.T) *Openflow14 {
	p := gopacket.NewPacket(openflowpacket, LayerTypeOpenflow, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}
	checkLayers(p, []gopacket.LayerType{LayerTypeOpenflow, LayerTypeOpenflow14}, t)

	ofpL := p.Layer(LayerTypeOpenflow14)
	if ofpL == nil {
		t.Error("No Openflow Layer found")
	}

	ofp, ok := ofpL.(*Openflow14)
	if !ok {
		return nil
	}
	return ofp
}

var testOpenflowHelloRequest = []byte{
	5, 0, 0, 16, 0, 0, 3, 182, 0, 1, 0, 8, 0, 0, 0, 32,
}

func TestOpenflow14PacketHelloRequest(t *testing.T) {
	ofp := loadOpenflow(testOpenflowHelloRequest, t)
	t.Errorf("%#+v\n", ofp)
}
