// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
	"errors"
)

// PFLog provides the layer for 'pf' packet-filter logging, as described at
// http://www.freebsd.org/cgi/man.cgi?query=pflog&sektion=4
type PFLog struct {
	BaseLayer
	Length              uint8
	Family              ProtocolFamily
	Action, Reason      uint8
	IFName, Ruleset     []byte
	RuleNum, SubruleNum uint32
	// There's some other fields here that we currently don't pull out.
}

func (pf *PFLog) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	pf.Length = data[0]
	pf.Family = ProtocolFamily(data[1])
	pf.Action = data[2]
	pf.Reason = data[3]
	pf.IFName = data[4:20]
	pf.Ruleset = data[20:36]
	pf.RuleNum = binary.BigEndian.Uint32(data[36:40])
	pf.SubruleNum = binary.BigEndian.Uint32(data[40:44])
	if pf.Length%4 != 1 {
		return errors.New("PFLog header length should be 3 less than multiple of 4")
	}
	actualLength := int(pf.Length) + 3
	pf.Contents = data[:actualLength]
	pf.Payload = data[actualLength:]
	return nil
}

// LayerType returns layers.LayerTypePFLog
func (pf *PFLog) LayerType() gopacket.LayerType { return LayerTypePFLog }

func (pf *PFLog) CanDecode() gopacket.LayerClass { return LayerTypePFLog }

func (pf *PFLog) NextLayerType() gopacket.LayerType {
	return pf.Family.LayerType()
}

func decodePFLog(data []byte, p gopacket.PacketBuilder) error {
	pf := &PFLog{}
	return decodingLayerDecoder(pf, data, p)
}
