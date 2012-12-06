// Copyright (c) 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"encoding/binary"
)

// SCTP contains information on the top level of an SCTP packet
type SCTP struct {
	SrcPort, DstPort uint16
	VerificationTag  uint32
	Checksum         uint32
	sPort, dPort     []byte
}

// LayerType returns LayerTypeSCTP
func (s *SCTP) LayerType() LayerType { return LayerTypeSCTP }

func decodeSCTP(data []byte) (out DecodeResult, _ error) {
	sctp := &SCTP{
		SrcPort:         binary.BigEndian.Uint16(data[:2]),
		DstPort:         binary.BigEndian.Uint16(data[2:4]),
		VerificationTag: binary.BigEndian.Uint32(data[4:8]),
		Checksum:        binary.BigEndian.Uint32(data[8:12]),
		sPort:           data[:2],
		dPort:           data[2:4],
	}
	out.DecodedLayer = sctp
	out.TransportLayer = sctp
	out.NextDecoder = decodeWithSCTPChunkTypePrefix
	out.RemainingBytes = data[12:]
	return
}

func (s *SCTP) AppFlow() Flow {
	return Flow{LayerTypeSCTP, string(s.sPort), string(s.dPort)}
}

var decodeWithSCTPChunkTypePrefix decoderFunc = func(data []byte) (DecodeResult, error) {
	chunkType := SCTPChunkType(data[0])
	return chunkType.Decode(data)
}

type SCTPData struct {
	Type                                  SCTPChunkType
	Unordered, BeginFragment, EndFragment bool
	Length                                uint16
	TSN                                   uint32
	StreamId                              uint16
	StreamSequence                        uint16
	PayloadProtocol                       uint32
	PayloadData                           []byte
}

func (s *SCTPData) LayerType() LayerType { return LayerTypeSCTPData }

func (s *SCTPData) Payload() []byte {
	return s.PayloadData
}

func decodeSCTPData(data []byte) (out DecodeResult, err error) {
	sd := &SCTPData{
		Type:            SCTPChunkType(data[0]),
		Unordered:       data[1]&0x4 != 0,
		BeginFragment:   data[1]&0x2 != 0,
		EndFragment:     data[1]&0x1 != 0,
		Length:          binary.BigEndian.Uint16(data[2:4]),
		TSN:             binary.BigEndian.Uint32(data[4:8]),
		StreamId:        binary.BigEndian.Uint16(data[8:10]),
		StreamSequence:  binary.BigEndian.Uint16(data[10:12]),
		PayloadProtocol: binary.BigEndian.Uint32(data[12:16]),
	}
	// Length is the length in bytes of the data, INCLUDING the 16-byte header.
	sd.PayloadData = data[16:sd.Length]
	out.DecodedLayer = sd
	out.ApplicationLayer = sd
	out.NextDecoder = decodeWithSCTPChunkTypePrefix
	// SCTP chunks are padded to hit 4-byte boundaries, so round up our length.
	actualLength := int(sd.Length) + 4 - (int(sd.Length) % 4) // Round up to nearest 4
	if actualLength < len(data) {
		out.RemainingBytes = data[actualLength:]
	}
	return
}
