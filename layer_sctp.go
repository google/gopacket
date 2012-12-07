// Copyright (c) 2012 Google, Inc. All rights reserved.

package gopacket

import (
	"encoding/binary"
  "fmt"
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

// SCTPChunk contains the common fields in all SCTP chunks.
type SCTPChunk struct {
	Type                                  SCTPChunkType
  Flags uint8
	Length                                uint16
}

// ActualLength returns the actual number of bytes used by an SCTP chunk.
// Chunks all start and end at 4-byte boundaries, so this function rounds up
// s.Length to the nearest 4th byte.
func (s *SCTPChunk) ActualLength() int {
  if s.Length % 4 == 0 { return int(s.Length) }
  return int(s.Length) + 4 - (int(s.Length) % 4)
}

func decodeSCTPChunk(data []byte) SCTPChunk {
  return SCTPChunk{
    Type: SCTPChunkType(data[0]),
    Flags: data[1],
    Length: binary.BigEndian.Uint16(data[2:4]),
  }
}

// SCTPUnknownChunkType is the layer type returned when we don't recognize the
// chunk type.  Since there's a length in a known location, we can skip over
// it even if we don't know what it is, and continue parsing the rest of the
// chunks.
type SCTPUnknownChunkType struct {
  SCTPChunk
  bytes []byte
}

func decodeSCTPChunkTypeUnknown(data []byte) (out DecodeResult, err error) {
  sc := &SCTPUnknownChunkType{SCTPChunk: decodeSCTPChunk(data)}
  sc.bytes = data[:sc.ActualLength()]
  out.DecodedLayer = sc
  out.RemainingBytes = data[sc.ActualLength():]
  out.ErrorLayer = sc
  out.NextDecoder = decodeWithSCTPChunkTypePrefix
  return
}

// LayerType returns LayerTypeSCTPUnknownChunkType.
func (s *SCTPUnknownChunkType) LayerType() LayerType { return LayerTypeSCTPUnknownChunkType }

// Payload returns all bytes in this header, including the decoded Type, Length,
// and Flags.
func (s *SCTPUnknownChunkType) Payload() []byte { return s.bytes }

func (s *SCTPUnknownChunkType) Error() error {
  return fmt.Errorf("No decode method available for SCTP chunk type %s", s.Type)
}

type SCTPData struct {
  SCTPChunk
	Unordered, BeginFragment, EndFragment bool
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
	sc := &SCTPData{
    SCTPChunk: decodeSCTPChunk(data),
		Unordered:       data[1]&0x4 != 0,
		BeginFragment:   data[1]&0x2 != 0,
		EndFragment:     data[1]&0x1 != 0,
		TSN:             binary.BigEndian.Uint32(data[4:8]),
		StreamId:        binary.BigEndian.Uint16(data[8:10]),
		StreamSequence:  binary.BigEndian.Uint16(data[10:12]),
		PayloadProtocol: binary.BigEndian.Uint32(data[12:16]),
	}
	// Length is the length in bytes of the data, INCLUDING the 16-byte header.
	sc.PayloadData = data[16:sc.Length]
	out.DecodedLayer = sc
	out.ApplicationLayer = sc
	out.NextDecoder = decodeWithSCTPChunkTypePrefix
	out.RemainingBytes = data[sc.ActualLength():]
	return
}
