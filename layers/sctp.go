// Copyright 2012 Google, Inc. All rights reserved.

package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/gconnell/gopacket"
)

// SCTP contains information on the top level of an SCTP packet.
type SCTP struct {
	baseLayer
	SrcPort, DstPort uint16
	VerificationTag  uint32
	Checksum         uint32
	sPort, dPort     []byte
}

// LayerType returns gopacket.LayerTypeSCTP
func (s *SCTP) LayerType() gopacket.LayerType { return LayerTypeSCTP }

func decodeSCTP(data []byte) (out gopacket.DecodeResult, _ error) {
	sctp := &SCTP{
		SrcPort:         binary.BigEndian.Uint16(data[:2]),
		DstPort:         binary.BigEndian.Uint16(data[2:4]),
		VerificationTag: binary.BigEndian.Uint32(data[4:8]),
		Checksum:        binary.BigEndian.Uint32(data[8:12]),
		sPort:           data[:2],
		dPort:           data[2:4],
		baseLayer:       baseLayer{data[:12], data[12:]},
	}
	out.DecodedLayer = sctp
	out.TransportLayer = sctp
	out.NextDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)
	return
}

// TransportFlow returns a flow based on the source and destination SCTP port.
func (s *SCTP) TransportFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointSCTPPort, s.sPort, s.dPort)
}

func decodeWithSCTPChunkTypePrefix(data []byte) (gopacket.DecodeResult, error) {
	chunkType := SCTPChunkType(data[0])
	return chunkType.Decode(data)
}

// SCTPChunk contains the common fields in all SCTP chunks.
type SCTPChunk struct {
	baseLayer
	Type   SCTPChunkType
	Flags  uint8
	Length uint16
	// ActualLength is the total length of an SCTP chunk, including padding.
	// SCTP chunks start and end on 4-byte boundaries.  So if a chunk has a length
	// of 18, it means that it has data up to and including byte 18, then padding
	// up to the next 4-byte boundary, 20.  In this case, Length would be 18, and
	// ActualLength would be 20.
	ActualLength int
}

func roundUpToNearest4(i int) int {
	if i%4 == 0 {
		return i
	}
	return i + 4 - (i % 4)
}

func decodeSCTPChunk(data []byte) SCTPChunk {
	length := binary.BigEndian.Uint16(data[2:4])
	actual := roundUpToNearest4(int(length))
	return SCTPChunk{
		Type:         SCTPChunkType(data[0]),
		Flags:        data[1],
		Length:       length,
		ActualLength: actual,
		baseLayer:    baseLayer{data[:actual], data[actual:]},
	}
}

// SCTPParameter is a TLV parameter inside a SCTPChunk.
type SCTPParameter struct {
	Type         uint16
	Length       uint16
	ActualLength int
	Value        []byte
}

func decodeSCTPParameter(data []byte) SCTPParameter {
	length := binary.BigEndian.Uint16(data[2:4])
	return SCTPParameter{
		Type:         binary.BigEndian.Uint16(data[0:2]),
		Length:       length,
		Value:        data[4:length],
		ActualLength: roundUpToNearest4(int(length)),
	}
}

// SCTPUnknownChunkType is the layer type returned when we don't recognize the
// chunk type.  Since there's a length in a known location, we can skip over
// it even if we don't know what it is, and continue parsing the rest of the
// chunks.  This chunk is stored as an ErrorLayer in the packet.
type SCTPUnknownChunkType struct {
	SCTPChunk
	bytes []byte
}

func decodeSCTPChunkTypeUnknown(data []byte) (out gopacket.DecodeResult, err error) {
	sc := &SCTPUnknownChunkType{SCTPChunk: decodeSCTPChunk(data)}
	sc.bytes = data[:sc.ActualLength]
	out.DecodedLayer = sc
	out.ErrorLayer = sc
	out.NextDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)
	return
}

// LayerType returns gopacket.LayerTypeSCTPUnknownChunkType.
func (s *SCTPUnknownChunkType) LayerType() gopacket.LayerType { return LayerTypeSCTPUnknownChunkType }

// Payload returns all bytes in this header, including the decoded Type, Length,
// and Flags.
func (s *SCTPUnknownChunkType) Payload() []byte { return s.bytes }

// Error implements ErrorLayer.
func (s *SCTPUnknownChunkType) Error() error {
	return fmt.Errorf("No decode method available for SCTP chunk type %s", s.Type)
}

// SCTPData is the SCTP Data chunk layer.
type SCTPData struct {
	SCTPChunk
	Unordered, BeginFragment, EndFragment bool
	TSN                                   uint32
	StreamId                              uint16
	StreamSequence                        uint16
	PayloadProtocol                       uint32
	PayloadData                           []byte
}

// LayerType returns gopacket.LayerTypeSCTPData.
func (s *SCTPData) LayerType() gopacket.LayerType { return LayerTypeSCTPData }

// Payload returns the data payload of the SCTP data chunk.
func (s *SCTPData) Payload() []byte {
	return s.PayloadData
}

func decodeSCTPData(data []byte) (out gopacket.DecodeResult, _ error) {
	sc := &SCTPData{
		SCTPChunk:       decodeSCTPChunk(data),
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
	out.NextDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)
	return
}

// SCTPInitParameter is a parameter for an SCTP Init or InitAck packet.
type SCTPInitParameter SCTPParameter

// SCTPInit is used as the return value for both SCTPInit and SCTPInitAck
// messages.
type SCTPInit struct {
	SCTPChunk
	InitiateTag                     uint32
	AdvertisedReceiverWindowCredit  uint32
	OutboundStreams, InboundStreams uint16
	InitialTSN                      uint32
	Parameters                      []SCTPInitParameter
}

// LayerType returns either gopacket.LayerTypeSCTPInit or gopacket.LayerTypeSCTPInitAck.
func (sc *SCTPInit) LayerType() gopacket.LayerType {
	if sc.Type == SCTPChunkTypeInitAck {
		return LayerTypeSCTPInitAck
	}
	// sc.Type == SCTPChunkTypeInit
	return LayerTypeSCTPInit
}

func decodeSCTPInit(data []byte) (out gopacket.DecodeResult, _ error) {
	sc := &SCTPInit{
		SCTPChunk:                      decodeSCTPChunk(data),
		InitiateTag:                    binary.BigEndian.Uint32(data[4:8]),
		AdvertisedReceiverWindowCredit: binary.BigEndian.Uint32(data[8:12]),
		OutboundStreams:                binary.BigEndian.Uint16(data[12:14]),
		InboundStreams:                 binary.BigEndian.Uint16(data[14:16]),
		InitialTSN:                     binary.BigEndian.Uint32(data[16:20]),
	}
	paramData := data[20:sc.ActualLength]
	for len(paramData) > 0 {
		p := SCTPInitParameter(decodeSCTPParameter(paramData))
		paramData = paramData[p.ActualLength:]
		sc.Parameters = append(sc.Parameters, p)
	}
	out.DecodedLayer = sc
	out.NextDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)
	return
}

// SCTPSack is the SCTP Selective ACK chunk layer.
type SCTPSack struct {
	SCTPChunk
	CumulativeTSNAck               uint32
	AdvertisedReceiverWindowCredit uint32
	NumGapACKs, NumDuplicateTSNs   uint16
	GapACKs                        []uint16
	DuplicateTSNs                  []uint32
}

// LayerType return LayerTypeSCTPSack
func (sc *SCTPSack) LayerType() gopacket.LayerType {
	return LayerTypeSCTPSack
}

func decodeSCTPSack(data []byte) (out gopacket.DecodeResult, _ error) {
	sc := &SCTPSack{
		SCTPChunk:                      decodeSCTPChunk(data),
		CumulativeTSNAck:               binary.BigEndian.Uint32(data[4:8]),
		AdvertisedReceiverWindowCredit: binary.BigEndian.Uint32(data[8:12]),
		NumGapACKs:                     binary.BigEndian.Uint16(data[12:14]),
		NumDuplicateTSNs:               binary.BigEndian.Uint16(data[14:16]),
	}
	// We maximize gapAcks and dupTSNs here so we're not allocating tons
	// of memory based on a user-controlable field.  Our maximums are not exact,
	// but should give us sane defaults... we'll still hit slice boundaries and
	// fail if the user-supplied values are too high (in the for loops below), but
	// the amount of memory we'll have allocated because of that should be small
	// (< sc.ActualLength)
	gapAcks := sc.SCTPChunk.ActualLength / 2
	dupTSNs := (sc.SCTPChunk.ActualLength - gapAcks*2) / 4
	if gapAcks > int(sc.NumGapACKs) {
		gapAcks = int(sc.NumGapACKs)
	}
	if dupTSNs > int(sc.NumDuplicateTSNs) {
		dupTSNs = int(sc.NumDuplicateTSNs)
	}
	sc.GapACKs = make([]uint16, 0, gapAcks)
	sc.DuplicateTSNs = make([]uint32, 0, dupTSNs)
	bytesRemaining := data[16:]
	for i := 0; i < int(sc.NumGapACKs); i++ {
		sc.GapACKs = append(sc.GapACKs, binary.BigEndian.Uint16(bytesRemaining[:2]))
		bytesRemaining = bytesRemaining[2:]
	}
	for i := 0; i < int(sc.NumDuplicateTSNs); i++ {
		sc.DuplicateTSNs = append(sc.DuplicateTSNs, binary.BigEndian.Uint32(bytesRemaining[:4]))
		bytesRemaining = bytesRemaining[4:]
	}
	out.DecodedLayer = sc
	out.NextDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)
	return
}

// SCTPHeartbeatParameter is the parameter type used by SCTP heartbeat and
// heartbeat ack layers.
type SCTPHeartbeatParameter SCTPParameter

// SCTPHeartbeat is the SCTP heartbeat layer, also used for heatbeat ack.
type SCTPHeartbeat struct {
	SCTPChunk
	Parameters []SCTPHeartbeatParameter
}

// LayerType returns gopacket.LayerTypeSCTPHeartbeat.
func (sc *SCTPHeartbeat) LayerType() gopacket.LayerType {
	if sc.Type == SCTPChunkTypeHeartbeatAck {
		return LayerTypeSCTPHeartbeatAck
	}
	// sc.Type == SCTPChunkTypeHeartbeat
	return LayerTypeSCTPHeartbeat
}

func decodeSCTPHeartbeat(data []byte) (out gopacket.DecodeResult, _ error) {
	sc := &SCTPHeartbeat{
		SCTPChunk: decodeSCTPChunk(data),
	}
	paramData := data[4:sc.Length]
	for len(paramData) > 0 {
		p := SCTPHeartbeatParameter(decodeSCTPParameter(paramData))
		paramData = paramData[p.ActualLength:]
		sc.Parameters = append(sc.Parameters, p)
	}
	out.DecodedLayer = sc
	out.NextDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)
	return
}

// SCTPErrorParameter is the parameter type used by SCTP Abort and Error layers.
type SCTPErrorParameter SCTPParameter

// SCTPError is the SCTP error layer, also used for SCTP aborts.
type SCTPError struct {
	SCTPChunk
	Parameters []SCTPErrorParameter
}

func (sc *SCTPError) LayerType() gopacket.LayerType {
	if sc.Type == SCTPChunkTypeAbort {
		return LayerTypeSCTPAbort
	}
	// sc.Type == SCTPChunkTypeError
	return LayerTypeSCTPError
}

func decodeSCTPError(data []byte) (out gopacket.DecodeResult, _ error) {
	// remarkably similarot decodeSCTPHeartbeat ;)
	sc := &SCTPError{
		SCTPChunk: decodeSCTPChunk(data),
	}
	paramData := data[4:sc.Length]
	for len(paramData) > 0 {
		p := SCTPErrorParameter(decodeSCTPParameter(paramData))
		paramData = paramData[p.ActualLength:]
		sc.Parameters = append(sc.Parameters, p)
	}
	out.DecodedLayer = sc
	out.NextDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)
	return
}

// SCTPShutdown is the SCTP shutdown layer.
type SCTPShutdown struct {
	SCTPChunk
	CumulativeTSNAck uint32
}

// LayerType returns gopacket.LayerTypeSCTPShutdown.
func (sc *SCTPShutdown) LayerType() gopacket.LayerType { return LayerTypeSCTPShutdown }

func decodeSCTPShutdown(data []byte) (out gopacket.DecodeResult, _ error) {
	sc := &SCTPShutdown{
		SCTPChunk:        decodeSCTPChunk(data),
		CumulativeTSNAck: binary.BigEndian.Uint32(data[4:8]),
	}
	out.DecodedLayer = sc
	out.NextDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)
	return
}

// SCTPShutdownAck is the SCTP shutdown layer.
type SCTPShutdownAck struct {
	SCTPChunk
}

// LayerType returns gopacket.LayerTypeSCTPShutdownAck.
func (sc *SCTPShutdownAck) LayerType() gopacket.LayerType { return LayerTypeSCTPShutdownAck }

func decodeSCTPShutdownAck(data []byte) (out gopacket.DecodeResult, _ error) {
	sc := &SCTPShutdownAck{
		SCTPChunk: decodeSCTPChunk(data),
	}
	out.DecodedLayer = sc
	out.NextDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)
	return
}

// SCTPCookieEcho is the SCTP Cookie Echo layer.
type SCTPCookieEcho struct {
	SCTPChunk
	Cookie []byte
}

// LayerType returns gopacket.LayerTypeSCTPCookieEcho.
func (sc *SCTPCookieEcho) LayerType() gopacket.LayerType { return LayerTypeSCTPCookieEcho }

func decodeSCTPCookieEcho(data []byte) (out gopacket.DecodeResult, _ error) {
	sc := &SCTPCookieEcho{
		SCTPChunk: decodeSCTPChunk(data),
	}
	sc.Cookie = data[4:sc.Length]
	out.DecodedLayer = sc
	out.NextDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)
	return
}

// This struct is used by all empty SCTP chunks (currently CookieAck and
// ShutdownComplete).
type SCTPEmptyLayer struct {
	SCTPChunk
}

// LayerType returns either gopacket.LayerTypeSCTPShutdownComplete or
// LayerTypeSCTPCookieAck.
func (sc *SCTPEmptyLayer) LayerType() gopacket.LayerType {
	if sc.Type == SCTPChunkTypeShutdownComplete {
		return LayerTypeSCTPShutdownComplete
	}
	// sc.Type == SCTPChunkTypeCookieAck
	return LayerTypeSCTPCookieAck
}

func decodeSCTPEmptyLayer(data []byte) (out gopacket.DecodeResult, _ error) {
	sc := &SCTPEmptyLayer{
		SCTPChunk: decodeSCTPChunk(data),
	}
	out.DecodedLayer = sc
	out.NextDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)
	return
}
