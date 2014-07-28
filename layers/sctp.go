// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
	"fmt"
)

// SCTP contains information on the top level of an SCTP packet.
type SCTP struct {
	BaseLayer
	SrcPort, DstPort SCTPPort
	VerificationTag  uint32
	Checksum         uint32
	sPort, dPort     []byte
}

// LayerType returns gopacket.LayerTypeSCTP
func (s *SCTP) LayerType() gopacket.LayerType { return LayerTypeSCTP }

func decodeSCTP(data []byte, p gopacket.PacketBuilder) error {
	sctp := &SCTP{
		SrcPort:         SCTPPort(binary.BigEndian.Uint16(data[:2])),
		sPort:           data[:2],
		DstPort:         SCTPPort(binary.BigEndian.Uint16(data[2:4])),
		dPort:           data[2:4],
		VerificationTag: binary.BigEndian.Uint32(data[4:8]),
		Checksum:        binary.BigEndian.Uint32(data[8:12]),
		BaseLayer:       BaseLayer{data[:12], data[12:]},
	}
	p.AddLayer(sctp)
	p.SetTransportLayer(sctp)
	return p.NextDecoder(sctpChunkTypePrefixDecoder)
}

var sctpChunkTypePrefixDecoder = gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix)

// TransportFlow returns a flow based on the source and destination SCTP port.
func (s *SCTP) TransportFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointSCTPPort, s.sPort, s.dPort)
}

func decodeWithSCTPChunkTypePrefix(data []byte, p gopacket.PacketBuilder) error {
	chunkType := SCTPChunkType(data[0])
	return chunkType.Decode(data, p)
}

// SerializeTo is for gopacket.SerializableLayer.
func (s SCTP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var payload []byte
	if opts.ComputeChecksums {
		payload = b.Bytes()
	}
	bytes, err := b.PrependBytes(12)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes[0:2], uint16(s.SrcPort))
	binary.BigEndian.PutUint16(bytes[2:4], uint16(s.DstPort))
	binary.BigEndian.PutUint32(bytes[4:8], s.VerificationTag)
	if opts.ComputeChecksums {
		binary.LittleEndian.PutUint32(bytes[8:12], s.computeChecksum(payload))
	}
	return nil
}

func (s SCTP) computeChecksum(payload []byte) uint32 {
	s.Checksum = 0
	sb := gopacket.NewSerializeBuffer()
	s.SerializeTo(sb, gopacket.SerializeOptions{ComputeChecksums: false})
	// RFC 3309
	crc_c := [256]uint32{
		0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
		0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
		0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
		0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
		0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
		0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
		0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
		0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
		0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
		0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
		0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
		0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
		0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
		0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
		0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
		0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
		0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
		0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
		0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
		0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
		0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
		0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
		0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
		0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
		0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
		0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
		0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
		0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
		0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
		0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
		0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
		0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
		0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
		0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
		0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
		0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
		0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
		0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
		0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
		0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
		0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
		0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
		0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
		0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
		0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
		0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
		0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
		0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
		0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
		0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
		0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
		0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
		0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
		0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
		0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
		0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
		0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
		0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
		0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
		0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
		0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
		0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
		0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
		0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
	}

	crc32 := uint32(0xffffffff)
	for _, b := range sb.Bytes() {
		crc32 = (crc32 >> 8) ^ crc_c[(byte(crc32)^b)&0xFF]
	}
	for _, b := range payload {
		crc32 = (crc32 >> 8) ^ crc_c[(byte(crc32)^b)&0xFF]
	}
	return 0xffffffff &^ crc32
}

// SCTPChunk contains the common fields in all SCTP chunks.
type SCTPChunk struct {
	BaseLayer
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
		BaseLayer:    BaseLayer{data[:actual], data[actual:]},
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

func (p SCTPParameter) Bytes() []byte {
	length := 4 + len(p.Value)
	data := make([]byte, roundUpToNearest4(length))
	binary.BigEndian.PutUint16(data[0:2], p.Type)
	binary.BigEndian.PutUint16(data[2:4], uint16(length))
	copy(data[4:], p.Value)
	return data
}

// SCTPUnknownChunkType is the layer type returned when we don't recognize the
// chunk type.  Since there's a length in a known location, we can skip over
// it even if we don't know what it is, and continue parsing the rest of the
// chunks.  This chunk is stored as an ErrorLayer in the packet.
type SCTPUnknownChunkType struct {
	SCTPChunk
	bytes []byte
}

func decodeSCTPChunkTypeUnknown(data []byte, p gopacket.PacketBuilder) error {
	sc := &SCTPUnknownChunkType{SCTPChunk: decodeSCTPChunk(data)}
	sc.bytes = data[:sc.ActualLength]
	p.AddLayer(sc)
	p.SetErrorLayer(sc)
	return p.NextDecoder(gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix))
}

// SerializeTo is for gopacket.SerializableLayer.
func (s SCTPUnknownChunkType) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(s.ActualLength)
	if err != nil {
		return err
	}
	copy(bytes, s.bytes)
	return nil
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

func decodeSCTPData(data []byte, p gopacket.PacketBuilder) error {
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
	p.AddLayer(sc)
	p.SetApplicationLayer(sc)
	return p.NextDecoder(gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix))
}

// SerializeTo is for gopacket.SerializableLayer.
func (sc SCTPData) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	length := 16 + len(sc.PayloadData)
	bytes, err := b.PrependBytes(roundUpToNearest4(length))
	if err != nil {
		return err
	}
	bytes[0] = uint8(sc.Type)
	flags := uint8(0)
	if sc.Unordered {
		flags |= 0x4
	}
	if sc.BeginFragment {
		flags |= 0x2
	}
	if sc.EndFragment {
		flags |= 0x1
	}
	bytes[1] = flags
	binary.BigEndian.PutUint16(bytes[2:4], uint16(length))
	binary.BigEndian.PutUint32(bytes[4:8], sc.TSN)
	binary.BigEndian.PutUint16(bytes[8:10], sc.StreamId)
	binary.BigEndian.PutUint16(bytes[10:12], sc.StreamSequence)
	binary.BigEndian.PutUint32(bytes[12:16], sc.PayloadProtocol)
	copy(bytes[16:], sc.PayloadData)
	return nil
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

func decodeSCTPInit(data []byte, p gopacket.PacketBuilder) error {
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
	p.AddLayer(sc)
	return p.NextDecoder(gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix))
}

// SerializeTo is for gopacket.SerializableLayer.
func (sc SCTPInit) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var payload []byte
	for _, param := range sc.Parameters {
		payload = append(payload, SCTPParameter(param).Bytes()...)
	}
	length := 20 + len(payload)

	bytes, err := b.PrependBytes(roundUpToNearest4(length))
	if err != nil {
		return err
	}
	bytes[0] = uint8(sc.Type)
	bytes[1] = sc.Flags
	binary.BigEndian.PutUint16(bytes[2:4], uint16(length))
	binary.BigEndian.PutUint32(bytes[4:8], sc.InitiateTag)
	binary.BigEndian.PutUint32(bytes[8:12], sc.AdvertisedReceiverWindowCredit)
	binary.BigEndian.PutUint16(bytes[12:14], sc.OutboundStreams)
	binary.BigEndian.PutUint16(bytes[14:16], sc.InboundStreams)
	binary.BigEndian.PutUint32(bytes[16:20], sc.InitialTSN)
	copy(bytes[20:], payload)
	return nil
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

func decodeSCTPSack(data []byte, p gopacket.PacketBuilder) error {
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
	p.AddLayer(sc)
	return p.NextDecoder(gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix))
}

// SerializeTo is for gopacket.SerializableLayer.
func (sc SCTPSack) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	length := 16 + 2*len(sc.GapACKs) + 4*len(sc.DuplicateTSNs)
	bytes, err := b.PrependBytes(roundUpToNearest4(length))
	if err != nil {
		return err
	}
	bytes[0] = uint8(sc.Type)
	bytes[1] = sc.Flags
	binary.BigEndian.PutUint16(bytes[2:4], uint16(length))
	binary.BigEndian.PutUint32(bytes[4:8], sc.CumulativeTSNAck)
	binary.BigEndian.PutUint32(bytes[8:12], sc.AdvertisedReceiverWindowCredit)
	binary.BigEndian.PutUint16(bytes[12:14], uint16(len(sc.GapACKs)))
	binary.BigEndian.PutUint16(bytes[14:16], uint16(len(sc.DuplicateTSNs)))
	for i, v := range sc.GapACKs {
		binary.BigEndian.PutUint16(bytes[16+i*2:], v)
	}
	offset := 16 + 2*len(sc.GapACKs)
	for i, v := range sc.DuplicateTSNs {
		binary.BigEndian.PutUint32(bytes[offset+i*4:], v)
	}
	return nil
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

func decodeSCTPHeartbeat(data []byte, p gopacket.PacketBuilder) error {
	sc := &SCTPHeartbeat{
		SCTPChunk: decodeSCTPChunk(data),
	}
	paramData := data[4:sc.Length]
	for len(paramData) > 0 {
		p := SCTPHeartbeatParameter(decodeSCTPParameter(paramData))
		paramData = paramData[p.ActualLength:]
		sc.Parameters = append(sc.Parameters, p)
	}
	p.AddLayer(sc)
	return p.NextDecoder(gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix))
}

// SerializeTo is for gopacket.SerializableLayer.
func (sc SCTPHeartbeat) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var payload []byte
	for _, param := range sc.Parameters {
		payload = append(payload, SCTPParameter(param).Bytes()...)
	}
	length := 4 + len(payload)

	bytes, err := b.PrependBytes(roundUpToNearest4(length))
	if err != nil {
		return err
	}
	bytes[0] = uint8(sc.Type)
	bytes[1] = sc.Flags
	binary.BigEndian.PutUint16(bytes[2:4], uint16(length))
	copy(bytes[4:], payload)
	return nil
}

// SCTPErrorParameter is the parameter type used by SCTP Abort and Error layers.
type SCTPErrorParameter SCTPParameter

// SCTPError is the SCTP error layer, also used for SCTP aborts.
type SCTPError struct {
	SCTPChunk
	Parameters []SCTPErrorParameter
}

// LayerType returns LayerTypeSCTPAbort or LayerTypeSCTPError.
func (sc *SCTPError) LayerType() gopacket.LayerType {
	if sc.Type == SCTPChunkTypeAbort {
		return LayerTypeSCTPAbort
	}
	// sc.Type == SCTPChunkTypeError
	return LayerTypeSCTPError
}

func decodeSCTPError(data []byte, p gopacket.PacketBuilder) error {
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
	p.AddLayer(sc)
	return p.NextDecoder(gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix))
}

// SerializeTo is for gopacket.SerializableLayer.
func (sc SCTPError) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	var payload []byte
	for _, param := range sc.Parameters {
		payload = append(payload, SCTPParameter(param).Bytes()...)
	}
	length := 4 + len(payload)

	bytes, err := b.PrependBytes(roundUpToNearest4(length))
	if err != nil {
		return err
	}
	bytes[0] = uint8(sc.Type)
	bytes[1] = sc.Flags
	binary.BigEndian.PutUint16(bytes[2:4], uint16(length))
	copy(bytes[4:], payload)
	return nil
}

// SCTPShutdown is the SCTP shutdown layer.
type SCTPShutdown struct {
	SCTPChunk
	CumulativeTSNAck uint32
}

// LayerType returns gopacket.LayerTypeSCTPShutdown.
func (sc *SCTPShutdown) LayerType() gopacket.LayerType { return LayerTypeSCTPShutdown }

func decodeSCTPShutdown(data []byte, p gopacket.PacketBuilder) error {
	sc := &SCTPShutdown{
		SCTPChunk:        decodeSCTPChunk(data),
		CumulativeTSNAck: binary.BigEndian.Uint32(data[4:8]),
	}
	p.AddLayer(sc)
	return p.NextDecoder(gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix))
}

// SerializeTo is for gopacket.SerializableLayer.
func (sc SCTPShutdown) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return err
	}
	bytes[0] = uint8(sc.Type)
	bytes[1] = sc.Flags
	binary.BigEndian.PutUint16(bytes[2:4], 8)
	binary.BigEndian.PutUint32(bytes[4:8], sc.CumulativeTSNAck)
	return nil
}

// SCTPShutdownAck is the SCTP shutdown layer.
type SCTPShutdownAck struct {
	SCTPChunk
}

// LayerType returns gopacket.LayerTypeSCTPShutdownAck.
func (sc *SCTPShutdownAck) LayerType() gopacket.LayerType { return LayerTypeSCTPShutdownAck }

func decodeSCTPShutdownAck(data []byte, p gopacket.PacketBuilder) error {
	sc := &SCTPShutdownAck{
		SCTPChunk: decodeSCTPChunk(data),
	}
	p.AddLayer(sc)
	return p.NextDecoder(gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix))
}

// SerializeTo is for gopacket.SerializableLayer.
func (sc SCTPShutdownAck) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	bytes[0] = uint8(sc.Type)
	bytes[1] = sc.Flags
	binary.BigEndian.PutUint16(bytes[2:4], 4)
	return nil
}

// SCTPCookieEcho is the SCTP Cookie Echo layer.
type SCTPCookieEcho struct {
	SCTPChunk
	Cookie []byte
}

// LayerType returns gopacket.LayerTypeSCTPCookieEcho.
func (sc *SCTPCookieEcho) LayerType() gopacket.LayerType { return LayerTypeSCTPCookieEcho }

func decodeSCTPCookieEcho(data []byte, p gopacket.PacketBuilder) error {
	sc := &SCTPCookieEcho{
		SCTPChunk: decodeSCTPChunk(data),
	}
	sc.Cookie = data[4:sc.Length]
	p.AddLayer(sc)
	return p.NextDecoder(gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix))
}

// SerializeTo is for gopacket.SerializableLayer.
func (sc SCTPCookieEcho) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	length := 4 + len(sc.Cookie)
	bytes, err := b.PrependBytes(roundUpToNearest4(length))
	if err != nil {
		return err
	}
	bytes[0] = uint8(sc.Type)
	bytes[1] = sc.Flags
	binary.BigEndian.PutUint16(bytes[2:4], uint16(length))
	copy(bytes[4:], sc.Cookie)
	return nil
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

func decodeSCTPEmptyLayer(data []byte, p gopacket.PacketBuilder) error {
	sc := &SCTPEmptyLayer{
		SCTPChunk: decodeSCTPChunk(data),
	}
	p.AddLayer(sc)
	return p.NextDecoder(gopacket.DecodeFunc(decodeWithSCTPChunkTypePrefix))
}

// SerializeTo is for gopacket.SerializableLayer.
func (sc SCTPEmptyLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	bytes[0] = uint8(sc.Type)
	bytes[1] = sc.Flags
	binary.BigEndian.PutUint16(bytes[2:4], 4)
	return nil
}
