// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"net"
)

const (
	ipv6MaxPayloadLength = 65535
)

// https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
type IPv6HeaderTLVOptionType uint8

const (
	IPv6TLVOptionPad1      IPv6HeaderTLVOptionType = 0x00
	IPv6TLVOptionPadN      IPv6HeaderTLVOptionType = 0x01
	IPv6TLVOptionJumbogram IPv6HeaderTLVOptionType = 0xc2
)

type DecodeIPv6TLVOptionFunc func([]byte, gopacket.DecodeFeedback) (IPv6HeaderTLVOption, error)

type IPv6TLVOptionEnumMetadata struct {
	DecodeWith DecodeIPv6TLVOptionFunc
}

type IPv6RoutingType uint8

const (
	IPv6RoutingSourceRoute IPv6RoutingType = 0
)

func (a IPv6RoutingType) Decode(data []byte, p gopacket.PacketBuilder) error {
	m, ok := IPv6RoutingTypeMetadata[a]
	if !ok {
		return fmt.Errorf("Unknown IPv6 routing type %d", a)
	}
	return m.DecodeWith.Decode(data, p)
}
func (a IPv6RoutingType) String() string {
	m, ok := IPv6RoutingTypeMetadata[a]
	if !ok {
		return fmt.Sprintf("Unknown IPv6RoutingType %d", a)
	}
	return m.Name
}
func (a IPv6RoutingType) LayerType() gopacket.LayerType {
	return LayerTypeIPv6Routing
}

type IPv6RoutingEnumMetadata struct {
	DecodeWith gopacket.Decoder
	Name       string
	LayerType  gopacket.LayerType
}

var (
	IPv6TLVOptionTypeMetadata map[IPv6HeaderTLVOptionType]*IPv6TLVOptionEnumMetadata
	IPv6RoutingTypeMetadata   map[IPv6RoutingType]*IPv6RoutingEnumMetadata
)

func init() {
	IPv6TLVOptionTypeMetadata = make(map[IPv6HeaderTLVOptionType]*IPv6TLVOptionEnumMetadata)

	IPv6TLVOptionTypeMetadata[IPv6TLVOptionPad1] = &IPv6TLVOptionEnumMetadata{DecodeWith: DecodeIPv6TLVOptionFunc(decodeIPv6HeaderTLVOption)}
	IPv6TLVOptionTypeMetadata[IPv6TLVOptionPadN] = &IPv6TLVOptionEnumMetadata{DecodeWith: DecodeIPv6TLVOptionFunc(decodeIPv6HeaderTLVOption)}
	IPv6TLVOptionTypeMetadata[IPv6TLVOptionJumbogram] = &IPv6TLVOptionEnumMetadata{DecodeWith: DecodeIPv6TLVOptionFunc(decodeIPv6HeaderTLVOption)}

	IPv6RoutingTypeMetadata = make(map[IPv6RoutingType]*IPv6RoutingEnumMetadata)

	IPv6RoutingTypeMetadata[IPv6RoutingSourceRoute] = &IPv6RoutingEnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6RoutingType0), Name: "IPv6RoutingSourceRoute"}
}

// IPv6 is the layer for the IPv6 header.
type IPv6 struct {
	// http://www.networksorcery.com/enp/protocol/ipv6.htm
	BaseLayer
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	Length       uint16
	NextHeader   IPProtocol
	HopLimit     uint8
	SrcIP        net.IP
	DstIP        net.IP
	RoutingDstIP net.IP
}

// LayerType returns LayerTypeIPv6
func (i *IPv6) LayerType() gopacket.LayerType { return LayerTypeIPv6 }

func (i *IPv6) NetworkFlow() gopacket.Flow {
	dst := i.DstIP
	if i.RoutingDstIP != nil {
		dst = i.RoutingDstIP
	}
	return gopacket.NewFlow(EndpointIPv6, i.SrcIP, dst)
}

func (i *IPv6) CanDecode() gopacket.LayerClass {
	return LayerTypeIPv6
}
func (i *IPv6) NextLayerType() gopacket.LayerType {
	return i.NextHeader.LayerType()
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (ip6 *IPv6) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	payload := b.Bytes()
	pLen := len(payload)
	if opts.FixLengths && pLen > ipv6MaxPayloadLength {
		if ip6.NextHeader != IPProtocolIPv6HopByHop {
			return fmt.Errorf("Cannot fit payload length of %d into IPv6 packet, need Hop-By-Hop", pLen)
		}
		pLen = 0
	}
	bytes, err := b.PrependBytes(40)
	if err != nil {
		return err
	}
	bytes[0] = (ip6.Version << 4) | (ip6.TrafficClass >> 4)
	bytes[1] = (ip6.TrafficClass << 4) | uint8(ip6.FlowLabel>>16)
	binary.BigEndian.PutUint16(bytes[2:], uint16(ip6.FlowLabel))
	if opts.FixLengths {
		ip6.Length = uint16(pLen)
	}
	binary.BigEndian.PutUint16(bytes[4:], ip6.Length)
	bytes[6] = byte(ip6.NextHeader)
	bytes[7] = byte(ip6.HopLimit)
	if err := ip6.AddressTo16(); err != nil {
		return err
	}
	copy(bytes[8:], ip6.SrcIP)
	copy(bytes[24:], ip6.DstIP)
	return nil
}

func (ip6 *IPv6) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	ip6.Version = uint8(data[0]) >> 4
	ip6.TrafficClass = uint8((binary.BigEndian.Uint16(data[0:2]) >> 4) & 0x00FF)
	ip6.FlowLabel = binary.BigEndian.Uint32(data[0:4]) & 0x000FFFFF
	ip6.Length = binary.BigEndian.Uint16(data[4:6])
	ip6.NextHeader = IPProtocol(data[6])
	ip6.HopLimit = data[7]
	ip6.SrcIP = data[8:24]
	ip6.DstIP = data[24:40]
	ip6.BaseLayer = BaseLayer{data[:40], data[40:]}

	if ip6.Length == 0 && ip6.NextHeader != IPProtocolIPv6HopByHop {
		return fmt.Errorf("IPv6 length 0, but next header is %v, not HopByHop", ip6.NextHeader)
	} else if ip6.Length != 0 {
		pEnd := int(ip6.Length)
		if pEnd > len(ip6.Payload) {
			df.SetTruncated()
			pEnd = len(ip6.Payload)
		}
		ip6.Payload = ip6.Payload[:pEnd]
	}
	return nil
}

func decodeIPv6(data []byte, p gopacket.PacketBuilder) error {
	ip6 := &IPv6{}
	err := ip6.DecodeFromBytes(data, p)
	p.AddLayer(ip6)
	p.SetNetworkLayer(ip6)
	if err != nil {
		return err
	}
	return p.NextDecoder(ip6.NextHeader)
}

type IPv6HeaderTLVOption interface {
	OptionType() uint8
	OptionLength() uint8
	ActualLength() int
	OptionValue([]byte)
	ActualData([]byte)
	OptionAlignment() [2]uint8 // Xn+Y = [2]uint8{X, Y}
}

type IPv6HeaderTLVOptionUnknown struct {
	Type      uint8
	Value     []byte
	Alignment [2]uint8
}

func (o IPv6HeaderTLVOptionUnknown) OptionType() uint8 { return o.Type }

func (o IPv6HeaderTLVOptionUnknown) OptionLength() uint8 { return uint8(len(o.Value)) }

func (o IPv6HeaderTLVOptionUnknown) ActualLength() int {
	return 2 + int(o.OptionLength())
}

func (o IPv6HeaderTLVOptionUnknown) OptionValue(data []byte) {
	copy(data, o.Value)
}

func (o IPv6HeaderTLVOptionUnknown) ActualData(data []byte) {
	data[0] = o.OptionType()
	data[1] = o.OptionLength()
	o.OptionValue(data[2:])
}

func (o IPv6HeaderTLVOptionUnknown) OptionAlignment() [2]uint8 { return o.Alignment }

type IPv6HeaderTLVOptionPad uint8

func (o IPv6HeaderTLVOptionPad) OptionType() uint8 {
	if o <= 1 {
		return 0
	}
	return 1
}

func (o IPv6HeaderTLVOptionPad) OptionLength() uint8 {
	if o < 2 {
		return 0
	}
	return uint8(o) - 2
}

func (o IPv6HeaderTLVOptionPad) ActualLength() int {
	if o == 1 {
		return 1
	}
	return 2 + int(o.OptionLength())
}

func (o IPv6HeaderTLVOptionPad) OptionValue(data []byte) {
	if o.ActualLength() == 1 {
		data[0] = 0
		return
	}
	for i := uint8(0); i < o.OptionLength(); i++ {
		data[i] = 0
	}
}

func (o IPv6HeaderTLVOptionPad) ActualData(data []byte) {
	data[0] = o.OptionType()
	if o.OptionType() == 0 {
		return
	}
	data[1] = o.OptionLength()
	o.OptionValue(data[2:])
}

func (o IPv6HeaderTLVOptionPad) GoString() string {
	if o < 2 {
		return "IPv6HeaderTLVOptionPad1"
	}
	return fmt.Sprintf("IPv6HeaderTLVOptionPadN(%d)", o)
}

func (o IPv6HeaderTLVOptionPad) OptionAlignment() [2]uint8 { return [2]uint8{0, 0} }

type IPv6HeaderTLVOptionJumbo uint32

func (o IPv6HeaderTLVOptionJumbo) OptionType() uint8 { return uint8(IPv6TLVOptionJumbogram) }

func (o IPv6HeaderTLVOptionJumbo) OptionLength() uint8 { return 4 }

func (o IPv6HeaderTLVOptionJumbo) ActualLength() int { return 6 }

func (o IPv6HeaderTLVOptionJumbo) OptionValue(data []byte) {
	binary.BigEndian.PutUint32(data, uint32(o))
}

func (o IPv6HeaderTLVOptionJumbo) ActualData(data []byte) {
	data[0] = o.OptionType()
	data[1] = o.OptionLength()
	o.OptionValue(data[2:])
}

func (o IPv6HeaderTLVOptionJumbo) OptionAlignment() [2]uint8 { return [2]uint8{4, 2} }

func (o IPv6HeaderTLVOptionJumbo) GoString() string {
	return fmt.Sprintf("IPv6HeaderTLVOptionJumbo(%d)", o)
}

func IPv6AlignHeaderTLVOptions(options *[]IPv6HeaderTLVOption) {
	if len(*options) == 0 {
		return
	}
	oldOpt := *options
	newOpt := make([]IPv6HeaderTLVOption, 0, len(oldOpt))
	length := 2
	for _, opt := range oldOpt {
		x := int(opt.OptionAlignment()[0])
		y := int(opt.OptionAlignment()[1])
		if x != 0 {
			n := length / x
			offset := x*n + y
			if offset < length {
				offset += x
			}
			if length != offset {
				pad := offset - length
				newOpt = append(newOpt, IPv6HeaderTLVOptionPad(pad))
				length += pad
			}
		}
		newOpt = append(newOpt, opt)
		length += opt.ActualLength()
	}
	pad := length % 8
	if pad != 0 {
		newOpt = append(newOpt, IPv6HeaderTLVOptionPad(pad))
		length += pad
	}
	*options = newOpt
}

func serializeIPv6HeaderTLVOptions(b gopacket.SerializeBuffer, options []IPv6HeaderTLVOption, fixLengths bool) (int, error) {
	if fixLengths {
		IPv6AlignHeaderTLVOptions(&options)
	}
	var length int
	for _, opt := range options {
		length += opt.ActualLength()
	}
	bytes, err := b.PrependBytes(length)
	if err != nil {
		return 0, err
	}
	for _, opt := range options {
		opt.ActualData(bytes)
		bytes = bytes[opt.ActualLength():]
	}
	return length, nil
}

func decodeIPv6HeaderTLVOption(data []byte, df gopacket.DecodeFeedback) (IPv6HeaderTLVOption, error) {
	var tlv IPv6HeaderTLVOption
	var err error

	t := IPv6HeaderTLVOptionType(data[0])
	if t == IPv6TLVOptionPad1 {
		return IPv6HeaderTLVOptionPad(1), nil
	}
	l := int(data[1])
	switch t {
	case IPv6TLVOptionPadN:
		tlv = IPv6HeaderTLVOptionPad(l + 2)
	case IPv6TLVOptionJumbogram:
		if l != 4 {
			err = fmt.Errorf("Invalid jumbo TLV length (%d bytes)", l)
		} else {
			tlv = IPv6HeaderTLVOptionJumbo(binary.BigEndian.Uint32(data[2:]))
		}
	default:
		m, ok := IPv6TLVOptionTypeMetadata[t]
		if ok {
			return m.DecodeWith(data, df)
		}
		tlv := IPv6HeaderTLVOptionUnknown{}
		tlv.Type = data[0]
		l := int(data[1])
		tlv.Value = make([]byte, l)
		copy(tlv.Value, data[2:])
	}
	return tlv, err
}

type ipv6ExtensionBase struct {
	BaseLayer
	NextHeader   IPProtocol
	HeaderLength uint8
	ActualLength int
}

func decodeIPv6ExtensionBase(data []byte) (i ipv6ExtensionBase) {
	i.NextHeader = IPProtocol(data[0])
	i.HeaderLength = data[1]
	i.ActualLength = int(i.HeaderLength)*8 + 8
	i.Contents = data[:i.ActualLength]
	i.Payload = data[i.ActualLength:]
	return
}

// IPv6HopByHop is the IPv6 hop-by-hop extension.
type IPv6HopByHop struct {
	ipv6ExtensionBase
	Options []IPv6HeaderTLVOption
}

// LayerType returns LayerTypeIPv6HopByHop.
func (i *IPv6HopByHop) LayerType() gopacket.LayerType { return LayerTypeIPv6HopByHop }

func (i *IPv6HopByHop) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	payload := b.Bytes()
	pLen := len(payload)
	if opts.FixLengths {
		var l int
		IPv6AlignHeaderTLVOptions(&i.Options)
		l = 2
		for _, t := range i.Options {
			l += t.ActualLength()
		}
		pLen += l
	}
	if pLen > ipv6MaxPayloadLength {
		var jmb *IPv6HeaderTLVOptionJumbo
		// Check if Jumbo option is present
		for _, t := range i.Options {
			if j, ok := t.(IPv6HeaderTLVOptionJumbo); ok {
				jmb = &j
				break
			}
		}
		if jmb == nil && !opts.FixLengths {
			return fmt.Errorf("Missing jumbo length hop-by-hop option")
		} else if opts.FixLengths {
			var l int
			// If not, insert it
			if jmb == nil {
				jmb = new(IPv6HeaderTLVOptionJumbo)
				i.Options = append(i.Options, jmb)
				IPv6AlignHeaderTLVOptions(&i.Options)
				l = 2
				for _, t := range i.Options {
					l += t.ActualLength()
				}
				pLen = len(payload) + l
			}
			*jmb = IPv6HeaderTLVOptionJumbo(pLen)
		}
	}

	l, err := serializeIPv6HeaderTLVOptions(b, i.Options, opts.FixLengths)
	if err != nil {
		return err
	}
	length := l + 2
	if length%8 != 0 {
		return fmt.Errorf("IPv6HopByHop actual length must be multiple of 8")
	}
	bytes, err := b.PrependBytes(2)
	if err != nil {
		return err
	}
	bytes[0] = uint8(i.NextHeader)
	if opts.FixLengths {
		i.HeaderLength = uint8((length / 8) - 1)
	}
	bytes[1] = uint8(i.HeaderLength)
	return nil
}

func (i *IPv6HopByHop) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	i.ipv6ExtensionBase = decodeIPv6ExtensionBase(data)
	offset := 2
	for offset < i.ActualLength {
		opt, err := decodeIPv6HeaderTLVOption(data[offset:], df)
		if err != nil {
			return err
		}
		i.Options = append(i.Options, opt)
		offset += opt.ActualLength()
	}
	return nil
}

func decodeIPv6HopByHop(data []byte, p gopacket.PacketBuilder) error {
	i := &IPv6HopByHop{}
	err := i.DecodeFromBytes(data, p)
	p.AddLayer(i)
	if err != nil {
		return err
	}
	l := p.LastNetworkLayer()
	if ip6, ok := l.(*IPv6); ok {
		var jmb *IPv6HeaderTLVOptionJumbo
		for _, t := range i.Options {
			if j, ok := t.(IPv6HeaderTLVOptionJumbo); ok {
				jmb = &j
				break
			}
		}
		if jmb != nil && ip6.Length == 0 {
			pEnd := int(*jmb)
			if pEnd > len(ip6.Payload) {
				p.SetTruncated()
				pEnd = len(ip6.Payload)
			}
			ip6.Payload = ip6.Payload[:pEnd]
		} else if jmb != nil && ip6.Length != 0 {
			return fmt.Errorf("IPv6 has jumbo length and IPv6 length is not 0")
		} else if jmb == nil && ip6.Length == 0 {
			return fmt.Errorf("IPv6 length 0, but HopByHop header does not have jumbogram option")
		}
	} else {
		p.AddWarning(fmt.Errorf("Packet has IPv6HopByHop but network layer is %s, not IPv6", l))
	}
	return p.NextDecoder(i.NextHeader)
}

// IPv6Destination is the IPv6 destination options header.
type IPv6Destination struct {
	ipv6ExtensionBase
	Options []IPv6HeaderTLVOption
}

// LayerType returns LayerTypeIPv6Destination.
func (i *IPv6Destination) LayerType() gopacket.LayerType { return LayerTypeIPv6Destination }

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (i *IPv6Destination) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	l, err := serializeIPv6HeaderTLVOptions(b, i.Options, opts.FixLengths)
	if err != nil {
		return err
	}
	length := l + 2
	if length%8 != 0 {
		return fmt.Errorf("IPv6Destination actual length must be multiple of 8")
	}
	bytes, err := b.PrependBytes(2)
	if err != nil {
		return err
	}
	bytes[0] = uint8(i.NextHeader)
	if opts.FixLengths {
		i.HeaderLength = uint8((length / 8) - 1)
	}
	bytes[1] = uint8(i.HeaderLength)
	return nil
}

func (i *IPv6Destination) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	i.ipv6ExtensionBase = decodeIPv6ExtensionBase(data)
	offset := 2
	for offset < i.ActualLength {
		opt, err := decodeIPv6HeaderTLVOption(data[offset:], df)
		if err != nil {
			return err
		}
		i.Options = append(i.Options, opt)
		offset += opt.ActualLength()
	}
	return nil
}

func decodeIPv6Destination(data []byte, p gopacket.PacketBuilder) error {
	i := &IPv6Destination{}
	err := i.DecodeFromBytes(data, p)
	p.AddLayer(i)
	if err != nil {
		return err
	}
	return p.NextDecoder(i.NextHeader)
}

// IPv6Routing is the IPv6 routing extension.
type ipv6RoutingBase struct {
	ipv6ExtensionBase
	RoutingType  uint8
	SegmentsLeft uint8
}

type IPv6RoutingType0 struct {
	ipv6RoutingBase
	// This segment is supposed to be zero according to RFC2460, the second set of
	// 4 bytes in the extension.
	Reserved []byte
	// SourceRoutingIPs is the set of IPv6 addresses requested for source routing
	SourceRoutingIPs []net.IP
}

// LayerType returns LayerTypeIPv6Routing.
func (i *IPv6RoutingType0) LayerType() gopacket.LayerType { return LayerTypeIPv6Routing }

func (i *IPv6RoutingType0) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	addrLength := len(i.SourceRoutingIPs) * net.IPv6len
	bytes, err := b.PrependBytes(8 + addrLength)
	if err != nil {
		return err
	}
	bytes[0] = uint8(i.NextHeader)
	if opts.FixLengths {
		if addrLength <= 0 {
			return fmt.Errorf("cannot serialize empty IPv6RoutingType0")
		}
		i.HeaderLength = uint8(addrLength / 8)
	}
	bytes[1] = i.HeaderLength
	bytes[2] = i.RoutingType
	bytes[3] = i.SegmentsLeft
	for n, a := range i.SourceRoutingIPs {
		if err := checkIPv6Address(a); err != nil {
			return fmt.Errorf("Invalid IPv6 routing type 0 address (addr[%d]: %s)", n, err)
		}
		i := 8 + n*net.IPv6len
		copy(bytes[i:], a)
	}
	return nil
}

func decodeIPv6RoutingType0(data []byte, p gopacket.PacketBuilder) error {
	i := &IPv6RoutingType0{ipv6RoutingBase: ipv6RoutingBase{
		ipv6ExtensionBase: decodeIPv6ExtensionBase(data),
		RoutingType:       data[2],
		SegmentsLeft:      data[3],
	},
	}
	i.Reserved = i.Contents[4:8]
	n := i.HeaderLength / 2
	if i.ActualLength != int(n)*16+8 {
		return fmt.Errorf("Invalid IPv6 source routing, length of type 0 packet %d", i.ActualLength)
	}
	for d := i.Contents[8:]; len(d) >= 16; d = d[16:] {
		i.SourceRoutingIPs = append(i.SourceRoutingIPs, net.IP(d[:16]))
	}
	l := p.LastNetworkLayer()
	if ip6, ok := l.(*IPv6); ok {
		if i.SegmentsLeft != 0 {
			ip6.RoutingDstIP = i.SourceRoutingIPs[n-1]
		}
	} else {
		p.AddWarning(fmt.Errorf("Packet has IPv6Routing but network layer is %s, not IPv6", l))
	}
	p.AddLayer(i)
	return p.NextDecoder(i.NextHeader)
}

func (i *IPv6RoutingType0) SetNetworkLayerForRouting(ip6 *IPv6) error {
	l := len(i.SourceRoutingIPs)
	if l == 0 {
		return fmt.Errorf("Empty routing address vector")
	}
	a := i.SourceRoutingIPs[l-1]
	if err := checkIPv6Address(a); err != nil {
		return fmt.Errorf("Invalid routing IPv6 address (%s)", err)
	}
	ip6.RoutingDstIP = a
	return nil
}

func decodeIPv6Routing(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 8 {
		return fmt.Errorf("IPv6 routing header too short (length %d)", len(data))
	}
	t := IPv6RoutingType(data[2])
	return t.Decode(data, p)
}

// IPv6Fragment is the IPv6 fragment header, used for packet
// fragmentation/defragmentation.
type IPv6Fragment struct {
	BaseLayer
	NextHeader IPProtocol
	// Reserved1 is bits [8-16), from least to most significant, 0-indexed
	Reserved1      uint8
	FragmentOffset uint16
	// Reserved2 is bits [29-31), from least to most significant, 0-indexed
	Reserved2      uint8
	MoreFragments  bool
	Identification uint32
}

// LayerType returns LayerTypeIPv6Fragment.
func (i *IPv6Fragment) LayerType() gopacket.LayerType { return LayerTypeIPv6Fragment }

func decodeIPv6Fragment(data []byte, p gopacket.PacketBuilder) error {
	i := &IPv6Fragment{
		BaseLayer:      BaseLayer{data[:8], data[8:]},
		NextHeader:     IPProtocol(data[0]),
		Reserved1:      data[1],
		FragmentOffset: binary.BigEndian.Uint16(data[2:4]) >> 3,
		Reserved2:      data[3] & 0x6 >> 1,
		MoreFragments:  data[3]&0x1 != 0,
		Identification: binary.BigEndian.Uint32(data[4:8]),
	}
	p.AddLayer(i)
	return p.NextDecoder(gopacket.DecodeFragment)
}

// IPv6ExtensionSkipper is a DecodingLayer which decodes and ignores v6
// extensions.  You can use it with a DecodingLayerParser to handle IPv6 stacks
// which may or may not have extensions.
type IPv6ExtensionSkipper struct {
	BaseLayer
	NextHeader IPProtocol
}

func (i *IPv6ExtensionSkipper) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	extension := decodeIPv6ExtensionBase(data)
	i.BaseLayer = BaseLayer{data[:extension.ActualLength], data[extension.ActualLength:]}
	i.NextHeader = extension.NextHeader
	return nil
}
func (i *IPv6ExtensionSkipper) CanDecode() gopacket.LayerClass {
	return LayerClassIPv6Extension
}
func (i *IPv6ExtensionSkipper) NextLayerType() gopacket.LayerType {
	return i.NextHeader.LayerType()
}

func checkIPv6Address(addr net.IP) error {
	if len(addr) == net.IPv6len {
		return nil
	}
	if len(addr) == net.IPv4len {
		return fmt.Errorf("address is IPv4")
	}
	return fmt.Errorf("wrong length of %d bytes instead of %d", len(addr), net.IPv6len)
}

func (ip *IPv6) AddressTo16() error {
	if err := checkIPv6Address(ip.SrcIP); err != nil {
		return fmt.Errorf("Invalid source IPv6 address (%s)", err)
	}
	if err := checkIPv6Address(ip.DstIP); err != nil {
		return fmt.Errorf("Invalid destination IPv6 address (%s)", err)
	}
	if ip.RoutingDstIP != nil {
		if err := checkIPv6Address(ip.RoutingDstIP); err != nil {
			return fmt.Errorf("Invalid routing destination IPv6 address (%s)", err)
		}
	}
	return nil
}
