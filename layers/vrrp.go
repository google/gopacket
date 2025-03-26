// Copyright 2016 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/google/gopacket"
)

/*
	This layer provides decoding for Virtual Router Redundancy Protocol (VRRP) v2.
	https://tools.ietf.org/html/rfc3768#section-5
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Type  | Virtual Rtr ID|   Priority    | Count IP Addrs|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Auth Type   |   Adver Int   |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         IP Address (1)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            .                                  |
   |                            .                                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         IP Address (n)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Authentication Data (1)                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Authentication Data (2)                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// VRRPv2Type is a VRRPv2 message
type VRRPv2Type uint8

// VRRPv2AuthType is a VRRPv2 auth message
type VRRPv2AuthType uint8

const (
	// VRRPv2Advertisement is a message type
	VRRPv2Advertisement VRRPv2Type = 0x01 // router advertisement
)

// String conversions for VRRPv2 message types
func (v VRRPv2Type) String() string {
	switch v {
	case VRRPv2Advertisement:
		return "VRRPv2 Advertisement"
	default:
		return ""
	}
}

// VRRP authentication types
const (
	VRRPv2AuthNoAuth    VRRPv2AuthType = 0x00 // No Authentication
	VRRPv2AuthReserved1 VRRPv2AuthType = 0x01 // Reserved field 1
	VRRPv2AuthReserved2 VRRPv2AuthType = 0x02 // Reserved field 2
)

// String conversions for VRRPv2 authentication types
func (v VRRPv2AuthType) String() string {
	switch v {
	case VRRPv2AuthNoAuth:
		return "No Authentication"
	case VRRPv2AuthReserved1:
		return "Reserved"
	case VRRPv2AuthReserved2:
		return "Reserved"
	default:
		return ""
	}
}

// VRRPv2 represents an VRRP v2 message.
type VRRPv2 struct {
	BaseLayer
	Version      uint8          // The version field specifies the VRRP protocol version of this packet (v2)
	Type         VRRPv2Type     // The type field specifies the type of this VRRP packet.  The only type defined in v2 is ADVERTISEMENT
	VirtualRtrID uint8          // identifies the virtual router this packet is reporting status for
	Priority     uint8          // specifies the sending VRRP router's priority for the virtual router (100 = default)
	CountIPAddr  uint8          // The number of IP addresses contained in this VRRP advertisement.
	AuthType     VRRPv2AuthType // identifies the authentication method being utilized
	AdverInt     uint8          // The Advertisement interval indicates the time interval (in seconds) between ADVERTISEMENTS.  The default is 1 second
	Checksum     uint16         // used to detect data corruption in the VRRP message.
	IPAddress    []net.IP       // one or more IP addresses associated with the virtual router. Specified in the CountIPAddr field.
}

// LayerType returns LayerTypeVRRP for VRRP v2 message.
func (v *VRRPv2) LayerType() gopacket.LayerType { return LayerTypeVRRP }

// DecodeFromBytes decodes the VRRPv2 layer from bytes
func (v *VRRPv2) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	v.BaseLayer = BaseLayer{Contents: data[:len(data)]}
	v.Version = data[0] >> 4 // high nibble == VRRP version. We're expecting v2

	v.Type = VRRPv2Type(data[0] & 0x0F) // low nibble == VRRP type. Expecting 1 (advertisement)
	if v.Type != 1 {
		// rfc3768: A packet with unknown type MUST be discarded.
		return errors.New("unrecognized VRRPv2 type field")
	}

	v.VirtualRtrID = data[1]
	v.Priority = data[2]

	v.CountIPAddr = data[3]
	if v.CountIPAddr < 1 {
		return errors.New("the VRRPv2 number of IP addresses is not valid")
	}

	v.AuthType = VRRPv2AuthType(data[4])
	v.AdverInt = uint8(data[5])
	v.Checksum = binary.BigEndian.Uint16(data[6:8])

	// populate the IPAddress field. The number of addresses is specified in the v.CountIPAddr field
	// offset references the starting byte containing the list of ip addresses
	offset := 8
	for i := uint8(0); i < v.CountIPAddr; i++ {
		v.IPAddress = append(v.IPAddress, data[offset:offset+4])
		offset += 4
	}

	//	any trailing packets here may be authentication data and *should* be ignored in v2 as per RFC
	//
	//			5.3.10.  Authentication Data
	//
	//			The authentication string is currently only used to maintain
	//			backwards compatibility with RFC 2338.  It SHOULD be set to zero on
	//	   		transmission and ignored on reception.
	return nil
}

// CanDecode specifies the layer type in which we are attempting to unwrap.
func (v *VRRPv2) CanDecode() gopacket.LayerClass {
	return LayerTypeVRRP
}

// NextLayerType specifies the next layer that should be decoded. VRRP does not contain any further payload, so we set to 0
func (v *VRRPv2) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

//Payload layer. The VRRP packet does not include payload data. Setting byte slice to nil
func (v *VRRPv2) Payload() []byte {
	return nil
}

// https://tools.ietf.org/html/rfc5798#section-5
//   0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |(rsvd) |     Max Adver Int     |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// +                                                               +
// |                       IPvX Address(es)                        |
// +                                                               +
// +                                                               +
// +                                                               +
// +                                                               +
// |                                                               |
// +                                                               +
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// VRRPv3Type represents VRRP message type.
type VRRPv3Type uint8

const (
	// VRRPv3Advertisement is the only supported VRRP message type
	VRRPv3Advertisement VRRPv3Type = 0x01 // router advertisement
)

// VRRPv3 IANA assigned addresses
var (
	VRRPDstIPv4 = net.IP{224, 0, 0, 18}
	VRRPDstIPv6 = net.IP{
		0xFF, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x12,
	}

	VRRPDstMACv4 = net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x12}
	VRRPDstMACv6 = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x12}
)

// String conversions for message type.
func (v VRRPv3Type) String() string {
	switch v {
	case VRRPv3Advertisement:
		return "VRRPv3 Advertisement"
	default:
		return ""
	}
}

// VRRPv3 represent a VRRP v3 message structure.
type VRRPv3 struct {
	BaseLayer
	Version       uint8      // The version field specifies the VRRP protocol version of this packet (v3)
	Type          VRRPv3Type // The type field specifies the type of this VRRP packet.  The only type defined in v3 is ADVERTISEMENT
	VirtualRtrID  uint8      // identifies the virtual router this packet is reporting status for
	Priority      uint8      // specifies the sending VRRP router's priority for the virtual router (100 = default)
	CountIPvXAddr uint8      // The number of IP addresses contained in this VRRP advertisement.
	Rsvd          uint8      // reserved
	MaxAdverInt   uint16     // The Advertisement interval indicates the time interval (in centiseconds) between ADVERTISEMENTS.  The default is 1 second (100 centiseconds)
	Checksum      uint16     // used to detect data corruption in the VRRP message.
	IPvXAddress   []net.IP   // one or more IPv4 or IPv6 addresses associated with the virtual router. Specified in the CountIPAddr field. Must not mix IPv4 with IPv6
	tcpipchecksum
}

// LayerType returns LayerTypeVRRP.
func (v *VRRPv3) LayerType() gopacket.LayerType {
	return LayerTypeVRRP
}

// DecodeFromBytes decodes a given data to a VRRPv3 message.
func (v *VRRPv3) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	v.BaseLayer = BaseLayer{Contents: data[:]}

	v.Version = data[0] >> 4 // high nibble
	if v.Version != 3 {
		return errors.New("incorrect version number, should be 3")
	}

	v.Type = VRRPv3Type(data[0] & 0x0F) // low nibble
	if v.Type != VRRPv3Advertisement {
		return errors.New("unsupported VRRPv3 type field")
	}

	v.VirtualRtrID = data[1]

	v.Priority = data[2]

	v.CountIPvXAddr = data[3]
	if v.CountIPvXAddr < 1 {
		return errors.New("advertisement MUST have at least 1 address")
	}

	v.Rsvd = 0

	v.MaxAdverInt = binary.BigEndian.Uint16([]byte{data[4] & 0x0F, data[5]})
	v.Checksum = binary.BigEndian.Uint16(data[6:8])

	offset := uint8(8)
	addrSize := uint8(len(data[offset:])) / v.CountIPvXAddr
	if addrSize != 4 && addrSize != 16 {
		return errors.New("count field does not match neither IPv4 nor IPv6")
	}
	v.IPvXAddress = make([]net.IP, 0, v.CountIPvXAddr)
	for i := uint8(0); i < v.CountIPvXAddr; i++ {
		v.IPvXAddress = append(v.IPvXAddress, data[offset:offset+addrSize])
		offset += addrSize
	}

	return nil
}

// CanDecode specifies the layer type in which we are attempting to unwrap
func (v *VRRPv3) CanDecode() gopacket.LayerClass {
	return LayerTypeVRRP
}

// NextLayerType specifies the next layer that should be decoded. VRRP does not contain any payload, so we set to 0
func (v *VRRPv3) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

// Payload should return empty payload for VRRP
func (v *VRRPv3) Payload() []byte {
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (v *VRRPv3) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	//calculate message size
	offset := 8
	if len(v.IPvXAddress) < 1 {
		return errors.New("advertisement MUST have at least 1 address")
	}
	count := int(v.CountIPvXAddr)
	if len(v.IPvXAddress) != count {
		return errors.New("count value and given ip addresses mismatch")
	}

	var addrSize int
	switch v.IPvXAddress[0].To4 {
	case nil:
		addrSize = 16
	default:
		addrSize = 4
	}
	bytes, err := b.PrependBytes(offset + addrSize*count)
	if err != nil {
		return err
	}

	bytes[0] = (v.Version << 4) + uint8(v.Type)
	bytes[1] = v.VirtualRtrID
	bytes[2] = v.Priority
	bytes[3] = v.CountIPvXAddr

	binary.BigEndian.PutUint16(bytes[4:6], v.MaxAdverInt)

	for _, ip := range v.IPvXAddress {
		switch addrSize {
		case 4:
			if copy(bytes[offset:offset+addrSize], ip.To4()) != addrSize {
				return errors.New("illegal address")
			}
		case 16:
			if copy(bytes[offset:offset+addrSize], ip) != addrSize {
				return errors.New("illegal address")
			}
		}
		offset += addrSize
	}
	bytes[6], bytes[7] = 0, 0

	if opts.ComputeChecksums {
		csum, err := v.computeChecksum(b.Bytes(), IPProtocolVRRP)
		if err != nil {
			return err
		}
		v.Checksum = csum
	}

	binary.BigEndian.PutUint16(bytes[6:8], v.Checksum)
	return nil
}

// decodeVRRP will parse VRRP v2 or v3
func decodeVRRP(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 8 {
		return errors.New("not a valid VRRP packet. Packet length is too small")
	}
	switch data[0] >> 4 {
	case 2:
		v := &VRRPv2{}
		return decodingLayerDecoder(v, data, p)
	case 3:
		v := &VRRPv3{}
		return decodingLayerDecoder(v, data, p)
	}

	return errors.New("unsupported VRRP version")
}
