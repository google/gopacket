// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Enum types courtesy of...
//   http://search.cpan.org/~mchapman/Net-CDP-0.09/lib/Net/CDP.pm
//   https://code.google.com/p/ladvd/
//   http://anonsvn.wireshark.org/viewvc/releases/wireshark-1.8.6/epan/dissectors/packet-cdp.c

package layers

import (
	"code.google.com/p/gopacket"
	"encoding/binary"
	"fmt"
	"net"
)

// CDPTLVType is the type of each TLV value in a CiscoDiscovery packet.
type CDPTLVType uint16

const (
	CDPTLVDevID              CDPTLVType = 0x0001
	CDPTLVAddress            CDPTLVType = 0x0002
	CDPTLVPortID             CDPTLVType = 0x0003
	CDPTLVCapabilities       CDPTLVType = 0x0004
	CDPTLVVersion            CDPTLVType = 0x0005
	CDPTLVPlatform           CDPTLVType = 0x0006
	CDPTLVIPPrefix           CDPTLVType = 0x0007
	CDPTLVHello              CDPTLVType = 0x0008
	CDPTLVVTPDomain          CDPTLVType = 0x0009
	CDPTLVNativeVLAN         CDPTLVType = 0x000a
	CDPTLVFullDuplex         CDPTLVType = 0x000b
	CDPTLVVLANReply          CDPTLVType = 0x000e
	CDPTLVVLANQuery          CDPTLVType = 0x000f
	CDPTLVPower              CDPTLVType = 0x0010
	CDPTLVMTU                CDPTLVType = 0x0011
	CDPTLVExtendedTrust      CDPTLVType = 0x0012
	CDPTLVUntrustedCOS       CDPTLVType = 0x0013
	CDPTLVSysName            CDPTLVType = 0x0014
	CDPTLVSysOID             CDPTLVType = 0x0015
	CDPTLVMgmtAddresses      CDPTLVType = 0x0016
	CDPTLVLocation           CDPTLVType = 0x0017
	CDPTLVExternalPortID     CDPTLVType = 0x0018
	CDPTLVPowerRequested     CDPTLVType = 0x0019
	CDPTLVPowerAvailable     CDPTLVType = 0x001a
	CDPTLVPortUnidirectional CDPTLVType = 0x001b
	CDPTLVEnergyWise         CDPTLVType = 0x001d
	CDPTLVSparePairPOE       CDPTLVType = 0x001f
)

type CDPCapability uint32

const (
	CDPCapMaskRouter     CDPCapability = 0x0001
	CDPCapMaskTBBridge   CDPCapability = 0x0002
	CDPCapMaskSPBridge   CDPCapability = 0x0004
	CDPCapMaskSwitch     CDPCapability = 0x0008
	CDPCapMaskHost       CDPCapability = 0x0010
	CDPCapMaskIGMPFilter CDPCapability = 0x0020
	CDPCapMaskRepeater   CDPCapability = 0x0040
	CDPCapMaskPhone      CDPCapability = 0x0080
	CDPCapMaskRemote     CDPCapability = 0x0100
)

// CDPCapabilities represtents the capabilities of a device
type CDPCapabilities struct {
	L3Router        bool
	TBBridge        bool
	SPBridge        bool
	L2Switch        bool
	IsHost          bool
	IGMPFilter      bool
	L1Repeater      bool
	IsPhone         bool
	RemotelyManaged bool
}

const (
	CDPPoEFourWire  byte = 0x01
	CDPPoEPDArch    byte = 0x02
	CDPPoEPDRequest byte = 0x04
	CDPPoEPSE       byte = 0x08
)

type CDPSparePairPoE struct {
	PSEFourWire  bool // Supported / Not supported
	PDArchShared bool // Shared / Independent
	PDRequestOn  bool // On / Off
	PSEOn        bool // On / Off
}

// CDPVLANDialogue encapsulates a VLAN Query/Reply
type CDPVLANDialogue struct {
	ID   uint8
	VLAN uint16
}

// CDPPowerDialogue encapsulates a Power Query/Reply
type CDPPowerDialogue struct {
	ID     uint16
	MgmtID uint16
	Values []uint32
}

type CDPLocation struct {
	Type     uint8 // Undocumented
	Location string
}

// CiscoDiscovery is a packet layer containing the Cisco Discovery Protocol.
// See http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm#31885
type CiscoDiscovery struct {
	baseLayer
	Version  byte
	TTL      byte
	Checksum uint16
	Values   []CiscoDiscoveryValue
}

// CDPHello is a Cisco Hello message (undocumented, hence the "Unknown" fields)
type CDPHello struct {
	OUI              [3]byte
	ProtocolID       uint16
	ClusterMaster    net.IP
	Unknown1         net.IP
	Version          byte
	SubVersion       byte
	Status           byte
	Unknown2         byte
	ClusterCommander net.HardwareAddr
	SwitchMAC        net.HardwareAddr
	Unknown3         byte
	ManagementVLAN   uint16
}

// CiscoDiscoveryInfo represents the decoded details for a set of CiscoDiscoveryValues
type CiscoDiscoveryInfo struct {
	CDPHello
	DeviceID         string
	Addresses        []net.IP
	PortID           string
	Capabilities     CDPCapabilities
	Version          string
	Platform         string
	IPPrefixes       []net.IPNet
	VTPDomain        string
	NativeVLAN       uint16
	FullDuplex       bool
	VLANReply        CDPVLANDialogue
	VLANQuery        CDPVLANDialogue
	PowerConsumption uint16
	MTU              uint32
	ExtendedTrust    uint8
	UntrustedCOS     uint8
	SysName          string
	SysOID           string
	MgmtAddresses    []net.IP
	Location         CDPLocation
	PowerRequest     CDPPowerDialogue
	PowerAvailable   CDPPowerDialogue
	SparePairPoe     CDPSparePairPoE
	Unknown          []CiscoDiscoveryValue
}

// LayerType returns gopacket.LayerTypeCiscoDiscovery.
func (c *CiscoDiscovery) LayerType() gopacket.LayerType {
	return LayerTypeCiscoDiscovery
}

// CiscoDiscoveryValue is a TLV value inside a CiscoDiscovery packet layer.
type CiscoDiscoveryValue struct {
	Type   CDPTLVType
	Length uint16
	Value  []byte
}

func decodeCiscoDiscovery(data []byte, p gopacket.PacketBuilder) error {
	c := &CiscoDiscovery{
		Version:  data[0],
		TTL:      data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
	}
	if c.Version != 1 && c.Version != 2 {
		return fmt.Errorf("Invalid CiscoDiscovery version number %d", c.Version)
	}
	vData := data[4:]
	for len(vData) > 0 {
		val := CiscoDiscoveryValue{
			Type:   CDPTLVType(binary.BigEndian.Uint16(vData[:2])),
			Length: binary.BigEndian.Uint16(vData[2:4]),
		}
		if val.Length < 4 {
			return fmt.Errorf("Invalid CiscoDiscovery value length %d", val.Length)
		}
		val.Value = vData[4:val.Length]
		c.Values = append(c.Values, val)
		vData = vData[val.Length:]
	}
	c.contents = data
	p.AddLayer(c)
	return nil
}

// DecodeValues marshals CiscoDiscoveryValues into a CiscoDiscoveryInfo struct
func (c *CiscoDiscovery) DecodeValues() (info CiscoDiscoveryInfo, errors []error) {
	var err error
	var ok bool
	for _, val := range c.Values {
		switch val.Type {
		case CDPTLVDevID:
			info.DeviceID = string(val.Value)
		case CDPTLVAddress:
			if ok, errors = checkCDPTLVLen(val, 4, errors); ok {
				info.Addresses, err = decodeAddresses(val.Value)
				if err != nil {
					errors = append(errors, err)
				}
			}
		case CDPTLVPortID:
			info.PortID = string(val.Value)
		case CDPTLVCapabilities:
			if ok, errors = checkCDPTLVLen(val, 4, errors); ok {
				val := CDPCapability(binary.BigEndian.Uint32(val.Value[0:4]))
				info.Capabilities.L3Router = (val&CDPCapMaskRouter > 0)
				info.Capabilities.TBBridge = (val&CDPCapMaskTBBridge > 0)
				info.Capabilities.SPBridge = (val&CDPCapMaskSPBridge > 0)
				info.Capabilities.L2Switch = (val&CDPCapMaskSwitch > 0)
				info.Capabilities.IsHost = (val&CDPCapMaskHost > 0)
				info.Capabilities.IGMPFilter = (val&CDPCapMaskIGMPFilter > 0)
				info.Capabilities.L1Repeater = (val&CDPCapMaskRepeater > 0)
				info.Capabilities.IsPhone = (val&CDPCapMaskPhone > 0)
				info.Capabilities.RemotelyManaged = (val&CDPCapMaskRemote > 0)
			}
		case CDPTLVVersion:
			info.Version = string(val.Value)
		case CDPTLVPlatform:
			info.Platform = string(val.Value)
		case CDPTLVIPPrefix:
			v := val.Value
			l := len(v)
			if l%5 == 0 && l >= 5 {
				for len(v) > 0 {
					_, ipnet, _ := net.ParseCIDR(fmt.Sprintf("%d.%d.%d.%d/%d", v[0], v[1], v[2], v[3], v[4]))
					info.IPPrefixes = append(info.IPPrefixes, *ipnet)
					v = v[5:]
				}
			} else {
				errors = append(errors, fmt.Errorf("Invalid TLV %v length %d", val.Type, len(val.Value)))
			}
		case CDPTLVHello:
			if ok, errors = checkCDPTLVLen(val, 32, errors); ok {
				v := val.Value
				copy(info.CDPHello.OUI[0:3], v[0:3])
				info.CDPHello.ProtocolID = binary.BigEndian.Uint16(v[3:5])
				info.CDPHello.ClusterMaster = net.IPv4(v[5], v[6], v[7], v[8])
				info.CDPHello.Unknown1 = net.IPv4(v[9], v[10], v[11], v[12])
				info.CDPHello.Version = v[13]
				info.CDPHello.SubVersion = v[14]
				info.CDPHello.Status = v[15]
				info.CDPHello.Unknown2 = v[16]
				info.CDPHello.ClusterCommander = v[17:23]
				info.CDPHello.SwitchMAC = v[23:29]
				info.CDPHello.Unknown3 = v[29]
				info.CDPHello.ManagementVLAN = binary.BigEndian.Uint16(v[30:32])
			}
		case CDPTLVVTPDomain:
			info.VTPDomain = string(val.Value)
		case CDPTLVNativeVLAN:
			if ok, errors = checkCDPTLVLen(val, 2, errors); ok {
				info.NativeVLAN = binary.BigEndian.Uint16(val.Value[0:2])
			}
		case CDPTLVFullDuplex:
			if ok, errors = checkCDPTLVLen(val, 1, errors); ok {
				info.FullDuplex = (val.Value[0] == 1)
			}
		case CDPTLVVLANReply:
			if ok, errors = checkCDPTLVLen(val, 3, errors); ok {
				info.VLANReply.ID = uint8(val.Value[0])
				info.VLANReply.VLAN = binary.BigEndian.Uint16(val.Value[1:3])
			}
		case CDPTLVVLANQuery:
			if ok, errors = checkCDPTLVLen(val, 3, errors); ok {
				info.VLANQuery.ID = uint8(val.Value[0])
				info.VLANQuery.VLAN = binary.BigEndian.Uint16(val.Value[1:3])
			}
		case CDPTLVPower:
			if ok, errors = checkCDPTLVLen(val, 2, errors); ok {
				info.PowerConsumption = binary.BigEndian.Uint16(val.Value[0:2])
			}
		case CDPTLVMTU:
			if ok, errors = checkCDPTLVLen(val, 4, errors); ok {
				info.MTU = binary.BigEndian.Uint32(val.Value[0:4])
			}
		case CDPTLVExtendedTrust:
			if ok, errors = checkCDPTLVLen(val, 1, errors); ok {
				info.ExtendedTrust = uint8(val.Value[0])
			}
		case CDPTLVUntrustedCOS:
			if ok, errors = checkCDPTLVLen(val, 1, errors); ok {
				info.UntrustedCOS = uint8(val.Value[0])
			}
		case CDPTLVSysName:
			info.SysName = string(val.Value)
		case CDPTLVSysOID:
			info.SysOID = string(val.Value)
		case CDPTLVMgmtAddresses:
			if ok, errors = checkCDPTLVLen(val, 4, errors); ok {
				info.MgmtAddresses, err = decodeAddresses(val.Value)
				if err != nil {
					errors = append(errors, err)
				}
			}
		case CDPTLVLocation:
			if ok, errors = checkCDPTLVLen(val, 2, errors); ok {
				info.Location.Type = uint8(val.Value[0])
				info.Location.Location = string(val.Value[1:])
			}

			//		case CDPTLVLExternalPortID:
			//			Undocumented
		case CDPTLVPowerRequested:
			if ok, errors = checkCDPTLVLen(val, 4, errors); ok {
				info.PowerRequest.ID = binary.BigEndian.Uint16(val.Value[0:2])
				info.PowerRequest.MgmtID = binary.BigEndian.Uint16(val.Value[2:4])
				for n := 4; n < len(val.Value); n += 4 {
					info.PowerRequest.Values = append(info.PowerRequest.Values, binary.BigEndian.Uint32(val.Value[n:n+4]))
				}
			}

		case CDPTLVPowerAvailable:
			if ok, errors = checkCDPTLVLen(val, 4, errors); ok {
				info.PowerAvailable.ID = binary.BigEndian.Uint16(val.Value[0:2])
				info.PowerAvailable.MgmtID = binary.BigEndian.Uint16(val.Value[2:4])
				for n := 4; n < len(val.Value); n += 4 {
					info.PowerAvailable.Values = append(info.PowerAvailable.Values, binary.BigEndian.Uint32(val.Value[n:n+4]))
				}
			}
			//		case CDPTLVPortUnidirectional
			//			Undocumented
			//		case CDPTLVEnergyWise:
			//			Undocumented
		case CDPTLVSparePairPOE:
			if ok, errors = checkCDPTLVLen(val, 1, errors); ok {
				v := val.Value[0]
				info.SparePairPoe.PSEFourWire = (v&CDPPoEFourWire > 0)
				info.SparePairPoe.PDArchShared = (v&CDPPoEPDArch > 0)
				info.SparePairPoe.PDRequestOn = (v&CDPPoEPDRequest > 0)
				info.SparePairPoe.PSEOn = (v&CDPPoEPSE > 0)
			}
		default:
			info.Unknown = append(info.Unknown, val)
		}
	}
	return
}

// CDP Protocol Types
const (
	CDPProtocolTypeNLPID byte = 1
	CDPProtocolType802_2 byte = 2
)

type CDPAddressType uint64

// CDP Address types.
const (
	CDPAddressTypeCLNP      CDPAddressType = 0x81
	CDPAddressTypeIPV4      CDPAddressType = 0xcc
	CDPAddressTypeIPV6      CDPAddressType = 0xaaaa030000000800
	CDPAddressTypeDECNET    CDPAddressType = 0xaaaa030000006003
	CDPAddressTypeAPPLETALK CDPAddressType = 0xaaaa03000000809b
	CDPAddressTypeIPX       CDPAddressType = 0xaaaa030000008137
	CDPAddressTypeVINES     CDPAddressType = 0xaaaa0300000080c4
	CDPAddressTypeXNS       CDPAddressType = 0xaaaa030000000600
	CDPAddressTypeAPOLLO    CDPAddressType = 0xaaaa030000008019
)

func decodeAddresses(v []byte) (addresses []net.IP, err error) {
	numaddr := int(binary.BigEndian.Uint32(v[0:4]))
	if numaddr < 1 {
		return nil, fmt.Errorf("Invalid Address TLV number %d", numaddr)
	}
	v = v[4:]
	if len(v) < numaddr*8 {
		return nil, fmt.Errorf("Invalid Address TLV length %d", len(v))
	}
	for i := 0; i < numaddr; i++ {
		prottype := v[0]
		if prottype != CDPProtocolTypeNLPID && prottype != CDPProtocolType802_2 { // invalid protocol type
			return nil, fmt.Errorf("Invalid Address Protocol %d", prottype)
		}
		protlen := int(v[1])
		if (prottype == CDPProtocolTypeNLPID && protlen != 1) ||
			(prottype == CDPProtocolType802_2 && protlen != 3 && protlen != 8) { // invalid length
			return nil, fmt.Errorf("Invalid Address Protocol length %d", protlen)
		}
		plen := make([]byte, 8)
		copy(plen[8-protlen:], v[2:2+protlen])
		protocol := CDPAddressType(binary.BigEndian.Uint64(plen))
		v = v[2+protlen:]
		addrlen := binary.BigEndian.Uint16(v[0:2])
		ab := v[2 : 2+addrlen]
		if protocol == CDPAddressTypeIPV4 && addrlen == 4 {
			addresses = append(addresses, net.IPv4(ab[0], ab[1], ab[2], ab[3]))
		} else if protocol == CDPAddressTypeIPV6 && addrlen == 16 {
			addresses = append(addresses, net.IP(ab))
		} else {
			// only handle IPV4 & IPV6 for now
		}
		v = v[2+addrlen:]
		if len(v) < 8 {
			break
		}
	}
	return
}

func (t CDPTLVType) String() (s string) {
	switch t {
	case CDPTLVDevID:
		s = "Device ID"
	case CDPTLVAddress:
		s = "Addresses"
	case CDPTLVPortID:
		s = "Port ID"
	case CDPTLVCapabilities:
		s = "Capabilities"
	case CDPTLVVersion:
		s = "Software Version"
	case CDPTLVPlatform:
		s = "Platform"
	case CDPTLVIPPrefix:
		s = "IP Prefix"
	case CDPTLVHello:
		s = "Protocol Hello"
	case CDPTLVVTPDomain:
		s = "VTP Management Domain"
	case CDPTLVNativeVLAN:
		s = "Native VLAN"
	case CDPTLVFullDuplex:
		s = "Full Duplex"
	case CDPTLVVLANReply:
		s = "VoIP VLAN Reply"
	case CDPTLVVLANQuery:
		s = "VLANQuery"
	case CDPTLVPower:
		s = "Power consumption"
	case CDPTLVMTU:
		s = "MTU"
	case CDPTLVExtendedTrust:
		s = "Extended Trust Bitmap"
	case CDPTLVUntrustedCOS:
		s = "Untrusted Port CoS"
	case CDPTLVSysName:
		s = "System Name"
	case CDPTLVSysOID:
		s = "System OID"
	case CDPTLVMgmtAddresses:
		s = "Management Addresses"
	case CDPTLVLocation:
		s = "Location"
	case CDPTLVExternalPortID:
		s = "External Port ID"
	case CDPTLVPowerRequested:
		s = "Power Requested"
	case CDPTLVPowerAvailable:
		s = "Power Available"
	case CDPTLVPortUnidirectional:
		s = "Port Unidirectional"
	case CDPTLVEnergyWise:
		s = "Energy Wise"
	case CDPTLVSparePairPOE:
		s = "Spare Pair POE"
	}
	return
}

func (a CDPAddressType) String() (s string) {
	switch a {
	case CDPAddressTypeCLNP:
		s = "Connectionless Network Protocol"
	case CDPAddressTypeIPV4:
		s = "IPv4"
	case CDPAddressTypeIPV6:
		s = "IPv6"
	case CDPAddressTypeDECNET:
		s = "DECnet Phase IV"
	case CDPAddressTypeAPPLETALK:
		s = "Apple Talk"
	case CDPAddressTypeIPX:
		s = "Novell IPX"
	case CDPAddressTypeVINES:
		s = "Banyan VINES"
	case CDPAddressTypeXNS:
		s = "Xerox Network Systems"
	case CDPAddressTypeAPOLLO:
		s = "Apollo"
	}
	return
}

func checkCDPTLVLen(v CiscoDiscoveryValue, l int, e []error) (ok bool, errors []error) {
	errors = e
	if ok = (len(v.Value) >= l); !ok {
		errors = append(errors, fmt.Errorf("Invalid TLV %v length %d", v.Type, len(v.Value)))
	}
	return
}
