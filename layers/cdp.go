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
	"net"
)

// CiscoDiscoveryType is the type of each TLV value in a CiscoDiscovery packet.
type CiscoDiscoveryType uint16

const (
	CDP_TLV_DEVID         CiscoDiscoveryType = 0x0001
	CDP_TLV_ADDRESS       CiscoDiscoveryType = 0x0002
	CDP_TLV_PORTID        CiscoDiscoveryType = 0x0003
	CDP_TLV_CAPS          CiscoDiscoveryType = 0x0004
	CDP_TLV_VERS          CiscoDiscoveryType = 0x0005
	CDP_TLV_PLATFORM      CiscoDiscoveryType = 0x0006
	CDP_TLV_IPPREFIX      CiscoDiscoveryType = 0x0007
	CDP_TLV_HELLO         CiscoDiscoveryType = 0x0008
	CDP_TLV_VTPDOMAIN     CiscoDiscoveryType = 0x0009
	CDP_TLV_NATIVEVLAN    CiscoDiscoveryType = 0x000a
	CDP_TLV_DUPLEX        CiscoDiscoveryType = 0x000b
	CDP_TLV_APPLID        CiscoDiscoveryType = 0x000e
	CDP_TLV_APPLQRY       CiscoDiscoveryType = 0x000f
	CDP_TLV_POWER         CiscoDiscoveryType = 0x0010
	CDP_TLV_MTU           CiscoDiscoveryType = 0x0011
	CDP_TLV_EXTENDEDTRUST CiscoDiscoveryType = 0x0012
	CDP_TLV_UNTRUSTEDCOS  CiscoDiscoveryType = 0x0013
	CDP_TLV_SYSNAME       CiscoDiscoveryType = 0x0014
	CDP_TLV_SYSOID        CiscoDiscoveryType = 0x0015
	CDP_TLV_MGMTADDRESS   CiscoDiscoveryType = 0x0016
	CDP_TLV_LOCATION      CiscoDiscoveryType = 0x0017
	CDP_TLV_POWERREQ      CiscoDiscoveryType = 0x0019
	CDP_TLV_POWERAVAIL    CiscoDiscoveryType = 0x0019
)

type CiscoDiscoveryCaps uint32

const (
	CDP_CAPMASK_ROUTER     CiscoDiscoveryCaps = 0x0001
	CDP_CAPMASK_TBBRIDGE   CiscoDiscoveryCaps = 0x0002
	CDP_CAPMASK_SPBRIDGE   CiscoDiscoveryCaps = 0x0004
	CDP_CAPMASK_SWITCH     CiscoDiscoveryCaps = 0x0008
	CDP_CAPMASK_HOST       CiscoDiscoveryCaps = 0x0010
	CDP_CAPMASK_IGMPFILTER CiscoDiscoveryCaps = 0x0020
	CDP_CAPMASK_REPEATER   CiscoDiscoveryCaps = 0x0040
	CDP_CAPMASK_PHONE      CiscoDiscoveryCaps = 0x0080
	CDP_CAPMASK_REMOTE     CiscoDiscoveryCaps = 0x0100
)

// CiscoCaps represtents the capabilities of a device
type CiscoCaps struct {
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

type CiscoApplianceDialogue struct {
	ID   uint8
	VLAN uint16
}

type CiscoLocation struct {
	Type     uint8
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

type CDPHello struct {
	OUI              [3]byte
	ProtocolID       uint16
	ClusterMaster    net.IP
	UnknownIP        net.IP
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
	DeviceID   string
	Addresses  []net.IP
	PortID     string
	Caps       CiscoCaps
	Version    string
	Platform   string
	IPPrefixes []net.IPNet
	CDPHello
	VTPDomain        string
	NativeVLAN       uint16
	FullDuplex       bool
	ApplianceReply   CiscoApplianceDialogue
	ApplianceQuery   CiscoApplianceDialogue
	PowerConsumption uint16
	MTU              uint32
	ExtendedTrust    uint8
	UntrustedCOS     uint8
	SysName          string
	MgmtAddresses    []net.IP
	Location         CiscoLocation
	Unknown          []CiscoDiscoveryValue
}

// LayerType returns gopacket.LayerTypeCiscoDiscovery.
func (c *CiscoDiscovery) LayerType() gopacket.LayerType {
	return LayerTypeCiscoDiscovery
}

// CiscoDiscoveryValue is a TLV value inside a CiscoDiscovery packet layer.
type CiscoDiscoveryValue struct {
	Type   CiscoDiscoveryType
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
			Type:   CiscoDiscoveryType(binary.BigEndian.Uint16(vData[:2])),
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

func (c *CiscoDiscovery) DecodeValues() (info CiscoDiscoveryInfo) {
	for _, val := range c.Values {
		switch val.Type {
		case CDP_TLV_DEVID:
			info.DeviceID = string(val.Value)
		case CDP_TLV_ADDRESS:
			if len(val.Value) > 3 {
				info.Addresses = decodeAddresses(val.Value)
			}
		case CDP_TLV_PORTID:
			info.PortID = string(val.Value)
		case CDP_TLV_CAPS:
			if len(val.Value) > 3 {
				val := CiscoDiscoveryCaps(binary.BigEndian.Uint32(val.Value[0:4]))
				info.Caps.L3Router = (val&CDP_CAPMASK_ROUTER > 0)
				info.Caps.TBBridge = (val&CDP_CAPMASK_TBBRIDGE > 0)
				info.Caps.SPBridge = (val&CDP_CAPMASK_SPBRIDGE > 0)
				info.Caps.L2Switch = (val&CDP_CAPMASK_SWITCH > 0)
				info.Caps.IsHost = (val&CDP_CAPMASK_HOST > 0)
				info.Caps.IGMPFilter = (val&CDP_CAPMASK_IGMPFILTER > 0)
				info.Caps.L1Repeater = (val&CDP_CAPMASK_REPEATER > 0)
				info.Caps.IsPhone = (val&CDP_CAPMASK_PHONE > 0)
				info.Caps.RemotelyManaged = (val&CDP_CAPMASK_REMOTE > 0)
			}
		case CDP_TLV_VERS:
			info.Version = string(val.Value)
		case CDP_TLV_PLATFORM:
			info.Platform = string(val.Value)
		case CDP_TLV_IPPREFIX:
			v := val.Value
			l := len(v)
			if l%5 == 0 && l >= 5 {
				for len(v) > 0 {
					_, ipnet, _ := net.ParseCIDR(fmt.Sprintf("%d.%d.%d.%d/%d", v[0], v[1], v[2], v[3], v[4]))
					info.IPPrefixes = append(info.IPPrefixes, *ipnet)
					v = v[5:]
				}
			}
		case CDP_TLV_HELLO:
			if len(val.Value) == 32 {
				v := val.Value
				copy(info.CDPHello.OUI[0:3], v[0:3])
				info.CDPHello.ProtocolID = binary.BigEndian.Uint16(v[3:5])
				info.CDPHello.ClusterMaster = net.IPv4(v[5], v[6], v[7], v[8])
				info.CDPHello.UnknownIP = net.IPv4(v[9], v[10], v[11], v[12])
				info.CDPHello.Version = v[13]
				info.CDPHello.SubVersion = v[14]
				info.CDPHello.Status = v[15]
				info.CDPHello.Unknown2 = v[16]
				info.CDPHello.ClusterCommander = v[17:23]
				info.CDPHello.SwitchMAC = v[23:29]
				info.CDPHello.Unknown3 = v[29]
				info.CDPHello.ManagementVLAN = binary.BigEndian.Uint16(v[30:32])
			}
		case CDP_TLV_VTPDOMAIN:
			info.VTPDomain = string(val.Value)
		case CDP_TLV_NATIVEVLAN:
			if len(val.Value) > 1 {
				info.NativeVLAN = binary.BigEndian.Uint16(val.Value[0:2])
			}
		case CDP_TLV_DUPLEX:
			if len(val.Value) > 0 {
				info.FullDuplex = (val.Value[0] == 1)
			}
		case CDP_TLV_APPLID:
			if len(val.Value) > 2 {
				info.ApplianceReply.ID = uint8(val.Value[0])
				info.ApplianceReply.VLAN = binary.BigEndian.Uint16(val.Value[1:3])
			}
		case CDP_TLV_APPLQRY:
			if len(val.Value) > 2 {
				info.ApplianceQuery.ID = uint8(val.Value[0])
				info.ApplianceQuery.VLAN = binary.BigEndian.Uint16(val.Value[1:3])
			}
		case CDP_TLV_POWER:
			if len(val.Value) > 1 {
				info.PowerConsumption = binary.BigEndian.Uint16(val.Value[0:2])
			}
		case CDP_TLV_MTU:
			if len(val.Value) > 3 {
				info.MTU = binary.BigEndian.Uint32(val.Value[0:4])
			}
		case CDP_TLV_EXTENDEDTRUST:
			if len(val.Value) > 0 {
				info.ExtendedTrust = uint8(val.Value[0])
			}
		case CDP_TLV_UNTRUSTEDCOS:
			if len(val.Value) > 0 {
				info.UntrustedCOS = uint8(val.Value[0])
			}
		case CDP_TLV_SYSNAME:
			info.SysName = string(val.Value)
			//	case CDP_TLV_SYSOID: Undocumented...
		case CDP_TLV_MGMTADDRESS:
			if len(val.Value) > 3 {
				info.MgmtAddresses = decodeAddresses(val.Value)
			}
		case CDP_TLV_LOCATION:
			if len(val.Value) > 1 {
				info.Location.Type = uint8(val.Value[0])
				info.Location.Location = string(val.Value[1:])
			}
		default:
			info.Unknown = append(info.Unknown, val)
		}
	}
	return
}

// CDP Protocol Types
const (
	CDP_PROT_NLPID byte = 1
	CDP_PROT_802_2 byte = 2
)

// CDP Address types.
const (
	CDP_ADDR_CLNP      uint64 = 0x81
	CDP_ADDR_IPV4      uint64 = 0xcc
	CDP_ADDR_IPV6      uint64 = 0xaaaa030000000800
	CDP_ADDR_DECNET    uint64 = 0xaaaa030000006003
	CDP_ADDR_APPLETALK uint64 = 0xaaaa03000000809b
	CDP_ADDR_IPX       uint64 = 0xaaaa030000008137
	CDP_ADDR_VINES     uint64 = 0xaaaa0300000080c4
	CDP_ADDR_XNS       uint64 = 0xaaaa030000000600
	CDP_ADDR_APOLLO    uint64 = 0xaaaa030000008019
)

func decodeAddresses(v []byte) (addresses []net.IP) {
	numaddr := int(binary.BigEndian.Uint32(v[0:4]))
	v = v[4:]
	if numaddr < 1 || len(v) < numaddr*8 {
		return
	}
	for i := 0; i < numaddr; i++ {
		prottype := v[0]
		if prottype != CDP_PROT_NLPID && prottype != CDP_PROT_802_2 { // invalid protocol type
			return
		}
		protlen := int(v[1])
		if (prottype == CDP_PROT_NLPID && protlen != 1) ||
			(prottype == CDP_PROT_802_2 && protlen != 3 && protlen != 8) { // invalid length
			return
		}
		plen := make([]byte, 8)
		copy(plen[8-protlen:], v[2:2+protlen])
		protocol := binary.BigEndian.Uint64(plen)
		v = v[2+protlen:]
		addrlen := binary.BigEndian.Uint16(v[0:2])
		ab := v[2 : 2+addrlen]
		if protocol == CDP_ADDR_IPV4 && addrlen == 4 {
			addresses = append(addresses, net.IPv4(ab[0], ab[1], ab[2], ab[3]))
		} else if protocol == CDP_ADDR_IPV6 && addrlen == 16 {
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
