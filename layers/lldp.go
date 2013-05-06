// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"code.google.com/p/gopacket"
	"encoding/binary"
	"fmt"
)

// LinkLayerDiscoveryType is the type of each TLV value in a LinkLayerDiscovery packet.
type LinkLayerDiscoveryType byte

const (
	LLDP_TLV_END          LinkLayerDiscoveryType = 0
	LLDP_TLV_CHID         LinkLayerDiscoveryType = 1
	LLDP_TLV_PID          LinkLayerDiscoveryType = 2
	LLDP_TLV_TTL          LinkLayerDiscoveryType = 3
	LLDP_TLV_PORT_DESCR   LinkLayerDiscoveryType = 4
	LLDP_TLV_SYS_NAME     LinkLayerDiscoveryType = 5
	LLDP_TLV_SYS_DESCR    LinkLayerDiscoveryType = 6
	LLDP_TLV_SYS_CAPS     LinkLayerDiscoveryType = 7
	LLDP_TLV_MGMT_ADDR    LinkLayerDiscoveryType = 8
	LLDP_TLV_ORG_SPECIFIC LinkLayerDiscoveryType = 127
)

type LLDPChassisIDSubType byte

const (
	LLDP_CHASSIS_CHASSIS_COMP_SUBTYPE LLDPChassisIDSubType = 1
	LLDP_CHASSIS_INTF_ALIAS_SUBTYPE   LLDPChassisIDSubType = 2
	LLDP_CHASSIS_PORT_COMP_SUBTYPE    LLDPChassisIDSubType = 3
	LLDP_CHASSIS_MAC_ADDR_SUBTYPE     LLDPChassisIDSubType = 4
	LLDP_CHASSIS_NETWORK_ADDR_SUBTYPE LLDPChassisIDSubType = 5
	LLDP_CHASSIS_INTF_NAME_SUBTYPE    LLDPChassisIDSubType = 6
	LLDP_CHASSIS_LOCAL_SUBTYPE        LLDPChassisIDSubType = 7
)

type LLDPChassisID struct {
	Subtype LLDPChassisIDSubType
	ID      []byte
}

type LLDPPortIDSubType byte

const (
	LLDP_PORT_INTF_ALIAS_SUBTYPE    LLDPPortIDSubType = 1
	LLDP_PORT_PORT_COMP_SUBTYPE     LLDPPortIDSubType = 2
	LLDP_PORT_MAC_ADDR_SUBTYPE      LLDPPortIDSubType = 3
	LLDP_PORT_NETWORK_ADDR_SUBTYPE  LLDPPortIDSubType = 4
	LLDP_PORT_INTF_NAME_SUBTYPE     LLDPPortIDSubType = 5
	LLDP_PORT_AGENT_CIRC_ID_SUBTYPE LLDPPortIDSubType = 6
	LLDP_PORT_LOCAL_SUBTYPE         LLDPPortIDSubType = 7
)

type LLDPPortID struct {
	Subtype LLDPPortIDSubType
	ID      []byte
}

//LLDPCaps Types
const (
	LLDP_CAP_OTHER        uint16 = (1 << 0)
	LLDP_CAP_REPEATER     uint16 = (1 << 1)
	LLDP_CAP_BRIDGE       uint16 = (1 << 2)
	LLDP_CAP_WLAN_AP      uint16 = (1 << 3)
	LLDP_CAP_ROUTER       uint16 = (1 << 4)
	LLDP_CAP_PHONE        uint16 = (1 << 5)
	LLDP_CAP_DOCSIS       uint16 = (1 << 6)
	LLDP_CAP_STATION_ONLY uint16 = (1 << 7)
	LLDP_CAP_CVLAN        uint16 = (1 << 8)
	LLDP_CAP_SVLAN        uint16 = (1 << 9)
	LLDP_CAP_TMPR         uint16 = (1 << 10)
)

// LLDPCaps represents the capabilites of a device
type LLDPCaps struct {
	Other       bool
	Repeater    bool
	Bridge      bool
	WLANAP      bool
	Router      bool
	Phone       bool
	DocSis      bool
	StationOnly bool
	CVLAN       bool
	SVLAN       bool
	TMPR        bool
}

type LLDPSysCaps struct {
	ChassisID  byte
	SystemCap  LLDPCaps
	EnabledCap LLDPCaps
}

type LLDPMgmtAddr struct {
	Subtype          byte
	Address          []byte
	InterfaceSubtype byte
	InterfaceNumber  uint32
	OID              string
}

// LinkLayerDiscovery is a packet layer containing the LinkLayer Discovery Protocol.
// See http:http://standards.ieee.org/getieee802/download/802.1AB-2009.pdf
// ChassisID, PortID and TTL are mandatory TLV's. Other values can be decoded
// with DecodeValues()
type LinkLayerDiscovery struct {
	baseLayer
	ChassisID LLDPChassisID
	PortID    LLDPPortID
	TTL       uint16
	Values    []LinkLayerDiscoveryValue
}

// VLAN Port Protocol ID options
const (
	LLDP_PROTOCOLVLANID_CAPABILITY byte = (1 << 0)
	LLDP_PROTOCOLVLANID_STATUS     byte = (1 << 1)
)

type PortProtocolVLANID struct {
	Supported bool
	Enabled   bool
	ID        uint16
}

type VLANName struct {
	ID   uint16
	Name string
}

type ProtocolIdentity []byte

// LACP options
const (
	LLDP_AGGREGATION_CAPABILITY byte = (1 << 0)
	LLDP_AGGREGATION_STATUS     byte = (1 << 1)
)

type LinkAggregation struct {
	Supported bool
	Enabled   bool
	PortID    uint32
}

// MACPHY options
const (
	LLDP_MACPHY_CAPABILITY byte = (1 << 0)
	LLDP_MACPHY_STATUS     byte = (1 << 1)
)

// From IANA-MAU-MIB (introduced by RFC 4836) - dot3MauType
const (
	LLDP_MAU_TYPE_UNKNOWN          uint16 = 0
	LLDP_MAU_TYPE_AUI              uint16 = 1
	LLDP_MAU_TYPE_10BASE_5         uint16 = 2
	LLDP_MAU_TYPE_FOIRL            uint16 = 3
	LLDP_MAU_TYPE_10BASE_2         uint16 = 4
	LLDP_MAU_TYPE_10BASE_T         uint16 = 5
	LLDP_MAU_TYPE_10BASE_FP        uint16 = 6
	LLDP_MAU_TYPE_10BASE_FB        uint16 = 7
	LLDP_MAU_TYPE_10BASE_FL        uint16 = 8
	LLDP_MAU_TYPE_10BROAD36        uint16 = 9
	LLDP_MAU_TYPE_10BASE_T_HD      uint16 = 10
	LLDP_MAU_TYPE_10BASE_T_FD      uint16 = 11
	LLDP_MAU_TYPE_10BASE_FL_HD     uint16 = 12
	LLDP_MAU_TYPE_10BASE_FL_FD     uint16 = 13
	LLDP_MAU_TYPE_100BASE_T4       uint16 = 14
	LLDP_MAU_TYPE_100BASE_TX_HD    uint16 = 15
	LLDP_MAU_TYPE_100BASE_TX_FD    uint16 = 16
	LLDP_MAU_TYPE_100BASE_FX_HD    uint16 = 17
	LLDP_MAU_TYPE_100BASE_FX_FD    uint16 = 18
	LLDP_MAU_TYPE_100BASE_T2_HD    uint16 = 19
	LLDP_MAU_TYPE_100BASE_T2_FD    uint16 = 20
	LLDP_MAU_TYPE_1000BASE_X_HD    uint16 = 21
	LLDP_MAU_TYPE_1000BASE_X_FD    uint16 = 22
	LLDP_MAU_TYPE_1000BASE_LX_HD   uint16 = 23
	LLDP_MAU_TYPE_1000BASE_LX_FD   uint16 = 24
	LLDP_MAU_TYPE_1000BASE_SX_HD   uint16 = 25
	LLDP_MAU_TYPE_1000BASE_SX_FD   uint16 = 26
	LLDP_MAU_TYPE_1000BASE_CX_HD   uint16 = 27
	LLDP_MAU_TYPE_1000BASE_CX_FD   uint16 = 28
	LLDP_MAU_TYPE_1000BASE_T_HD    uint16 = 29
	LLDP_MAU_TYPE_1000BASE_T_FD    uint16 = 30
	LLDP_MAU_TYPE_10GBASE_X        uint16 = 31
	LLDP_MAU_TYPE_10GBASE_LX4      uint16 = 32
	LLDP_MAU_TYPE_10GBASE_R        uint16 = 33
	LLDP_MAU_TYPE_10GBASE_ER       uint16 = 34
	LLDP_MAU_TYPE_10GBASE_LR       uint16 = 35
	LLDP_MAU_TYPE_10GBASE_SR       uint16 = 36
	LLDP_MAU_TYPE_10GBASE_W        uint16 = 37
	LLDP_MAU_TYPE_10GBASE_EW       uint16 = 38
	LLDP_MAU_TYPE_10GBASE_LW       uint16 = 39
	LLDP_MAU_TYPE_10GBASE_SW       uint16 = 40
	LLDP_MAU_TYPE_10GBASE_CX4      uint16 = 41
	LLDP_MAU_TYPE_2BASE_TL         uint16 = 42
	LLDP_MAU_TYPE_10PASS_TS        uint16 = 43
	LLDP_MAU_TYPE_100BASE_BX10D    uint16 = 44
	LLDP_MAU_TYPE_100BASE_BX10U    uint16 = 45
	LLDP_MAU_TYPE_100BASE_LX10     uint16 = 46
	LLDP_MAU_TYPE_1000BASE_BX10D   uint16 = 47
	LLDP_MAU_TYPE_1000BASE_BX10U   uint16 = 48
	LLDP_MAU_TYPE_1000BASE_LX10    uint16 = 49
	LLDP_MAU_TYPE_1000BASE_PX10D   uint16 = 50
	LLDP_MAU_TYPE_1000BASE_PX10U   uint16 = 51
	LLDP_MAU_TYPE_1000BASE_PX20D   uint16 = 52
	LLDP_MAU_TYPE_1000BASE_PX20U   uint16 = 53
	LLDP_MAU_TYPE_10GBASE_T        uint16 = 54
	LLDP_MAU_TYPE_10GBASE_LRM      uint16 = 55
	LLDP_MAU_TYPE_1000BASE_KX      uint16 = 56
	LLDP_MAU_TYPE_10GBASE_KX4      uint16 = 57
	LLDP_MAU_TYPE_10GBASE_KR       uint16 = 58
	LLDP_MAU_TYPE_10_1GBASE_PRX_D1 uint16 = 59
	LLDP_MAU_TYPE_10_1GBASE_PRX_D2 uint16 = 60
	LLDP_MAU_TYPE_10_1GBASE_PRX_D3 uint16 = 61
	LLDP_MAU_TYPE_10_1GBASE_PRX_U1 uint16 = 62
	LLDP_MAU_TYPE_10_1GBASE_PRX_U2 uint16 = 63
	LLDP_MAU_TYPE_10_1GBASE_PRX_U3 uint16 = 64
	LLDP_MAU_TYPE_10GBASE_PR_D1    uint16 = 65
	LLDP_MAU_TYPE_10GBASE_PR_D2    uint16 = 66
	LLDP_MAU_TYPE_10GBASE_PR_D3    uint16 = 67
	LLDP_MAU_TYPE_10GBASE_PR_U1    uint16 = 68
	LLDP_MAU_TYPE_10GBASE_PR_U3    uint16 = 69
)

// From RFC 3636 - ifMauAutoNegCapAdvertisedBits
const (
	LLDP_MAU_PMD_OTHER         uint16 = (1 << 15)
	LLDP_MAU_PMD_10BASE_T      uint16 = (1 << 14)
	LLDP_MAU_PMD_10BASE_T_FD   uint16 = (1 << 13)
	LLDP_MAU_PMD_100BASE_T4    uint16 = (1 << 12)
	LLDP_MAU_PMD_100BASE_TX    uint16 = (1 << 11)
	LLDP_MAU_PMD_100BASE_TX_FD uint16 = (1 << 10)
	LLDP_MAU_PMD_100BASE_T2    uint16 = (1 << 9)
	LLDP_MAU_PMD_100BASE_T2_FD uint16 = (1 << 8)
	LLDP_MAU_PMD_FDXPAUSE      uint16 = (1 << 7)
	LLDP_MAU_PMD_FDXAPAUSE     uint16 = (1 << 6)
	LLDP_MAU_PMD_FDXSPAUSE     uint16 = (1 << 5)
	LLDP_MAU_PMD_FDXBPAUSE     uint16 = (1 << 4)
	LLDP_MAU_PMD_1000BASE_X    uint16 = (1 << 3)
	LLDP_MAU_PMD_1000BASE_X_FD uint16 = (1 << 2)
	LLDP_MAU_PMD_1000BASE_T    uint16 = (1 << 1)
	LLDP_MAU_PMD_1000BASE_T_FD uint16 = (1 << 0)
)

type MACPHYConfigStatus struct {
	AutoNegSupported  bool
	AutoNegEnabled    bool
	AutoNegCapability uint16
	MAUType           uint16
}

// MDI Power options
const (
	LLDP_MDIPOWER_PORTCLASS    byte = (1 << 0)
	LLDP_MDIPOWER_CAPABILITY   byte = (1 << 1)
	LLDP_MDIPOWER_STATUS       byte = (1 << 2)
	LLDP_MDIPOWER_PAIRSABILITY byte = (1 << 3)
)

type PowerViaMDI struct {
	PortClassPSE    bool // false = PD
	PSESupported    bool
	PSEEnabled      bool
	PSEPairsAbility bool
	PSEPowerPair    uint8
	PSEClass        uint8
}

/// 802.1 TLV Subtypes
const (
	LLDP_PRIVATE_8021_SUBTYPE_PORT_VLAN_ID      uint8 = 1
	LLDP_PRIVATE_8021_SUBTYPE_PROTOCOL_VLAN_ID  uint8 = 2
	LLDP_PRIVATE_8021_SUBTYPE_VLAN_NAME         uint8 = 3
	LLDP_PRIVATE_8021_SUBTYPE_PROTOCOL_IDENTITY uint8 = 4
	LLDP_PRIVATE_8021_SUBTYPE_VDI_USAGE_DIGEST  uint8 = 5
	LLDP_PRIVATE_8021_SUBTYPE_MANAGEMENT_VID    uint8 = 6
	LLDP_PRIVATE_8021_SUBTYPE_LINKAGGR          uint8 = 7
)

// 802.3 TLV Subtypes
const (
	LLDP_PRIVATE_8023_SUBTYPE_MACPHY   uint8 = 1
	LLDP_PRIVATE_8023_SUBTYPE_MDIPOWER uint8 = 2
	LLDP_PRIVATE_8023_SUBTYPE_LINKAGGR uint8 = 3
	LLDP_PRIVATE_8023_SUBTYPE_MTU      uint8 = 4
)

type OrgSpecificTLV struct {
	OUI     [3]byte
	SubType uint8
	Info    []byte
}

// LinkLayerDiscoveryInfo represents the decoded details for a set of LinkLayerDiscoveryValues
type LinkLayerDiscoveryInfo struct {
	PortDesc string
	SysName  string
	SysDesc  string
	SysCaps  LLDPSysCaps
	MgmtAddr LLDPMgmtAddr
	// 802.1 Subtypes
	PVID               uint16
	PPVIDs             []PortProtocolVLANID
	VLANNames          []VLANName
	ProtocolIdentities []ProtocolIdentity
	VIDUsageDigest     uint32
	ManagementVID      uint16
	LinkAggregation
	// 802.3 Subtypes
	MACPHYConfigStatus
	PowerViaMDI
	MTU     uint16
	OrgTLVs []OrgSpecificTLV          // undecoded Private TLVs
	Unknown []LinkLayerDiscoveryValue // undecoded TLVs
}

// LayerType returns gopacket.LayerTypeLinkLayerDiscovery.
func (c *LinkLayerDiscovery) LayerType() gopacket.LayerType {
	return LayerTypeLinkLayerDiscovery
}

// LinkLayerDiscoveryValue is a TLV value inside a LinkLayerDiscovery packet layer.
type LinkLayerDiscoveryValue struct {
	Type   LinkLayerDiscoveryType
	Length uint16
	Value  []byte
}

func decodeLinkLayerDiscovery(data []byte, p gopacket.PacketBuilder) error {
	var vals []LinkLayerDiscoveryValue
	vData := data[0:]
	for len(vData) > 0 {
		nbit := vData[0] & 0x01
		t := LinkLayerDiscoveryType(vData[0] >> 1)
		val := LinkLayerDiscoveryValue{Type: t, Length: uint16(nbit<<8 + vData[1])}
		if val.Length > 0 {
			val.Value = vData[2 : val.Length+2]
		}
		vals = append(vals, val)
		if t == LLDP_TLV_END {
			break
		}
		if len(vData) < int(2+val.Length) {
			return fmt.Errorf("Malformed LinkLayerDiscovery Header")
		}
		vData = vData[2+val.Length:]
	}
	if len(vals) < 4 {
		return fmt.Errorf("Missing mandatory LinkLayerDiscovery TLV")
	}
	c := &LinkLayerDiscovery{}
	gotend := false
	for _, v := range vals {
		switch v.Type {
		case LLDP_TLV_END:
			gotend = true
		case LLDP_TLV_CHID:
			if len(v.Value) < 2 {
				return fmt.Errorf("Malformed LinkLayerDiscovery ChassisID TLV")
			}
			c.ChassisID.Subtype = LLDPChassisIDSubType(v.Value[0])
			c.ChassisID.ID = v.Value[1:]
		case LLDP_TLV_PID:
			if len(v.Value) < 2 {
				return fmt.Errorf("Malformed LinkLayerDiscovery PortID TLV")
			}
			c.PortID.Subtype = LLDPPortIDSubType(v.Value[0])
			c.PortID.ID = v.Value[1:]
		case LLDP_TLV_TTL:
			if len(v.Value) < 2 {
				return fmt.Errorf("Malformed LinkLayerDiscovery TTL TLV")
			}
			c.TTL = binary.BigEndian.Uint16(v.Value[0:2])
		default:
			c.Values = append(c.Values, v)
		}
	}
	if c.ChassisID.Subtype == 0 || c.PortID.Subtype == 0 || !gotend {
		return fmt.Errorf("Missing mandatory LinkLayerDiscovery TLV")
	}
	c.contents = data
	p.AddLayer(c)
	return nil
}

func (l *LinkLayerDiscovery) DecodeValues() (info LinkLayerDiscoveryInfo) {
	for _, v := range l.Values {
		switch v.Type {
		case LLDP_TLV_PORT_DESCR:
			info.PortDesc = string(v.Value)
		case LLDP_TLV_SYS_NAME:
			info.SysName = string(v.Value)
		case LLDP_TLV_SYS_DESCR:
			info.SysDesc = string(v.Value)
		case LLDP_TLV_SYS_CAPS:
			if len(v.Value) > 4 {
				info.SysCaps.ChassisID = v.Value[0]
				info.SysCaps.SystemCap = getCaps(binary.BigEndian.Uint16(v.Value[1:3]))
				info.SysCaps.EnabledCap = getCaps(binary.BigEndian.Uint16(v.Value[3:5]))
			}
		case LLDP_TLV_MGMT_ADDR:
			if len(v.Value) < 9 {
				continue
			}
			mlen := v.Value[0]
			if len(v.Value) < int(mlen+8) {
				continue
			}
			info.MgmtAddr.Subtype = v.Value[1]
			info.MgmtAddr.Address = v.Value[2 : mlen+1]
			info.MgmtAddr.InterfaceSubtype = v.Value[mlen+1]
			info.MgmtAddr.InterfaceNumber = binary.BigEndian.Uint32(v.Value[mlen+2 : mlen+6])
			olen := v.Value[mlen+6]
			if len(v.Value) < int(mlen+6+olen) {
				continue //return fmt.Errorf("Malformed LinkLayerDiscovery MgmtAddr TLV")
			}
			info.MgmtAddr.OID = string(v.Value[mlen+9 : mlen+9+olen])
		case LLDP_TLV_ORG_SPECIFIC:
			if len(v.Value) < 4 {
				continue
			}
			o := OrgSpecificTLV{[3]byte{v.Value[0], v.Value[1], v.Value[2]}, uint8(v.Value[3]), v.Value[4:]}
			if bytes.Equal(o.OUI[0:3], []byte{0x00, 0x80, 0xc2}) { // IEEE 802.1
				switch o.SubType {
				case LLDP_PRIVATE_8021_SUBTYPE_PORT_VLAN_ID:
					if len(v.Value) > 1 {
						info.PVID = binary.BigEndian.Uint16(o.Info[0:2])
					}
				case LLDP_PRIVATE_8021_SUBTYPE_PROTOCOL_VLAN_ID:
					if len(v.Value) > 2 {
						sup := (o.Info[0]&LLDP_PROTOCOLVLANID_CAPABILITY > 0)
						en := (o.Info[0]&LLDP_AGGREGATION_STATUS > 0)
						id := binary.BigEndian.Uint16(o.Info[1:3])
						info.PPVIDs = append(info.PPVIDs, PortProtocolVLANID{sup, en, id})
					}
				case LLDP_PRIVATE_8021_SUBTYPE_VLAN_NAME:
					if len(v.Value) > 1 {
						id := binary.BigEndian.Uint16(o.Info[0:2])
						info.VLANNames = append(info.VLANNames, VLANName{id, string(o.Info[3:])})
					}
				case LLDP_PRIVATE_8021_SUBTYPE_PROTOCOL_IDENTITY:
					if len(v.Value) > 1 {
						info.ProtocolIdentities = append(info.ProtocolIdentities, o.Info[1:])
					}
				case LLDP_PRIVATE_8021_SUBTYPE_VDI_USAGE_DIGEST:
					if len(v.Value) > 3 {
						info.VIDUsageDigest = binary.BigEndian.Uint32(o.Info[0:4])
					}
				case LLDP_PRIVATE_8021_SUBTYPE_MANAGEMENT_VID:
					if len(v.Value) > 1 {
						info.ManagementVID = binary.BigEndian.Uint16(o.Info[0:2])
					}
				case LLDP_PRIVATE_8021_SUBTYPE_LINKAGGR:
					if len(v.Value) > 4 {
						sup := (o.Info[0]&LLDP_AGGREGATION_CAPABILITY > 0)
						en := (o.Info[0]&LLDP_AGGREGATION_STATUS > 0)
						id := binary.BigEndian.Uint32(o.Info[1:5])
						info.LinkAggregation = LinkAggregation{sup, en, id}
					}
				default:
					info.OrgTLVs = append(info.OrgTLVs, o)
				}
			} else if bytes.Equal(o.OUI[0:3], []byte{0x00, 0x12, 0x0f}) { // IEEE 802.3
				switch o.SubType {
				case LLDP_PRIVATE_8023_SUBTYPE_MACPHY:
					if len(v.Value) > 4 {
						sup := (o.Info[0]&LLDP_MACPHY_CAPABILITY > 0)
						en := (o.Info[0]&LLDP_MACPHY_STATUS > 0)
						ca := binary.BigEndian.Uint16(o.Info[1:3])
						mau := binary.BigEndian.Uint16(o.Info[3:5])
						info.MACPHYConfigStatus = MACPHYConfigStatus{sup, en, ca, mau}
					}
				case LLDP_PRIVATE_8023_SUBTYPE_MDIPOWER:
					if len(v.Value) > 2 {
						pse := (o.Info[0]&LLDP_MDIPOWER_PORTCLASS > 0)
						sup := (o.Info[0]&LLDP_MDIPOWER_CAPABILITY > 0)
						en := (o.Info[0]&LLDP_MDIPOWER_STATUS > 0)
						pairs := (o.Info[0]&LLDP_MDIPOWER_PAIRSABILITY > 0)
						pair := uint8(o.Info[1])
						class := uint8(o.Info[2])
						info.PowerViaMDI = PowerViaMDI{pse, sup, en, pairs, pair, class}
					}
				case LLDP_PRIVATE_8023_SUBTYPE_LINKAGGR:
					// deprecated
				case LLDP_PRIVATE_8023_SUBTYPE_MTU:
					if len(v.Value) > 1 {
						info.MTU = binary.BigEndian.Uint16(o.Info[0:2])
					}
				default:
					info.OrgTLVs = append(info.OrgTLVs, o)
				}
			} else {
				info.OrgTLVs = append(info.OrgTLVs, o)
			}
		default:
			info.Unknown = append(info.Unknown, v)
		}
	}
	return
}

func getCaps(v uint16) (c LLDPCaps) {
	c.Other = (v&LLDP_CAP_OTHER > 0)
	c.Repeater = (v&LLDP_CAP_REPEATER > 0)
	c.Bridge = (v&LLDP_CAP_BRIDGE > 0)
	c.WLANAP = (v&LLDP_CAP_WLAN_AP > 0)
	c.Router = (v&LLDP_CAP_ROUTER > 0)
	c.Phone = (v&LLDP_CAP_PHONE > 0)
	c.DocSis = (v&LLDP_CAP_DOCSIS > 0)
	c.StationOnly = (v&LLDP_CAP_STATION_ONLY > 0)
	c.CVLAN = (v&LLDP_CAP_CVLAN > 0)
	c.SVLAN = (v&LLDP_CAP_SVLAN > 0)
	c.TMPR = (v&LLDP_CAP_TMPR > 0)
	return
}
