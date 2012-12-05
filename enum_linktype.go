// Copyright (c) 2012 Google, Inc. All rights reserved.
// Copyright (c) 2009-2012 Andreas Krennmair. All rights reserved.

package gopacket

import (
	"fmt"
)

// LinkType is an enumeration of link types, and acts as a decoder for any
// link type it supports.
type LinkType int

const (
	// According to pcap-linktype(7).
	LinkTypeNull           LinkType = 0
	LinkTypeEthernet               LinkType= 1
	LinkTypeTokenRing              LinkType= 6
	LinkTypeArcNet                 LinkType= 7
	LinkTypeSLIP                   LinkType= 8
	LinkTypePPP                    LinkType= 9
	LinkTypeFDDI                   LinkType= 10
	LinkTypeATM_RFC1483            LinkType= 100
	LinkTypeRaw                    LinkType= 101
	LinkTypePPP_HDLC               LinkType= 50
	LinkTypePPPEthernet            LinkType= 51
	LinkTypeC_HDLC                 LinkType= 104
	LinkTypeIEEE802_11             LinkType= 105
	LinkTypeFRelay                 LinkType= 107
	LinkTypeLoop                   LinkType= 108
	LinkTypeLinuxSLL               LinkType= 113
	LinkTypeLTalk                  LinkType= 104
	LinkTypePFLog                  LinkType= 117
	LinkTypePrismHeader            LinkType= 119
	LinkTypeIPOverFC               LinkType= 122
	LinkTypeSunATM                 LinkType= 123
	LinkTypeIEEE80211Radio         LinkType= 127
	LinkTypeARCNetLinux            LinkType= 129
	LinkTypeLinuxIRDA              LinkType= 144
	LinkTypeLinuxLAPD              LinkType= 177
)

func (l LinkType) Decode(data []byte) (out DecodeResult, err error) {
	switch l {
	case LinkTypeEthernet:
		return decodeEthernet(data)
	case LinkTypePPP:
		return decodePPP(data)
	}
	err = fmt.Errorf("Unsupported link-layer type %d", l)
	return
}
