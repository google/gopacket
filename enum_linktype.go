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
	LinkTypeEthernet                = 1
	LinkTypeTokenRing               = 6
	LinkTypeArcNet                  = 7
	LinkTypeSLIP                    = 8
	LinkTypePPP                     = 9
	LinkTypeFDDI                    = 10
	LinkTypeATM_RFC1483             = 100
	LinkTypeRaw                     = 101
	LinkTypePPP_HDLC                = 50
	LinkTypePPPEthernet             = 51
	LinkTypeC_HDLC                  = 104
	LinkTypeIEEE802_11              = 105
	LinkTypeFRelay                  = 107
	LinkTypeLoop                    = 108
	LinkTypeLinuxSLL                = 113
	LinkTypeLTalk                   = 104
	LinkTypePFLog                   = 117
	LinkTypePrismHeader             = 119
	LinkTypeIPOverFC                = 122
	LinkTypeSunATM                  = 123
	LinkTypeIEEE80211Radio          = 127
	LinkTypeARCNetLinux             = 129
	LinkTypeLinuxIRDA               = 144
	LinkTypeLinuxLAPD               = 177
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
