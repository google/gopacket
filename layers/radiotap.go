/**!
 * The MIT License
 *
 * Copyright (c) 2014 Remco Verhoef (github.com/dutchcoders/gopacket-80211)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * gopacket-80211
 * http://github.com/dutchcoders/gopacket-80211
 *
 * @authors http://github.com/dutchcoders/gopacket-80211/graphs/contributors
*/

package layers

import (
	"encoding/binary"
	"fmt"
	"code.google.com/p/gopacket"
)

func align(offset uint, width uint) uint {
    return ( (((offset) + ((width) - 1)) & (^((width) - 1))) - offset )
}

type IEEE80211RadioPresent uint16;

const (
	IEEE80211RadioPresentTSFT               IEEE80211RadioPresent = 0
	IEEE80211RadioPresentFlags              IEEE80211RadioPresent = 1
	IEEE80211RadioPresentRate               IEEE80211RadioPresent = 2
	IEEE80211RadioPresentChannel            IEEE80211RadioPresent = 3
	IEEE80211RadioPresentFHSS               IEEE80211RadioPresent = 4
	IEEE80211RadioPresentDbmAntennaSignal   IEEE80211RadioPresent = 5
	IEEE80211RadioPresentDbmAntennaNoise    IEEE80211RadioPresent = 6
	IEEE80211RadioPresentLockQuality        IEEE80211RadioPresent = 7
	IEEE80211RadioPresentTxAttenuation      IEEE80211RadioPresent = 8
	IEEE80211RadioPresentDbTxAttenuation    IEEE80211RadioPresent = 9
	IEEE80211RadioPresentDbmTxPower         IEEE80211RadioPresent = 10
	IEEE80211RadioPresentAntenna            IEEE80211RadioPresent = 11
	IEEE80211RadioPresentDbAntennaSignal    IEEE80211RadioPresent = 12
	IEEE80211RadioPresentDbAntennaNoise     IEEE80211RadioPresent = 13
	IEEE80211RadioPresentEXT                IEEE80211RadioPresent = 31
)

type IEEE80211RadioChannelFlags uint16;

const (
        /* Channel flags. */
	IEEE80211RadioChannelFlagsTurbo     IEEE80211RadioChannelFlags = 0x0010	/* Turbo channel */
	IEEE80211RadioChannelFlagsCCK       IEEE80211RadioChannelFlags = 0x0020	/* CCK channel */
	IEEE80211RadioChannelFlagsOFDM      IEEE80211RadioChannelFlags = 0x0040	/* OFDM channel */
	IEEE80211RadioChannelFlags2Ghz	    IEEE80211RadioChannelFlags = 0x0080	/* 2 GHz spectrum channel. */
	IEEE80211RadioChannelFlags5Ghz	    IEEE80211RadioChannelFlags = 0x0100	/* 5 GHz spectrum channel */
	IEEE80211RadioChannelFlagsPassive   IEEE80211RadioChannelFlags = 0x0200	/* Only passive scan allowed */
	IEEE80211RadioChannelFlagsDynamic   IEEE80211RadioChannelFlags = 0x0400	/* Dynamic CCK-OFDM channel */
	IEEE80211RadioChannelFlagsGFSK	    IEEE80211RadioChannelFlags = 0x0800	/* GFSK channel (FHSS PHY) */
)

func (a IEEE80211RadioChannelFlags) String() string {
    outStr := ""
    if ((a & IEEE80211RadioChannelFlagsTurbo) == IEEE80211RadioChannelFlagsTurbo) {
        outStr += "Turbo,"
    }
    if ((a & IEEE80211RadioChannelFlagsCCK) == IEEE80211RadioChannelFlagsCCK) {
        outStr += "CCK,"
    }
    if ((a & IEEE80211RadioChannelFlagsOFDM) == IEEE80211RadioChannelFlagsOFDM) {
        outStr += "OFDM,"
    }
    if ((a & IEEE80211RadioChannelFlags2Ghz) == IEEE80211RadioChannelFlags2Ghz) {
        outStr += "2Ghz,"
    }
    if ((a & IEEE80211RadioChannelFlags5Ghz) == IEEE80211RadioChannelFlags5Ghz) {
        outStr += "5Ghz,"
    }
    if ((a & IEEE80211RadioChannelFlagsPassive) == IEEE80211RadioChannelFlagsPassive) {
        outStr += "Passive,"
    }
    if ((a & IEEE80211RadioChannelFlagsDynamic) == IEEE80211RadioChannelFlagsDynamic) {
        outStr += "Dynamic,"
    }
    if ((a & IEEE80211RadioChannelFlagsGFSK) == IEEE80211RadioChannelFlagsGFSK) {
        outStr += "GFSK,"
    }

    return outStr
}

/* For IEEE80211_RADIOTAP_FLAGS */
type IEEE80211RadioFlags uint8;

const (
        /* sent/received during CFP */
        IEEE80211RadioFlagsCFP	                IEEE80211RadioFlags = 0x01
        /* sent/received * with short * preamble */
	IEEE80211RadioFlagsShortPreamble        IEEE80211RadioFlags = 0x02
	/* sent/received * with WEP encryption */
        IEEE80211RadioFlagsWEP		        IEEE80211RadioFlags = 0x04
        /* sent/received * with fragmentation */
	IEEE80211RadioFlagsFrag                 IEEE80211RadioFlags = 0x08
        /* frame includes FCS */
	IEEE80211RadioFlagsFCS                  IEEE80211RadioFlags = 0x10
	/* frame has padding between * 802.11 header and payload * (to 32-bit boundary) */
        IEEE80211RadioFlagsDatapad              IEEE80211RadioFlags = 0x20
	/* does not pass FCS check */
        IEEE80211RadioFlagsBadFCS               IEEE80211RadioFlags = 0x40
	/* HT short GI */
        IEEE80211RadioFlagsShortGI              IEEE80211RadioFlags = 0x80
)

func (a IEEE80211RadioFlags) String() string {
    outStr := ""
    if ((a & IEEE80211RadioFlagsCFP) == IEEE80211RadioFlagsCFP) {
        outStr += "CFP,"
    }
    if ((a & IEEE80211RadioFlagsShortPreamble) == IEEE80211RadioFlagsShortPreamble) {
        outStr += "SHORT-PREAMBLE,"
    }
    if ((a & IEEE80211RadioFlagsWEP) == IEEE80211RadioFlagsWEP) {
        outStr += "WEP,"
    }
    if ((a & IEEE80211RadioFlagsFrag) == IEEE80211RadioFlagsFrag) {
        outStr += "FRAG,"
    }
    if ((a & IEEE80211RadioFlagsFCS) == IEEE80211RadioFlagsFCS) {
        outStr += "FCS,"
    }
    if ((a & IEEE80211RadioFlagsDatapad) == IEEE80211RadioFlagsDatapad) {
        outStr += "DATAPAD,"
    }
    if ((a & IEEE80211RadioFlagsShortGI) == IEEE80211RadioFlagsShortGI) {
        outStr += "SHORT-GI,"
    }

    return outStr
}


type IEEE80211RadioRate uint8

func (a IEEE80211RadioRate) String() string {
    return fmt.Sprintf("%v Mb/s", 0.5 * float32(a))
}

func decodeIEEE80211Radio(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE80211Radio{}
	return decodingLayerDecoder(d, data, p)
}

type IEEE80211Radio struct {
	BaseLayer

	// Version 0. Only increases for drastic changes, introduction of compatible new fields does not count.
	Version uint8 

        // length of the whole header in bytes, including it_version, it_pad, it_len, and data fields.
        Length uint16

	// A bitmap telling which fields are present. Set bit 31 (0x80000000) to extend the bitmap by another 32 bits. Additional extensions are made by setting bit 31.
	Present uint32 

	Tsft uint64
	Flags IEEE80211RadioFlags
	ChannelTx uint16
	ChannelRx uint16
	ChannelFlags IEEE80211RadioChannelFlags
	Rate IEEE80211RadioRate
	Fhss uint16
	DbmSignal int8
	DbmNoise int8
	LockQuality uint16
	TxAttenuation uint16
	DbTxAttenuation uint16
	Power int8	
	Antenna uint8
	DbSignal uint8
	DbNoise uint8
}

func (m IEEE80211Radio) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error { return nil }
func (m *IEEE80211Radio) LayerType() gopacket.LayerType { return LayerTypeIEEE80211Radio }

func (m *IEEE80211Radio) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	m.Version = (uint8)(data[0])
	m.Length = binary.LittleEndian.Uint16(data[2:4])
	m.Present = binary.LittleEndian.Uint32(data[4:8])
	if ((m.Present & 0x80000000) == 0x80000000 ) {
		// offsef = offset + 1
	}

	offset := uint(8)

	if ((m.Present & (1 << IEEE80211RadioPresentTSFT))>0) {
		offset+=align(offset, 8)
		m.Tsft=binary.LittleEndian.Uint64(data[offset:offset+8])
		offset+=8
	}

	if ((m.Present & (1 << IEEE80211RadioPresentFlags))>0) {
		m.Flags=(IEEE80211RadioFlags)(data[offset])
		offset++
	}

	if ((m.Present & (1 << IEEE80211RadioPresentRate))>0) {
		m.Rate=(IEEE80211RadioRate)(data[offset])
		offset++
	}

	if ((m.Present & (1 << IEEE80211RadioPresentChannel))>0) {
		offset+=align(offset, 2)
		m.ChannelTx=binary.LittleEndian.Uint16(data[offset:offset+2])
		offset += 2
		m.ChannelFlags=(IEEE80211RadioChannelFlags)(data[offset])
		offset++
	}

	if ((m.Present & (1 << IEEE80211RadioPresentDbmAntennaSignal))>0) {
		m.DbmSignal=(int8)(data[offset])
		offset++
	}


	if ((m.Present & (1 << IEEE80211RadioPresentDbmAntennaNoise))>0) {
		m.DbmNoise=(int8)(data[offset])
		offset++
	}


	if ((m.Present & (1 << IEEE80211RadioPresentLockQuality))>0) {
		offset+=align(offset, 2)
		m.LockQuality=binary.LittleEndian.Uint16(data[offset:offset+2])
		offset+=2
	}


	if ((m.Present & (1 << IEEE80211RadioPresentTxAttenuation))>0) {
		offset+=align(offset, 2)
		m.TxAttenuation=binary.LittleEndian.Uint16(data[offset:offset+2])
		offset+=2
	}


	if ((m.Present & (1 << IEEE80211RadioPresentDbTxAttenuation))>0) {
		offset+=align(offset, 2)
		m.DbTxAttenuation=binary.LittleEndian.Uint16(data[offset:offset+2])
		offset+=2
	}


	if ((m.Present & (1 << IEEE80211RadioPresentDbmTxPower))>0) {
		m.Power=(int8)(data[offset])
		offset++
	}


	if ((m.Present & (1 << IEEE80211RadioPresentAntenna))>0) {
		m.Antenna=(uint8)(data[offset])
		offset++
	}


	if ((m.Present & (1 << IEEE80211RadioPresentDbAntennaSignal))>0) {
		m.DbSignal=(uint8)(data[offset])
		offset++
	}


	if ((m.Present & (1 << IEEE80211RadioPresentDbAntennaNoise))>0) {
		m.DbNoise=(uint8)(data[offset])
		offset++
	}


	if ((m.Present & (1 << IEEE80211RadioPresentEXT))>0) {
		offset+=align(offset, 4)
		_ = data[offset:offset+4]
                offset+=4
	}

	// if present contains ext, parse extra header

	/*
	d.Priority = (data[0] & 0xE0) >> 13
	d.DropEligible = data[0]&0x10 != 0
	d.VLANIdentifier = binary.BigEndian.Uint16(data[:2]) & 0x0FFF
	d.Type = EthernetType(binary.BigEndian.Uint16(data[2:4]))
	*/

	if ((m.Flags & IEEE80211RadioFlagsDatapad) == IEEE80211RadioFlagsDatapad ) {
	}

	// fmt.Printf("%v %v %v %v",8+m.Length, offset, string(data[:(8+m.Length)]), string(data[(8+m.Length):]))
	m.BaseLayer = BaseLayer{Contents: data[:(m.Length)], Payload: data[(m.Length):]}
	return nil
}

func (m *IEEE80211Radio) CanDecode() gopacket.LayerClass { return LayerTypeIEEE80211Radio }
func (m *IEEE80211Radio) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11 }
