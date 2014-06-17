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

// This functions calculates the number of bytes needed to align with the width 
// on the offset.
// returns the number of bytes we need to skip to align to the offset (width) 
func align(offset uint, width uint) uint {
    return ( (((offset) + ((width) - 1)) & (^((width) - 1))) - offset )
}

type RadiotapPresent uint32

const (
	RadiotapPresentTSFT               RadiotapPresent = 1 << iota
	RadiotapPresentFlags
	RadiotapPresentRate
	RadiotapPresentChannel
	RadiotapPresentFHSS
	RadiotapPresentDbmAntennaSignal
	RadiotapPresentDbmAntennaNoise
	RadiotapPresentLockQuality
	RadiotapPresentTxAttenuation
	RadiotapPresentDbTxAttenuation
	RadiotapPresentDbmTxPower
	RadiotapPresentAntenna
	RadiotapPresentDbAntennaSignal
	RadiotapPresentDbAntennaNoise
	RadiotapPresentRxFlags
	RadiotapPresentTxFlags
	RadiotapPresentRtsRetries
	RadiotapPresentDataRetries
	RadiotapPresentEXT                 RadiotapPresent = 31 << iota
)

type RadiotapChannelFlags uint16

const (
        /* Turbo channel */
        RadiotapChannelFlagsTurbo           RadiotapChannelFlags = 0x0010
        /* CCK channel */
        RadiotapChannelFlagsCCK             RadiotapChannelFlags = 0x0020
        /* OFDM channel */
        RadiotapChannelFlagsOFDM            RadiotapChannelFlags = 0x0040
        /* 2 GHz spectrum channel. */
        RadiotapChannelFlags2Ghz	    RadiotapChannelFlags = 0x0080
        /* 5 GHz spectrum channel */
        RadiotapChannelFlags5Ghz	    RadiotapChannelFlags = 0x0100
        /* Only passive scan allowed */
        RadiotapChannelFlagsPassive         RadiotapChannelFlags = 0x0200
        /* Dynamic CCK-OFDM channel */
        RadiotapChannelFlagsDynamic         RadiotapChannelFlags = 0x0400
        /* GFSK channel (FHSS PHY) */
        RadiotapChannelFlagsGFSK	    RadiotapChannelFlags = 0x0800
      )

func (a RadiotapChannelFlags) String() string {
    outStr := ""
    if ((a & RadiotapChannelFlagsTurbo) == RadiotapChannelFlagsTurbo) {
        outStr += "Turbo,"
    }
    if ((a & RadiotapChannelFlagsCCK) == RadiotapChannelFlagsCCK) {
        outStr += "CCK,"
    }
    if ((a & RadiotapChannelFlagsOFDM) == RadiotapChannelFlagsOFDM) {
        outStr += "OFDM,"
    }
    if ((a & RadiotapChannelFlags2Ghz) == RadiotapChannelFlags2Ghz) {
        outStr += "2Ghz,"
    }
    if ((a & RadiotapChannelFlags5Ghz) == RadiotapChannelFlags5Ghz) {
        outStr += "5Ghz,"
    }
    if ((a & RadiotapChannelFlagsPassive) == RadiotapChannelFlagsPassive) {
        outStr += "Passive,"
    }
    if ((a & RadiotapChannelFlagsDynamic) == RadiotapChannelFlagsDynamic) {
        outStr += "Dynamic,"
    }
    if ((a & RadiotapChannelFlagsGFSK) == RadiotapChannelFlagsGFSK) {
        outStr += "GFSK,"
    }

    return outStr
}

type RadiotapFlags uint8

const (
        /* sent/received during CFP */
        RadiotapFlagsCFP	                RadiotapFlags = 1 << iota
        /* sent/received * with short * preamble */
	RadiotapFlagsShortPreamble
	/* sent/received * with WEP encryption */
        RadiotapFlagsWEP
        /* sent/received * with fragmentation */
	RadiotapFlagsFrag
        /* frame includes FCS */
	RadiotapFlagsFCS
	/* frame has padding between * 802.11 header and payload * (to 32-bit boundary) */
        RadiotapFlagsDatapad
	/* does not pass FCS check */
        RadiotapFlagsBadFCS
	/* HT short GI */
        RadiotapFlagsShortGI
)

func (a RadiotapFlags) String() string {
    outStr := ""
    if ((a & RadiotapFlagsCFP) == RadiotapFlagsCFP) {
        outStr += "CFP,"
    }
    if ((a & RadiotapFlagsShortPreamble) == RadiotapFlagsShortPreamble) {
        outStr += "SHORT-PREAMBLE,"
    }
    if ((a & RadiotapFlagsWEP) == RadiotapFlagsWEP) {
        outStr += "WEP,"
    }
    if ((a & RadiotapFlagsFrag) == RadiotapFlagsFrag) {
        outStr += "FRAG,"
    }
    if ((a & RadiotapFlagsFCS) == RadiotapFlagsFCS) {
        outStr += "FCS,"
    }
    if ((a & RadiotapFlagsDatapad) == RadiotapFlagsDatapad) {
        outStr += "DATAPAD,"
    }
    if ((a & RadiotapFlagsShortGI) == RadiotapFlagsShortGI) {
        outStr += "SHORT-GI,"
    }

    return outStr
}


type RadiotapRate uint8

func (a RadiotapRate) String() string {
    return fmt.Sprintf("%v Mb/s", 0.5 * float32(a))
}

type RadiotapChannelFrequency uint16

func (a RadiotapChannelFrequency) String() string {
    return fmt.Sprintf("%d MHz", a)
}

func decodeRadiotap(data []byte, p gopacket.PacketBuilder) error {
	d := &Radiotap{}
	return decodingLayerDecoder(d, data, p)
}

type Radiotap struct {
	BaseLayer

	// Version 0. Only increases for drastic changes, introduction of compatible new fields does not count.
	Version uint8
        // Length of the whole header in bytes, including it_version, it_pad, it_len, and data fields.
        Length uint16
	// Present is a bitmap telling which fields are present. Set bit 31 (0x80000000) to extend the bitmap by another 32 bits. Additional extensions are made by setting bit 31.
	Present RadiotapPresent
        // TSFT: value in microseconds of the MAC's 64-bit 802.11 Time Synchronization Function timer when the first bit of the MPDU arrived at the MAC. For received frames, only.  
	TSFT uint64
	Flags RadiotapFlags
        // Rate Tx/Rx data rate
	Rate RadiotapRate
        // ChannelFrequency Tx/Rx frequency in MHz, followed by flags 
	ChannelFrequency RadiotapChannelFrequency
	ChannelFlags RadiotapChannelFlags
	// FHSS For frequency-hopping radios, the hop set (first byte) and pattern (second byte).
        FHSS uint16
        // DbmAntennaSignal RF signal power at the antenna, decibel difference from one milliwatt.
	DbmAntennaSignal int8
        // DbmAntennaNoise RF noise power at the antenna, decibel difference from one milliwatt.
	DbmAntennaNoise int8
        // LockQuality Quality of Barker code lock. Unitless. Monotonically nondecreasing with "better" lock strength. Called "Signal Quality" in datasheets.  
	LockQuality uint16
        // TxAttenuation Transmit power expressed as unitless distance from max power set at factory calibration.  0 is max power. Monotonically nondecreasing with lower power levels.
	TxAttenuation uint16
        // DbTxAttenuation Transmit power expressed as decibel distance from max power set at factory calibration.  0 is max power.  Monotonically nondecreasing with lower power levels.
	DbTxAttenuation uint16
        // DbmTxPower Transmit power expressed as dBm (decibels from a 1 milliwatt reference). This is the absolute power level measured at the antenna port.
	DbmTxPower int8
        // Antenna Unitless indication of the Rx/Tx antenna for this packet. The first antenna is antenna 0.
	Antenna uint8
	// DbAntennaSignal RF signal power at the antenna, decibel difference from an arbitrary, fixed reference.
        DbAntennaSignal uint8
	// DbAntennaNoise RF noise power at the antenna, decibel difference from an arbitrary, fixed reference point.
	DbAntennaNoise uint8
}

func (m *Radiotap) LayerType() gopacket.LayerType { return LayerTypeRadiotap }

func (m *Radiotap) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	m.Version = (uint8)(data[0])
	m.Length = binary.LittleEndian.Uint16(data[2:4])
	m.Present = RadiotapPresent(binary.LittleEndian.Uint32(data[4:8]))

	offset := uint(4)

        for ((binary.LittleEndian.Uint32(data[offset:offset+4]) & 0x80000000) == 0x80000000 ) {
            // Extended bitmap. 
            offset+=4
	}

	m.BaseLayer = BaseLayer{Contents: data[:(m.Length)], Payload: data[(m.Length):]}

	if ((m.Present & RadiotapPresentTSFT)==RadiotapPresentTSFT) {
		offset+=align(offset, 8)
		m.TSFT=binary.LittleEndian.Uint64(data[offset:offset+8])
		offset+=8
	}

	if ((m.Present & RadiotapPresentFlags) == RadiotapPresentFlags) {
		m.Flags=(RadiotapFlags)(data[offset])
		offset++
	}

	if ((m.Present & RadiotapPresentRate) == RadiotapPresentRate) {
		m.Rate=(RadiotapRate)(data[offset])
		offset++
	}

	if ((m.Present & RadiotapPresentFHSS) == RadiotapPresentFHSS) {
		m.FHSS=binary.LittleEndian.Uint16(data[offset:offset+2])
		offset+=2
	}

	if ((m.Present & RadiotapPresentChannel) == RadiotapPresentChannel) {
		m.ChannelFrequency=RadiotapChannelFrequency(binary.LittleEndian.Uint16(data[offset:offset+2]))
		offset+=2
		m.ChannelFlags=(RadiotapChannelFlags)(data[offset])
		offset++
	}

	if ((m.Present & RadiotapPresentDbmAntennaSignal) == RadiotapPresentDbmAntennaSignal) {
		m.DbmAntennaSignal=(int8)(data[offset])
		offset++
	}


	if ((m.Present & RadiotapPresentDbmAntennaNoise) == RadiotapPresentDbmAntennaNoise) {
		m.DbmAntennaNoise=(int8)(data[offset])
		offset++
	}


	if ((m.Present & RadiotapPresentLockQuality) == RadiotapPresentLockQuality) {
		offset+=align(offset, 2)
		m.LockQuality=binary.LittleEndian.Uint16(data[offset:offset+2])
		offset+=2
	}


	if ((m.Present & RadiotapPresentTxAttenuation) == RadiotapPresentTxAttenuation) {
		offset+=align(offset, 2)
		m.TxAttenuation=binary.LittleEndian.Uint16(data[offset:offset+2])
		offset+=2
	}


	if ((m.Present & RadiotapPresentDbTxAttenuation) == RadiotapPresentDbTxAttenuation) {
		offset+=align(offset, 2)
		m.DbTxAttenuation=binary.LittleEndian.Uint16(data[offset:offset+2])
		offset+=2
	}


	if ((m.Present & RadiotapPresentDbmTxPower) == RadiotapPresentDbmTxPower) {
		m.DbmTxPower=(int8)(data[offset])
		offset++
	}


	if ((m.Present & RadiotapPresentAntenna) == RadiotapPresentAntenna) {
		m.Antenna=(uint8)(data[offset])
		offset++
	}


	if ((m.Present & RadiotapPresentDbAntennaSignal) == RadiotapPresentDbAntennaSignal) {
		m.DbAntennaSignal=(uint8)(data[offset])
		offset++
	}


	if ((m.Present & RadiotapPresentDbAntennaNoise) == RadiotapPresentDbAntennaNoise) {
		m.DbAntennaNoise=(uint8)(data[offset])
		offset++
	}


	if ((m.Present & RadiotapPresentEXT) == RadiotapPresentEXT) {
		offset+=align(offset, 4)
                // TODO: Implement EXT
		_ = data[offset:offset+4]
                offset+=4
	}


	if ((m.Flags & RadiotapFlagsDatapad) == RadiotapFlagsDatapad ) {
                // frame has padding between 802.11 header and payload (to 32-bit boundary)
		offset+=align(offset, 4)
	}

	return nil
}

func (m *Radiotap) CanDecode() gopacket.LayerClass { return LayerTypeRadiotap }
func (m *Radiotap) NextLayerType() gopacket.LayerType { return LayerTypeDot11 }
