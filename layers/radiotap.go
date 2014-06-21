// Copyright 2014 Google, Inc. All rights reserved.
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

// align calculates the number of bytes needed to align with the width
// on the offset, returning the number of bytes we need to skip to
// align to the offset (width).
func align(offset uint16, width uint16) uint16 {
	return ((((offset) + ((width) - 1)) & (^((width) - 1))) - offset)
}

type RadioTapPresent uint32

const (
	RadioTapPresentTSFT RadioTapPresent = 1 << iota
	RadioTapPresentFlags
	RadioTapPresentRate
	RadioTapPresentChannel
	RadioTapPresentFHSS
	RadioTapPresentDBMAntennaSignal
	RadioTapPresentDBMAntennaNoise
	RadioTapPresentLockQuality
	RadioTapPresentTxAttenuation
	RadioTapPresentDBTxAttenuation
	RadioTapPresentDBMTxPower
	RadioTapPresentAntenna
	RadioTapPresentDBAntennaSignal
	RadioTapPresentDBAntennaNoise
	RadioTapPresentRxFlags
	RadioTapPresentTxFlags
	RadioTapPresentRtsRetries
	RadioTapPresentDataRetries
	RadioTapPresentEXT RadioTapPresent = 1 << 31
)

type RadioTapChannelFlags uint16

const (
	RadioTapChannelFlagsTurbo   RadioTapChannelFlags = 0x0010 // Turbo channel
	RadioTapChannelFlagsCCK     RadioTapChannelFlags = 0x0020 // CCK channel
	RadioTapChannelFlagsOFDM    RadioTapChannelFlags = 0x0040 // OFDM channel
	RadioTapChannelFlags2Ghz    RadioTapChannelFlags = 0x0080 // 2 GHz spectrum channel.
	RadioTapChannelFlags5Ghz    RadioTapChannelFlags = 0x0100 // 5 GHz spectrum channel
	RadioTapChannelFlagsPassive RadioTapChannelFlags = 0x0200 // Only passive scan allowed
	RadioTapChannelFlagsDynamic RadioTapChannelFlags = 0x0400 // Dynamic CCK-OFDM channel
	RadioTapChannelFlagsGFSK    RadioTapChannelFlags = 0x0800 // GFSK channel (FHSS PHY)
)

func (a RadioTapChannelFlags) String() string {
	outStr := ""
	if (a & RadioTapChannelFlagsTurbo) != 0 {
		outStr += "Turbo,"
	}
	if (a & RadioTapChannelFlagsCCK) != 0 {
		outStr += "CCK,"
	}
	if (a & RadioTapChannelFlagsOFDM) != 0 {
		outStr += "OFDM,"
	}
	if (a & RadioTapChannelFlags2Ghz) != 0 {
		outStr += "2Ghz,"
	}
	if (a & RadioTapChannelFlags5Ghz) != 0 {
		outStr += "5Ghz,"
	}
	if (a & RadioTapChannelFlagsPassive) != 0 {
		outStr += "Passive,"
	}
	if (a & RadioTapChannelFlagsDynamic) != 0 {
		outStr += "Dynamic,"
	}
	if (a & RadioTapChannelFlagsGFSK) != 0 {
		outStr += "GFSK,"
	}

	return outStr
}

type RadioTapFlags uint8

const (
	RadioTapFlagsCFP           RadioTapFlags = 1 << iota // sent/received during CFP
	RadioTapFlagsShortPreamble                           // sent/received * with short * preamble
	RadioTapFlagsWEP                                     // sent/received * with WEP encryption
	RadioTapFlagsFrag                                    // sent/received * with fragmentation
	RadioTapFlagsFCS                                     // frame includes FCS
	RadioTapFlagsDatapad                                 // frame has padding between * 802.11 header and payload * (to 32-bit boundary)
	RadioTapFlagsBadFCS                                  // does not pass FCS check
	RadioTapFlagsShortGI                                 // HT short GI
)

func (a RadioTapFlags) String() string {
	outStr := ""
	if (a & RadioTapFlagsCFP) != 0 {
		outStr += "CFP,"
	}
	if (a & RadioTapFlagsShortPreamble) != 0 {
		outStr += "SHORT-PREAMBLE,"
	}
	if (a & RadioTapFlagsWEP) != 0 {
		outStr += "WEP,"
	}
	if (a & RadioTapFlagsFrag) != 0 {
		outStr += "FRAG,"
	}
	if (a & RadioTapFlagsFCS) != 0 {
		outStr += "FCS,"
	}
	if (a & RadioTapFlagsDatapad) != 0 {
		outStr += "DATAPAD,"
	}
	if (a & RadioTapFlagsShortGI) != 0 {
		outStr += "SHORT-GI,"
	}

	return outStr
}

type RadioTapRate uint8

func (a RadioTapRate) String() string {
	return fmt.Sprintf("%v Mb/s", 0.5*float32(a))
}

type RadioTapChannelFrequency uint16

func (a RadioTapChannelFrequency) String() string {
	return fmt.Sprintf("%d MHz", a)
}

func decodeRadioTap(data []byte, p gopacket.PacketBuilder) error {
	d := &RadioTap{}
        // TODO: Should we set LinkLayer here? And implement LinkFlow
	return decodingLayerDecoder(d, data, p)
}

type RadioTap struct {
	BaseLayer

	// Version 0. Only increases for drastic changes, introduction of compatible new fields does not count.
	Version uint8
	// Length of the whole header in bytes, including it_version, it_pad, it_len, and data fields.
	Length uint16
	// Present is a bitmap telling which fields are present. Set bit 31 (0x80000000) to extend the bitmap by another 32 bits. Additional extensions are made by setting bit 31.
	Present RadioTapPresent
	// TSFT: value in microseconds of the MAC's 64-bit 802.11 Time Synchronization Function timer when the first bit of the MPDU arrived at the MAC. For received frames, only.
	TSFT  uint64
	Flags RadioTapFlags
	// Rate Tx/Rx data rate
	Rate RadioTapRate
	// ChannelFrequency Tx/Rx frequency in MHz, followed by flags
	ChannelFrequency RadioTapChannelFrequency
	ChannelFlags     RadioTapChannelFlags
	// FHSS For frequency-hopping radios, the hop set (first byte) and pattern (second byte).
	FHSS uint16
	// DBMAntennaSignal RF signal power at the antenna, decibel difference from one milliwatt.
	DBMAntennaSignal int8
	// DBMAntennaNoise RF noise power at the antenna, decibel difference from one milliwatt.
	DBMAntennaNoise int8
	// LockQuality Quality of Barker code lock. Unitless. Monotonically nondecreasing with "better" lock strength. Called "Signal Quality" in datasheets.
	LockQuality uint16
	// TxAttenuation Transmit power expressed as unitless distance from max power set at factory calibration.  0 is max power. Monotonically nondecreasing with lower power levels.
	TxAttenuation uint16
	// DBTxAttenuation Transmit power expressed as decibel distance from max power set at factory calibration.  0 is max power.  Monotonically nondecreasing with lower power levels.
	DBTxAttenuation uint16
	// DBMTxPower Transmit power expressed as dBm (decibels from a 1 milliwatt reference). This is the absolute power level measured at the antenna port.
	DBMTxPower int8
	// Antenna Unitless indication of the Rx/Tx antenna for this packet. The first antenna is antenna 0.
	Antenna uint8
	// DBAntennaSignal RF signal power at the antenna, decibel difference from an arbitrary, fixed reference.
	DBAntennaSignal uint8
	// DBAntennaNoise RF noise power at the antenna, decibel difference from an arbitrary, fixed reference point.
	DBAntennaNoise uint8
}

func (m *RadioTap) LayerType() gopacket.LayerType { return LayerTypeRadioTap }

func (m *RadioTap) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	m.Version = uint8(data[0])
	m.Length = binary.LittleEndian.Uint16(data[2:4])
	m.Present = RadioTapPresent(binary.LittleEndian.Uint32(data[4:8]))

	offset := uint16(4)

	for (binary.LittleEndian.Uint32(data[offset:offset+4]) & 0x80000000) != 0 {
		// Extended bitmap.
		offset += 4
	}

	if (m.Present & RadioTapPresentTSFT) != 0 {
		offset += align(offset, 8)
		m.TSFT = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}
	if (m.Present & RadioTapPresentFlags) != 0 {
		m.Flags = RadioTapFlags(data[offset])
		offset++
	}
	if (m.Present & RadioTapPresentRate) != 0 {
		m.Rate = RadioTapRate(data[offset])
		offset++
	}
	if (m.Present & RadioTapPresentFHSS) != 0 {
		m.FHSS = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if (m.Present & RadioTapPresentChannel) != 0 {
		m.ChannelFrequency = RadioTapChannelFrequency(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		m.ChannelFlags = RadioTapChannelFlags(data[offset])
		offset++
	}
	if (m.Present & RadioTapPresentDBMAntennaSignal) != 0 {
		m.DBMAntennaSignal = int8(data[offset])
		offset++
	}
	if (m.Present & RadioTapPresentDBMAntennaNoise) != 0 {
		m.DBMAntennaNoise = int8(data[offset])
		offset++
	}
	if (m.Present & RadioTapPresentLockQuality) != 0 {
		offset += align(offset, 2)
		m.LockQuality = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if (m.Present & RadioTapPresentTxAttenuation) != 0 {
		offset += align(offset, 2)
		m.TxAttenuation = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if (m.Present & RadioTapPresentDBTxAttenuation) != 0 {
		offset += align(offset, 2)
		m.DBTxAttenuation = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if (m.Present & RadioTapPresentDBMTxPower) != 0 {
		m.DBMTxPower = int8(data[offset])
		offset++
	}
	if (m.Present & RadioTapPresentAntenna) != 0 {
		m.Antenna = uint8(data[offset])
		offset++
	}
	if (m.Present & RadioTapPresentDBAntennaSignal) != 0 {
		m.DBAntennaSignal = uint8(data[offset])
		offset++
	}
	if (m.Present & RadioTapPresentDBAntennaNoise) != 0 {
		m.DBAntennaNoise = uint8(data[offset])
		offset++
	}
	if (m.Present & RadioTapPresentRxFlags) != 0 {
		// TODO: Implement RxFlags
	}
	if (m.Present & RadioTapPresentTxFlags) != 0 {
		// TODO: Implement TxFlags
	}
	if (m.Present & RadioTapPresentRtsRetries) != 0 {
		// TODO: Implement RtsRetries
	}
	if (m.Present & RadioTapPresentDataRetries) != 0 {
		// TODO: Implement DataRetries
	}
	if (m.Present & RadioTapPresentEXT) != 0 {
		offset += align(offset, 4)
		// TODO: Implement EXT
		_ = data[offset : offset+4]
		offset += 4
	}

	if (m.Flags & RadioTapFlagsDatapad) != 0 {
		// frame has padding between 802.11 header and payload (to 32-bit boundary)
		offset += align(offset, 4)
	}

	m.BaseLayer = BaseLayer{Contents: data[:m.Length], Payload: data[m.Length:]}

	return nil
}

func (m *RadioTap) CanDecode() gopacket.LayerClass    { return LayerTypeRadioTap }
func (m *RadioTap) NextLayerType() gopacket.LayerType { return LayerTypeDot11 }
