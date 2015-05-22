// Copyright 2014 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"hash/crc32"
	"strings"
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
	_
	RadioTapPresentMcs
	RadioTapPresentAmpduStatus
	RadioTapPresentVht
	RadioTapPresentEXT RadioTapPresent = 1 << 31
)

func (r RadioTapPresent) TSFT() bool {
	return r&RadioTapPresentTSFT != 0
}
func (r RadioTapPresent) Flags() bool {
	return r&RadioTapPresentFlags != 0
}
func (r RadioTapPresent) Rate() bool {
	return r&RadioTapPresentRate != 0
}
func (r RadioTapPresent) Channel() bool {
	return r&RadioTapPresentChannel != 0
}
func (r RadioTapPresent) FHSS() bool {
	return r&RadioTapPresentFHSS != 0
}
func (r RadioTapPresent) DBMAntennaSignal() bool {
	return r&RadioTapPresentDBMAntennaSignal != 0
}
func (r RadioTapPresent) DBMAntennaNoise() bool {
	return r&RadioTapPresentDBMAntennaNoise != 0
}
func (r RadioTapPresent) LockQuality() bool {
	return r&RadioTapPresentLockQuality != 0
}
func (r RadioTapPresent) TxAttenuation() bool {
	return r&RadioTapPresentTxAttenuation != 0
}
func (r RadioTapPresent) DBTxAttenuation() bool {
	return r&RadioTapPresentDBTxAttenuation != 0
}
func (r RadioTapPresent) DBMTxPower() bool {
	return r&RadioTapPresentDBMTxPower != 0
}
func (r RadioTapPresent) Antenna() bool {
	return r&RadioTapPresentAntenna != 0
}
func (r RadioTapPresent) DBAntennaSignal() bool {
	return r&RadioTapPresentDBAntennaSignal != 0
}
func (r RadioTapPresent) DBAntennaNoise() bool {
	return r&RadioTapPresentDBAntennaNoise != 0
}
func (r RadioTapPresent) RxFlags() bool {
	return r&RadioTapPresentRxFlags != 0
}
func (r RadioTapPresent) TxFlags() bool {
	return r&RadioTapPresentTxFlags != 0
}
func (r RadioTapPresent) RtsRetries() bool {
	return r&RadioTapPresentRtsRetries != 0
}
func (r RadioTapPresent) DataRetries() bool {
	return r&RadioTapPresentDataRetries != 0
}
func (r RadioTapPresent) Mcs() bool {
	return r&RadioTapPresentMcs != 0
}
func (r RadioTapPresent) AmpduStatus() bool {
	return r&RadioTapPresentAmpduStatus != 0
}
func (r RadioTapPresent) Vht() bool {
	return r&RadioTapPresentVht != 0
}
func (r RadioTapPresent) EXT() bool {
	return r&RadioTapPresentEXT != 0
}

type RadioTapChannelFlags uint16

const (
	RadioTapChannelFlagsTurbo   RadioTapChannelFlags = 0x0010 // Turbo channel
	RadioTapChannelFlagsCCK     RadioTapChannelFlags = 0x0020 // CCK channel
	RadioTapChannelFlagsOFDM    RadioTapChannelFlags = 0x0040 // OFDM channel
	RadioTapChannelFlagsGhz2    RadioTapChannelFlags = 0x0080 // 2 GHz spectrum channel.
	RadioTapChannelFlagsGhz5    RadioTapChannelFlags = 0x0100 // 5 GHz spectrum channel
	RadioTapChannelFlagsPassive RadioTapChannelFlags = 0x0200 // Only passive scan allowed
	RadioTapChannelFlagsDynamic RadioTapChannelFlags = 0x0400 // Dynamic CCK-OFDM channel
	RadioTapChannelFlagsGFSK    RadioTapChannelFlags = 0x0800 // GFSK channel (FHSS PHY)
)

func (r RadioTapChannelFlags) Turbo() bool {
	return r&RadioTapChannelFlagsTurbo != 0
}
func (r RadioTapChannelFlags) CCK() bool {
	return r&RadioTapChannelFlagsCCK != 0
}
func (r RadioTapChannelFlags) OFDM() bool {
	return r&RadioTapChannelFlagsOFDM != 0
}
func (r RadioTapChannelFlags) Ghz2() bool {
	return r&RadioTapChannelFlagsGhz2 != 0
}
func (r RadioTapChannelFlags) Ghz5() bool {
	return r&RadioTapChannelFlagsGhz5 != 0
}
func (r RadioTapChannelFlags) Passive() bool {
	return r&RadioTapChannelFlagsPassive != 0
}
func (r RadioTapChannelFlags) Dynamic() bool {
	return r&RadioTapChannelFlagsDynamic != 0
}
func (r RadioTapChannelFlags) GFSK() bool {
	return r&RadioTapChannelFlagsGFSK != 0
}

// String provides a human readable string for RadioTapChannelFlags.
// This string is possibly subject to change over time; if you're storing this
// persistently, you should probably store the RadioTapChannelFlags value, not its string.
func (a RadioTapChannelFlags) String() string {
	var out bytes.Buffer
	if a.Turbo() {
		out.WriteString("Turbo,")
	}
	if a.CCK() {
		out.WriteString("CCK,")
	}
	if a.OFDM() {
		out.WriteString("OFDM,")
	}
	if a.Ghz2() {
		out.WriteString("Ghz2,")
	}
	if a.Ghz5() {
		out.WriteString("Ghz5,")
	}
	if a.Passive() {
		out.WriteString("Passive,")
	}
	if a.Dynamic() {
		out.WriteString("Dynamic,")
	}
	if a.GFSK() {
		out.WriteString("GFSK,")
	}

	if length := out.Len(); length > 0 {
		return string(out.Bytes()[:length-1]) // strip final comma
	}
	return ""
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

func (r RadioTapFlags) CFP() bool {
	return r&RadioTapFlagsCFP != 0
}
func (r RadioTapFlags) ShortPreamble() bool {
	return r&RadioTapFlagsShortPreamble != 0
}
func (r RadioTapFlags) WEP() bool {
	return r&RadioTapFlagsWEP != 0
}
func (r RadioTapFlags) Frag() bool {
	return r&RadioTapFlagsFrag != 0
}
func (r RadioTapFlags) FCS() bool {
	return r&RadioTapFlagsFCS != 0
}
func (r RadioTapFlags) Datapad() bool {
	return r&RadioTapFlagsDatapad != 0
}
func (r RadioTapFlags) BadFCS() bool {
	return r&RadioTapFlagsBadFCS != 0
}
func (r RadioTapFlags) ShortGI() bool {
	return r&RadioTapFlagsShortGI != 0
}

// String provides a human readable string for RadioTapFlags.
// This string is possibly subject to change over time; if you're storing this
// persistently, you should probably store the RadioTapFlags value, not its string.
func (a RadioTapFlags) String() string {
	var out bytes.Buffer
	if a.CFP() {
		out.WriteString("CFP,")
	}
	if a.ShortPreamble() {
		out.WriteString("SHORT-PREAMBLE,")
	}
	if a.WEP() {
		out.WriteString("WEP,")
	}
	if a.Frag() {
		out.WriteString("FRAG,")
	}
	if a.FCS() {
		out.WriteString("FCS,")
	}
	if a.Datapad() {
		out.WriteString("DATAPAD,")
	}
	if a.ShortGI() {
		out.WriteString("SHORT-GI,")
	}

	if length := out.Len(); length > 0 {
		return string(out.Bytes()[:length-1]) // strip final comma
	}
	return ""
}

type RadioTapRate uint8

func (a RadioTapRate) String() string {
	return fmt.Sprintf("%v Mb/s", 0.5*float32(a))
}

type RadioTapChannelFrequency uint16

func (a RadioTapChannelFrequency) String() string {
	return fmt.Sprintf("%d MHz", a)
}

type RadioTapRxFlags uint16

const (
	RadioTapRxFlagsBadPlcp RadioTapRxFlags = 0x0002
)

func (self RadioTapRxFlags) BadPlcp() bool {
	return self&RadioTapRxFlagsBadPlcp != 0
}

func (self RadioTapRxFlags) String() string {
	if self.BadPlcp() {
		return "BADPLCP"
	}
	return ""
}

type RadioTapTxFlags uint16

const (
	RadioTapTxFlagsFail RadioTapTxFlags = 1 << iota
	RadioTapTxFlagsCts
	RadioTapTxFlagsRts
	RadioTapTxFlagsNoack
)

func (self RadioTapTxFlags) Fail() bool  { return self&RadioTapTxFlagsFail != 0 }
func (self RadioTapTxFlags) Cts() bool   { return self&RadioTapTxFlagsCts != 0 }
func (self RadioTapTxFlags) Rts() bool   { return self&RadioTapTxFlagsRts != 0 }
func (self RadioTapTxFlags) Noack() bool { return self&RadioTapTxFlagsNoack != 0 }

func (self RadioTapTxFlags) String() string {
	var tokens []string
	if self.Fail() {
		tokens = append(tokens, "Fail")
	}
	if self.Cts() {
		tokens = append(tokens, "Cts")
	}
	if self.Rts() {
		tokens = append(tokens, "Rts")
	}
	if self.Noack() {
		tokens = append(tokens, "Noack")
	}
	return strings.Join(tokens, ",")
}

type RadioTapMcs struct {
	Known RadioTapMcsKnown
	Flags RadioTapMcsFlags
	Mcs   uint8
}

func (self RadioTapMcs) String() string {
	var tokens []string
	if self.Known.Bandwidth() {
		tokens = append(tokens, []string{
			"20", "40", "40(20L)", "40(20U)",
		}[self.Flags.Bandwidth()])
	}
	if self.Known.McsIndex() {
		tokens = append(tokens, fmt.Sprintf("mcsIndex#%d", self.Mcs))
	}
	if self.Known.GuardInterval() {
		if self.Flags.ShortGI() {
			tokens = append(tokens, fmt.Sprintf("shortGI"))
		} else {
			tokens = append(tokens, fmt.Sprintf("longGI"))
		}
	}
	if self.Known.HtFormat() {
		if self.Flags.Greenfield() {
			tokens = append(tokens, fmt.Sprintf("HT-greenfield"))
		} else {
			tokens = append(tokens, fmt.Sprintf("HT-mixed"))
		}
	}
	if self.Known.FecType() {
		if self.Flags.FecLdpc() {
			tokens = append(tokens, fmt.Sprintf("LDPC"))
		} else {
			tokens = append(tokens, fmt.Sprintf("BCC"))
		}
	}
	if self.Known.Stbc() {
		tokens = append(tokens, fmt.Sprintf("STBC#%d", self.Flags.Stbc()))
	}
	if self.Known.Ness() {
		num := 0
		if self.Known.Ness1() {
			num |= 0x02
		}
		if self.Flags.Ness0() {
			num |= 0x01
		}
		tokens = append(tokens, fmt.Sprintf("num-of-ESS#%d", num))
	}
	return strings.Join(tokens, ",")
}

type RadioTapMcsKnown uint8

const (
	RadioTapMcsKnownBandwidth RadioTapMcsKnown = 1 << iota
	RadioTapMcsKnownMcsIndex
	RadioTapMcsKnownGuardInterval
	RadioTapMcsKnownHtFormat
	RadioTapMcsKnownFecType
	RadioTapMcsKnownStbc
	RadioTapMcsKnownNess
	RadioTapMcsKnownNess1
)

func (self RadioTapMcsKnown) Bandwidth() bool     { return self&RadioTapMcsKnownBandwidth != 0 }
func (self RadioTapMcsKnown) McsIndex() bool      { return self&RadioTapMcsKnownMcsIndex != 0 }
func (self RadioTapMcsKnown) GuardInterval() bool { return self&RadioTapMcsKnownGuardInterval != 0 }
func (self RadioTapMcsKnown) HtFormat() bool      { return self&RadioTapMcsKnownHtFormat != 0 }
func (self RadioTapMcsKnown) FecType() bool       { return self&RadioTapMcsKnownFecType != 0 }
func (self RadioTapMcsKnown) Stbc() bool          { return self&RadioTapMcsKnownStbc != 0 }
func (self RadioTapMcsKnown) Ness() bool          { return self&RadioTapMcsKnownNess != 0 }
func (self RadioTapMcsKnown) Ness1() bool         { return self&RadioTapMcsKnownNess1 != 0 }

type RadioTapMcsFlags uint8

const (
	RadioTapMcsFlagsBandwidthMask RadioTapMcsFlags = 0x03
	RadioTapMcsFlagsShortGI                        = 0x04
	RadioTapMcsFlagsGreenfield                     = 0x08
	RadioTapMcsFlagsFecLdpc                        = 0x10
	RadioTapMcsFlagsStbcMask                       = 0x60
	RadioTapMcsFlagsNess0                          = 0x80
)

func (self RadioTapMcsFlags) Bandwidth() int {
	return int(self & RadioTapMcsFlagsBandwidthMask)
}
func (self RadioTapMcsFlags) ShortGI() bool    { return self&RadioTapMcsFlagsShortGI != 0 }
func (self RadioTapMcsFlags) Greenfield() bool { return self&RadioTapMcsFlagsGreenfield != 0 }
func (self RadioTapMcsFlags) FecLdpc() bool    { return self&RadioTapMcsFlagsFecLdpc != 0 }
func (self RadioTapMcsFlags) Stbc() int {
	return int(self&RadioTapMcsFlagsStbcMask) >> 5
}
func (self RadioTapMcsFlags) Ness0() bool { return self&RadioTapMcsFlagsNess0 != 0 }

type RadioTapAmpduStatus struct {
	Reference uint32
	Flags     RadioTapAmpduStatusFlags
	Crc       uint8
}

func (self RadioTapAmpduStatus) String() string {
	tokens := []string{
		fmt.Sprintf("ref#%x", self.Reference),
	}
	if self.Flags.ReportZerolen() && self.Flags.IsZerolen() {
		tokens = append(tokens, fmt.Sprintf("zero-length"))
	}
	if self.Flags.LastKnown() && self.Flags.IsLast() {
		tokens = append(tokens, "last")
	}
	if self.Flags.DelimCrcErr() {
		tokens = append(tokens, "delimiter CRC error")
	}
	if self.Flags.DelimCrcKnown() {
		tokens = append(tokens, fmt.Sprintf("delimiter-CRC=%02x", self.Crc))
	}
	return strings.Join(tokens, ",")
}

type RadioTapAmpduStatusFlags uint16

const (
	RadioTapAmpduStatusFlagsReportZerolen RadioTapAmpduStatusFlags = 1 << iota
	RadioTapAmpduIsZerolen
	RadioTapAmpduLastKnown
	RadioTapAmpduIsLast
	RadioTapAmpduDelimCrcErr
	RadioTapAmpduDelimCrcKnown
)

func (self RadioTapAmpduStatusFlags) ReportZerolen() bool {
	return self&RadioTapAmpduStatusFlagsReportZerolen != 0
}
func (self RadioTapAmpduStatusFlags) IsZerolen() bool     { return self&RadioTapAmpduIsZerolen != 0 }
func (self RadioTapAmpduStatusFlags) LastKnown() bool     { return self&RadioTapAmpduLastKnown != 0 }
func (self RadioTapAmpduStatusFlags) IsLast() bool        { return self&RadioTapAmpduIsLast != 0 }
func (self RadioTapAmpduStatusFlags) DelimCrcErr() bool   { return self&RadioTapAmpduDelimCrcErr != 0 }
func (self RadioTapAmpduStatusFlags) DelimCrcKnown() bool { return self&RadioTapAmpduDelimCrcKnown != 0 }

type RadioTapVht struct {
	Known      RadioTapVhtKnown
	Flags      RadioTapVhtFlags
	Bandwidth  uint8
	McsNss     [4]RadioTapVhtMcsNss
	Coding     uint8
	GroupId    uint8
	PartialAid uint16
}

func (self RadioTapVht) String() string {
	var tokens []string
	if self.Known.Stbc() {
		if self.Flags.Stbc() {
			tokens = append(tokens, "STBC")
		} else {
			tokens = append(tokens, "no STBC")
		}
	}
	if self.Known.TxopPsNa() {
		if self.Flags.TxopPsNa() {
			tokens = append(tokens, "TXOP doze not allowed")
		} else {
			tokens = append(tokens, "TXOP doze allowed")
		}
	}
	if self.Known.Gi() {
		if self.Flags.Sgi() {
			tokens = append(tokens, "short GI")
		} else {
			tokens = append(tokens, "long GI")
		}
	}
	if self.Known.SgiNsymDis() {
		if self.Flags.SgiNsymMod() {
			tokens = append(tokens, "NSYM mod 10=9")
		} else {
			tokens = append(tokens, "NSYM mod 10!=9 or no short GI")
		}
	}
	if self.Known.LdpcExtraOfdmSym() {
		if self.Flags.LdpcExtraOfdmSym() {
			tokens = append(tokens, "LDPC extra OFDM symbols")
		} else {
			tokens = append(tokens, "no LDPC extra OFDM symbols")
		}
	}
	if self.Known.Beamformed() {
		if self.Flags.Beamformed() {
			tokens = append(tokens, "beamformed")
		} else {
			tokens = append(tokens, "no beamformed")
		}
	}
	if self.Known.Bandwidth() {
		tokens = append(tokens, []string{
			"20",
			"40", "40(20L)", "40(20U)",
			"80", "80(40L)", "80(40U)",
			"80(20LL)", "80(20LU)", "80(20UL)", "80(20UU)",
			"160", "160(80L)", "160(80U)",
			"160(40LL)", "160(40LU)", "160(40UL)", "160(40UU)",
			"160(20LLL)", "160(20LLU)", "160(20LUL)", "160(20LUU)",
			"160(20ULL)", "160(20ULU)", "160(20UUL)", "160(20UUU)",
		}[self.Bandwidth&0x1f])
	}
	for i, mcsNss := range self.McsNss {
		if mcsNss.Present() {
			tokens = append(tokens, fmt.Sprintf("user%d(%s,%s)",
				i, mcsNss.String(), []string{"BCC", "LDPC"}[self.Coding&(1<<uint8(i))]))
		}
	}
	if self.Known.GroupId() {
		tokens = append(tokens,
			fmt.Sprintf("group=%d", self.GroupId))
	}
	if self.Known.PartialAid() {
		tokens = append(tokens,
			fmt.Sprintf("partial-AID=%d", self.PartialAid))
	}
	return strings.Join(tokens, ",")
}

type RadioTapVhtKnown uint16

const (
	RadioTapVhtKnownStbc RadioTapVhtKnown = 1 << iota
	RadioTapVhtKnownTxopPsNa
	RadioTapVhtKnownGi
	RadioTapVhtKnownSgiNsymDis
	RadioTapVhtKnownLdpcExtraOfdmSym
	RadioTapVhtKnownBeamformed
	RadioTapVhtKnownBandwidth
	RadioTapVhtKnownGroupId
	RadioTapVhtKnownPartialAid
)

func (self RadioTapVhtKnown) Stbc() bool       { return self&RadioTapVhtKnownStbc != 0 }
func (self RadioTapVhtKnown) TxopPsNa() bool   { return self&RadioTapVhtKnownTxopPsNa != 0 }
func (self RadioTapVhtKnown) Gi() bool         { return self&RadioTapVhtKnownGi != 0 }
func (self RadioTapVhtKnown) SgiNsymDis() bool { return self&RadioTapVhtKnownSgiNsymDis != 0 }
func (self RadioTapVhtKnown) LdpcExtraOfdmSym() bool {
	return self&RadioTapVhtKnownLdpcExtraOfdmSym != 0
}
func (self RadioTapVhtKnown) Beamformed() bool { return self&RadioTapVhtKnownBeamformed != 0 }
func (self RadioTapVhtKnown) Bandwidth() bool  { return self&RadioTapVhtKnownBandwidth != 0 }
func (self RadioTapVhtKnown) GroupId() bool    { return self&RadioTapVhtKnownGroupId != 0 }
func (self RadioTapVhtKnown) PartialAid() bool { return self&RadioTapVhtKnownPartialAid != 0 }

type RadioTapVhtFlags uint8

const (
	RadioTapVhtFlagsStbc RadioTapVhtFlags = 1 << iota
	RadioTapVhtFlagsTxopPsNa
	RadioTapVhtFlagsSgi
	RadioTapVhtFlagsSgiNsymMod
	RadioTapVhtFlagsLdpcExtraOfdmSym
	RadioTapVhtFlagsBeamformed
)

func (self RadioTapVhtFlags) Stbc() bool       { return self&RadioTapVhtFlagsStbc != 0 }
func (self RadioTapVhtFlags) TxopPsNa() bool   { return self&RadioTapVhtFlagsTxopPsNa != 0 }
func (self RadioTapVhtFlags) Sgi() bool        { return self&RadioTapVhtFlagsSgi != 0 }
func (self RadioTapVhtFlags) SgiNsymMod() bool { return self&RadioTapVhtFlagsSgiNsymMod != 0 }
func (self RadioTapVhtFlags) LdpcExtraOfdmSym() bool {
	return self&RadioTapVhtFlagsLdpcExtraOfdmSym != 0
}
func (self RadioTapVhtFlags) Beamformed() bool { return self&RadioTapVhtFlagsBeamformed != 0 }

type RadioTapVhtMcsNss uint8

func (self RadioTapVhtMcsNss) Present() bool {
	return self&0x0F != 0
}

func (self RadioTapVhtMcsNss) String() string {
	return fmt.Sprintf("NSS#%dMCS#%d", uint32(self&0xf), uint32(self>>4))
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
	//
	RxFlags     RadioTapRxFlags
	TxFlags     RadioTapTxFlags
	RtsRetries  uint8
	DataRetries uint8
	Mcs         RadioTapMcs
	AmpduStatus RadioTapAmpduStatus
	Vht         RadioTapVht
}

func (m *RadioTap) LayerType() gopacket.LayerType { return LayerTypeRadioTap }

func (m *RadioTap) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	m.Version = uint8(data[0])
	m.Length = binary.LittleEndian.Uint16(data[2:4])
	m.Present = RadioTapPresent(binary.LittleEndian.Uint32(data[4:8]))

	offset := uint16(4)

	for (binary.LittleEndian.Uint32(data[offset:offset+4]) & 0x80000000) != 0 {
		// This parser only handles standard radiotap namespace,
		// and expects all fields are packed in the first it_present.
		// Extended bitmap will be just ignored.
		offset += 4
	}
	offset += 4 // skip the bitmap

	if m.Present.TSFT() {
		offset += align(offset, 8)
		m.TSFT = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}
	if m.Present.Flags() {
		m.Flags = RadioTapFlags(data[offset])
		offset++
	}
	if m.Present.Rate() {
		m.Rate = RadioTapRate(data[offset])
		offset++
	}
	if m.Present.Channel() {
		offset += align(offset, 2)
		m.ChannelFrequency = RadioTapChannelFrequency(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		m.ChannelFlags = RadioTapChannelFlags(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
	}
	if m.Present.FHSS() {
		m.FHSS = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if m.Present.DBMAntennaSignal() {
		m.DBMAntennaSignal = int8(data[offset])
		offset++
	}
	if m.Present.DBMAntennaNoise() {
		m.DBMAntennaNoise = int8(data[offset])
		offset++
	}
	if m.Present.LockQuality() {
		offset += align(offset, 2)
		m.LockQuality = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if m.Present.TxAttenuation() {
		offset += align(offset, 2)
		m.TxAttenuation = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if m.Present.DBTxAttenuation() {
		offset += align(offset, 2)
		m.DBTxAttenuation = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if m.Present.DBMTxPower() {
		m.DBMTxPower = int8(data[offset])
		offset++
	}
	if m.Present.Antenna() {
		m.Antenna = uint8(data[offset])
		offset++
	}
	if m.Present.DBAntennaSignal() {
		m.DBAntennaSignal = uint8(data[offset])
		offset++
	}
	if m.Present.DBAntennaNoise() {
		m.DBAntennaNoise = uint8(data[offset])
		offset++
	}
	if m.Present.RxFlags() {
		offset += align(offset, 2)
		m.RxFlags = RadioTapRxFlags(binary.LittleEndian.Uint16(data[offset:]))
		offset += 2
	}
	if m.Present.TxFlags() {
		offset += align(offset, 2)
		m.TxFlags = RadioTapTxFlags(binary.LittleEndian.Uint16(data[offset:]))
		offset += 2
	}
	if m.Present.RtsRetries() {
		m.RtsRetries = uint8(data[offset])
		offset++
	}
	if m.Present.DataRetries() {
		m.DataRetries = uint8(data[offset])
		offset++
	}
	if m.Present.Mcs() {
		m.Mcs = RadioTapMcs{
			RadioTapMcsKnown(data[offset]),
			RadioTapMcsFlags(data[offset+1]),
			uint8(data[offset+2]),
		}
		offset += 3
	}
	if m.Present.AmpduStatus() {
		offset += align(offset, 4)
		m.AmpduStatus = RadioTapAmpduStatus{
			Reference: binary.LittleEndian.Uint32(data[offset:]),
			Flags:     RadioTapAmpduStatusFlags(binary.LittleEndian.Uint16(data[offset+4:])),
			Crc:       uint8(data[offset+6]),
		}
		offset += 8
	}
	if m.Present.Vht() {
		offset += align(offset, 2)
		m.Vht = RadioTapVht{
			Known:     RadioTapVhtKnown(binary.LittleEndian.Uint16(data[offset:])),
			Flags:     RadioTapVhtFlags(data[offset+2]),
			Bandwidth: uint8(data[offset+3]),
			McsNss: [4]RadioTapVhtMcsNss{
				RadioTapVhtMcsNss(data[offset+4]),
				RadioTapVhtMcsNss(data[offset+5]),
				RadioTapVhtMcsNss(data[offset+6]),
				RadioTapVhtMcsNss(data[offset+7]),
			},
			Coding:     uint8(data[offset+8]),
			GroupId:    uint8(data[offset+9]),
			PartialAid: binary.LittleEndian.Uint16(data[offset+10:]),
		}
		offset += 12
	}

	payload := data[m.Length:]
	if !m.Flags.FCS() { // Dot11.DecodeFromBytes() expects FCS present
		fcs := make([]byte, 4)
		h := crc32.NewIEEE()
		h.Write(payload)
		binary.LittleEndian.PutUint32(fcs, h.Sum32())
		payload = append(payload, fcs...)
	}
	m.BaseLayer = BaseLayer{Contents: data[:m.Length], Payload: payload}

	return nil
}

func (m *RadioTap) CanDecode() gopacket.LayerClass    { return LayerTypeRadioTap }
func (m *RadioTap) NextLayerType() gopacket.LayerType { return LayerTypeDot11 }
