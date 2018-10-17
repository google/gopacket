// Copyright 2018 The GoPacket Authors. All rights reserved.

/*
Package pcapnggo provides native PCAPNG support, not requiring C libpcap to be installed.

Basic Usage

Pcapng files can be read and written. Reading supports both big and little endian files, packet blocks,
simple packet blocks, enhanced packets blocks, interface blocks, and interface statistics blocks. All
the options also by Wireshark are supported. The default reader options match libpcap behaviour. Have
a look at ReaderOptions for more advanced usage. Both ReadPacketData and ZeroCopyReadPacketData is
supported (which means PacketDataSource and ZeroCopyPacketDataSource is supported).

		f, err := os.Open("somefile.pcapng")
		if err != nil {
			...
		}
		defer f.Close()

		r, err := NewReader(f, DefaultReaderOptions)
		if err != nil {
			...
		}

		data, ci, err := r.ReadPacketData()
		...

Write supports only little endian, enhanced packets blocks, interface blocks, and interface statistics
blocks. The same options as with writing are supported. Interface timestamp resolution is fixed to
10^-9s to match time.Time. Any other values are ignored. Upon creating a writer, a section, and an
interface block is automatically written. Additional interfaces can be added at any time. Since
the writer uses a bufio.Writer internally, Flush must be called before closing the file! Have a look
at NewWriterInterface for more advanced usage.

		f, err := os.Create("somefile.pcapng")
		if err != nil {
			...
		}
		defer f.Close()

		r, err = NewWriter(f, layers.LinkTypeEthernet)
		if err != nil {
			...
		}
		defer r.Flush()

		err = r.WritePacket(ci, data)
		...

*/
package pcapnggo

import (
	"errors"
	"math"
	"time"

	"github.com/google/gopacket/layers"
)

// ErrVersionMismatch gets returned for unknown pcapng section versions. This can only happen if ReaderOptions.SkipUnknownVersion == false
var ErrVersionMismatch = errors.New("Unknown pcapng Version in Section Header")

// ErrLinkTypeMismatch gets returned if the link type of an interface is not the same as the link type from the first interface. This can only happen if ReaderOptions.ErrorOnMismatchingLinkType == true && ReaderOptions.WantMixedLinkType == false
var ErrLinkTypeMismatch = errors.New("Link type of current interface is different from first one")

const (
	byteOrderMagic = 0x1A2B3C4D

	// We can handle only version 1.0
	versionMajor = 1
	versionMinor = 0
)

type blockType uint32

const (
	blockTypeInterfaceDescriptor blockType = 1          // Interface description block
	blockTypePacket              blockType = 2          // Packet block (deprecated)
	blockTypeSimplePacket        blockType = 3          // Simple packet block
	blockTypeInterfaceStatistics blockType = 5          // Interface statistics block
	blockTypeEnhancedPacket      blockType = 6          // Enhanced packet block
	blockTypeSectionHeader       blockType = 0x0A0D0D0A // Section header block (same in both endians)
)

type optionCode uint16

const (
	optionEndOfOptions    optionCode = iota // end of options. must be at the end of options in a block
	optionComment                           // comment
	optionHardware                          // description of the hardware
	optionOS                                // name of the operating system
	optionUserApplication                   // name of the application
)

const (
	optionInterfaceName                optionCode = iota + 2 // interface name
	optionInterfaceDescription                               // interface description
	optionInterfaceIPV4Address                               // IPv4 network address and netmask for the interface
	optionInterfaceIPV6Address                               // IPv6 network address and prefix length for the interface
	optionInterfaceMACAddress                                // interface hardware MAC address
	optionInterfaceEUIAddress                                // interface hardware EUI address
	optionInterfaceSpeed                                     // interface speed in bits/s
	optionInterfaceTimestampResolution                       // timestamp resolution
	optionInterfaceTimezone                                  // time zone
	optionInterfaceFilter                                    // capture filter
	optionInterfaceOS                                        // operating system
	optionInterfaceFCSLength                                 // length of the Frame Check Sequence in bits
	optionInterfaceTimestampOffset                           // offset (in seconds) that must be added to packet timestamp
)

const (
	optionInterfaceStatisticsStartTime         optionCode = iota + 2 // Start of capture
	optionInterfaceStatisticsEndTime                                 // End of capture
	optionInterfaceStatisticsInterfaceReceived                       // Packets received by physical interface
	optionInterfaceStatisticsInterfaceDropped                        // Packets dropped by physical interface
	optionInterfaceStatisticsFilterAccept                            // Packets accepted by filter
	optionInterfaceStatisticsOSDrop                                  // Packets dropped by operating system
	optionInterfaceStatisticsDelivered                               // Packets delivered to user
)

// option is a pcapng option
type option struct {
	code   optionCode
	value  []byte
	raw    interface{}
	length uint16
}

// block is a pcapng block header
type block struct {
	typ    blockType
	length uint32 // remaining length of block
}

// Resolution represents a pcapng timestamp resolution
type Resolution uint8

// Binary returns true if the timestamp resolution is a negative power of two. Otherwise Resolution is a negative power of 10.
func (r Resolution) Binary() bool {
	if r&0x80 == 0x80 {
		return true
	}
	return false
}

// Exponent returns the negative exponent of the resolution.
func (r Resolution) Exponent() uint8 {
	return uint8(r) & 0x7f
}

// NoValue64 is a placeholder for an empty numeric 64 bit value.
const NoValue64 = math.MaxUint64

// InterfaceStatistics hold the statistic for an interface at a single point in time. These values are already supposed to be accumulated. Most pcapng files contain this information at the end of the file/section.
type InterfaceStatistics struct {
	// LastUpdate is the last time the statistics were updated.
	LastUpdate time.Time
	// StartTime is the time packet capture started on this interface. This value might be zero if this option is missing.
	StartTime time.Time
	// EndTime is the time packet capture ended on this interface This value might be zero if this option is missing.
	EndTime time.Time
	// Comment can be an arbitrary comment. This value might be empty if this option is missing.
	Comment string
	// PacketsReceived are the number of received packets. This value might be NoValue64 if this option is missing.
	PacketsReceived uint64
	// PacketsReceived are the number of received packets. This value might be NoValue64 if this option is missing.
	PacketsDropped uint64
}

var emptyStatistics = InterfaceStatistics{
	PacketsReceived: NoValue64,
	PacketsDropped:  NoValue64,
}

// Interface holds all the information of a pcapng interface.
type Interface struct {
	// Name is the name of the interface. This value might be empty if this option is missing.
	Name string
	// Comment can be an arbitrary comment. This value might be empty if this option is missing.
	Comment string
	// Description is a description of the interface. This value might be empty if this option is missing.
	Description string
	// Filter is the filter used during packet capture. This value might be empty if this option is missing.
	Filter string
	// OS is the operating system this interface was controlled by. This value might be empty if this option is missing.
	OS string
	// LinkType is the linktype of the interface.
	LinkType layers.LinkType
	// TimestampResolution is the timestamp resolution of the packets in the pcapng file belonging to this interface.
	TimestampResolution Resolution
	// TimestampResolution is the timestamp offset in seconds of the packets in the pcapng file belonging to this interface.
	TimestampOffset uint64
	// SnapLength is the maximum packet length captured by this interface. 0 for unlimited
	SnapLength uint32
	// Statistics holds the interface statistics
	Statistics InterfaceStatistics

	secondMask uint64
	scaleUp    uint64
	scaleDown  uint64
}

// SectionInfo contains additional information of a pcapng section
type SectionInfo struct {
	// Hardware is the hardware this file was generated on. This value might be empty if this option is missing.
	Hardware string
	// OS is the operating system this file was generated on. This value might be empty if this option is missing.
	OS string
	// Application is the user space application this file was generated with. This value might be empty if this option is missing.
	Application string
	// Comment can be an arbitrary comment. This value might be empty if this option is missing.
	Comment string
}
