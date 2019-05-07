// Copyright - Copyleft 2019 Ripx80, All rights reserved.

// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// Package snoop implements the snoop file format for gopacket
package snoop

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const snoopMagic uint64 = 0x706f6f6e73 //000000 //8 byte in big endian
const snoopVersion uint32 = 2
const defaultBufLen uint32 = 150
const maxCaptureLen int = 4096

// Errors
const unknownMagic = "Unknown Snoop Magic Bytes"
const unknownVersion = "Unknown Snoop Format Version"
const unkownLinkType = "Unknown Link Type"
const originalLenExceeded = "Capture length exceeds original packet length"
const captureLenExceeded = "Capture length exceeds max capture length"

// LinkTypes maps from snoop to gopacket layers
type LinkTypes struct {
	Code uint8
	layers.LinkType
}

type snoopHeader struct {
	Magic    uint64
	Version  uint32
	linkType uint32
}

// Reader wraps an underlying io.Reader to read packet data in SNOOP
// format.  See https://tools.ietf.org/html/rfc1761
// for information on the file format.
//
// We currenty read v2 file format and convert microsecond to nanoseconds
// byte order in big-endian encoding.
type Reader struct {
	r      io.Reader
	header snoopHeader
	//reuseable
	pad       int
	packetBuf []byte
	buf       [24]byte
}

var (
	layerTypes = map[uint32]layers.LinkType{
		0: layers.LinkTypeEthernet,  // IEEE 802.3
		2: layers.LinkTypeTokenRing, // IEEE 802.5 Token Ring
		4: layers.LinkTypeEthernet,  // Ethernet
		5: layers.LinkTypeC_HDLC,    // HDLC
		8: layers.LinkTypeFDDI,      // FDDI
		/*
			10 - 4294967295 Unassigned
			not supported:
			1 - IEEE 802.4 Token Bus
			3 - IEEE 802.6 Metro Net
			6 - Character Synchronous
			7 - IBM Channel-to-Channel
			9 - Other
		*/
	}
)

// LinkType return the mapped gopacket LinkType
func (r *Reader) LinkType() (*layers.LinkType, error) {
	if _, ok := layerTypes[r.header.linkType]; ok {
		lt := layerTypes[r.header.linkType]
		return &lt, nil
	}
	return nil, fmt.Errorf("%s, Code:%d", unkownLinkType, r.header.linkType)

}

// NewReader returns a new reader object, for reading packet data from
// the given reader. The reader must be open and header data is
// read from it at this point.
// If the file format is not supported an error is returned
func NewReader(r io.Reader) (*Reader, error) {
	ret := Reader{r: r}

	if err := ret.readHeader(); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (r *Reader) readHeader() error {
	buf := make([]byte, 16)

	if n, err := io.ReadFull(r.r, buf); err != nil {
		return err
	} else if n < 16 {
		return errors.New("Not enough data for read")
	}

	if magic := binary.LittleEndian.Uint64(buf[0:8]); magic != snoopMagic {
		return fmt.Errorf("%s: %x", unknownMagic, magic)
	}

	if r.header.Version = binary.BigEndian.Uint32(buf[8:12]); r.header.Version != snoopVersion {
		return fmt.Errorf("%s: %d", unknownVersion, r.header.Version)
	}

	if r.header.linkType = binary.BigEndian.Uint32(buf[12:16]); r.header.linkType > 10 {
		return fmt.Errorf("%s, Code:%d", unkownLinkType, r.header.linkType)
	}
	return nil
}

func (r *Reader) readPacketHeader() (ci gopacket.CaptureInfo, err error) {

	if _, err = io.ReadFull(r.r, r.buf[:]); err != nil {
		return
	}
	// 	OriginalLength        uint32	4
	// 	IncludedLength        uint32	8
	// 	PacketRecordLength    uint32	12
	// 	CumulativeDrops       uint32	16
	// 	TimestampSeconds      uint32	20
	// 	TimestampMicroseconds uint32	24

	ci.Timestamp = time.Unix(int64(binary.BigEndian.Uint32(r.buf[16:20])), int64(binary.BigEndian.Uint32(r.buf[20:24])*1000)).UTC()
	ci.Length = int(binary.BigEndian.Uint32(r.buf[0:4]))
	ci.CaptureLength = int(binary.BigEndian.Uint32(r.buf[4:8]))
	r.pad = int(binary.BigEndian.Uint32(r.buf[8:12])) - (24 + ci.Length)

	if ci.CaptureLength > ci.Length {
		err = errors.New(originalLenExceeded)
		return
	}

	if ci.CaptureLength > maxCaptureLen {
		err = errors.New(captureLenExceeded)
	}

	return
}

// ReadPacketData reads next packet data.
func (r *Reader) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if ci, err = r.readPacketHeader(); err != nil {
		return
	}
	data = make([]byte, ci.CaptureLength+r.pad)
	_, err = io.ReadFull(r.r, data)
	return data[:ci.CaptureLength], ci, err

}

// ZeroCopyReadPacketData reads next packet data. The data buffer is owned by the Reader,
// and each call to ZeroCopyReadPacketData invalidates data returned by the previous one.
//
// It is not true zero copy, as data is still copied from the underlying reader. However,
// this method avoids allocating heap memory for every packet.
func (r *Reader) ZeroCopyReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	if ci, err = r.readPacketHeader(); err != nil {
		return
	}

	if cap(r.packetBuf) < ci.CaptureLength+r.pad {
		r.packetBuf = make([]byte, ci.CaptureLength+r.pad)
	}
	_, err = io.ReadFull(r.r, r.packetBuf[:ci.CaptureLength+r.pad])
	return r.packetBuf[:ci.CaptureLength], ci, err
}
