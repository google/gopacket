// Copyright 2018 The GoPacket Authors. All rights reserved.

package pcapnggo

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// WriterOptions holds options for creating a pcapng file
type WriterOptions struct {
	// SectionInfo will be written to the section header
	SectionInfo SectionInfo
}

// DefaultWriterOptions contain defaults for a pcapng writer used by NewWriter
var DefaultWriterOptions = WriterOptions{
	SectionInfo: SectionInfo{
		Hardware:    runtime.GOARCH,
		OS:          runtime.GOOS,
		Application: "gopacket", //spread the word
	},
}

// DefaultInterface contains default interface options used by NewWriter
var DefaultInterface = Interface{
	Name:                "intf0",
	OS:                  runtime.GOOS,
	SnapLength:          0, //unlimited
	TimestampResolution: 9,
}

// Writer holds the internal state of a pcapng file writer. Internally a bufio.Writer is used, therefore Flush must be called before closing the underlying file.
type Writer struct {
	w       *bufio.Writer
	options WriterOptions
	intf    uint32
	buf     [28]byte
}

// NewWriter initializes and returns a new writer. Additionally, one section and one interface (without statistics) is written to the file. Interface and section options are used from DefaultInterface and DefaultWriterOptions.
// Flush must be called before the file is closed, or if eventual unwritten information should be written out to the storage device.
//
// Written files are in little endian format. Interface timestamp resolution is fixed to 9 (to match time.Time).
func NewWriter(w io.Writer, linkType layers.LinkType) (*Writer, error) {
	intf := DefaultInterface
	intf.LinkType = linkType
	return NewWriterInterface(w, intf, DefaultWriterOptions)
}

// NewWriterInterface initializes and returns a new writer. Additionally, one section and one interface (without statistics) is written to the file.
// Flush must be called before the file is closed, or if eventual unwritten information should be written out to the storage device.
//
// Written files are in little endian format. Interface timestamp resolution is fixed to 9 (to match time.Time).
func NewWriterInterface(w io.Writer, intf Interface, options WriterOptions) (*Writer, error) {
	ret := &Writer{
		w:       bufio.NewWriter(w),
		options: options,
	}
	if err := ret.writeSectionHeader(); err != nil {
		return nil, err
	}

	if _, err := ret.AddInterface(intf); err != nil {
		return nil, err
	}
	return ret, nil
}

// optionLength returns the needed length for one option value (without padding)
func optionLength(option option) (length int) {
	switch val := option.raw.(type) {
	case []byte:
		return len(val)
	case string:
		return len(val)
	case time.Time:
		return 8
	case uint64:
		return 8
	case uint32:
		return 4
	case uint8:
		return 1
	default:
		panic("This should never happen")
	}
}

// prepareOptions fills out the length value of the given options and returns the number of octets needed for all the given options including padding.
func prepareOptions(options []option) (ret uint32) {
	for i, option := range options {
		length := optionLength(option)
		options[i].length = uint16(length)
		length += (4-length&3)&3 + // padding
			4 //header
		ret += uint32(length)
	}
	if ret > 0 {
		ret += 4 // end of options
	}
	return
}

// writeOptions writes the given options to the file. prepareOptions must be called beforehand.
func (w *Writer) writeOptions(options []option) (err error) {
	if len(options) == 0 {
		return
	}

	var zero [4]byte
	for _, option := range options {
		binary.LittleEndian.PutUint16(w.buf[0:2], uint16(option.code))
		binary.LittleEndian.PutUint16(w.buf[2:4], option.length)
		if _, err = w.w.Write(w.buf[:4]); err != nil {
			return
		}
		switch val := option.raw.(type) {
		case []byte:
			if _, err = w.w.Write(val); err != nil {
				return
			}
			padding := uint8((4 - option.length&3) & 3)
			if padding < 4 {
				if _, err = w.w.Write(zero[:padding]); err != nil {
					return
				}
			}
		case string:
			if _, err = w.w.Write([]byte(val)); err != nil {
				return
			}
			padding := uint8((4 - option.length&3) & 3)
			if padding < 4 {
				if _, err = w.w.Write(zero[:padding]); err != nil {
					return
				}
			}
		case time.Time:
			ts := val.UnixNano()
			binary.LittleEndian.PutUint32(w.buf[:4], uint32(ts>>32))
			binary.LittleEndian.PutUint32(w.buf[4:8], uint32(ts))
			if _, err = w.w.Write(w.buf[:8]); err != nil {
				return
			}
		case uint64:
			binary.LittleEndian.PutUint64(w.buf[:8], val)
			if _, err = w.w.Write(w.buf[:8]); err != nil {
				return
			}
		case uint32:
			binary.LittleEndian.PutUint32(w.buf[:4], val)
			if _, err = w.w.Write(w.buf[:4]); err != nil {
				return
			}
		case uint8:
			binary.LittleEndian.PutUint32(w.buf[:4], 0) // padding
			w.buf[0] = val
			if _, err = w.w.Write(w.buf[:4]); err != nil {
				return
			}
		default:
			panic("This should never happen")
		}
	}

	// options must be folled by an end of options option
	binary.LittleEndian.PutUint16(w.buf[0:2], uint16(optionEndOfOptions))
	binary.LittleEndian.PutUint16(w.buf[2:4], 0)
	_, err = w.w.Write(w.buf[:4])
	return
}

// writeSectionHeader writes a section header to the file
func (w *Writer) writeSectionHeader() (err error) {
	var scratch [4]option
	i := 0
	info := w.options.SectionInfo
	if info.Application != "" {
		scratch[i].code = optionUserApplication
		scratch[i].raw = info.Application
		i++
	}
	if info.Comment != "" {
		scratch[i].code = optionComment
		scratch[i].raw = info.Comment
		i++
	}
	if info.Hardware != "" {
		scratch[i].code = optionHardware
		scratch[i].raw = info.Hardware
		i++
	}
	if info.OS != "" {
		scratch[i].code = optionOS
		scratch[i].raw = info.OS
		i++
	}
	options := scratch[:i]

	length := prepareOptions(options) +
		24 + // header
		4 // trailer

	binary.LittleEndian.PutUint32(w.buf[:4], uint32(blockTypeSectionHeader))
	binary.LittleEndian.PutUint32(w.buf[4:8], length)
	binary.LittleEndian.PutUint32(w.buf[8:12], byteOrderMagic)
	binary.LittleEndian.PutUint16(w.buf[12:14], versionMajor)
	binary.LittleEndian.PutUint16(w.buf[14:16], versionMinor)
	binary.LittleEndian.PutUint64(w.buf[16:24], 0xFFFFFFFFFFFFFFFF) // unspecified
	if _, err = w.w.Write(w.buf[:24]); err != nil {
		return
	}

	if err = w.writeOptions(options); err != nil {
		return
	}

	binary.LittleEndian.PutUint32(w.buf[0:4], length)
	_, err = w.w.Write(w.buf[:4])
	return
}

// AddInterface adds the specified interface to the file, excluding statistics. Interface timestamp resolution is fixed to 9 (to match time.Time). Empty values are not written.
func (w *Writer) AddInterface(intf Interface) (id int, err error) {
	id = int(w.intf)
	w.intf++

	var scratch [7]option
	i := 0
	if intf.Name != "" {
		scratch[i].code = optionInterfaceName
		scratch[i].raw = intf.Name
		i++
	}
	if intf.Comment != "" {
		scratch[i].code = optionComment
		scratch[i].raw = intf.Comment
		i++
	}
	if intf.Description != "" {
		scratch[i].code = optionInterfaceDescription
		scratch[i].raw = intf.Description
		i++
	}
	if intf.Filter != "" {
		scratch[i].code = optionInterfaceFilter
		scratch[i].raw = append([]byte{0}, []byte(intf.Filter)...)
		i++
	}
	if intf.OS != "" {
		scratch[i].code = optionInterfaceOS
		scratch[i].raw = intf.OS
		i++
	}
	if intf.TimestampOffset != 0 {
		scratch[i].code = optionInterfaceTimestampOffset
		scratch[i].raw = intf.TimestampOffset
		i++
	}
	scratch[i].code = optionInterfaceTimestampResolution
	scratch[i].raw = uint8(9) // fix resolution to nanoseconds (time.Time) in decimal
	i++
	options := scratch[:i]

	length := prepareOptions(options) +
		16 + // header
		4 // trailer

	binary.LittleEndian.PutUint32(w.buf[:4], uint32(blockTypeInterfaceDescriptor))
	binary.LittleEndian.PutUint32(w.buf[4:8], length)
	binary.LittleEndian.PutUint16(w.buf[8:10], uint16(intf.LinkType))
	binary.LittleEndian.PutUint16(w.buf[10:12], 0) // reserved value
	binary.LittleEndian.PutUint32(w.buf[12:16], intf.SnapLength)
	if _, err = w.w.Write(w.buf[:16]); err != nil {
		return
	}

	if err = w.writeOptions(options); err != nil {
		return
	}

	binary.LittleEndian.PutUint32(w.buf[0:4], length)
	_, err = w.w.Write(w.buf[:4])
	return
}

// WriteInterfaceStats writes the given interface statistics for the given interface id to the file. Empty values are not written.
func (w *Writer) WriteInterfaceStats(intf int, stats InterfaceStatistics) (err error) {
	if intf >= int(w.intf) || intf < 0 {
		return fmt.Errorf("Can't send statistics for non existent interface %d; have only %d interfaces", intf, w.intf)
	}

	var scratch [4]option
	i := 0
	if !stats.StartTime.IsZero() {
		scratch[i].code = optionInterfaceStatisticsStartTime
		scratch[i].raw = stats.StartTime
		i++
	}
	if !stats.EndTime.IsZero() {
		scratch[i].code = optionInterfaceStatisticsEndTime
		scratch[i].raw = stats.EndTime
		i++
	}
	if stats.PacketsDropped != NoValue64 {
		scratch[i].code = optionInterfaceStatisticsInterfaceDropped
		scratch[i].raw = stats.PacketsDropped
		i++
	}
	if stats.PacketsReceived != NoValue64 {
		scratch[i].code = optionInterfaceStatisticsInterfaceReceived
		scratch[i].raw = stats.PacketsReceived
		i++
	}
	options := scratch[:i]

	length := prepareOptions(options) + 24

	ts := stats.LastUpdate.UnixNano()
	if stats.LastUpdate.IsZero() {
		ts = 0
	}

	binary.LittleEndian.PutUint32(w.buf[:4], uint32(blockTypeInterfaceStatistics))
	binary.LittleEndian.PutUint32(w.buf[4:8], length)
	binary.LittleEndian.PutUint32(w.buf[8:12], uint32(intf))
	binary.LittleEndian.PutUint32(w.buf[12:16], uint32(ts>>32))
	binary.LittleEndian.PutUint32(w.buf[16:20], uint32(ts))
	if _, err = w.w.Write(w.buf[:20]); err != nil {
		return
	}

	if err = w.writeOptions(options); err != nil {
		return
	}

	binary.LittleEndian.PutUint32(w.buf[0:4], length)
	_, err = w.w.Write(w.buf[:4])
	return
}

// WritePacket writes out packet with the given data and capture info. The given InterfaceIndex must already be added to the file. InterfaceIndex 0 is automatically added by the NewWriter* methods.
func (w *Writer) WritePacket(ci gopacket.CaptureInfo, data []byte) (err error) {
	if ci.InterfaceIndex >= int(w.intf) || ci.InterfaceIndex < 0 {
		return fmt.Errorf("Can't send statistics for non existent interface %d; have only %d interfaces", ci.InterfaceIndex, w.intf)
	}
	if ci.CaptureLength != len(data) {
		return fmt.Errorf("capture length %d does not match data length %d", ci.CaptureLength, len(data))
	}
	if ci.CaptureLength > ci.Length {
		return fmt.Errorf("invalid capture info %+v:  capture length > length", ci)
	}

	length := uint32(len(data)) + 32
	padding := (4 - length&3) & 3
	length += padding

	ts := ci.Timestamp.UnixNano()

	binary.LittleEndian.PutUint32(w.buf[:4], uint32(blockTypeEnhancedPacket))
	binary.LittleEndian.PutUint32(w.buf[4:8], length)
	binary.LittleEndian.PutUint32(w.buf[8:12], uint32(ci.InterfaceIndex))
	binary.LittleEndian.PutUint32(w.buf[12:16], uint32(ts>>32))
	binary.LittleEndian.PutUint32(w.buf[16:20], uint32(ts))
	binary.LittleEndian.PutUint32(w.buf[20:24], uint32(ci.CaptureLength))
	binary.LittleEndian.PutUint32(w.buf[24:28], uint32(ci.Length))

	if _, err = w.w.Write(w.buf[:28]); err != nil {
		return
	}

	if _, err = w.w.Write(data); err != nil {
		return
	}

	binary.LittleEndian.PutUint32(w.buf[:4], 0)
	_, err = w.w.Write(w.buf[4-padding : 8]) // padding + length
	return
}

// Flush writes out buffered data to the storage media. Must be called before closing the underlying file.
func (w *Writer) Flush() error {
	return w.w.Flush()
}
