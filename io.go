package pcap

import (
	"fmt"
	"io"
)

// FileHeader is the parsed header of a pcap file.
// http://wiki.wireshark.org/Development/LibpcapFileFormat
type FileHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	TimeZone     int32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32
}

type PacketTime struct {
	Sec  int32
	Usec int32
}

// Packet is a single packet parsed from a pcap file.
type Packet struct {
	Time   PacketTime // packet send/receive time
	Caplen uint32     // bytes stored in the file (caplen <= len)
	Len    uint32     // bytes sent/received
	Data   []byte     // packet data

	Type    int // protocol type, see LINKTYPE_*
	DestMac uint64
	SrcMac  uint64

	Headers []interface{} // decoded headers, in order
	Payload []byte        // remaining non-header bytes
}

// Reader parses pcap files.
type Reader struct {
	flip         bool
	buf          io.Reader
	err          error
	fourBytes    []byte
	twoBytes     []byte
	sixteenBytes []byte
	Header       FileHeader
}

// NewReader reads pcap data from an os.Reader.
func NewReader(reader io.Reader) (*Reader, error) {
	r := &Reader{
		buf:          reader,
		fourBytes:    make([]byte, 4),
		twoBytes:     make([]byte, 2),
		sixteenBytes: make([]byte, 16),
	}
	magic := r.readUint32()
	if magic == 0xa1b2c3d4 {
		r.flip = false
	} else if magic == 0xd4c3b2a1 {
		r.flip = true
	} else {
		return nil, fmt.Errorf("pcap: bad magic number: %0x", magic)
	}
	r.Header = FileHeader{
		MagicNumber:  0xa1b2c3d4,
		VersionMajor: r.readUint16(),
		VersionMinor: r.readUint16(),
		TimeZone:     r.readInt32(),
		SigFigs:      r.readUint32(),
		SnapLen:      r.readUint32(),
		Network:      r.readUint32(),
	}
	return r, nil
}

// Next returns the next packet or nil if no more packets can be read.
func (r *Reader) Next() *Packet {
	d := r.sixteenBytes
	r.err = r.read(d)
	if r.err != nil {
		return nil
	}
	timeSec := asUint32(d[0:4], r.flip)
	timeUsec := asUint32(d[4:8], r.flip)
	capLen := asUint32(d[8:12], r.flip)
	origLen := asUint32(d[12:16], r.flip)

	data := make([]byte, capLen)
	r.err = r.read(data)
	if r.err != nil {
		return nil
	}
	return &Packet{
		Time: PacketTime{
			Sec:  int32(timeSec),
			Usec: int32(timeUsec),
		},
		Caplen: capLen,
		Len:    origLen,
		Data:   data,
	}
}

func (r *Reader) read(data []byte) error {
	var err error
	n, err := r.buf.Read(data)
	for err == nil && n != len(data) {
		var chunk int
		chunk, err = r.buf.Read(data[n:])
		n += chunk
	}
	if len(data) == n {
		return nil
	}
	return err
}

func (r *Reader) readUint32() uint32 {
	data := r.fourBytes
	r.err = r.read(data)
	if r.err != nil {
		return 0
	}
	return asUint32(data, r.flip)
}

func (r *Reader) readInt32() int32 {
	data := r.fourBytes
	r.err = r.read(data)
	if r.err != nil {
		return 0
	}
	return asInt32(data, r.flip)
}

func (r *Reader) readUint16() uint16 {
	data := r.twoBytes
	r.err = r.read(data)
	if r.err != nil {
		return 0
	}
	return asUint16(data, r.flip)
}

// Writer writes a pcap file.
type Writer struct {
	writer io.Writer
	buf    []byte
}

// NewWriter creates a Writer that stores output in an io.Writer.
// The FileHeader is written immediately.
func NewWriter(writer io.Writer, header *FileHeader) (*Writer, error) {
	w := &Writer{
		writer: writer,
		buf:    make([]byte, 24),
	}
	e := encoder{w.buf}
	e.put4(header.MagicNumber)
	e.put2(header.VersionMajor)
	e.put2(header.VersionMinor)
	e.put4(uint32(header.TimeZone))
	e.put4(header.SigFigs)
	e.put4(header.SnapLen)
	e.put4(header.Network)
	_, err := writer.Write(w.buf)
	if err != nil {
		return nil, err
	}
	return w, nil
}

// Writer writes a packet to the underlying writer.
func (w *Writer) Write(pkt *Packet) error {
	e := encoder{w.buf}
	e.put4(uint32(pkt.Time.Sec))
	e.put4(uint32(pkt.Time.Usec))
	e.put4(pkt.Caplen)
	e.put4(pkt.Len)
	_, err := w.writer.Write(w.buf[:16])
	if err != nil {
		return err
	}
	_, err = w.writer.Write(pkt.Data)
	return err
}

type encoder struct {
	buf []byte
}

func (e *encoder) put4(v uint32) {
	e.buf[0] = byte(v)
	e.buf[1] = byte(v >> 8)
	e.buf[2] = byte(v >> 16)
	e.buf[3] = byte(v >> 24)
	e.buf = e.buf[4:]
}

func (e *encoder) put2(v uint16) {
	e.buf[0] = byte(v)
	e.buf[1] = byte(v >> 8)
	e.buf = e.buf[2:]
}

func asUint32(data []byte, flip bool) uint32 {
	if flip {
		return uint32(uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3]))
	}
	return uint32(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24)
}

func asInt32(data []byte, flip bool) int32 {
	return int32(asUint32(data, flip))
}

func asUint16(data []byte, flip bool) uint16 {
	if flip {
		return uint16(uint16(data[0])<<8 | uint16(data[1]))
	}
	return uint16(uint16(data[0]) | uint16(data[1])<<8)
}
