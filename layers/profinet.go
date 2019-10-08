package layers

import (
	"encoding/binary"
	"errors"
	"log"

	"github.com/google/gopacket"
)

type PNFrameID uint16

const (
	PNFrameIDTimeSynchronization PNFrameID = 0x0000
	PNFrameIDRTClass3            PNFrameID = 0x0100
	PNFrameIDRTClass2            PNFrameID = 0x8000
	PNFrameIDRTClass1            PNFrameID = 0xc000
	PNFrameIDAcyclicHigh         PNFrameID = 0xfc00
	PNFrameIDReserved            PNFrameID = 0xfd00
	PNFrameIDAcyclicLow          PNFrameID = 0xfe00
	PNFrameIDHello               PNFrameID = 0xfefc
	PNFrameIDDCPGetOrSet         PNFrameID = 0xfefd
	PNFrameIDDCPIdentifyRequest  PNFrameID = 0xfefe
	PNFrameIDDCPIdentifyResponse PNFrameID = 0xfeff
)

func PNDCPMulticastMAC() []byte {
	return []byte{0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00}
}

type PNDCPServiceID uint8

const (
	PNDCPServiceIDGet      PNDCPServiceID = 0x03
	PNDCPServiceIDSet      PNDCPServiceID = 0x04
	PNDCPServiceIDIdentify PNDCPServiceID = 0x05
	PNDCPServiceIDHello    PNDCPServiceID = 0x06
)

type PNDCPServiceType uint8

const (
	PNDCPServiceTypeRequest     PNDCPServiceType = 0
	PNDCPServiceTypeSuccess     PNDCPServiceType = 1
	PNDCPServiceTypeUnsupported PNDCPServiceType = 5
)

type PNDCPOption uint8

const (
	PNDCPOptionIP               PNDCPOption = 0x01
	PNDCPOptionDevice           PNDCPOption = 0x02
	PNDCPOptionDHPC             PNDCPOption = 0x03
	PNDCPOptionReserved         PNDCPOption = 0x04
	PNDCPOptionControl          PNDCPOption = 0x05
	PNDCPOptionDeviceInitiative PNDCPOption = 0x06
	PNDCPOptionManufX80         PNDCPOption = 0x80
	PNDCPOptionManufX81         PNDCPOption = 0x81
	PNDCPOptionManufX82         PNDCPOption = 0x82
	PNDCPOptionManufX83         PNDCPOption = 0x83
	PNDCPOptionManufX84         PNDCPOption = 0x84
	PNDCPOptionManufX85         PNDCPOption = 0x85
	PNDCPOptionManufX86         PNDCPOption = 0x86
	PNDCPOptionAllselector      PNDCPOption = 0xff
)

type PNDCPSuboption uint8

const (
	PNDCPSuboptionAllselector PNDCPSuboption = 0xff
)

type PNDCPSuboptionIP PNDCPSuboption

const (
	PNDCPSuboptionIPMAC PNDCPSuboptionIP = 0x01
	PNDCPSuboptionIPIP  PNDCPSuboptionIP = 0x02
)

type PNDCPSuboptionDevice PNDCPSuboption

const (
	PNDCPSuboptionDeviceManufacturer  PNDCPSuboptionDevice = 0x01
	PNDCPSuboptionDeviceNameOfStation PNDCPSuboptionDevice = 0x02
	PNDCPSuboptionDeviceID            PNDCPSuboptionDevice = 0x03
	PNDCPSuboptionDeviceRole          PNDCPSuboptionDevice = 0x04
	PNDCPSuboptionDeviceOptions       PNDCPSuboptionDevice = 0x05
	PNDCPSuboptionDeviceAliasName     PNDCPSuboptionDevice = 0x06
	PNDCPSuboptionDeviceInstance      PNDCPSuboptionDevice = 0x07
)

type PNDCPSuboptionControl PNDCPSuboption

const (
	PNDCPSuboptionControlStartTransaction PNDCPSuboptionControl = 0x01
	PNDCPSuboptionControlEndTransaction   PNDCPSuboptionControl = 0x02
	PNDCPSuboptionControlSignal           PNDCPSuboptionControl = 0x03
	PNDCPSuboptionControlResponse         PNDCPSuboptionControl = 0x04
	PNDCPSuboptionControlFactoryReset     PNDCPSuboptionControl = 0x05
)

const (
	PNDCPOptionDeviceRoleIODevice      uint8 = 0x01
	PNDCPOptionDeviceRoleIOController  uint8 = 0x02
	PNDCPOptionDeviceRoleIOMultidevice uint8 = 0x02
	PNDCPOptionDeviceRoleIOSupervisor  uint8 = 0x02
)

type PNDCPBlockError uint8

const (
	PNDCPBlockErrorOK                   PNDCPBlockError = 0x00
	PNDCPBlockErrorOptionUnsupported    PNDCPBlockError = 0x01
	PNDCPBlockErrorSuboptionUnsupported PNDCPBlockError = 0x02
	PNDCPBlockErrorSuboptionNotSet      PNDCPBlockError = 0x03
	PNDCPBlockErrorResourceError        PNDCPBlockError = 0x04
	PNDCPBlockErrorSetImpossible        PNDCPBlockError = 0x05
	PNDCPBlockErrorInOperation          PNDCPBlockError = 0x06
)

type Profinet struct {
	BaseLayer
	FrameID PNFrameID
}

func (p Profinet) LayerType() gopacket.LayerType { return LayerTypeProfinet }

func (p *Profinet) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 2 {
		return errors.New("Profinet packet too small")
	}

	p.FrameID = PNFrameID(binary.BigEndian.Uint16(data[0:2]))
	p.Payload = data[2:]

	return nil
}

func (p *Profinet) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, uint16(p.FrameID))

	return nil
}

type ProfinetDCP struct {
	BaseLayer
	ServiceID     PNDCPServiceID
	ServiceType   PNDCPServiceType
	Xid           uint32
	ResponseDelay uint16
	BlockLength   uint16
	Blocks        []ProfinetDCPBlock
}

type ProfinetDCPBlock struct {
	Option    PNDCPOption
	Suboption uint8
	Length    uint16
	Data      []byte
}

func (p ProfinetDCP) LayerType() gopacket.LayerType { return LayerTypeProfinetDCP }

func (p *ProfinetDCP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {

	var blocksLen int
	for _, block := range p.Blocks {
		blockLen := len(block.Data)
		blockLen = blockLen + blockLen%2 // static params + byte array length + padding

		if opts.FixLengths {
			block.Length = uint16(blockLen)
		}

		blocksLen = blocksLen + 4 + blockLen
	}
	if opts.FixLengths {
		p.BlockLength = uint16(blocksLen)
	}

	bytes, err := b.PrependBytes(10 + blocksLen)
	if err != nil {
		return err
	}
	bytes[0] = uint8(p.ServiceID)
	bytes[1] = uint8(p.ServiceType)
	binary.BigEndian.PutUint32(bytes[2:], p.Xid)
	binary.BigEndian.PutUint16(bytes[6:], p.ResponseDelay)
	binary.BigEndian.PutUint16(bytes[8:], p.BlockLength)

	blocksLen = 10
	for _, block := range p.Blocks {
		blockLen := len(block.Data)
		blockLen = blockLen + blockLen%2 // static params + byte array length + padding

		bytes[blocksLen] = uint8(block.Option)
		bytes[blocksLen+1] = block.Suboption
		binary.BigEndian.PutUint16(bytes[blocksLen+2:], uint16(blockLen))
		copy(bytes[blocksLen+4:], block.Data)

		blocksLen = blocksLen + 4 + blockLen
	}

	return nil
}

func (b *ProfinetDCPBlock) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, []byte, error) {
	if len(data) < 4 {
		return 0, data, errors.New("Profinet DCP block too small")
	}

	b.Option = PNDCPOption(uint8(data[0]))
	b.Suboption = uint8(data[1])
	b.Length = binary.BigEndian.Uint16(data[2:4])
	if b.Length > 0 {
		if len(data[5:]) < int(b.Length) {
			df.SetTruncated()
			// TODO still return error here, even if packet is truncated?
			return 4, data[5:], errors.New("Profinet DCP block data too small")
		}

		b.Data = data[5 : b.Length+5]
	}

	// including padding here
	lenDecoded := int(b.Length) + 4 + int(b.Length)%2

	return lenDecoded, data[lenDecoded:], nil
}

type ProfinetRT struct {
	BaseLayer
	Data           []byte
	CycleCounter   uint16
	DataStatus     uint8
	TransferStatus uint8
}

func (p ProfinetRT) LayerType() gopacket.LayerType { return LayerTypeProfinetRT }

func decodeProfinet(data []byte, p gopacket.PacketBuilder) error {
	// assertion, if data is too small
	if len(data) < 2 {
		return errors.New("Malformed Profinet Packet")
	}

	d := &Profinet{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)

	if d.FrameID >= PNFrameIDTimeSynchronization && d.FrameID < PNFrameIDRTClass3 {
		// fmt.Println("This is a Profinet Time Synchronization packet")
	} else if d.FrameID >= PNFrameIDRTClass3 && d.FrameID < PNFrameIDRTClass2 {
		// fmt.Println("This is a Profinet RT Class 3 packet")
		return p.NextDecoder(LayerTypeProfinetRT)
	} else if d.FrameID >= PNFrameIDRTClass2 && d.FrameID < PNFrameIDRTClass1 {
		// fmt.Println("This is a Profinet RT Class 2 packet")
		return p.NextDecoder(LayerTypeProfinetRT)
	} else if d.FrameID >= PNFrameIDRTClass1 && d.FrameID < PNFrameIDAcyclicHigh {
		// fmt.Println("This is a Profinet RT Class 1 packet")
		return p.NextDecoder(LayerTypeProfinetRT)
	} else if d.FrameID >= PNFrameIDAcyclicHigh && d.FrameID < PNFrameIDReserved {
		// fmt.Println("This is a Profinet Acyclic High packet")
	} else if d.FrameID >= PNFrameIDReserved && d.FrameID < PNFrameIDAcyclicLow {
		// fmt.Println("This is a Profinet Reserved packet")
	} else if d.FrameID >= PNFrameIDAcyclicLow && d.FrameID < PNFrameIDDCPGetOrSet {
		// fmt.Println("This is a Profinet Acyclic Low packet")
	} else if d.FrameID >= PNFrameIDDCPGetOrSet && d.FrameID <= PNFrameIDDCPIdentifyResponse {
		// fmt.Println("This is a Profinet DCP packet")
		return p.NextDecoder(LayerTypeProfinetDCP)
	}

	return nil
}

func decodeProfinetDCP(data []byte, p gopacket.PacketBuilder) error {
	// assertion, if data is too small
	if len(data) < 10 {
		return errors.New("Malformed Profinet DCP Packet")
	}

	d := &ProfinetDCP{}

	d.ServiceID = PNDCPServiceID(data[0])
	d.ServiceType = PNDCPServiceType(data[1])
	d.Xid = binary.BigEndian.Uint32(data[2:6])
	d.ResponseDelay = binary.BigEndian.Uint16(data[6:8])
	d.BlockLength = binary.BigEndian.Uint16(data[8:10])

	// decode first block
	dcpBlock := &ProfinetDCPBlock{}
	len, rest, err := dcpBlock.DecodeFromBytes(data[10:], p)
	if err != nil {
		log.Println("dcpBlock.DecodeFromBytes error:", err)
		return err
	}
	d.Blocks = append(d.Blocks, *dcpBlock)

	// decode more blocks
	len = int(d.BlockLength) - len
	for len >= 4 {
		dcpBlock = &ProfinetDCPBlock{}
		decodedLen, rest2, err := dcpBlock.DecodeFromBytes(rest, p)
		if err != nil {
			log.Println("dcpBlock.DecodeFromBytes error:", err)
			return err
		}
		rest = rest2

		d.Blocks = append(d.Blocks, *dcpBlock)
		len = len - decodedLen
	}
	p.AddLayer(d)

	return nil
}

func decodeProfinetRT(data []byte, p gopacket.PacketBuilder) error {
	// assertion, if data is too small
	// if len(data) < 10 {
	// 	return errors.New("Malformed Profinet DCP Packet")
	// }

	// d := &ProfinetDCP{}

	// d.ServiceID = PNDCPServiceID(data[0])
	// d.ServiceType = PNDCPServiceType(data[1])
	// d.Xid = binary.BigEndian.Uint32(data[2:6])
	// d.ResponseDelay = binary.BigEndian.Uint16(data[6:8])
	// d.DCPDataLength = binary.BigEndian.Uint16(data[8:10])

	// fmt.Println(*d)
	// p.AddLayer(d)

	return nil
}
