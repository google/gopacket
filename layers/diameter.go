package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
)

const (
	headerLen              = 20
	avpHeaderLen           = 8
	avpHeaderLenWithVendor = 12
	vendorBit              = 1 << 7 // If this bit is set in the avp flags then the vendor ID is provided in the AVP
)

// paddedAVPFormates are AVP formates which could have a padding with zeros after them
var paddedAVPFormates = [...]string{"DiameterIdentity", "OctetString", "IPAddress", "UTF8String"}

// AVP contains dieferent parts of the diameter AVP defined in RFC 6733 section 4
type AVP struct {
	// Value in the header sectoin of the AVP
	AttributeCode   uint32
	AttributeName   string
	AttributeFormat string
	Flags           uint8
	HeaderLen       uint8
	Len             uint32
	VendorCode      uint32
	VendorName      string
	VendorID        string

	// the value associated with the Attribute, padding with zeros is sometimes added after the value in some case
	DecodedValue string
	Padding      uint32
	Value        []byte
	ValueLen     uint32

	// Used to decode the specific format of the AVP
	decoder avpDecoder

	Grouped []*AVP
}

func (a *AVP) IsVendorSpecific() bool {
	return a.Flags&128 != 0
}
func (a *AVP) IsMandatory() bool {
	return a.Flags&64 != 0
}
func (a *AVP) IsProtected() bool {
	return a.Flags&32 != 0
}

func (a *AVP) setVendor(data []byte) {
	a.HeaderLen = avpHeaderLenWithVendor

	if len(data) == 4 {
		a.VendorCode = binary.BigEndian.Uint32(data)
		VendorDetails, ok := diameterVendors[a.VendorCode]
		if ok {
			a.VendorID = VendorDetails.vendorID
			a.VendorName = VendorDetails.vendorName
		}
	}
}

func (a *AVP) setAttribute() error {
	var ok bool
	var avpDetails avpType

	if a.VendorCode != 0 {
		avpDetails, ok = vendorsAvps[a.VendorCode][a.AttributeCode]
	} else {
		avpDetails, ok = avpCodes[a.AttributeCode]
	}

	if ok {
		a.AttributeName = avpDetails.name
		a.AttributeFormat = avpDetails.format
		return nil
	}
	return fmt.Errorf("could not find details for AVP attribute code %d (vendor %d)", a.AttributeCode, a.VendorCode)
}

func (a *AVP) setDecoder() error {
	if a.AttributeFormat != "" {
		a.decoder = getAVPFormatDecoder(a.AttributeFormat, a.AttributeCode)
	}
	if a.decoder == nil {
		return fmt.Errorf("could not decode avp, format type '%s' is not yet supported", a.AttributeFormat)
	}
	return nil
}

func (a *AVP) decodeAVPHeader(data []byte) error {
	var err error
	avpVendorIDExists := a.Flags&vendorBit == vendorBit

	if avpVendorIDExists {
		a.setVendor(data[8:12])
	} else {
		a.HeaderLen = 8
	}

	err = a.setAttribute()
	if err != nil {
		return err
	}

	err = a.setDecoder()
	if err != nil {
		return err
	}

	return nil
}

func (a *AVP) decodeValue(data []byte) {
	a.Value = data
	a.decoder.decode(a.Value)
	a.DecodedValue = a.decoder.getDecodedData()
}

func (a *AVP) setPadding() {
	var flag bool

	for _, b := range paddedAVPFormates {

		if a.AttributeFormat == b {
			flag = true
			break
		}
	}

	if flag {
		if a.Len%4 != 0 {
			a.Padding = uint32((a.Len|3)+1) - a.Len
		}
	}
}

// Diameter is the layer for Application layer protocol Diameter
type Diameter struct {
	BaseLayer

	// Diameter Header Information
	Version       uint8
	Flags         uint8
	MessageLen    uint32
	CommandCode   uint32
	ApplicationID uint32
	HopByHopID    uint32
	EndToEndID    uint32

	// Diameter AVPs (Attribute Value Pair)
	AVPs []*AVP
}

// LayerType returns gopacket.LayerTypeDiameter
func (d *Diameter) LayerType() gopacket.LayerType { return LayerTypeDiameter }

// Payload for Diameter is nil; no other layers encapsulated by it
func (d *Diameter) Payload() []byte {
	return nil
}

func (d *Diameter) IsRequest() bool {
	return d.Flags&128 != 0
}
func (d *Diameter) IsAnswer() bool {
	return !d.IsRequest()
}
func (d *Diameter) IsProxyable() bool {
	return d.Flags&64 != 0
}
func (d *Diameter) IsError() bool {
	return d.Flags&32 != 0
}

func decodeAVP(data []byte) (*AVP, error) {
	avp := new(AVP)
	avp.Flags = data[4]
	avp.AttributeCode = binary.BigEndian.Uint32(data[0:4])
	avp.Len = binary.BigEndian.Uint32(append([]byte{0}, data[5:8]...))

	// if true, message either trancated or malformed
	if len(data) < int(avp.Len) {
		return avp, fmt.Errorf("could not decode avp. Provided avp length: %d, available bites to decode %d", avp.Len, len(data))
	}

	avpChunk := data[:avp.Len]
	err := avp.decodeAVPHeader(avpChunk)

	if err != nil {
		return avp, err
	}

	avp.decodeValue(avpChunk[avp.HeaderLen:])
	avp.setPadding()

	// if group, iterate through
	if avp.AttributeFormat == "Grouped" {
		avp.Grouped = make([]*AVP, 0)
		data = avp.Value
		i := 0
		for i < len(data) {
			avp2, err := decodeAVP(data[i:])
			if err != nil {
				return avp, err
			}
			avp.Grouped = append(avp.Grouped, avp2)
			i += int(avp2.Len + avp2.Padding)
		}
	}

	avpValueLength := avp.Len - uint32(avp.HeaderLen)
	if len(avp.Value) < int(avpValueLength) {
		return avp, fmt.Errorf("could not decode avp. Calculated avp value length: %d, Actual Value length %d",
			int(avpValueLength), len(avp.Value))
	}

	return avp, nil
}

func (d *Diameter) decodeDiameterAVPs(data []byte) (int, error) {
	var avp *AVP
	var err error

	i := 0 // will eventually represent the number of decoded bytes, so it is definied in this scope
	for i < len(data) {

		if len(data[i:]) < 8 {
			return i, errors.New("cannot form diameter avp, message too short")
		}

		avp, err = decodeAVP(data[i:])
		if err != nil {
			return i, err
		}

		d.AVPs = append(d.AVPs, avp)
		i += int(avp.Len + avp.Padding)
	}
	return i, nil
}

func (d *Diameter) decodeDiameterHeader(data []byte) error {
	if len(data) < headerLen {
		return errors.New("cannot form diameter header, message too short")
	}

	headerBytes := data[:headerLen]
	d.Version = headerBytes[0]
	d.Flags = headerBytes[4]

	// the Message leng is a 3 octate value (24 bits), the code line pads it with 0 and interpret it as uint32
	d.MessageLen = binary.BigEndian.Uint32(append([]byte{0}, headerBytes[1:4]...))
	d.CommandCode = binary.BigEndian.Uint32(append([]byte{0}, headerBytes[5:8]...))

	d.ApplicationID = binary.BigEndian.Uint32(headerBytes[8:12])
	d.HopByHopID = binary.BigEndian.Uint32(headerBytes[12:16])
	d.EndToEndID = binary.BigEndian.Uint32(headerBytes[16:20])

	return nil
}

// DecodeFromBytes recieves the application layer payload bytes, translates them into diameter Header and AVPs and
func (d *Diameter) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	err := d.decodeDiameterHeader(data)
	if err != nil {
		return err
	}

	decodedAVPsBytesLen, err := d.decodeDiameterAVPs(data[headerLen:])
	if err != nil {
		return err
	}

	totalDecodedContentLen := decodedAVPsBytesLen + headerLen
	d.BaseLayer = BaseLayer{Contents: data[:totalDecodedContentLen]}

	return nil
}

func decodeDiameter(data []byte, p gopacket.PacketBuilder) error {
	diameter := new(Diameter)

	err := diameter.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}

	p.AddLayer(diameter)
	p.SetApplicationLayer(diameter)

	return nil
}
