package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
)

type avpDecoder interface {
	decode([]byte) error
	getDecodedData() string
}

type diameterOctetString struct {
	decodedData string
	padding     uint32
}

type diameterInteger32 struct {
	decodedData int32
}

type diameterInteger64 struct {
	decodedData int64
}

type diameterUnsigned32 struct {
	decodedData uint32
}

type diameterUnsigned64 struct {
	decodedData uint64
}

type diameterFloat32 struct {
	decodedData float32
}

type diameterFloat64 struct {
	decodedData float64
}

type diameterIPAddress struct {
	decodedData string
}

func (d diameterIPAddress) getDecodedData() string   { return d.decodedData }
func (d diameterOctetString) getDecodedData() string { return d.decodedData }
func (d diameterInteger32) getDecodedData() string   { return strconv.Itoa(int(d.decodedData)) }
func (d diameterInteger64) getDecodedData() string   { return strconv.Itoa(int(d.decodedData)) }
func (d diameterFloat32) getDecodedData() string     { return fmt.Sprintf("%f", d.decodedData) }
func (d diameterFloat64) getDecodedData() string     { return fmt.Sprintf("%f", d.decodedData) }

func (d diameterUnsigned32) getDecodedData() string {
	return strconv.FormatUint(uint64(d.decodedData), 10)
}
func (d diameterUnsigned64) getDecodedData() string {
	return strconv.FormatUint(uint64(d.decodedData), 10)
}

func (d *diameterOctetString) decode(data []byte) error {
	dataLen := len(data)

	if dataLen == 0 {
		return errors.New("AVP contains no data to decode")
	}

	d.decodedData = string(data)

	return nil
}

func (d *diameterUnsigned32) decode(data []byte) error {

	if len(data) != 4 {
		return errors.New("not enough data to decode Unsigned Interger32")
	}

	d.decodedData = binary.BigEndian.Uint32(data)

	return nil
}

func (d *diameterUnsigned64) decode(data []byte) error {

	if len(data) != 8 {
		return errors.New("not enough data to decode Unsigned Interger64")
	}

	d.decodedData = binary.BigEndian.Uint64(data)

	return nil
}

func (d *diameterInteger32) decode(data []byte) error {

	if len(data) != 4 {
		return errors.New("not enough data to decode Unsigned Interger32")
	}

	d.decodedData = int32(binary.BigEndian.Uint32(data))

	return nil
}

func (d *diameterInteger64) decode(data []byte) error {

	if len(data) != 8 {
		return errors.New("not enough data to decode Unsigned Interger64")
	}

	d.decodedData = int64(binary.BigEndian.Uint64(data))

	return nil
}

func (d *diameterFloat32) decode(data []byte) error {

	if len(data) != 4 {
		return errors.New("not enough data to decode Unsigned Interger32")
	}

	d.decodedData = math.Float32frombits(binary.BigEndian.Uint32(data))

	return nil
}

func (d *diameterFloat64) decode(data []byte) error {

	if len(data) != 8 {
		return errors.New("not enough data to decode Unsigned Interger64")
	}

	d.decodedData = math.Float64frombits(binary.BigEndian.Uint64(data))

	return nil
}

func (d *diameterIPAddress) decode(data []byte) error {

	var ip net.IP
	// IPv4 is 4 bytes, IPv6 is 16 bytes. add 2 bytes each which is the chunk representing the type of the address (first two bits of data)
	if len(data) != 6 && len(data) != 18 {
		return errors.New("not enough data to decode Unsigned Interger64")
	}

	// byte 0 and 1 will representing the type of the address which is either v4 or v6 in the IP addresses case
	ip = data[2:]
	d.decodedData = ip.String()

	return nil
}

func getAVPFormatDecoder(avpFormat string) avpDecoder {
	switch avpFormat {
	case "OctetString":
		return &diameterOctetString{}
	case "Integer32":
		return &diameterInteger32{}
	case "Integer64":
		return &diameterInteger64{}
	case "Unsigned32":
		return &diameterUnsigned32{}
	case "Unsigned64":
		return &diameterUnsigned64{}
	case "Float32":
		return &diameterFloat32{}
	case "Float64":
		return &diameterFloat64{}
	case "DiameterIdentity":
		return &diameterOctetString{}
	case "IPAddress":
		return &diameterIPAddress{}
	case "UTF8String":
		return &diameterOctetString{}
	case "AppId":
		return &diameterUnsigned32{}
	case "VendorId":
		return &diameterUnsigned64{}
	default:
		// TODO: add other AVP Formats covered in RFC 6733
		return nil
	}
}
