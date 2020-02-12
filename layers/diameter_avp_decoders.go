package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"
)

type avpDecoder interface {
	decode([]byte) error
	getDecodedData() string
}

type diameterOctetString struct {
	decodedData string
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

type diameterEnumerated struct { // vendor code?
	attributeCode uint32
	decodedData   uint32
}

type diameterTime struct {
	decodedData time.Time
}

func (d diameterIPAddress) getDecodedData() string {
	if len(d.decodedData) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", d.decodedData[0], d.decodedData[1], d.decodedData[2], d.decodedData[3])
	} // TODO ipv6
	return d.decodedData
}
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
func (d diameterEnumerated) getDecodedData() string {
	return avpAttributeEnumerations[d.attributeCode][d.decodedData]
}
func (d diameterTime) getDecodedData() string {
	return d.decodedData.String()
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
		return errors.New("not enough data to decode Unsigned Integer32")
	}

	d.decodedData = binary.BigEndian.Uint32(data)

	return nil
}

func (d *diameterUnsigned64) decode(data []byte) error {

	if len(data) != 8 {
		return errors.New("not enough data to decode Unsigned Integer64")
	}

	d.decodedData = binary.BigEndian.Uint64(data)

	return nil
}

func (d *diameterInteger32) decode(data []byte) error {

	if len(data) != 4 {
		return errors.New("not enough data to decode Unsigned Integer32")
	}

	d.decodedData = int32(binary.BigEndian.Uint32(data))

	return nil
}

func (d *diameterInteger64) decode(data []byte) error {

	if len(data) != 8 {
		return errors.New("not enough data to decode Unsigned Integer64")
	}

	d.decodedData = int64(binary.BigEndian.Uint64(data))

	return nil
}

func (d *diameterFloat32) decode(data []byte) error {

	if len(data) != 4 {
		return errors.New("not enough data to decode Unsigned Integer32")
	}

	d.decodedData = math.Float32frombits(binary.BigEndian.Uint32(data))

	return nil
}

func (d *diameterFloat64) decode(data []byte) error {

	if len(data) != 8 {
		return errors.New("not enough data to decode Unsigned Integer64")
	}

	d.decodedData = math.Float64frombits(binary.BigEndian.Uint64(data))

	return nil
}

func (d *diameterIPAddress) decode(data []byte) error {

	var ip net.IP
	// IPv4 is 4 bytes, IPv6 is 16 bytes. add 2 bytes each which is the chunk representing the type of the address (first two bits of data)
	if len(data) != 6 && len(data) != 18 {
		return errors.New("not enough data to decode Unsigned Integer64")
	}

	// byte 0 and 1 will representing the type of the address which is either v4 or v6 in the IP addresses case
	ip = data[2:]
	d.decodedData = ip.String()

	return nil
}

func (d *diameterEnumerated) decode(data []byte) error {

	if len(data) != 4 {
		return errors.New("not enough data to decode Enumerated (Unsigned Integer32)")
	}

	d.decodedData = binary.BigEndian.Uint32(data)

	return nil
}

func (d *diameterTime) decode(data []byte) error {

	// RFC6733 specifies Time as octetstring, but with length of 4 and uint32 defined as having network
	// byte order (big endian), it is equivalent to uint32.
	if len(data) != 4 {
		return errors.New("not enough data to decode Time")
	}
	ntp_timestamp := binary.BigEndian.Uint32(data)
	unix_timestamp := int64(ntp_timestamp) - 2208988800

	// if we see a date < year 2000, then we've overflowed into the next NTP era
	if ntp_timestamp < 3174737699 {
		unix_timestamp += int64(^uint32(0)) + 1
	}

	d.decodedData = time.Unix(unix_timestamp, 0)

	return nil
}

func getAVPFormatDecoder(avpFormat string, attributeCode uint32) avpDecoder {
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
	case "Enumerated":
		// parse value as Unsigned32, map value per attributeCode
		return &diameterEnumerated{attributeCode: attributeCode}
	case "Time":
		return &diameterTime{}
	case "Grouped":
		return &diameterOctetString{}
	default:
		// TODO: add other AVP Formats covered in RFC 6733
		// IPFilterRule, DiameterURI
		return nil
	}
}
