// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
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


// TODO: dissect_linux_usb_pseudo_header_ext
// TODO: mmapp
// URB: USB Request Block

type USBEventType uint8

const (
	USBEventTypeSubmit           USBEventType = 'S'
	USBEventTypeComplete         USBEventType = 'C'
	USBEventTypeError            USBEventType = 'E'
)

func (a USBEventType) String() string {
	switch a {
	case USBEventTypeSubmit:
		return "SUBMIT"
	case USBEventTypeComplete:
		return "COMPLETE"
	case USBEventTypeError:
		return "ERROR"
	default:
		return "Unknown event type"
	}
}

type UsbUrbSetupRequest uint8

const (
	UsbUrbSetupRequestGetStatus                 UsbUrbSetupRequest = 0x00
	UsbUrbSetupRequestClearFeature              UsbUrbSetupRequest = 0x01
	UsbUrbSetupRequestSetFeature                UsbUrbSetupRequest = 0x03
	UsbUrbSetupRequestSetAddress                UsbUrbSetupRequest = 0x05
	UsbUrbSetupRequestGetDescriptor             UsbUrbSetupRequest = 0x06
	UsbUrbSetupRequestSetDescriptor             UsbUrbSetupRequest = 0x07
	UsbUrbSetupRequestGetConfiguration          UsbUrbSetupRequest = 0x08
	UsbUrbSetupRequestSetConfiguration          UsbUrbSetupRequest = 0x09
	UsbUrbSetupRequestSetIdle                   UsbUrbSetupRequest = 0x0a
)

func (a UsbUrbSetupRequest) String() string {
	switch a {
            case UsbUrbSetupRequestGetStatus:
		return "GET_STATUS"
            case UsbUrbSetupRequestClearFeature:
		return "CLEAR_FEATURE"
            case UsbUrbSetupRequestSetFeature:
		return "SET_FEATURE"
            case UsbUrbSetupRequestSetAddress:
		return "SET_ADDRESS"
            case UsbUrbSetupRequestGetDescriptor:
		return "GET_DESCRIPTOR"
            case UsbUrbSetupRequestSetDescriptor:
		return "SET_DESCRIPTOR"
            case UsbUrbSetupRequestGetConfiguration:
		return "GET_CONFIGURATION"
            case UsbUrbSetupRequestSetConfiguration:
		return "SET_CONFIGURATION"
            case UsbUrbSetupRequestSetIdle:
		return "SET_IDLE"
            default:
                return "UNKNOWN"
	}
}



type USBTransportType uint8

const (
	USBTransportTypeTransferIn           USBTransportType = 0x80
	USBTransportTypeIsochronous         USBTransportType = 0x00
	USBTransportTypeInterrupt            USBTransportType = 0x01
	USBTransportTypeControl            USBTransportType = 0x02
	USBTransportTypeBulk            USBTransportType = 0x03
)

func (a USBTransportType) LayerType() gopacket.LayerType {
	return UsbTypeMetadata[a].LayerType
}

func (a USBTransportType) String() string {
	switch a {
	case USBTransportTypeTransferIn:
		return "Transfer In"
	case USBTransportTypeIsochronous:
		return "Isochronous"
	case USBTransportTypeInterrupt:
		return "Interrupt"
	case USBTransportTypeControl:
		return "Control"
	case USBTransportTypeBulk:
		return "Bulk"
	default:
		return "Unknown transport type"
	}
}

type USBDirectionType uint8

const (
        USBDirectionTypeUnknown                 USBDirectionType = iota
        USBDirectionTypeIn
	USBDirectionTypeOut
)

func (a USBDirectionType) String() string {
	switch a {
	case USBDirectionTypeIn:
		return "In"
	case USBDirectionTypeOut:
		return "Out"
	default:
		return "Unknown direction type"
	}
}

type Usb struct {
	BaseLayer
        Id uint64
        EventType USBEventType
        TransferType USBTransportType
        Direction USBDirectionType
        EndpointNumber uint8
        DeviceAddress uint8
        BusId uint16
        TimestampSec int64
        TimestampUsec int32
        SetupFlag bool
        DataFlag bool
        Status int32
        UrbLength uint32
        UrbDataLength uint32

        UrbInterval uint32
        UrbStartFrame uint32
        UrbCopyOfTransferFlags uint32
        IsoNumDesc uint32
}

func (u *Usb) LayerType() gopacket.LayerType { return LayerTypeUsb }

func (m *Usb) NextLayerType() gopacket.LayerType { 
    if (m.SetupFlag) {
        return LayerTypeUsbUrbSetup 
    } else if (m.DataFlag) {
    } 

    return m.TransferType.LayerType()
}

func decodeUsb(data []byte, p gopacket.PacketBuilder) error {
	d := &Usb{
	}
        
	return decodingLayerDecoder(d, data, p)
}


func (m *Usb) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	m.Id = binary.LittleEndian.Uint64(data[0:8])
	m.EventType = USBEventType(data[8])
	m.TransferType = USBTransportType(data[9])

        endPointByte := uint8(data[10]) 
	m.EndpointNumber = endPointByte & 0x7f
    
        if (endPointByte & uint8(USBTransportTypeTransferIn) > 0) {
            m.Direction = USBDirectionTypeIn
        } else {
            m.Direction = USBDirectionTypeOut
        }

        m.DeviceAddress = uint8(data[11])
        m.BusId = binary.LittleEndian.Uint16(data[12:14])

        if uint(data[14]) == 0  {
            // Setupflag
            m.SetupFlag = true

            // TODO: Check transfer type for URB_CONTROL
        } 

        if uint(data[15]) == 0  {
            // Dataflag
            m.DataFlag = true
        } 

	m.TimestampSec = int64(binary.LittleEndian.Uint64(data[16:24]))
	m.TimestampUsec = int32(binary.LittleEndian.Uint32(data[24:28]))
	m.Status = int32(binary.LittleEndian.Uint32(data[28:32]))
	m.UrbLength = binary.LittleEndian.Uint32(data[32:36])
	m.UrbDataLength = binary.LittleEndian.Uint32(data[36:40])

        m.Contents = data[:40]
        // 24 bytes?
        // data length vs urb length?
        m.Payload = data[40:]

        if (m.SetupFlag) {
            m.Payload = data[40:]
        } else if (m.DataFlag) {
            m.Payload = data[uint32(len(data)) - m.UrbDataLength:]
        }

        // if 64 bit, dissect_linux_usb_pseudo_header_ext
        if (false) {
            m.UrbInterval = binary.LittleEndian.Uint32(data[40:44])
            m.UrbStartFrame = binary.LittleEndian.Uint32(data[44:48])
            m.UrbDataLength = binary.LittleEndian.Uint32(data[48:52])
            m.IsoNumDesc = binary.LittleEndian.Uint32(data[52:56])
            m.Contents = data[:56]
            m.Payload = data[56:]
        }

        // crc5 or crc16
        // eop (end of packet)

	return nil
}

type UsbUrbSetup struct {
	BaseLayer
        RequestType uint8
        Request UsbUrbSetupRequest
        Value uint16
        Index uint16
        Length uint16
}

func (u *UsbUrbSetup) LayerType() gopacket.LayerType { return LayerTypeUsbUrbSetup }

func (m *UsbUrbSetup) NextLayerType() gopacket.LayerType { 
    // TODO: if m.Request == UsbUrbSetupRequestGetDescriptor && Response
    return gopacket.LayerTypePayload
}

func (m *UsbUrbSetup) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.RequestType = uint8(data[0])
    m.Request = UsbUrbSetupRequest(data[1])
    m.Value = binary.LittleEndian.Uint16(data[2:4])
    m.Index = binary.LittleEndian.Uint16(data[4:6])
    m.Length = binary.LittleEndian.Uint16(data[6:8])
    m.Contents = data[:8]
    m.Payload = data[8:]
    return nil
}

func decodeUsbUrbSetup(data []byte, p gopacket.PacketBuilder) error {
	d := &UsbUrbSetup{
	}
        
	return decodingLayerDecoder(d, data, p)
}

type UsbControl struct {
	BaseLayer
}

func (u *UsbControl) LayerType() gopacket.LayerType { return LayerTypeUsbControl }

func (m *UsbControl) NextLayerType() gopacket.LayerType { 
    return gopacket.LayerTypePayload 
}

func (m *UsbControl) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Contents = data
    fmt.Println("Control", data)
    return nil
}

func decodeUsbControl(data []byte, p gopacket.PacketBuilder) error {
        
	d := &UsbControl{
	}
        
	return decodingLayerDecoder(d, data, p)
}

type UsbInterrupt struct {
	BaseLayer
}

func (u *UsbInterrupt) LayerType() gopacket.LayerType { return LayerTypeUsbInterrupt }

func (m *UsbInterrupt) NextLayerType() gopacket.LayerType { 
    return gopacket.LayerTypePayload
}

func (m *UsbInterrupt) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Contents = data
    return nil
}

func decodeUsbInterrupt(data []byte, p gopacket.PacketBuilder) error {
	d := &UsbInterrupt{
	}
        
	return decodingLayerDecoder(d, data, p)
}

type UsbBulk struct {
	BaseLayer
}

func (u *UsbBulk) LayerType() gopacket.LayerType { return LayerTypeUsbBulk }

func (m *UsbBulk) NextLayerType() gopacket.LayerType { 
    return gopacket.LayerTypePayload
}

func (m *UsbBulk) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Contents = data
    return nil
}

func decodeUsbBulk(data []byte, p gopacket.PacketBuilder) error {
	d := &UsbBulk{
	}
        
	return decodingLayerDecoder(d, data, p)
}
