// Copyright 2017 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
)

const (
	MBAPHeaderLen      int    = 7
	MinModbusPacketLen int    = MBAPHeaderLen + 1
	modbusPort         uint16 = 502
)

var (
	ErrDataTooSmall = errors.New("Data too small for Modbus")
)

type FC byte

type MBAP struct {
	TransactionID uint16
	ProtocolID    uint16
	Length        uint16
	UnitID        uint8
}

type Modbus struct {
	BaseLayer
	MBAP
	FunctionCode FC
}

func init() {
	RegisterTCPPortLayerType(TCPPort(modbusPort), LayerTypeModbus)
}

func (m *Modbus) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < MinModbusPacketLen {
		df.SetTruncated()
		return ErrDataTooSmall
	}
	m.TransactionID = binary.BigEndian.Uint16(data[0:2])
	m.ProtocolID = binary.BigEndian.Uint16(data[2:4])
	m.Length = binary.BigEndian.Uint16(data[4:6])
	m.UnitID = data[6]
	m.FunctionCode = FC(data[7])
	m.Contents = data[:8]
	if len(data) > 7 {
		m.Payload = data[8:]
	}
	return nil
}

func (m *Modbus) LayerType() gopacket.LayerType {
	return LayerTypeModbus
}

func (m *Modbus) NextLayerType() gopacket.LayerType {
	if m.FunctionCode.exception() {
		return LayerTypeModbusException
	}
	return gopacket.LayerTypeZero
}

func (m *Modbus) CanDecode() gopacket.LayerClass {
	return LayerTypeModbus
}

func decodeModbus(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < MinModbusPacketLen {
		return ErrDataTooSmall
	}
	modbus := &Modbus{}
	return decodingLayerDecoder(modbus, data, p)
}

func (fc FC) exception() bool {
	return (byte(fc) & 0x80) != 0
}

func (fc FC) masked() FC {
	return fc & 0x7F
}

func (fc FC) String() (s string) {
	if fc.exception() {
		s = `Exception: `
		fc = fc.masked() //we aren't passing by pointer, so its not a problem to reuse
	}

	switch fc {
	case 1:
		s += `Read Coil`
	case 2:
		s += `Read Discrete Inputs`
	case 3:
		s += `Read Holding Registers`
	case 4:
		s += `Read Input Registers`
	case 5:
		s += `Write Single Coil`
	case 6:
		s += `Wright Single Register`
	case 7:
		s += `Read Exception Status`
	case 8:
		s += `Diagnostics`
	case 0xb:
		s += `Get Comm Event Counter`
	case 0xc:
		s += `Get Comm Event Log`
	case 0xF:
		s += `Write Multiple Coils`
	case 0x10:
		s += `Write Multiple Registers`
	case 0x11:
		s += `Report Slave ID`
	case 0x14:
		s += `Read File Record`
	case 0x15:
		s += `Write File Record`
	case 0x16:
		s += `Mask Write Register`
	case 0x17:
		s += `Read/Write Multiple Registers`
	case 0x18:
		s += `Read FIFO Queue`
	case 0x2B:
		s += `General References Request`
	default:
		s += `UNKNOWN`
	}
	return
}

/* Modbus Exception response structures */
type ModbusException struct {
	BaseLayer
	Exception byte
}

func decodeModbusException(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < 1 {
		return ErrDataTooSmall
	}
	mbe := &ModbusException{}
	return decodingLayerDecoder(mbe, data, p)
}

func (mbe *ModbusException) LayerType() gopacket.LayerType     { return LayerTypeModbusException }
func (mbe *ModbusException) CanDecode() gopacket.LayerClass    { return LayerTypeModbusException }
func (mbe *ModbusException) NextLayerType() gopacket.LayerType { return gopacket.LayerTypeZero }

func (mbe *ModbusException) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 1 {
		df.SetTruncated()
		return ErrDataTooSmall
	}
	mbe.Exception = data[0]
	mbe.Contents = data[:1]
	mbe.Payload = data[1:]
	return nil
}

func (mbe *ModbusException) String() string {
	switch mbe.Exception {
	case 1:
		return `ILLEGAL FUNCTION`
	case 2:
		return `ILLEGAL DATA ADDRESS`
	case 3:
		return `ILLEGAL DATA VALUE`
	case 4:
		return `SLAVE DEVICE FAILURE`
	case 5:
		return `ACKNOWLEDGE`
	case 6:
		return `SLAVE DEVICE BUSY`
	case 8:
		return `MEMORY PARITY ERROR`
	case 0xA:
		return `GATEWAY PATH UNAVAILABLE`
	case 0xB:
		return `GATEWAY TARGET DEVICE FAILED TO RESPONSE`
	}
	return `UNKNOWN EXCEPTION`
}
