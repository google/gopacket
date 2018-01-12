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
	ErrModbusDataTooSmall = errors.New("Data too small for Modbus")
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
	FunctionCode uint8
	Exception    bool
	ReqResp      []byte
}

func init() {
	RegisterTCPPortLayerType(TCPPort(modbusPort), LayerTypeModbus)
}

func (m *Modbus) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < MinModbusPacketLen {
		df.SetTruncated()
		return ErrModbusDataTooSmall
	}
	m.TransactionID = binary.BigEndian.Uint16(data[0:2])
	m.ProtocolID = binary.BigEndian.Uint16(data[2:4])
	m.Length = binary.BigEndian.Uint16(data[4:6])
	m.UnitID = data[6]
	m.Exception = FC(data[7]).exception()
	m.FunctionCode = data[7] & 0x7f
	end := int(m.Length) + 6
	if len(data) < end || end < 8 {
		df.SetTruncated()
		return ErrModbusDataTooSmall
	}
	m.ReqResp = data[8:end]
	m.Contents = data[:end]
	m.Payload = data[end:]
	return nil
}

func (m *Modbus) LayerType() gopacket.LayerType {
	return LayerTypeModbus
}

func (m *Modbus) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (m *Modbus) CanDecode() gopacket.LayerClass {
	return LayerTypeModbus
}

func decodeModbus(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < MinModbusPacketLen {
		p.SetTruncated()
		return ErrModbusDataTooSmall
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
