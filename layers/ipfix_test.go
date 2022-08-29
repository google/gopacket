package layers

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/gopacket"
)

var udpHeader = []byte{
	0x84, 0x2b, 0x2b, 0x16, 0x8b, 0x62, 0xf0, 0x50, 0x56, 0x85, 0x3a, 0xfd, 0x08, 0x00, 0x45, 0x00,
	0x05, 0xbc, 0x9c, 0x04, 0x40, 0x00, 0xff, 0x11, 0xc7, 0x00, 0x0a, 0x01, 0xff, 0x0e, 0x0a, 0x01,
	0x00, 0x1b, 0xc7, 0x57, 0x12, 0x83, 0x00, 0x18, 0x22, 0x3b,
}

var header = []byte{
	0x00, 0x0a, // Version Number 10
	0x00, 0x00, // Length (should be 140 bytes for that sample)
	0x61, 0x84, 0xa6, 0xd4, // Export Time 1636083412
	0x00, 0x00, 0x00, 0x00, // Sequence Number 0
	0x00, 0x00, 0x00, 0x01, // Observation Domain ID 1
}

var templateSetHeader = []byte{
	0x00, 0x02, // Template Set ID
	0x00, 0x00, // Length (should be 124 bytes for that sample)
}

var templateRecord1 = []byte{
	0x01, 0x00, //             ID 256
	0x00, 0x14, //             Field Count 20
	0x00, 0x08, 0x00, 0x04, // FS  1
	0x00, 0x0c, 0x00, 0x04, // FS  2
	0x00, 0x07, 0x00, 0x02, // FS  3
	0x00, 0x0b, 0x00, 0x02, // FS  4
	0x00, 0x04, 0x00, 0x01, // FS  5
	0x00, 0x96, 0x00, 0x04, // FS  6
	0x00, 0x97, 0x00, 0x04, // FS  7
	0x00, 0x88, 0x00, 0x01, // FS  8
	0x00, 0x56, 0x00, 0x08, // FS  9
	0x00, 0x02, 0x00, 0x08, // FS 10
	0x00, 0x55, 0x00, 0x08, // FS 11
	0x80, 0x65, 0xff, 0xff, // FS 12
	0x00, 0x00, 0xdc, 0xba, // Enterprise ID 56506
	0x80, 0x67, 0xff, 0xff, // FS 13
	0x00, 0x00, 0xdc, 0xba, // Enterprise ID 56506
	0x80, 0x6c, 0x00, 0x02, // FS 14
	0x00, 0x00, 0xdc, 0xba, // Enterprise ID 56506
	0x80, 0x89, 0x00, 0x01, // FS 15
	0x00, 0x00, 0xdc, 0xba, // Enterprise ID 56506
	0x80, 0x88, 0xff, 0xff, // FS 16
	0x00, 0x00, 0xdc, 0xba, // Enterprise ID 56506
	0x80, 0x6a, 0x00, 0x04, // FS 17
	0x00, 0x00, 0xdc, 0xba, // Enterprise ID 56506
	0x80, 0x56, 0x00, 0x08, // FS 18
	0x00, 0x00, 0x72, 0x79, // Enterprise ID 29305
	0x80, 0x02, 0x00, 0x08, // FS 19
	0x00, 0x00, 0x72, 0x79, // Enterprise ID 29305
	0x80, 0x55, 0x00, 0x08, // FS 20
	0x00, 0x00, 0x72, 0x79, // Enterprise ID 29305
}

var templateRecord2 = []byte{
	0x01, 0x01, //             ID 257
	0x00, 0x02, //             Field Count 2
	0x00, 0x08, 0x00, 0x04, // FS  1
	0x00, 0x0c, 0x00, 0x04, // FS  2
}

var optionTemplateSetHeader = []byte{
	0x00, 0x03, // Option Template ID
	0x00, 0x00, // Length (should be 124 bytes for that sample)
}

var optionTemplateRecord1 = []byte{
	0x01, 0x01, //             ID 257
	0x00, 0x03, //             Field count 3
	0x00, 0x02, //             Scoped Field Count 2
	0x80, 0x6c, 0x00, 0x02, // FS 1 (14)
	0x00, 0x00, 0xdc, 0xba, // Enterprise ID 56506
	0x00, 0x07, 0x00, 0x02, // FS 2 (3)
	0x00, 0x56, 0x00, 0x08, // FS 3 (9)
}

var optionTemplateRecord2 = []byte{
	0x01, 0x02, //             ID 258
	0x00, 0x02, //             Field count 2
	0x00, 0x01, //             Scoped Field Count 1
	0x00, 0x07, 0x00, 0x02, // FS 1 (3)
	0x00, 0x56, 0x00, 0x08, // FS 2 (9)
}

var dataSetHeader = []byte{
	0x01, 0x00, // Template ID 256
	0x00, 0x00, // Length (should be 99 bytes for that sample)
}

var dataRecord = []byte{
	0x0a, 0x00, 0x00, 0x01, //                                                 F  1
	0x0a, 0x00, 0x00, 0x02, //                                                 F  2
	0x04, 0xd2, //                                                             F  3
	0x16, 0x2e, //                                                             F  4
	0x06,                   //                                                 F  5
	0x4a, 0xf9, 0xec, 0x88, //                                                 F  6
	0x4a, 0xf9, 0xf0, 0x70, //                                                 F  7
	0x02,                                           //                         F  8
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, //                         F  9
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xf4, //                         F 10
	0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x35, 0x00, //                         F 11
	0x04, 0x70, 0x6f, 0x64, 0x31, //                                           F 12
	0x00,       //                                                             F 13
	0x12, 0x83, //                                                             F 14
	0x02,                                                                   // F 15
	0x0b, 0x45, 0x53, 0x54, 0x41, 0x42, 0x4c, 0x49, 0x53, 0x48, 0x45, 0x44, // F 16
	0x0a, 0x00, 0x00, 0x03, //                                                 F 17
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2c, //                         F 18
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96, //                         F 19
	0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x35, 0x00, //                         F 20
}

var optionDataSetHeader = []byte{
	0x01, 0x01, // Template ID 257
	0x00, 0x00, // Length (should be 99 bytes for that sample)
}

var optionDataRecord = []byte{
	0x12, 0x83, //                                     F 1
	0x04, 0xd2, //                                     F 2
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, // F 3
}

var dataWithTemplateStr = "000a00405685b3700000000000bc614e000200140100000300080004000c0004000200040100001cc0a800c9c0a80001000000ebc0a800cac0a800010000002a"

// var dataPacket1IPv4 = []byte{0x00, 0x0a, 0x00, 0x73, 0x61, 0x84, 0xa6, 0xd4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x63, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x04, 0xd2, 0x16, 0x2e, 0x06, 0x4a, 0xf9, 0xec, 0x88, 0x4a, 0xf9, 0xf0, 0x70, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x35, 0x00, 0x04, 0x70, 0x6f, 0x64, 0x31, 0x00, 0x12, 0x83, 0x02, 0x0b, 0x45, 0x53, 0x54, 0x41, 0x42, 0x4c, 0x49, 0x53, 0x48, 0x45, 0x44, 0x0a, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x35, 0x00}
// var dataPacket2IPv4 = []byte{0x00, 0x0a, 0x00, 0x73, 0x61, 0x84, 0xa6, 0xd4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x63, 0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x04, 0xd2, 0x16, 0x2e, 0x06, 0x4a, 0xf9, 0xec, 0x88, 0x4a, 0xf9, 0xf8, 0x40, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40, 0x00, 0x04, 0x70, 0x6f, 0x64, 0x32, 0x00, 0x00, 0x02, 0x0b, 0x45, 0x53, 0x54, 0x41, 0x42, 0x4c, 0x49, 0x53, 0x48, 0x45, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x42, 0x40}

var opts = []cmp.Option{
	cmp.AllowUnexported(IPFIXTemplateRecord{}),
	cmp.AllowUnexported(IPFIXOptionTemplateRecord{}),
	cmpopts.IgnoreUnexported(IPFIXDataRecord{}),
}

func setLengthHeader(data []byte) {
	if len(data) > 4 {
		binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	}
}

func TestDecodeUDPIPFIX(t *testing.T) {
	setLengthHeader(header)
	payload := append(udpHeader, header...)

	p := gopacket.NewPacket(payload, LayerTypeEthernet, gopacket.Default)
	if p.ErrorLayer() != nil {
		t.Error("Failed to decode packet:", p.ErrorLayer().Error())
	}

	checkLayers(p, []gopacket.LayerType{LayerTypeEthernet, LayerTypeIPv4, LayerTypeUDP, gopacket.LayerTypePayload}, t)
	if got, ok := p.TransportLayer().(*UDP); ok {
		if !reflect.DeepEqual(payload[34:42], got.LayerContents()) {
			t.Errorf("UDP layer contents mismatch, \nwant  %#v\ngot %#v\n", header, got.LayerContents())
		}
		if !reflect.DeepEqual(payload[42:], got.LayerPayload()) {
			t.Errorf("UDP layer payload mismatch, \nwant  %#v\ngot %#v\n", header, got.LayerPayload())
		}
		if got.SrcPort != 51031 {
			t.Errorf("UDP layer source port mismatch, want 51031 got %d\n", got.SrcPort)
		}
		if got.DstPort != 4739 {
			t.Errorf("UDP layer destination port mismatch, want 4739 got %d\n", got.DstPort)
		}
		if got.Length != 24 {
			t.Errorf("UDP layer length mismatch, want 24 got %d\n", got.Length)
		}
		if got.Checksum != 8763 {
			t.Errorf("UDP layer checksum mismatch, want 8763 got %d\n", got.Checksum)
		}
		want := &UDP{
			BaseLayer:     BaseLayer{payload[34:42], payload[42:]},
			SrcPort:       51031,
			DstPort:       4739,
			Length:        24,
			Checksum:      8763,
			sPort:         []byte{0xc7, 0x57},
			dPort:         []byte{0x12, 0x83},
			tcpipchecksum: tcpipchecksum{},
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("UDP layer mismatch, \nwant  %#v\ngot %#v\n", want, got)
		}
	} else {
		t.Error("Transport layer packet not UDP")
	}
}

// TODO:
//  - add TCP and SCTP transport test

func TestIPFIXHeader(t *testing.T) {
	invalidLength := append([]byte{}, header[:len(header)-1]...)
	setLengthHeader(invalidLength)

	invalidDataLength := append([]byte{}, header...)
	invalidDataLength = append(invalidDataLength, 0x00)
	setLengthHeader(invalidDataLength)
	invalidDataLength = invalidDataLength[:len(invalidDataLength)-1]

	invalidVersion := append([]byte{}, header...)
	invalidVersion[1] = 0x05
	setLengthHeader(invalidVersion)

	validHeader := append([]byte{}, header...)
	setLengthHeader(validHeader)

	tests := []struct {
		name    string
		payload []byte
		want    IPFIXMessageHeader
		wantErr bool
	}{
		{"invalid header length", invalidLength, IPFIXMessageHeader{}, true},
		{"invalid data length", invalidDataLength, IPFIXMessageHeader{}, true},
		{"invalid header version", invalidVersion, IPFIXMessageHeader{}, true},
		{
			"valid header",
			validHeader,
			IPFIXMessageHeader{
				Version:             10,
				Length:              uint16(len(header)),
				ExportTime:          1636083412,
				SequenceNumber:      0,
				ObservationDomainID: 1,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := gopacket.NewPacket(tt.payload, LayerTypeIPFIX, gopacket.Default)
			if (p.ErrorLayer() != nil) != tt.wantErr {
				t.Errorf("New gopacket IPFIX error = %v, wantErr %v", p.ErrorLayer().Error(), tt.wantErr)
			}

			if !tt.wantErr {
				got := p.ApplicationLayer().(*IPFIX)
				want := &IPFIX{
					BaseLayer: BaseLayer{},
					Header:    tt.want,
					Templates: make(map[IPFIXSetIDType]IPFIXTemplateAccessor),
				}
				if !reflect.DeepEqual(want, got) {
					t.Errorf("IPFIX layer mismatch, \nwant  %#v\ngot %#v\n", want, got)
				}
			}
		})
	}
}

func TestIPFIXSetHeader(t *testing.T) {
	setPayload := append([]byte{}, templateSetHeader...)
	setPayload = append(setPayload, []byte{0x01, 0x00, 0x00, 0x00}...)
	setLengthHeader(setPayload)
	payload := append([]byte{}, header...)
	payload = append(payload, setPayload...)
	setLengthHeader(payload)

	invalidID1 := append([]byte{}, payload...)
	invalidID1[len(payload)-7] = 0x01

	invalidID2 := append([]byte{}, payload...)
	invalidID2[len(payload)-7] = 0xee

	invalidLength := append(
		[]byte{},
		payload[:IPFIXMessageHeader{}.Len()+IPFIXSetHeader{}.Len()-1]...)
	setLengthHeader(invalidLength)

	invalidDataLength := append([]byte{}, payload[:len(payload)-1]...)
	setLengthHeader(invalidDataLength)

	tests := []struct {
		name    string
		payload []byte
		want    *IPFIX
		wantErr bool
	}{
		{"invalid set header ID netflow v9 ID", invalidID1, &IPFIX{}, true},
		{"invalid set header ID reserved ID", invalidID2, &IPFIX{}, true},
		{"invalid set header length", invalidLength, &IPFIX{}, true},
		{"invalid data length", invalidDataLength, &IPFIX{}, true},
		{
			"valid template set header",
			payload,
			&IPFIX{
				BaseLayer: BaseLayer{},
				Header: IPFIXMessageHeader{
					Version:             10,
					Length:              uint16(len(payload)),
					ExportTime:          1636083412,
					SequenceNumber:      0,
					ObservationDomainID: 1,
				},
				Templates: map[IPFIXSetIDType]IPFIXTemplateAccessor{
					256: &IPFIXTemplateRecord{
						ID:         256,
						FieldCount: 0,
						Fields:     []IPFIXFieldSpecifier{},
					},
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := gopacket.NewPacket(tt.payload, LayerTypeIPFIX, gopacket.Default)
			if (p.ErrorLayer() != nil) != tt.wantErr {
				t.Errorf("New gopacket IPFIX error = %v, wantErr %v", p.ErrorLayer().Error(), tt.wantErr)
			}

			if !tt.wantErr {
				got := p.ApplicationLayer().(*IPFIX)
				if !reflect.DeepEqual(tt.want, got) {
					t.Errorf("IPFIX layer mismatch, \nwant  %#v\ngot %#v\n", tt.want, got)
				}
			}
		})
	}
}

func TestIPFIXOptionTemplateRecord(t *testing.T) {
	payload := append([]byte{}, header...)
	optionTemplateSet1 := append([]byte{}, optionTemplateSetHeader...)
	optionTemplateSet1 = append(optionTemplateSet1, optionTemplateRecord1...)
	optionTemplateSet1 = append(optionTemplateSet1, optionTemplateRecord2...)
	// add some padding
	optionTemplateSet1 = append(optionTemplateSet1, []byte{0x00, 0x00, 0x00, 0x00}...)
	setLengthHeader(optionTemplateSet1)
	payload = append(payload, optionTemplateSet1...)
	setLengthHeader(payload)

	invalidScopeFieldLength := append([]byte{}, header...)
	optionTemplateSet := append([]byte{}, optionTemplateSetHeader...)
	optionTemplateSet = append(optionTemplateSet, []byte{0x01, 0x01, 0x00, 0x02, 0x00, 0x00}...)
	setLengthHeader(optionTemplateSet)
	invalidScopeFieldLength = append(invalidScopeFieldLength, optionTemplateSet...)
	setLengthHeader(invalidScopeFieldLength)

	invalidLength1 := append([]byte{}, header...)
	optionTemplateSet = append([]byte{}, optionTemplateSetHeader...)
	optionTemplateSet = append(optionTemplateSet, optionTemplateRecord1[:IPFIXOptionTemplateRecord{}.Len()-1]...)
	setLengthHeader(optionTemplateSet)
	invalidLength1 = append(invalidLength1, optionTemplateSet...)
	setLengthHeader(invalidLength1)

	invalidLength2 := append([]byte{}, header...)
	optionTemplateSet = append([]byte{}, optionTemplateSetHeader...)
	optionTemplateSet = append(optionTemplateSet, optionTemplateRecord1[:len(optionTemplateRecord1)-5]...)
	setLengthHeader(optionTemplateSet)
	invalidLength2 = append(invalidLength2, optionTemplateSet...)
	setLengthHeader(invalidLength2)

	invalidLength3 := append([]byte{}, header...)
	optionTemplateSet = append([]byte{}, optionTemplateSetHeader...)
	optionTemplateSet = append(optionTemplateSet, optionTemplateRecord1[:len(optionTemplateRecord1)-1]...)
	setLengthHeader(optionTemplateSet)
	invalidLength3 = append(invalidLength3, optionTemplateSet...)
	setLengthHeader(invalidLength3)

	invalidFieldCount := append([]byte{}, header...)
	optionTemplateSet = append([]byte{}, optionTemplateSetHeader...)
	optionTemplateSet = append(optionTemplateSet, optionTemplateRecord1...)
	optionTemplateSet[7] = 0x04
	optionTemplateSet[9] = 0x03
	setLengthHeader(optionTemplateSet)
	invalidFieldCount = append(invalidFieldCount, optionTemplateSet...)
	setLengthHeader(invalidFieldCount)

	invalidPaddingLength := append([]byte{}, header...)
	optionTemplateSet = append([]byte{}, optionTemplateSetHeader...)
	optionTemplateSet = append(optionTemplateSet, optionTemplateRecord1...)
	optionTemplateSet = append(optionTemplateSet, []byte{0x00, 0x00, 0x00}...)
	setLengthHeader(optionTemplateSet)
	invalidPaddingLength = append(invalidPaddingLength, optionTemplateSet...)
	setLengthHeader(invalidPaddingLength)

	invalidPaddingValue := append([]byte{}, header...)
	optionTemplateSet = append([]byte{}, optionTemplateSetHeader...)
	optionTemplateSet = append(optionTemplateSet, optionTemplateRecord1...)
	optionTemplateSet = append(optionTemplateSet, []byte{0x00, 0x00, 0xbe, 0xef}...)
	setLengthHeader(optionTemplateSet)
	invalidPaddingValue = append(invalidPaddingValue, optionTemplateSet...)
	setLengthHeader(invalidPaddingValue)

	tests := []struct {
		name    string
		payload []byte
		want    *IPFIX
		wantErr bool
	}{
		{"invalid scope template length", invalidLength1, &IPFIX{}, true},
		{"invalid scope field count", invalidScopeFieldLength, &IPFIX{}, true},
		{"invalid scope field specifier length", invalidLength2, &IPFIX{}, true},
		{"invalid field specifier length", invalidLength3, &IPFIX{}, true},
		{"invalid field count", invalidFieldCount, &IPFIX{}, true},
		{"invalid padding length", invalidPaddingLength, &IPFIX{}, true},
		{"invalid padding value", invalidPaddingValue, &IPFIX{}, true},
		{
			"valid template set",
			payload,
			&IPFIX{
				BaseLayer: BaseLayer{},
				Header: IPFIXMessageHeader{
					Version:             10,
					Length:              uint16(len(payload)),
					ExportTime:          1636083412,
					SequenceNumber:      0,
					ObservationDomainID: 1,
				},
				Templates: map[IPFIXSetIDType]IPFIXTemplateAccessor{
					257: &IPFIXOptionTemplateRecord{
						ID:                  257,
						FieldCount:          3,
						ScopeFieldCount:     2,
						minDataRecordLength: 12,
						ScopeFields: []IPFIXFieldSpecifier{
							{InformationElementID: 0x6c, FieldLength: 0x2, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x7, FieldLength: 0x2, EnterpriseNumber: 0x0, EnterpriseBit: false},
						},
						Fields: []IPFIXFieldSpecifier{
							{InformationElementID: 0x56, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
						},
					},
					258: &IPFIXOptionTemplateRecord{
						ID:                  258,
						FieldCount:          2,
						ScopeFieldCount:     1,
						minDataRecordLength: 10,
						ScopeFields: []IPFIXFieldSpecifier{
							{InformationElementID: 0x7, FieldLength: 0x2, EnterpriseNumber: 0x0, EnterpriseBit: false},
						},
						Fields: []IPFIXFieldSpecifier{
							{InformationElementID: 0x56, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
						},
					},
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := gopacket.NewPacket(tt.payload, LayerTypeIPFIX, gopacket.Default)
			if (p.ErrorLayer() != nil) != tt.wantErr {
				t.Errorf("New gopacket IPFIX error = %v, wantErr %v", p.ErrorLayer().Error(), tt.wantErr)
			}

			if !tt.wantErr {
				got := p.ApplicationLayer().(*IPFIX)
				if !reflect.DeepEqual(tt.want, got) {
					t.Errorf("IPFIX layer mismatch, \nwant  %#v\ngot %#v\n", tt.want, got)
				}
			}
		})
	}
}

func TestIPFIXTemplateRecord(t *testing.T) {
	payload := append([]byte{}, header...)
	templateSet1 := append([]byte{}, templateSetHeader...)
	templateSet1 = append(templateSet1, templateRecord1...)
	templateSet1 = append(templateSet1, templateRecord2...)
	// add some padding
	templateSet1 = append(templateSet1, []byte{0x00, 0x00, 0x00, 0x00}...)
	setLengthHeader(templateSet1)
	payload = append(payload, templateSet1...)
	setLengthHeader(payload)

	invalidLength1 := append([]byte{}, header...)
	templateSet := append([]byte{}, templateSetHeader...)
	templateSet = append(templateSet, templateRecord1[:IPFIXTemplateRecord{}.Len()-1]...)
	setLengthHeader(templateSet)
	invalidLength1 = append(invalidLength1, templateSet...)
	setLengthHeader(invalidLength1)

	invalidLength2 := append([]byte{}, header...)
	templateSet = append([]byte{}, templateSetHeader...)
	templateSet = append(templateSet, templateRecord1[:len(templateRecord1)-1]...)
	setLengthHeader(templateSet)
	invalidLength2 = append(invalidLength2, templateSet...)
	setLengthHeader(invalidLength2)

	invalidFieldCount := append([]byte{}, payload...)
	invalidFieldCount[23] = 0x16

	invalidPaddingLength := append([]byte{}, header...)
	templateSet = append([]byte{}, templateSetHeader...)
	templateSet = append(templateSet, templateRecord1...)
	templateSet = append(templateSet, []byte{0x00, 0x00, 0x00}...)
	setLengthHeader(templateSet)
	invalidPaddingLength = append(invalidPaddingLength, templateSet...)
	setLengthHeader(invalidPaddingLength)

	invalidPaddingValue := append([]byte{}, header...)
	templateSet = append([]byte{}, templateSetHeader...)
	templateSet = append(templateSet, templateRecord1...)
	templateSet = append(templateSet, []byte{0x00, 0x00, 0xbe, 0xef}...)
	setLengthHeader(templateSet)
	invalidPaddingValue = append(invalidPaddingValue, templateSet...)
	setLengthHeader(invalidPaddingValue)

	tests := []struct {
		name    string
		payload []byte
		want    *IPFIX
		wantErr bool
	}{
		{"invalid template length", invalidLength1, &IPFIX{}, true},
		{"invalid field specifier length", invalidLength2, &IPFIX{}, true},
		{"invalid template set field count", invalidFieldCount, &IPFIX{}, true},
		{"invalid padding length", invalidPaddingLength, &IPFIX{}, true},
		{"invalid padding value", invalidPaddingValue, &IPFIX{}, true},
		{
			"valid template set",
			payload,
			&IPFIX{
				BaseLayer: BaseLayer{},
				Header: IPFIXMessageHeader{
					Version:             10,
					Length:              uint16(len(payload)),
					ExportTime:          1636083412,
					SequenceNumber:      0,
					ObservationDomainID: 1,
				},
				Templates: map[IPFIXSetIDType]IPFIXTemplateAccessor{
					256: &IPFIXTemplateRecord{
						ID:                  256,
						FieldCount:          20,
						minDataRecordLength: 74,
						Fields: []IPFIXFieldSpecifier{
							{InformationElementID: 0x8, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0xc, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x7, FieldLength: 0x2, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0xb, FieldLength: 0x2, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x4, FieldLength: 0x1, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x96, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x97, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x88, FieldLength: 0x1, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x56, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x2, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x55, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x65, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x67, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x6c, FieldLength: 0x2, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x89, FieldLength: 0x1, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x88, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x6a, FieldLength: 0x4, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x56, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
							{InformationElementID: 0x2, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
							{InformationElementID: 0x55, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
						},
					},
					257: &IPFIXTemplateRecord{
						ID:                  257,
						FieldCount:          2,
						minDataRecordLength: 8,
						Fields: []IPFIXFieldSpecifier{
							{InformationElementID: 0x8, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0xc, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
						},
					},
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := gopacket.NewPacket(tt.payload, LayerTypeIPFIX, gopacket.Default)
			if (p.ErrorLayer() != nil) != tt.wantErr {
				t.Errorf("New gopacket IPFIX error = %v, wantErr %v", p.ErrorLayer().Error(), tt.wantErr)
			}

			if !tt.wantErr {
				got := p.ApplicationLayer().(*IPFIX)
				if !reflect.DeepEqual(tt.want, got) {
					t.Errorf("IPFIX layer mismatch, \nwant  %#v\ngot %#v\n", tt.want, got)
				}
			}
		})
	}
}

func TestIPFIXDataRecord(t *testing.T) {
	payload := append([]byte{}, header...)
	templateSet := append([]byte{}, templateSetHeader...)
	templateSet = append(templateSet, templateRecord1...)
	setLengthHeader(templateSet)
	payload = append(payload, templateSet...)
	dataSet1 := append([]byte{}, dataSetHeader...)
	dataSet1 = append(dataSet1, dataRecord...)
	setLengthHeader(dataSet1)
	payload = append(payload, dataSet1...)
	setLengthHeader(payload)

	unknownTemplate := append([]byte{}, header...)
	unknownTemplate = append(unknownTemplate, dataSet1...)
	setLengthHeader(unknownTemplate)

	invalidLength := append([]byte{}, header...)
	invalidLength = append(invalidLength, templateSet...)
	invalidDataSetLength := append([]byte{}, dataSetHeader...)
	// corrupt last data record field length
	invalidDataSetLength = append(invalidDataSetLength, dataRecord[:len(dataRecord)-1]...)
	setLengthHeader(invalidDataSetLength)
	invalidLength = append(invalidLength, invalidDataSetLength...)
	setLengthHeader(invalidLength)

	invalidPaddingValue := append([]byte{}, header...)
	invalidPaddingValue = append(invalidPaddingValue, templateSet...)
	dataSet2 := append([]byte{}, dataSetHeader...)
	dataSet2 = append(dataSet2, dataRecord...)
	dataSet2 = append(dataSet2, []byte{0xde, 0xad, 0xbe, 0xef}...)
	setLengthHeader(dataSet2)
	invalidPaddingValue = append(invalidPaddingValue, dataSet2...)
	setLengthHeader(invalidPaddingValue)

	hugeVariableLength := append([]byte{}, header...)
	hugeVariableLength = append(hugeVariableLength, templateSet...)
	dataSet3 := append([]byte{}, dataSetHeader...)
	dataRecord2 := append([]byte{}, dataRecord[:len(dataRecord)-40]...)
	dataRecord2 = append(dataRecord2, []byte{0xff, 0x00, 0x01, 0x00}...)
	dataRecord2 = append(dataRecord2, dataRecord[len(dataRecord)-28:]...)
	dataSet3 = append(dataSet3, dataRecord2...)
	setLengthHeader(dataSet3)
	hugeVariableLength = append(hugeVariableLength, dataSet3...)
	setLengthHeader(hugeVariableLength)

	multipleRecords := append([]byte{}, header...)
	multipleRecords = append(multipleRecords, templateSet...)
	optionTemplateSet := append([]byte{}, optionTemplateSetHeader...)
	optionTemplateSet = append(optionTemplateSet, optionTemplateRecord1...)
	setLengthHeader(optionTemplateSet)
	multipleRecords = append(multipleRecords, optionTemplateSet...)
	// put two records in the set
	dataSet4 := append([]byte{}, dataSetHeader...)
	dataSet4 = append(dataSet4, dataRecord...)
	dataSet4 = append(dataSet4, dataRecord2...)
	setLengthHeader(dataSet4)
	multipleRecords = append(multipleRecords, dataSet4...)
	dataSet5 := append([]byte{}, optionDataSetHeader...)
	dataSet5 = append(dataSet5, optionDataRecord...)
	setLengthHeader(dataSet5)
	multipleRecords = append(multipleRecords, dataSet5...)
	setLengthHeader(multipleRecords)

	tests := []struct {
		name    string
		payload []byte
		want    *IPFIX
		wantErr bool
	}{
		{"invalid field length", invalidLength, &IPFIX{}, true},
		{"invalid padding value", invalidPaddingValue, &IPFIX{}, true},
		{
			"unknown template",
			unknownTemplate,
			&IPFIX{
				BaseLayer: BaseLayer{},
				Header: IPFIXMessageHeader{
					Version:             10,
					Length:              uint16(len(unknownTemplate)),
					ExportTime:          1636083412,
					SequenceNumber:      0,
					ObservationDomainID: 1,
				},
				Templates: map[IPFIXSetIDType]IPFIXTemplateAccessor{},
				Data: []IPFIXDataSet{
					{
						Header: IPFIXSetHeader{ID: 256, Length: uint16(len(dataSet1))},
						Bytes:  dataRecord,
					},
				},
			},
			false,
		},
		{
			"known template",
			payload,
			&IPFIX{
				BaseLayer: BaseLayer{},
				Header: IPFIXMessageHeader{
					Version:             10,
					Length:              uint16(len(payload)),
					ExportTime:          1636083412,
					SequenceNumber:      0,
					ObservationDomainID: 1,
				},
				Templates: map[IPFIXSetIDType]IPFIXTemplateAccessor{
					256: &IPFIXTemplateRecord{
						ID:                  256,
						FieldCount:          20,
						minDataRecordLength: 74,
						Fields: []IPFIXFieldSpecifier{
							{InformationElementID: 0x8, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0xc, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x7, FieldLength: 0x2, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0xb, FieldLength: 0x2, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x4, FieldLength: 0x1, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x96, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x97, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x88, FieldLength: 0x1, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x56, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x2, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x55, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x65, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x67, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x6c, FieldLength: 0x2, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x89, FieldLength: 0x1, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x88, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x6a, FieldLength: 0x4, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x56, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
							{InformationElementID: 0x2, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
							{InformationElementID: 0x55, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
						},
					},
				},
				Data: []IPFIXDataSet{
					{
						Header: IPFIXSetHeader{ID: 256, Length: uint16(len(dataRecord) + IPFIXSetHeader{}.Len())},
						Records: []IPFIXDataRecord{
							{
								ID: 256,
								Fields: []IPFIXField{
									{InformationElementID: 0x8, EnterpriseNumber: 0x0, Bytes: []uint8{0xa, 0x0, 0x0, 0x1}},
									{InformationElementID: 0xc, EnterpriseNumber: 0x0, Bytes: []uint8{0xa, 0x0, 0x0, 0x2}},
									{InformationElementID: 0x7, EnterpriseNumber: 0x0, Bytes: []uint8{0x4, 0xd2}},
									{InformationElementID: 0xb, EnterpriseNumber: 0x0, Bytes: []uint8{0x16, 0x2e}},
									{InformationElementID: 0x4, EnterpriseNumber: 0x0, Bytes: []uint8{0x6}},
									{InformationElementID: 0x96, EnterpriseNumber: 0x0, Bytes: []uint8{0x4a, 0xf9, 0xec, 0x88}},
									{InformationElementID: 0x97, EnterpriseNumber: 0x0, Bytes: []uint8{0x4a, 0xf9, 0xf0, 0x70}},
									{InformationElementID: 0x88, EnterpriseNumber: 0x0, Bytes: []uint8{0x2}},
									{InformationElementID: 0x56, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x20}},
									{InformationElementID: 0x2, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xf4}},
									{InformationElementID: 0x55, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x35, 0x0}},
									{InformationElementID: 0x65, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x70, 0x6f, 0x64, 0x31}},
									{InformationElementID: 0x67, EnterpriseNumber: 0xdcba, Bytes: []uint8{}},
									{InformationElementID: 0x6c, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x12, 0x83}},
									{InformationElementID: 0x89, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x2}},
									{InformationElementID: 0x88, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x45, 0x53, 0x54, 0x41, 0x42, 0x4c, 0x49, 0x53, 0x48, 0x45, 0x44}},
									{InformationElementID: 0x6a, EnterpriseNumber: 0xdcba, Bytes: []uint8{0xa, 0x0, 0x0, 0x3}},
									{InformationElementID: 0x56, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2c}},
									{InformationElementID: 0x2, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x96}},
									{InformationElementID: 0x55, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x35, 0x0}},
								},
							},
						},
					},
				},
			},
			false,
		},
		{
			"known template with huge variable length field",
			hugeVariableLength,
			&IPFIX{
				BaseLayer: BaseLayer{},
				Header: IPFIXMessageHeader{
					Version:             10,
					Length:              uint16(len(hugeVariableLength)),
					ExportTime:          1636083412,
					SequenceNumber:      0,
					ObservationDomainID: 1,
				},
				Templates: map[IPFIXSetIDType]IPFIXTemplateAccessor{
					256: &IPFIXTemplateRecord{
						ID:                  256,
						FieldCount:          20,
						minDataRecordLength: 74,
						Fields: []IPFIXFieldSpecifier{
							{InformationElementID: 0x8, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0xc, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x7, FieldLength: 0x2, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0xb, FieldLength: 0x2, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x4, FieldLength: 0x1, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x96, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x97, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x88, FieldLength: 0x1, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x56, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x2, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x55, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x65, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x67, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x6c, FieldLength: 0x2, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x89, FieldLength: 0x1, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x88, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x6a, FieldLength: 0x4, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x56, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
							{InformationElementID: 0x2, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
							{InformationElementID: 0x55, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
						},
					},
				},
				Data: []IPFIXDataSet{
					{
						Header: IPFIXSetHeader{ID: 256, Length: uint16(len(dataSet3))},
						Records: []IPFIXDataRecord{
							{
								ID: 256,
								Fields: []IPFIXField{
									{InformationElementID: 0x8, EnterpriseNumber: 0x0, Bytes: []uint8{0xa, 0x0, 0x0, 0x1}},
									{InformationElementID: 0xc, EnterpriseNumber: 0x0, Bytes: []uint8{0xa, 0x0, 0x0, 0x2}},
									{InformationElementID: 0x7, EnterpriseNumber: 0x0, Bytes: []uint8{0x4, 0xd2}},
									{InformationElementID: 0xb, EnterpriseNumber: 0x0, Bytes: []uint8{0x16, 0x2e}},
									{InformationElementID: 0x4, EnterpriseNumber: 0x0, Bytes: []uint8{0x6}},
									{InformationElementID: 0x96, EnterpriseNumber: 0x0, Bytes: []uint8{0x4a, 0xf9, 0xec, 0x88}},
									{InformationElementID: 0x97, EnterpriseNumber: 0x0, Bytes: []uint8{0x4a, 0xf9, 0xf0, 0x70}},
									{InformationElementID: 0x88, EnterpriseNumber: 0x0, Bytes: []uint8{0x2}},
									{InformationElementID: 0x56, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x20}},
									{InformationElementID: 0x2, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xf4}},
									{InformationElementID: 0x55, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x35, 0x0}},
									{InformationElementID: 0x65, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x70, 0x6f, 0x64, 0x31}},
									{InformationElementID: 0x67, EnterpriseNumber: 0xdcba, Bytes: []uint8{}},
									{InformationElementID: 0x6c, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x12, 0x83}},
									{InformationElementID: 0x89, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x2}},
									{InformationElementID: 0x88, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x0}},
									{InformationElementID: 0x6a, EnterpriseNumber: 0xdcba, Bytes: []uint8{0xa, 0x0, 0x0, 0x3}},
									{InformationElementID: 0x56, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2c}},
									{InformationElementID: 0x2, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x96}},
									{InformationElementID: 0x55, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x35, 0x0}},
								},
							},
						},
					},
				},
			},
			false,
		},
		{
			"known template with multiple data records",
			multipleRecords,
			&IPFIX{
				BaseLayer: BaseLayer{},
				Header: IPFIXMessageHeader{
					Version:             10,
					Length:              uint16(len(multipleRecords)),
					ExportTime:          1636083412,
					SequenceNumber:      0,
					ObservationDomainID: 1,
				},
				Templates: map[IPFIXSetIDType]IPFIXTemplateAccessor{
					256: &IPFIXTemplateRecord{
						ID:                  256,
						FieldCount:          20,
						minDataRecordLength: 74,
						Fields: []IPFIXFieldSpecifier{
							{InformationElementID: 0x8, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0xc, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x7, FieldLength: 0x2, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0xb, FieldLength: 0x2, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x4, FieldLength: 0x1, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x96, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x97, FieldLength: 0x4, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x88, FieldLength: 0x1, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x56, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x2, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x55, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
							{InformationElementID: 0x65, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x67, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x6c, FieldLength: 0x2, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x89, FieldLength: 0x1, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x88, FieldLength: 0xffff, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x6a, FieldLength: 0x4, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x56, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
							{InformationElementID: 0x2, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
							{InformationElementID: 0x55, FieldLength: 0x8, EnterpriseNumber: 0x7279, EnterpriseBit: true},
						},
					},
					257: &IPFIXOptionTemplateRecord{
						ID:                  257,
						FieldCount:          3,
						ScopeFieldCount:     2,
						minDataRecordLength: 12,
						ScopeFields: []IPFIXFieldSpecifier{
							{InformationElementID: 0x6c, FieldLength: 0x2, EnterpriseNumber: 0xdcba, EnterpriseBit: true},
							{InformationElementID: 0x7, FieldLength: 0x2, EnterpriseNumber: 0x0, EnterpriseBit: false},
						},
						Fields: []IPFIXFieldSpecifier{
							{InformationElementID: 0x56, FieldLength: 0x8, EnterpriseNumber: 0x0, EnterpriseBit: false},
						},
					},
				},
				Data: []IPFIXDataSet{
					{
						Header: IPFIXSetHeader{ID: 256, Length: uint16(len(dataSet4))},
						Records: []IPFIXDataRecord{
							{
								ID: 256,
								Fields: []IPFIXField{
									{InformationElementID: 0x8, EnterpriseNumber: 0x0, Bytes: []uint8{0xa, 0x0, 0x0, 0x1}},
									{InformationElementID: 0xc, EnterpriseNumber: 0x0, Bytes: []uint8{0xa, 0x0, 0x0, 0x2}},
									{InformationElementID: 0x7, EnterpriseNumber: 0x0, Bytes: []uint8{0x4, 0xd2}},
									{InformationElementID: 0xb, EnterpriseNumber: 0x0, Bytes: []uint8{0x16, 0x2e}},
									{InformationElementID: 0x4, EnterpriseNumber: 0x0, Bytes: []uint8{0x6}},
									{InformationElementID: 0x96, EnterpriseNumber: 0x0, Bytes: []uint8{0x4a, 0xf9, 0xec, 0x88}},
									{InformationElementID: 0x97, EnterpriseNumber: 0x0, Bytes: []uint8{0x4a, 0xf9, 0xf0, 0x70}},
									{InformationElementID: 0x88, EnterpriseNumber: 0x0, Bytes: []uint8{0x2}},
									{InformationElementID: 0x56, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x20}},
									{InformationElementID: 0x2, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xf4}},
									{InformationElementID: 0x55, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x35, 0x0}},
									{InformationElementID: 0x65, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x70, 0x6f, 0x64, 0x31}},
									{InformationElementID: 0x67, EnterpriseNumber: 0xdcba, Bytes: []uint8{}},
									{InformationElementID: 0x6c, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x12, 0x83}},
									{InformationElementID: 0x89, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x2}},
									{InformationElementID: 0x88, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x45, 0x53, 0x54, 0x41, 0x42, 0x4c, 0x49, 0x53, 0x48, 0x45, 0x44}},
									{InformationElementID: 0x6a, EnterpriseNumber: 0xdcba, Bytes: []uint8{0xa, 0x0, 0x0, 0x3}},
									{InformationElementID: 0x56, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2c}},
									{InformationElementID: 0x2, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x96}},
									{InformationElementID: 0x55, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x35, 0x0}},
								},
							},
							{
								ID: 256,
								Fields: []IPFIXField{
									{InformationElementID: 0x8, EnterpriseNumber: 0x0, Bytes: []uint8{0xa, 0x0, 0x0, 0x1}},
									{InformationElementID: 0xc, EnterpriseNumber: 0x0, Bytes: []uint8{0xa, 0x0, 0x0, 0x2}},
									{InformationElementID: 0x7, EnterpriseNumber: 0x0, Bytes: []uint8{0x4, 0xd2}},
									{InformationElementID: 0xb, EnterpriseNumber: 0x0, Bytes: []uint8{0x16, 0x2e}},
									{InformationElementID: 0x4, EnterpriseNumber: 0x0, Bytes: []uint8{0x6}},
									{InformationElementID: 0x96, EnterpriseNumber: 0x0, Bytes: []uint8{0x4a, 0xf9, 0xec, 0x88}},
									{InformationElementID: 0x97, EnterpriseNumber: 0x0, Bytes: []uint8{0x4a, 0xf9, 0xf0, 0x70}},
									{InformationElementID: 0x88, EnterpriseNumber: 0x0, Bytes: []uint8{0x2}},
									{InformationElementID: 0x56, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x20}},
									{InformationElementID: 0x2, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0xf4}},
									{InformationElementID: 0x55, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x35, 0x0}},
									{InformationElementID: 0x65, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x70, 0x6f, 0x64, 0x31}},
									{InformationElementID: 0x67, EnterpriseNumber: 0xdcba, Bytes: []uint8{}},
									{InformationElementID: 0x6c, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x12, 0x83}},
									{InformationElementID: 0x89, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x2}},
									{InformationElementID: 0x88, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x0}},
									{InformationElementID: 0x6a, EnterpriseNumber: 0xdcba, Bytes: []uint8{0xa, 0x0, 0x0, 0x3}},
									{InformationElementID: 0x56, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x2c}},
									{InformationElementID: 0x2, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x96}},
									{InformationElementID: 0x55, EnterpriseNumber: 0x7279, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0xc, 0x35, 0x0}},
								},
							},
						},
					},
					{
						Header: IPFIXSetHeader{ID: 257, Length: uint16(len(dataSet5))},
						Records: []IPFIXDataRecord{
							{
								ID: 257,
								Fields: []IPFIXField{
									{InformationElementID: 0x6c, EnterpriseNumber: 0xdcba, Bytes: []uint8{0x12, 0x83}},
									{InformationElementID: 0x7, EnterpriseNumber: 0x0, Bytes: []uint8{0x4, 0xd2}},
									{InformationElementID: 0x56, EnterpriseNumber: 0x0, Bytes: []uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, 0x20}},
								},
							},
						},
					},
				},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := gopacket.NewPacket(tt.payload, LayerTypeIPFIX, gopacket.Default)
			if (p.ErrorLayer() != nil) != tt.wantErr {
				t.Errorf("New gopacket IPFIX error = %v, wantErr %v", p.ErrorLayer().Error(), tt.wantErr)
			}

			if !tt.wantErr {
				got := p.ApplicationLayer().(*IPFIX)
				// use go-cmp instead of reflect.DeepEqual to ginore
				// DR.fieldIndex unexported field, see `opts`
				if !cmp.Equal(tt.want, got, opts...) {
					t.Errorf("IPFIX layer mismatch, \nwant  %#v\ngot %#v\n", tt.want, got)
				}
			}
		})
	}
}

func BenchmarkDecodeIPFIXPacket(b *testing.B) {
	templateSet := append([]byte{}, templateSetHeader...)
	templateSet = append(templateSet, templateRecord1...)
	setLengthHeader(templateSet)

	optionTemplateSet := append([]byte{}, optionTemplateSetHeader...)
	optionTemplateSet = append(optionTemplateSet, optionTemplateRecord1...)
	setLengthHeader(optionTemplateSet)

	dataSet1 := append([]byte{}, dataSetHeader...)
	dataSet1 = append(dataSet1, dataRecord...)
	setLengthHeader(dataSet1)

	dataSet2 := append([]byte{}, optionDataSetHeader...)
	dataSet2 = append(dataSet2, optionDataRecord...)
	setLengthHeader(dataSet2)

	payload1 := append([]byte{}, header...)
	payload1 = append(payload1, dataSet1...)
	payload1 = append(payload1, dataSet2...)
	setLengthHeader(payload1)

	payload2 := append([]byte{}, header...)
	payload2 = append(payload2, templateSet...)
	payload2 = append(payload2, dataSet1...)
	setLengthHeader(payload2)

	payload3, _ := hex.DecodeString(dataWithTemplateStr)

	payload4 := append([]byte{}, header...)
	payload4 = append(payload4, templateSet...)
	payload4 = append(payload4, optionTemplateSet...)
	payload4 = append(payload4, dataSet1...)
	payload4 = append(payload4, dataSet2...)
	setLengthHeader(payload4)

	tc := []struct {
		name   string
		packet []byte
	}{
		{"data without template", payload1},
		{"data with template 1", payload2},
		{"data with template 2", payload3},
		{"data with template and option template", payload4},
	}

	for _, t := range tc {
		b.Run(fmt.Sprintf("%s (%d)", t.name, len(t.packet)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				p := gopacket.NewPacket(t.packet, LayerTypeIPFIX, gopacket.NoCopy)
				if p.ErrorLayer() != nil {
					b.Error(p.ErrorLayer().Error())
				}
			}
		})
	}
}

func TestIPFIXDataSet_DecodeWithTemplate(t *testing.T) {
	templateSet1 := append([]byte{}, templateSetHeader...)
	templateSet1 = append(templateSet1, templateRecord1...)
	setLengthHeader(templateSet1)

	dataSet1 := append([]byte{}, dataSetHeader...)
	dataSet1 = append(dataSet1, dataRecord...)
	setLengthHeader(dataSet1)

	dataSet2 := append([]byte{}, dataSetHeader...)
	dataSet2[0] = 0x02 // shange template ID from 256 to 512
	dataSet2 = append(dataSet2, dataRecord...)
	setLengthHeader(dataSet2)
	tests := []struct {
		name     string
		template []byte
		dataSet  []byte
		wantErr  bool
	}{
		{"valid template", templateSet1, dataSet1, false},
		{"wrong template", templateSet1, dataSet2, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &IPFIXSetHeader{}
			if err := h.decodeFromBytes(&tt.template); err != nil {
				t.Error(err)
			}
			template := &IPFIXTemplateRecord{}
			if err := template.decodeFromBytes(&tt.template); err != nil {
				t.Error(err)
			}

			h = &IPFIXSetHeader{}
			if err := h.decodeFromBytes(&tt.dataSet); err != nil {
				t.Error(err)
			}
			dataSet := &IPFIXDataSet{Header: *h}
			if err := dataSet.decodeFromBytes(&tt.dataSet, nil); err != nil {
				t.Error(err)
			}

			if err := dataSet.DecodeWithTemplate(template); (err != nil) != tt.wantErr {
				t.Errorf("IPFIXDataSet.DecodeWithTemplate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIPFIXDataRecord_GetField(t *testing.T) {
	templateSet := append([]byte{}, templateSetHeader...)
	templateSet = append(templateSet, templateRecord1...)
	setLengthHeader(templateSet)

	dataSet := append([]byte{}, dataSetHeader...)
	dataSet = append(dataSet, dataRecord...)
	setLengthHeader(dataSet)

	payload := append([]byte{}, header...)
	payload = append(payload, templateSet...)
	payload = append(payload, dataSet...)
	setLengthHeader(payload)

	type args struct {
		en  uint32
		iei uint16
	}
	tests := []struct {
		name    string
		payload []byte
		args    args
		want    *IPFIXField
		want1   bool
	}{
		{
			"hit",
			payload,
			args{uint32(56506), uint16(108)},
			&IPFIXField{
				EnterpriseNumber:     56506,
				InformationElementID: 108,
				Bytes:                []byte{0x12, 0x83},
			},
			true,
		},
		{
			"miss",
			payload,
			args{uint32(56506), uint16(42)},
			nil,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := gopacket.NewPacket(tt.payload, LayerTypeIPFIX, gopacket.NoCopy)
			if p.ErrorLayer() != nil {
				t.Error(p.ErrorLayer().Error())
			}
			ipfix := p.ApplicationLayer().(*IPFIX)
			dr := ipfix.Data[0].Records[0]
			got, got1 := dr.GetField(tt.args.en, tt.args.iei)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IPFIXDataRecord.GetField() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("IPFIXDataRecord.GetField() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
