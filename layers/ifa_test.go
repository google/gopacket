package layers

import (
	"reflect"
	"testing"
)

var (
	testIFAHeader = []byte{
		0x2f, 0x11, 0x00, 0xff, // v2.0, GNS 15, next proto UDP, no frag, no tail, copy, not turn around, no checksum, max length = 65535
	}
	testIFAMetadataHeader = []byte{
		0xff, 0xff, 0x1e, 0x10, // vector 255, loss, colored, hop limit 30, current length 16
	}
	testIFAMetadata1 = []byte{
		0x10, 0x42, 0xff, 0x3d, 0x12, 0xe0, 0x0a, 0x19, 0x00, 0x40, 0x00, 0x01, 0x36, 0xfe, 0x74, 0x42,
		0x3b, 0x9a, 0xcc, 0xd6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	testIFAMetadata2 = []byte{
		0x10, 0xb7, 0x7f, 0x3f, 0x40, 0x00, 0x0e, 0xc6, 0x00, 0x01, 0x00, 0x3f, 0x27, 0xe6, 0x2c, 0xf8,
		0x3b, 0x9a, 0xcc, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

func TestIFAHeader(t *testing.T) {
	invalidLength := append([]byte{}, testIFAHeader[:len(testIFAHeader)-1]...)
	invalidVersion := append([]byte{}, testIFAHeader...)
	invalidVersion[0] = 0x3f
	validHeader := append([]byte{}, testIFAHeader...)

	tests := []struct {
		name    string
		payload []byte
		want    IFAHeader
		wantErr bool
	}{
		{"invalid header length", invalidLength, IFAHeader{}, true},
		{"invalid header version", invalidVersion, IFAHeader{Version: 3}, true},
		{
			"valid header",
			validHeader,
			IFAHeader{
				Version:          2,
				GlobalNameSpace:  15,
				NextHeader:       IPProtocolUDP,
				MetadataFragment: false,
				TailStamp:        false,
				Inband:           false,
				TurnAround:       false,
				Checksum:         false,
				MaxLength:        255,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IFAHeader{}
			err := got.decodeFromBytes(&tt.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("IFAHeader decode error = %v, wantErr %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(tt.want, got) {
				t.Errorf("IFA header mismatch, \nwant  %#v\ngot %#v\n", tt.want, got)
			}
		})
	}
}

func TestIFAMetadataHeader(t *testing.T) {
	invalidLength := append([]byte{}, testIFAMetadataHeader[:len(testIFAMetadataHeader)-1]...)
	validHeader := append([]byte{}, testIFAMetadataHeader...)

	tests := []struct {
		name    string
		payload []byte
		want    IFAMetadataHeader
		wantErr bool
	}{
		{"invalid metadata header length", invalidLength, IFAMetadataHeader{}, true},
		{
			"valid metadata header",
			validHeader,
			IFAMetadataHeader{
				RequestVector: 255,
				Loss:          true,
				Color:         true,
				HopLimit:      30,
				CurrentLength: 16,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IFAMetadataHeader{}
			err := got.decodeFromBytes(&tt.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("IFAMetadataHeader decode error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.want, got) {
				t.Errorf("IFA metadata header mismatch, \nwant  %#v\ngot %#v\n", tt.want, got)
			}
		})
	}
}

func TestIFAMetadata(t *testing.T) {
	invalidLength := append([]byte{}, testIFAMetadata1[:len(testIFAMetadata1)-1]...)
	validHeader := append([]byte{}, testIFAMetadata1...)

	tests := []struct {
		name    string
		payload []byte
		want    IFAMetadata
		wantErr bool
	}{
		{"invalid metadata length", invalidLength, IFAMetadata{}, true},
		{
			"valid metadata",
			validHeader,
			IFAMetadata{
				LocalNameSpace:         1,
				DeviceID:               17151,
				IPTTL:                  61,
				EgressPortSpeed:        IFAPortSpeed25G,
				Congestion:             0,
				QueueID:                46,
				RXTimestampSeconds:     2585,
				EgressSystemPort:       64,
				IngressSystemPort:      1,
				RXTimestampNanoSeconds: 922645570,
				ResidenceTime:          1000000726,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IFAMetadata{}
			err := got.decodeFromBytes(&tt.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("IFAMetadata decode error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.want, got) {
				t.Errorf("IFA metadata mismatch, \nwant  %#v\ngot %#v\n", tt.want, got)
			}
		})
	}
}

func TestIFA(t *testing.T) {
	gnsDefined := append([]byte{}, testIFAHeader...)
	gnsDefined[0] = 0x28
	fragmentEnabled := append([]byte{}, testIFAHeader...)
	fragmentEnabled[2] = fragmentEnabled[2] | 0x10
	checksumEnabled := append([]byte{}, testIFAHeader...)
	checksumEnabled[2] = checksumEnabled[2] | 0x01
	tailStampEnabled := append([]byte{}, testIFAHeader...)
	tailStampEnabled[2] = tailStampEnabled[2] | 0x08
	metadataStack := append([]byte{}, testIFAHeader...)
	metadataStack = append(metadataStack, testIFAMetadataHeader...)
	metadataStack = append(metadataStack, testIFAMetadata1...)
	metadataStack = append(metadataStack, testIFAMetadata2...)
	invalidMetadataLength1 := append([]byte{}, testIFAHeader...)
	invalidMetadataLength1 = append(invalidMetadataLength1, testIFAMetadataHeader...)
	invalidMetadataLength1[len(invalidMetadataLength1)-1] = 0x11
	invalidMetadataLength1 = append(invalidMetadataLength1, testIFAMetadata1...)
	invalidMetadataLength1 = append(invalidMetadataLength1, testIFAMetadata2...)
	invalidMetadataLength2 := append([]byte{}, testIFAHeader...)
	invalidMetadataLength2 = append(invalidMetadataLength2, testIFAMetadataHeader...)
	invalidMetadataLength2 = append(invalidMetadataLength2, 0x00)

	tests := []struct {
		name    string
		payload []byte
		want    IFA
		wantErr bool
	}{
		{
			"global name space identifier not supported",
			gnsDefined,
			IFA{
				Header: IFAHeader{
					Version:          2,
					GlobalNameSpace:  8,
					NextHeader:       IPProtocolUDP,
					MetadataFragment: false,
					TailStamp:        false,
					Inband:           false,
					TurnAround:       false,
					Checksum:         false,
					MaxLength:        255,
				},
			},
			true,
		},
		{
			"fragment optional header not supported",
			fragmentEnabled,
			IFA{
				Header: IFAHeader{
					Version:          2,
					GlobalNameSpace:  15,
					NextHeader:       IPProtocolUDP,
					MetadataFragment: true,
					TailStamp:        false,
					Inband:           false,
					TurnAround:       false,
					Checksum:         false,
					MaxLength:        255,
				},
			},
			true,
		},
		{
			"checksum optional header not supported",
			checksumEnabled,
			IFA{
				Header: IFAHeader{
					Version:          2,
					GlobalNameSpace:  15,
					NextHeader:       IPProtocolUDP,
					MetadataFragment: false,
					TailStamp:        false,
					Inband:           false,
					TurnAround:       false,
					Checksum:         true,
					MaxLength:        255,
				},
			},
			true,
		},
		{
			"tail stamp metadata not supported",
			tailStampEnabled,
			IFA{
				Header: IFAHeader{
					Version:          2,
					GlobalNameSpace:  15,
					NextHeader:       IPProtocolUDP,
					MetadataFragment: false,
					TailStamp:        true,
					Inband:           false,
					TurnAround:       false,
					Checksum:         false,
					MaxLength:        255,
				},
			},
			true,
		},
		{
			"metadata stack",
			metadataStack,
			IFA{
				Header: IFAHeader{
					Version:          2,
					GlobalNameSpace:  15,
					NextHeader:       IPProtocolUDP,
					MetadataFragment: false,
					TailStamp:        false,
					Inband:           false,
					TurnAround:       false,
					Checksum:         false,
					MaxLength:        255,
				},
				MetadataHeader: IFAMetadataHeader{
					RequestVector: 255,
					Loss:          true,
					Color:         true,
					HopLimit:      30,
					CurrentLength: 16,
				},
				Metadatas: []IFAMetadata{
					{
						LocalNameSpace:         1,
						DeviceID:               17151,
						IPTTL:                  61,
						EgressPortSpeed:        IFAPortSpeed25G,
						Congestion:             0,
						QueueID:                46,
						RXTimestampSeconds:     2585,
						EgressSystemPort:       64,
						IngressSystemPort:      1,
						RXTimestampNanoSeconds: 922645570,
						ResidenceTime:          1000000726,
					},
					{
						LocalNameSpace:         1,
						DeviceID:               46975,
						IPTTL:                  63,
						EgressPortSpeed:        IFAPortSpeed200G,
						Congestion:             0,
						QueueID:                0,
						RXTimestampSeconds:     3782,
						EgressSystemPort:       1,
						IngressSystemPort:      63,
						RXTimestampNanoSeconds: 669396216,
						ResidenceTime:          1000000668,
					},
				},
			},
			false,
		},
		{
			"metadata stack length not corresponding to the header length",
			invalidMetadataLength1,
			IFA{
				Header: IFAHeader{
					Version:          2,
					GlobalNameSpace:  15,
					NextHeader:       IPProtocolUDP,
					MetadataFragment: false,
					TailStamp:        false,
					Inband:           false,
					TurnAround:       false,
					Checksum:         false,
					MaxLength:        255,
				},
				MetadataHeader: IFAMetadataHeader{
					RequestVector: 255,
					Loss:          true,
					Color:         true,
					HopLimit:      30,
					CurrentLength: 17,
				},
				Metadatas: []IFAMetadata{
					{
						LocalNameSpace:         1,
						DeviceID:               17151,
						IPTTL:                  61,
						EgressPortSpeed:        IFAPortSpeed25G,
						Congestion:             0,
						QueueID:                46,
						RXTimestampSeconds:     2585,
						EgressSystemPort:       64,
						IngressSystemPort:      1,
						RXTimestampNanoSeconds: 922645570,
						ResidenceTime:          1000000726,
					},
					{
						LocalNameSpace:         1,
						DeviceID:               46975,
						IPTTL:                  63,
						EgressPortSpeed:        IFAPortSpeed200G,
						Congestion:             0,
						QueueID:                0,
						RXTimestampSeconds:     3782,
						EgressSystemPort:       1,
						IngressSystemPort:      63,
						RXTimestampNanoSeconds: 669396216,
						ResidenceTime:          1000000668,
					},
				},
			},
			true,
		},
		{
			"metadata stack length not a multiple of 4 octets",
			invalidMetadataLength2,
			IFA{
				Header: IFAHeader{
					Version:          2,
					GlobalNameSpace:  15,
					NextHeader:       IPProtocolUDP,
					MetadataFragment: false,
					TailStamp:        false,
					Inband:           false,
					TurnAround:       false,
					Checksum:         false,
					MaxLength:        255,
				},
				MetadataHeader: IFAMetadataHeader{
					RequestVector: 255,
					Loss:          true,
					Color:         true,
					HopLimit:      30,
					CurrentLength: 16,
				},
			},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IFA{}
			err := got.DecodeFromBytes(tt.payload, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("IFA decode error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.want, got) {
				t.Errorf("IFA metadata header mismatch, \nwant  %#v\ngot %#v\n", tt.want, got)
			}
		})
	}
}
