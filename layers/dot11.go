// Copyright 2014 Google, Inc. All rights reserved.
// Copyright 2014 Remco Verhoef. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	_ "bytes"
	"encoding/binary"
        "fmt"
	"net"
        "hash/crc32"
	"code.google.com/p/gopacket"
)

const (
    Dot11ManagementType                             uint8=iota  // Frame type is management 
    Dot11ControlType                                            // Frame type is control 
    Dot11DataType                                               // Frame type is Data 
    Dot11ReservedType                                           // Frame type is Reserved 

)

const (
    Dot11ManagementAssocReqSubtype                  uint8=0x00  // association request        
    Dot11ManagementAssocRespSubtype                 uint8=0x01  // association response       
    Dot11ManagementReassocReqSubtype                uint8=0x02  // reassociation request      
    Dot11ManagementReassocRespSubtype               uint8=0x03  // reassociation response     
    Dot11ManagementProbeReqSubtype                  uint8=0x04  // Probe request              
    Dot11ManagementProbeRespSubtype                 uint8=0x05  // Probe response             
    Dot11ManagementMeasurementPilotSubtype          uint8=0x06  // Measurement Pilot          
    Dot11ManagementBeaconSubtype                    uint8=0x08  // Beacon frame               
    Dot11ManagementATIMSubtype                      uint8=0x09  // ATIM                       
    Dot11ManagementDisassociationSubtype            uint8=0x0A  // Disassociation             
    Dot11ManagementAuthenticationSubtype            uint8=0x0B  // Authentication             
    Dot11ManagementDeauthenticationSubtype          uint8=0x0C  // Deauthentication           
    Dot11ManagementActionSubtype                    uint8=0x0D  // Action                     
    Dot11ManagementActionNoAckSubtype               uint8=0x0E  // Action No Ack              
    Dot11ManagementArubaWlanSubtype                 uint8=0x0F  // Aruba WLAN Specific        

    Dot11ControlWrapper                             uint8=0x07  // Control Wrapper        
    Dot11ControlBlockAckReqSubtype                  uint8=0x08  // Block ack Request        
    Dot11ControlBlockAckSubtype                     uint8=0x09  // Block ack          
    Dot11ControlPowersavePollSubtype                uint8=0x0A  // power-save poll               
    Dot11ControlBlockRequestToSendSubtype           uint8=0x0B  // request to send               
    Dot11ControlClearToSendSubtype                  uint8=0x0C  // clear to send                 
    Dot11ControlAckSubtype              uint8=0x0D  // acknowledgement               
    Dot11ControlCFPeriodEndSubtype      uint8=0x0E  // contention-free period end    
    Dot11ControlCFPeriodEndAckSubtype   uint8=0x0F  // contention-free period end/ack 

    Dot11DataSubtype                                uint8=0x00  // Data                       
    Dot11DataCFAckSubtype                           uint8=0x01  // Data + CF-Ack              
    Dot11DataCFPollSubtype                          uint8=0x02  // Data + CF-Poll             
    Dot11DataCFAckPollSubtype                       uint8=0x03  // Data + CF-Ack + CF-Poll    
    Dot11DataNullFunctionSubtype                    uint8=0x04  // Null function (no data)    
    Dot11DataCFAckNoDataSubtype                     uint8=0x05  // CF-Ack (no data)           
    Dot11DataCFPollNoDataSubtype                    uint8=0x06  // CF-Poll (No data)          
    Dot11DataCFAckPollNoDataSubtype                 uint8=0x07  // CF-Ack + CF-Poll (no data) 
    Dot11DataQOSDataSubtype                         uint8=0x08  // QOS Data                   
    Dot11DataQOSDataCFAckSubtype                    uint8=0x09  // QOS Data + CF-Ack        
    Dot11DataQOSDataCFPollSubtype                   uint8=0x0A  // QOS Data + CF-Poll      
    Dot11DataQOSDataCFAckPollSubtype                uint8=0x0B  // QOS Data + CF-Ack + CF-Poll    
    Dot11DataQOSNullSubtype                         uint8=0x0C  // QOS Null        
    Dot11DataQOSCFPollNoDataSubtype                 uint8=0x0E  // QOS CF-Poll (No Data)      
    Dot11DataQOSCFAckPollNoDataSubtype              uint8=0x0F  // QOS CF-Ack + CF-Poll (No Data) 
)

type Dot11Flags uint8

const (
        Dot11FlagsToDS	                Dot11Flags = 1 << iota
	Dot11FlagsFromDS
        Dot11FlagsMF
	Dot11FlagsRetry
	Dot11FlagsPowerManagement
        Dot11FlagsMD
        Dot11FlagsWEP
        Dot11FlagsOrder
)

func (a Dot11Flags) String() string {
    outStr := ""
    if ((a & Dot11FlagsToDS) == Dot11FlagsToDS) {
        outStr += "TO-DS,"
    }
    if ((a & Dot11FlagsFromDS) == Dot11FlagsFromDS) {
        outStr += "FROM-DS,"
    }
    if ((a & Dot11FlagsMF) == Dot11FlagsMF) {
        outStr += "MF,"
    }
    if ((a & Dot11FlagsRetry) == Dot11FlagsRetry) {
        outStr += "Retry,"
    }
    if ((a & Dot11FlagsPowerManagement) == Dot11FlagsPowerManagement) {
        outStr += "PowerManagement,"
    }
    if ((a & Dot11FlagsMD) == Dot11FlagsMD) {
        outStr += "MD,"
    }
    if ((a & Dot11FlagsWEP) == Dot11FlagsWEP) {
        outStr += "WEP,"
    }
    if ((a & Dot11FlagsOrder) == Dot11FlagsOrder) {
        outStr += "Order,"
    }

    return outStr
}

type Dot11Reason uint16

// TODO: Verify these reasons, and append more reasons if more.

const (
        Dot11ReasonReserved	                Dot11Reason = 1
	Dot11ReasonUnspecified                  Dot11Reason = 2
        Dot11ReasonAuthExpired                  Dot11Reason = 3
	Dot11ReasonDeauthStLeaving              Dot11Reason = 4
	Dot11ReasonInactivity                   Dot11Reason = 5
        Dot11ReasonApFull                       Dot11Reason = 6
        Dot11ReasonClass2FromNonAuth            Dot11Reason = 7
        Dot11ReasonClass3FromNonAss             Dot11Reason = 8
        Dot11ReasonDisasStLeaving               Dot11Reason = 9
        Dot11ReasonStNotAuth                    Dot11Reason = 10
)

func (a Dot11Reason) String() string {
    switch a {
        case Dot11ReasonReserved:
            return "Reserved"
        case Dot11ReasonUnspecified:
            return "Unspecified"
        case Dot11ReasonAuthExpired:
            return "Auth. expired"
        case Dot11ReasonDeauthStLeaving:
            return "Deauth. st. leaving"
        case Dot11ReasonInactivity:
            return "Inactivity"
        case Dot11ReasonApFull:
            return "Ap. full"
        case Dot11ReasonClass2FromNonAuth:
            return "Class2 from non auth."
        case Dot11ReasonClass3FromNonAss:
            return "Class3 from non ass."
        case Dot11ReasonDisasStLeaving:
            return "Disass st. leaving"
        case Dot11ReasonStNotAuth:
            return "St. not auth."
        default:
            return "Unknown reason"
    }
}

type Dot11Status uint16 

const (
        Dot11StatusSuccess	                Dot11Status = 0  // 
	Dot11StatusFailure                      Dot11Status = 1  // Unspecified failure
	Dot11StatusCannotSupportAllCapabilities Dot11Status = 10 // Cannot support all requested capabilities in the Capability Information field
	Dot11StatusInabilityExistsAssociation   Dot11Status = 11 // Reassociation denied due to inability to confirm that association exists
	Dot11StatusAssociationDenied            Dot11Status = 12 // Association denied due to reason outside the scope of this standard
	Dot11StatusAlgorithmUnsupported         Dot11Status = 13 // Responding station does not support the specified authentication algorithm
	Dot11StatusOufOfExpectedSequence        Dot11Status = 14 // Received an Authentication frame with authentication transaction sequence number out of expected sequence
	Dot11StatusChallengeFailure             Dot11Status = 15 // Authentication rejected because of challenge failure
	Dot11StatusTimeout                      Dot11Status = 16 // Authentication rejected due to timeout waiting for next frame in sequence
	Dot11StatusAPUnableToHandle             Dot11Status = 17 // Association denied because AP is unable to handle additional associated stations
	Dot11StatusRateUnsupported              Dot11Status = 18 // Association denied due to requesting station not supporting all of the data rates in the BSSBasicRateSet parameter
)

func (a Dot11Status) String() string {
    switch a {
        case Dot11StatusSuccess:
            return "success"
        case Dot11StatusFailure:
            return "failure"
        case Dot11StatusCannotSupportAllCapabilities:
            return "cannot-support-all-capabilities"
        case Dot11StatusInabilityExistsAssociation:
            return "inability-exists-association"
        case Dot11StatusAssociationDenied:
            return "association-denied"
        case Dot11StatusAlgorithmUnsupported:
            return "algorithm-unsupported"
        case Dot11StatusOufOfExpectedSequence:
            return "out-of-expected-sequence"
        case Dot11StatusChallengeFailure:
            return "challenge-failure"
        case Dot11StatusTimeout:
            return "timeout"
        case Dot11StatusAPUnableToHandle:
            return "ap-unable-to-handle"
        case Dot11StatusRateUnsupported:
            return "rate-unsupported"
        default:
            return "unknown status"
    }
}

type Dot11AckPolicy uint8 

const (
        Dot11AckPolicyNormalAck	                Dot11AckPolicy = 0
        Dot11AckPolicyNoAck	                Dot11AckPolicy = 1
        Dot11AckPolicyNoExplicitAck             Dot11AckPolicy = 2
        Dot11AckPolicyBlockAck                  Dot11AckPolicy = 3
)

func (a Dot11AckPolicy) String() string {
    switch a {
        case Dot11AckPolicyNormalAck:
            return "normal-ack"
        case Dot11AckPolicyNoAck:
            return "no-ack"
        case Dot11AckPolicyNoExplicitAck:
            return "no-explicit-ack"
        case Dot11AckPolicyBlockAck:
            return "block-ack"
        default:
            return "unknown-ack-policy"
    }
}

type Dot11Algorithm uint16 

const (
        Dot11AlgorithmOpen	                Dot11Algorithm = 0
	Dot11AlgorithmSharedKey                 Dot11Algorithm = 1
)

func (a Dot11Algorithm) String() string {
    switch a {
        case Dot11AlgorithmOpen:
            return "open"
        case Dot11AlgorithmSharedKey:
            return "shared-key"
        default:
            return "unknown-algorithm"
    }
}

type Dot11InformationElementId uint8

// TODO: Verify these element ids, and append more ids if more.

const (
        Dot11InformationElementIdSSID	                Dot11InformationElementId = 0
        Dot11InformationElementIdRates	                Dot11InformationElementId = 1
        Dot11InformationElementIdFHSet	                Dot11InformationElementId = 2
        Dot11InformationElementIdDSSet	                Dot11InformationElementId = 3
        Dot11InformationElementIdCFSet	                Dot11InformationElementId = 4
        Dot11InformationElementIdTIM	                Dot11InformationElementId = 5
        Dot11InformationElementIdIBSSSet	        Dot11InformationElementId = 6
        Dot11InformationElementIdChallenge	        Dot11InformationElementId = 16
        Dot11InformationElementIdERPInfo	        Dot11InformationElementId = 42
        Dot11InformationElementIdQOSCapability	        Dot11InformationElementId = 46
        Dot11InformationElementIdERPInfo2	        Dot11InformationElementId = 47
        Dot11InformationElementIdRSNInfo	        Dot11InformationElementId = 48
        Dot11InformationElementIdESRates	        Dot11InformationElementId = 50
        Dot11InformationElementIdVendor 	        Dot11InformationElementId = 221
        Dot11InformationElementIdReserved 	        Dot11InformationElementId = 68
)

func (a Dot11InformationElementId) String() string {
    switch a {
        case Dot11InformationElementIdSSID:
            return "SSID"
        case Dot11InformationElementIdRates:
            return "Rates"
        case Dot11InformationElementIdFHSet:
            return "FHset"
        case Dot11InformationElementIdDSSet:
            return "DSset"
        case Dot11InformationElementIdCFSet:
            return "CFset"
        case Dot11InformationElementIdTIM:
            return "TIM"
        case Dot11InformationElementIdIBSSSet:
            return "IBSSset"
        case Dot11InformationElementIdChallenge:
            return "Challenge"
        case Dot11InformationElementIdERPInfo:
            return "ERPinfo"
        case Dot11InformationElementIdQOSCapability:
            return "QOS capability"
        case Dot11InformationElementIdERPInfo2:
            return "ERPinfo2"
        case Dot11InformationElementIdRSNInfo:
            return "RSNinfo"
        case Dot11InformationElementIdESRates:
            return "ESrates"
        case Dot11InformationElementIdVendor:
            return "Vendor"
        case Dot11InformationElementIdReserved:
            return "Reserved"
        default:
            return "Unknown information element id"
    }
}

type Dot11 struct {
	BaseLayer
        Subtype uint8
        Type uint8
        Proto uint8
        Flags Dot11Flags
        Valid bool
        DurationId uint16
        // DurationId []byte
        Address1 net.HardwareAddr
        Address2 net.HardwareAddr
        Address3 net.HardwareAddr
        Address4 net.HardwareAddr
}

func decodeDot11(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11) LayerType() gopacket.LayerType { return LayerTypeDot11 }
func (m *Dot11) CanDecode() gopacket.LayerClass { return LayerTypeDot11 }
func (m *Dot11) NextLayerType() gopacket.LayerType {
        switch(m.Type) {
            case Dot11ManagementType: {
                // same header for all management frames, 24 bytes
                switch (m.Subtype) {
                    case Dot11ManagementAssocReqSubtype: {
                        return LayerTypeDot11MgmtAssocReq
                    }
                    case Dot11ManagementAssocRespSubtype: {
                        return LayerTypeDot11MgmtAssocResp
                    }
                    case Dot11ManagementReassocReqSubtype: {
                        return LayerTypeDot11MgmtReassocReq
                    }
                    case Dot11ManagementReassocRespSubtype: {
                        return LayerTypeDot11MgmtReassocResp
                    }
                    case Dot11ManagementProbeReqSubtype: {
                        return LayerTypeDot11MgmtProbeReq
                    }
                    case Dot11ManagementProbeRespSubtype: {
                        return LayerTypeDot11MgmtProbeResp
                    }
                    case Dot11ManagementMeasurementPilotSubtype: {
                        return LayerTypeDot11MgmtMeasurementPilot
                    }
                    case Dot11ManagementBeaconSubtype: {
                        return LayerTypeDot11MgmtBeacon
                    }
                    case Dot11ManagementATIMSubtype: {
                        return LayerTypeDot11MgmtATIM
                    }
                    case Dot11ManagementDisassociationSubtype: {
                        return LayerTypeDot11MgmtDisassociation
                    }
                    case Dot11ManagementAuthenticationSubtype: {
                        return LayerTypeDot11MgmtAuthentication
                    }
                    case Dot11ManagementDeauthenticationSubtype: {
                        return LayerTypeDot11MgmtDeauthentication
                    }
                    case Dot11ManagementActionSubtype: {
                        return LayerTypeDot11MgmtAction
                    }
                    case Dot11ManagementActionNoAckSubtype: {
                        return LayerTypeDot11MgmtActionNoAck
                    }
                    case Dot11ManagementArubaWlanSubtype: {
                        return LayerTypeDot11MgmtArubaWlan
                    }
                }
            }
            case Dot11ControlType: {
                switch (m.Subtype) {
                    case Dot11ControlBlockAckReqSubtype: {
                        return LayerTypeDot11ControlBlockAckReq
                    }
                    case Dot11ControlBlockAckSubtype: {
                        return LayerTypeDot11ControlBlockAck
                    }
                    case Dot11ControlBlockRequestToSendSubtype: {
                        return LayerTypeDot11ControlRequestToSend
                    }
                    case Dot11ControlClearToSendSubtype: {
                        return LayerTypeDot11ControlClearToSend
                    }
                    case Dot11ControlPowersavePollSubtype: {
                        return LayerTypeDot11ControlPowersavePoll
                    }
                    case Dot11ControlAckSubtype: {
                        return LayerTypeDot11ControlAck
                    }
                    case Dot11ControlCFPeriodEndSubtype: {
                        return LayerTypeDot11ControlCFPeriodEnd
                    }
                    case Dot11ControlCFPeriodEndAckSubtype: {
                        return LayerTypeDot11ControlCFPeriodEndAck
                    }
                }
                return gopacket.LayerTypePayload
            }
            case Dot11DataType: {
                switch (m.Subtype) {
                    case Dot11DataSubtype: {
                        return LayerTypeDot11DataFrame
                    }
                    case Dot11DataCFAckSubtype: {
                        return LayerTypeDot11DataCFAck
                    }
                    case Dot11DataCFPollSubtype: {
                        return LayerTypeDot11DataCFPoll
                    }
                    case Dot11DataCFAckPollSubtype: {
                        return LayerTypeDot11DataCFAckPoll
                    }
                    case Dot11DataNullFunctionSubtype: {
                        return LayerTypeDot11DataNull
                    }
                    case Dot11DataCFAckNoDataSubtype: {
                        return LayerTypeDot11DataCFAckNoData
                    }
                    case Dot11DataCFPollNoDataSubtype: {
                        return LayerTypeDot11DataCFPollNoData
                    }
                    case Dot11DataCFAckPollNoDataSubtype: {
                        return LayerTypeDot11DataCFAckPollNoData
                    }
                    case Dot11DataQOSDataSubtype: {
                        return LayerTypeDot11DataQOSData
                    }
                    case Dot11DataQOSDataCFAckSubtype: {
                        return LayerTypeDot11DataQOSDataCFAck
                    }
                    case Dot11DataQOSDataCFPollSubtype: {
                        return LayerTypeDot11DataQOSDataCFPoll
                    }
                    case Dot11DataQOSDataCFAckPollSubtype: {
                        return LayerTypeDot11DataQOSDataCFAckPoll
                    }
                    case Dot11DataQOSNullSubtype: {
                        return LayerTypeDot11DataQOSNull
                    }
                    case Dot11DataQOSCFPollNoDataSubtype: {
                        return LayerTypeDot11DataQOSCFPollNoData
                    }
                    case Dot11DataQOSCFAckPollNoDataSubtype: {
                        return LayerTypeDot11DataQOSCFAckPollNoData
                    }
                }
                return gopacket.LayerTypePayload
            }
        }

        // not implemented yet
	return gopacket.LayerTypePayload}

func (m *Dot11) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Subtype = (uint8(data[0]) & 0xF0) >> 4
    m.Type = (uint8(data[0]) & 0x000C) >> 2
    m.Proto = uint8(data[0]) & 0x0003
    m.Flags = Dot11Flags(data[1])
    m.DurationId=binary.LittleEndian.Uint16(data[2:4])
    m.Address1=net.HardwareAddr(data[4:10])

    offset := 10

    if (m.Type == Dot11ControlType) {
        switch(m.Subtype) { 
            case Dot11ControlBlockRequestToSendSubtype, Dot11ControlPowersavePollSubtype, Dot11ControlCFPeriodEndSubtype, Dot11ControlCFPeriodEndAckSubtype: {
                m.Address2=net.HardwareAddr(data[offset:offset+6])
                offset += 6
            }
        }
    } else {
        m.Address2=net.HardwareAddr(data[offset:offset+6])
        offset += 6
    }

    if (m.Type == Dot11ManagementType || m.Type == Dot11DataType) {
        m.Address3=net.HardwareAddr(data[offset:offset+6])
        offset += 6
    }

    if (m.Type != Dot11ControlType) {
        // Sequence
        offset +=2 
    }

    if (m.Type == Dot11DataType && ((m.Flags & Dot11FlagsFromDS) == Dot11FlagsFromDS) && ((m.Flags & Dot11FlagsToDS)==Dot11FlagsToDS)) {
        m.Address4=net.HardwareAddr(data[offset:offset+6])
        offset += 6
    }

    // 29:31 SequenceControl

    // Frame body
    switch(m.Type) {
        case Dot11ManagementType: {
            m.BaseLayer = BaseLayer{Contents: data[0:offset], Payload: data[offset:len(data)-4]}
            offset = len(data)-4
        }
        case Dot11ControlType: {
            m.BaseLayer = BaseLayer{Contents: data[0:offset], Payload: data[offset:len(data)-4]}
            offset = len(data)-4
        }
        case Dot11DataType: {
            m.BaseLayer = BaseLayer{Contents: data[0:offset], Payload: data[offset:len(data)-4]}
            offset = len(data)-4
        }
    }

    checksum := crc32.ChecksumIEEE(data[:offset])
    m.Valid = (checksum == binary.LittleEndian.Uint32(data[offset:offset+4]))
   
    return (nil)
}

type Dot11MgmtFrame struct {
	BaseLayer
}

func (m *Dot11MgmtFrame) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }
func (m *Dot11MgmtFrame) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11ControlFrame struct {
	BaseLayer
}

func (m *Dot11ControlFrame) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

func (m *Dot11ControlFrame) LayerType() gopacket.LayerType { return LayerTypeDot11ControlFrame }
func (m *Dot11ControlFrame) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlFrame }
func (m *Dot11ControlFrame) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

func decodeDot11ControlFrame(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlFrame{}
	return decodingLayerDecoder(d, data, p)
}

type Dot11DataFrame struct {
	BaseLayer
}

func (m *Dot11DataFrame) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

func (m *Dot11DataFrame) LayerType() gopacket.LayerType { return LayerTypeDot11DataFrame }
func (m *Dot11DataFrame) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataFrame }
func (m *Dot11DataFrame) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

func decodeDot11DataFrame(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataFrame{}
	return decodingLayerDecoder(d, data, p)
}


type Dot11DataCFAck struct {
	Dot11ControlFrame
}

func decodeDot11DataCFAck(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCFAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCFAck) LayerType() gopacket.LayerType { return LayerTypeDot11DataCFAck }
func (m *Dot11DataCFAck) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCFAck }
func (m *Dot11DataCFAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11DataCFPoll struct {
	Dot11ControlFrame
}

func decodeDot11DataCFPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCFPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCFPoll) LayerType() gopacket.LayerType { return LayerTypeDot11DataCFPoll }
func (m *Dot11DataCFPoll) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCFPoll }
func (m *Dot11DataCFPoll) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11DataCFAckPoll struct {
	Dot11ControlFrame
}

func decodeDot11DataCFAckPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCFAckPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCFAckPoll) LayerType() gopacket.LayerType { return LayerTypeDot11DataCFAckPoll }
func (m *Dot11DataCFAckPoll) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCFAckPoll }
func (m *Dot11DataCFAckPoll) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11DataNull struct {
	Dot11ControlFrame
}

func decodeDot11DataNull(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataNull{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataNull) LayerType() gopacket.LayerType { return LayerTypeDot11DataNull }
func (m *Dot11DataNull) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataNull }
func (m *Dot11DataNull) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11DataCFAckNoData struct {
	Dot11ControlFrame
}

func decodeDot11DataCFAckNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCFAckNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCFAckNoData) LayerType() gopacket.LayerType { return LayerTypeDot11DataCFAckNoData }
func (m *Dot11DataCFAckNoData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCFAckNoData }
func (m *Dot11DataCFAckNoData) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11DataCFPollNoData struct {
	Dot11ControlFrame
}

func decodeDot11DataCFPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCFPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCFPollNoData) LayerType() gopacket.LayerType { return LayerTypeDot11DataCFPollNoData }
func (m *Dot11DataCFPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCFPollNoData }
func (m *Dot11DataCFPollNoData) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11DataCFAckPollNoData struct {
	Dot11ControlFrame
}

func decodeDot11DataCFAckPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCFAckPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCFAckPollNoData) LayerType() gopacket.LayerType { return LayerTypeDot11DataCFAckPollNoData }
func (m *Dot11DataCFAckPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCFAckPollNoData }
func (m *Dot11DataCFAckPollNoData) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11DataQOS struct {
        Dot11ControlFrame
        TID uint8 /* Traffic Identifier */
        EOSP bool /* End of service period */
        AckPolicy Dot11AckPolicy
        TXOP uint8
}

func (m *Dot11DataQOS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.TID = (uint8(data[0]) & 0x0F)
        m.EOSP = (uint8(data[0]) & 0x10) == 0x10
        m.AckPolicy = Dot11AckPolicy((uint8(data[0]) & 0x60) >> 5)
        m.TXOP = uint8(data[1])
        m.BaseLayer = BaseLayer{Contents: data[0:2], Payload: data[2:]}
        return nil
}

type Dot11DataQOSData struct {
	Dot11DataQOS
}

func decodeDot11DataQOSData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQOSData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQOSData) LayerType() gopacket.LayerType { return LayerTypeDot11DataQOSData }
func (m *Dot11DataQOSData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQOSData }

func (m *Dot11DataQOSData) NextLayerType() gopacket.LayerType { 
        return LayerTypeDot11DataFrame
}

type Dot11DataQOSDataCFAck struct {
	Dot11DataQOS
}

func decodeDot11DataQOSDataCFAck(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQOSDataCFAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQOSDataCFAck) LayerType() gopacket.LayerType { return LayerTypeDot11DataQOSDataCFAck }
func (m *Dot11DataQOSDataCFAck) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQOSDataCFAck }
func (m *Dot11DataQOSDataCFAck) NextLayerType() gopacket.LayerType { return LayerTypeDot11DataCFAck }

type Dot11DataQOSDataCFPoll struct {
	Dot11DataQOS
}

func decodeDot11DataQOSDataCFPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQOSDataCFPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQOSDataCFPoll) LayerType() gopacket.LayerType { return LayerTypeDot11DataQOSDataCFPoll }
func (m *Dot11DataQOSDataCFPoll) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQOSDataCFPoll }
func (m *Dot11DataQOSDataCFPoll) NextLayerType() gopacket.LayerType { return LayerTypeDot11DataCFPoll } 

type Dot11DataQOSDataCFAckPoll struct {
	Dot11DataQOS
}

func decodeDot11DataQOSDataCFAckPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQOSDataCFAckPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQOSDataCFAckPoll) LayerType() gopacket.LayerType { return LayerTypeDot11DataQOSDataCFAckPoll }
func (m *Dot11DataQOSDataCFAckPoll) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQOSDataCFAckPoll }
func (m *Dot11DataQOSDataCFAckPoll) NextLayerType() gopacket.LayerType { return LayerTypeDot11DataCFAckPoll }

type Dot11DataQOSNull struct {
	Dot11DataQOS
}

func decodeDot11DataQOSNull(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQOSNull{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQOSNull) LayerType() gopacket.LayerType { return LayerTypeDot11DataQOSNull }
func (m *Dot11DataQOSNull) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQOSNull }
func (m *Dot11DataQOSNull) NextLayerType() gopacket.LayerType { return LayerTypeDot11DataNull } 

type Dot11DataQOSCFPollNoData struct {
	Dot11DataQOS
}

func decodeDot11DataQOSCFPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQOSCFPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQOSCFPollNoData) LayerType() gopacket.LayerType { return LayerTypeDot11DataQOSCFPollNoData }
func (m *Dot11DataQOSCFPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQOSCFPollNoData }
func (m *Dot11DataQOSCFPollNoData) NextLayerType() gopacket.LayerType { return LayerTypeDot11DataCFPollNoData } 

type Dot11DataQOSCFAckPollNoData struct {
	Dot11DataQOS
}

func decodeDot11DataQOSCFAckPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQOSCFAckPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQOSCFAckPollNoData) LayerType() gopacket.LayerType { return LayerTypeDot11DataQOSCFAckPollNoData }
func (m *Dot11DataQOSCFAckPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQOSCFAckPollNoData }
func (m *Dot11DataQOSCFAckPollNoData) NextLayerType() gopacket.LayerType { return LayerTypeDot11DataCFAckPollNoData } 

type Dot11InformationElement struct {
	BaseLayer
        Id Dot11InformationElementId 
        Length uint8
        Oui []byte
        Info []byte
}

func (m *Dot11InformationElement) LayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }
func (m *Dot11InformationElement) CanDecode() gopacket.LayerClass { return LayerTypeDot11InformationElement }

func (m *Dot11InformationElement) NextLayerType() gopacket.LayerType {
        return LayerTypeDot11InformationElement
}

func (m *Dot11InformationElement) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Id = Dot11InformationElementId(data[0])
        m.Length = data[1]
        offset := uint8(2)

        if (m.Id==221) {
            // Vendor extension
            m.Oui=data[offset:offset+4]
            m.Info = data[offset+4:offset+m.Length]
        } else {
            m.Info = data[offset:offset+m.Length]
        }

        offset += m.Length

        m.BaseLayer = BaseLayer{Contents: data[:offset], Payload: data[offset:]}
        return nil
}

func (d *Dot11InformationElement) String() string {
        if (d.Id==0) {
            return fmt.Sprintf("802.11 Information Element (SSID: %v)", string(d.Info))
        } else if (d.Id==1) {
            rates := ""
            for i:=0;i<len(d.Info);i++ {
                if (d.Info[i] & 0x80 == 0) {
                rates+=fmt.Sprintf("%.1f ", float32(d.Info[i]) * 0.5)
                } else {
                rates+=fmt.Sprintf("%.1f* ", float32(d.Info[i] & 0x7F) * 0.5)
                }
            }
            return fmt.Sprintf("802.11 Information Element (Rates: %s Mbit)", rates)
        } else if (d.Id==221) {
            return fmt.Sprintf("802.11 Information Element (Vendor: ID: %v, Length: %v, OUI: %X, Info: %X)", d.Id, d.Length, d.Oui, d.Info)
        } else {
            return fmt.Sprintf("802.11 Information Element (ID: %v, Length: %v, Info: %X)", d.Id, d.Length, d.Info)
        }
}

func decodeDot11InformationElement(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11InformationElement{}
	return decodingLayerDecoder(d, data, p)
}


type Dot11ControlClearToSend struct {
	Dot11ControlFrame
}

func decodeDot11ControlClearToSend(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlClearToSend{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlClearToSend) LayerType() gopacket.LayerType { return LayerTypeDot11ControlClearToSend }
func (m *Dot11ControlClearToSend) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlClearToSend }
func (m *Dot11ControlClearToSend) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11ControlRequestToSend struct {
	Dot11ControlFrame
}

func decodeDot11ControlRequestToSend(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlRequestToSend{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlRequestToSend) LayerType() gopacket.LayerType { return LayerTypeDot11ControlRequestToSend }
func (m *Dot11ControlRequestToSend) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlRequestToSend }
func (m *Dot11ControlRequestToSend) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11ControlBlockAckReq struct {
	Dot11ControlFrame
}

func decodeDot11ControlBlockAckReq(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlBlockAckReq{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlBlockAckReq) LayerType() gopacket.LayerType { return LayerTypeDot11ControlBlockAckReq }
func (m *Dot11ControlBlockAckReq) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlBlockAckReq }
func (m *Dot11ControlBlockAckReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11ControlBlockAck struct {
	Dot11ControlFrame
}

func decodeDot11ControlBlockAck(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlBlockAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlBlockAck) LayerType() gopacket.LayerType { return LayerTypeDot11ControlBlockAck }
func (m *Dot11ControlBlockAck) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlBlockAck }
func (m *Dot11ControlBlockAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11ControlPowersavePoll struct {
	Dot11ControlFrame
}

func decodeDot11ControlPowersavePoll(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlPowersavePoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlPowersavePoll) LayerType() gopacket.LayerType { return LayerTypeDot11ControlPowersavePoll }
func (m *Dot11ControlPowersavePoll) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlPowersavePoll }
func (m *Dot11ControlPowersavePoll) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11ControlAck struct {
	Dot11ControlFrame
}

func decodeDot11ControlAck(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlAck) LayerType() gopacket.LayerType { return LayerTypeDot11ControlAck }
func (m *Dot11ControlAck) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlAck }
func (m *Dot11ControlAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11ControlCFPeriodEnd struct {
	Dot11ControlFrame
}

func decodeDot11ControlCFPeriodEnd(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlCFPeriodEnd{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlCFPeriodEnd) LayerType() gopacket.LayerType { return LayerTypeDot11ControlCFPeriodEnd }
func (m *Dot11ControlCFPeriodEnd) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlCFPeriodEnd }
func (m *Dot11ControlCFPeriodEnd) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11ControlCFPeriodEndAck struct {
	Dot11ControlFrame
}

func decodeDot11ControlCFPeriodEndAck(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlCFPeriodEndAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlCFPeriodEndAck) LayerType() gopacket.LayerType { return LayerTypeDot11ControlCFPeriodEndAck }
func (m *Dot11ControlCFPeriodEndAck) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlCFPeriodEndAck }
func (m *Dot11ControlCFPeriodEndAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Contents = data
        return nil
}

type Dot11MgmtAssocReq struct {
	Dot11MgmtFrame
        CapabilityInfo uint16
        ListenInterval uint16
}

func decodeDot11MgmtAssocReq(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtAssocReq{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtAssocReq) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtAssocReq }
func (m *Dot11MgmtAssocReq) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtAssocReq }
func (m *Dot11MgmtAssocReq) NextLayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }
func (m *Dot11MgmtAssocReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.CapabilityInfo=binary.LittleEndian.Uint16(data[0:2])
        m.ListenInterval=binary.LittleEndian.Uint16(data[2:4])
        m.Contents = data
        return nil
}

type Dot11MgmtAssocResp struct {
	Dot11MgmtFrame
        CapabilityInfo uint16
        Status Dot11Status
        AID uint16
}

func decodeDot11MgmtAssocResp(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtAssocResp{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtAssocResp) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtAssocResp }
func (m *Dot11MgmtAssocResp) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtAssocResp }
func (m *Dot11MgmtAssocResp) NextLayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }
func (m *Dot11MgmtAssocResp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.CapabilityInfo=binary.LittleEndian.Uint16(data[0:2])
        m.Status=Dot11Status(binary.LittleEndian.Uint16(data[2:4]))
        m.AID=binary.LittleEndian.Uint16(data[4:6])
        m.Contents = data
        return nil
}

type Dot11MgmtReassocReq struct {
	Dot11MgmtFrame
        CapabilityInfo uint16
        ListenInterval uint16
        CurrentApAddress net.HardwareAddr
}

func decodeDot11MgmtReassocReq(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtReassocReq{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtReassocReq) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtReassocReq }
func (m *Dot11MgmtReassocReq) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtReassocReq }
func (m *Dot11MgmtReassocReq) NextLayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }
func (m *Dot11MgmtReassocReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.CapabilityInfo=binary.LittleEndian.Uint16(data[0:2])
        m.ListenInterval=binary.LittleEndian.Uint16(data[2:4])
        m.CurrentApAddress=net.HardwareAddr(data[4:10])
        m.Contents = data
        return nil
}

type Dot11MgmtReassocResp struct {
	Dot11MgmtFrame
}

func decodeDot11MgmtReassocResp(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtReassocResp{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtReassocResp) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtReassocResp }
func (m *Dot11MgmtReassocResp) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtReassocResp }
func (m *Dot11MgmtReassocResp) NextLayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }

type Dot11MgmtProbeReq struct {
	Dot11MgmtFrame
}

func decodeDot11MgmtProbeReq(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtProbeReq{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtProbeReq) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtProbeReq }
func (m *Dot11MgmtProbeReq) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtProbeReq }
func (m *Dot11MgmtProbeReq) NextLayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }

type Dot11MgmtProbeResp struct {
	Dot11MgmtFrame
}

func decodeDot11MgmtProbeResp(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtProbeResp{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtProbeResp) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtProbeResp }
func (m *Dot11MgmtProbeResp) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtProbeResp }
func (m *Dot11MgmtProbeResp) NextLayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }

type Dot11MgmtMeasurementPilot struct {
	Dot11MgmtFrame
}

func decodeDot11MgmtMeasurementPilot(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtMeasurementPilot{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtMeasurementPilot) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtMeasurementPilot }
func (m *Dot11MgmtMeasurementPilot) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtMeasurementPilot }

type Dot11MgmtBeacon struct {
	Dot11MgmtFrame
        Timestamp uint64 
        Interval uint16
        Flags uint16
}

func decodeDot11MgmtBeacon(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtBeacon{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtBeacon) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtBeacon }
func (m *Dot11MgmtBeacon) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtBeacon }
func (m *Dot11MgmtBeacon) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Timestamp=binary.LittleEndian.Uint64(data[0:8])
        m.Interval=binary.LittleEndian.Uint16(data[8:10])
        m.Flags=binary.LittleEndian.Uint16(data[10:12])
        m.Contents = data
        return nil
}

func (m *Dot11MgmtBeacon) NextLayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }

type Dot11MgmtATIM struct {
	Dot11MgmtFrame
}

func decodeDot11MgmtATIM(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtATIM{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtATIM) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtATIM }
func (m *Dot11MgmtATIM) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtATIM }

type Dot11MgmtDisassociation struct {
	Dot11MgmtFrame
        Reason Dot11Reason 
}

func decodeDot11MgmtDisassociation(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtDisassociation{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtDisassociation) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtDisassociation }
func (m *Dot11MgmtDisassociation) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtDisassociation }
func (m *Dot11MgmtDisassociation) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Reason=Dot11Reason(binary.LittleEndian.Uint16(data[0:2]))
        m.Contents = data
        return nil
}

type Dot11MgmtAuthentication struct {
	Dot11MgmtFrame
        Algorithm Dot11Algorithm
        Sequence uint16
        Status Dot11Status
}

func decodeDot11MgmtAuthentication(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtAuthentication{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtAuthentication) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtAuthentication }
func (m *Dot11MgmtAuthentication) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtAuthentication }
func (m *Dot11MgmtAuthentication) NextLayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }
func (m *Dot11MgmtAuthentication) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Algorithm=Dot11Algorithm(binary.LittleEndian.Uint16(data[0:2]))
        m.Sequence=binary.LittleEndian.Uint16(data[2:4])
        m.Status=Dot11Status(binary.LittleEndian.Uint16(data[4:6]))
        m.Contents = data
        return nil
}

type Dot11MgmtDeauthentication struct {
	Dot11MgmtFrame
        Reason Dot11Reason
}

func decodeDot11MgmtDeauthentication(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtDeauthentication{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtDeauthentication) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtDeauthentication }
func (m *Dot11MgmtDeauthentication) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtDeauthentication }
func (m *Dot11MgmtDeauthentication) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
        m.Reason=Dot11Reason(binary.LittleEndian.Uint16(data[0:2]))
        m.Contents = data
        return nil
}

type Dot11MgmtAction struct {
	Dot11MgmtFrame
}

func decodeDot11MgmtAction(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtAction{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtAction) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtAction }
func (m *Dot11MgmtAction) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtAction }

type Dot11MgmtActionNoAck struct {
	Dot11MgmtFrame
}

func decodeDot11MgmtActionNoAck(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtActionNoAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtActionNoAck) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtActionNoAck }
func (m *Dot11MgmtActionNoAck) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtActionNoAck }

type Dot11MgmtArubaWlan struct {
	Dot11MgmtFrame
}

func decodeDot11MgmtArubaWlan(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtArubaWlan{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtArubaWlan) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtArubaWlan }
func (m *Dot11MgmtArubaWlan) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtArubaWlan }
