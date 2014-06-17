/**!
 * The MIT License
 *
 * Copyright (c) 2014 Remco Verhoef (github.com/dutchcoders/gopacket-80211)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * gopacket-80211
 * http://github.com/dutchcoders/gopacket-80211
 *
 * @authors http://github.com/dutchcoders/gopacket-80211/graphs/contributors
*/

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
    /* Frame type is management */
    Dot11ManagementType         uint8=0x00  
    /* Frame type is control */
    Dot11ControlType            uint8=0x01  
    /* Frame type is Data */
    Dot11DataType               uint8=0x02  
    /* Frame type is Reserved */
    Dot11ReservedType           uint8=0x03  
)

const (
    Dot11ManagementAssocReqSubtype          uint8=0x00  /* association request        */
    Dot11ManagementAssocRespSubtype         uint8=0x01  /* association response       */
    Dot11ManagementReassocReqSubtype        uint8=0x02  /* reassociation request      */
    Dot11ManagementReassocRespSubtype       uint8=0x03  /* reassociation response     */
    Dot11ManagementProbeReqSubtype          uint8=0x04  /* Probe request              */
    Dot11ManagementProbeRespSubtype         uint8=0x05  /* Probe response             */
    Dot11ManagementMeasurementPilotSubtype  uint8=0x06  /* Measurement Pilot          */
    Dot11ManagementBeaconSubtype             uint8=0x08  /* Beacon frame               */
    Dot11ManagementATIMSubtype               uint8=0x09  /* ATIM                       */
    Dot11ManagementDisassociationSubtype             uint8=0x0A  /* Disassociation             */
    Dot11ManagementAuthenticationSubtype     uint8=0x0B  /* Authentication             */
    Dot11ManagementDeauthenticationSubtype   uint8=0x0C  /* Deauthentication           */
    Dot11ManagementActionSubtype             uint8=0x0D  /* Action                     */
    Dot11ManagementActionNoAckSubtype      uint8=0x0E  /* Action No Ack              */
    Dot11ManagementArubaWlanSubtype         uint8=0x0F  /* Aruba WLAN Specific        */

    Dot11ControlWrapper uint8=0x07  /* Control Wrapper        */
    Dot11ControlBlockAckReqSubtype   uint8=0x08  /* Block ack Request        */
    Dot11ControlBlockAckSubtype       uint8=0x09  /* Block ack          */
    Dot11ControlPowersavePollSubtype         uint8=0x0A  /* power-save poll               */
    Dot11ControlBlockRequestToSendSubtype             uint8=0x0B  /* request to send               */
    Dot11ControlClearToSendSubtype             uint8=0x0C  /* clear to send                 */
    Dot11ControlAcknowledgementSubtype uint8=0x0D  /* acknowledgement               */
    Dot11ControlContentionFreePeriodEndSubtype         uint8=0x0E  /* contention-free period end    */
    Dot11ControlContentionFreePeriodEndAckSubtype      uint8=0x0F  /* contention-free period end/ack */

    Dot11DataSubtype                        uint8=0x00  /* Data                       */
    Dot11DataCfAckSubtype                 uint8=0x01  /* Data + CF-Ack              */
    Dot11DataCfPollSubtype                uint8=0x02  /* Data + CF-Poll             */
    Dot11DataCfAckPollSubtype            uint8=0x03  /* Data + CF-Ack + CF-Poll    */
    Dot11DataNullFunctionSubtype          uint8=0x04  /* Null function (no data)    */
    Dot11DataCfAckNoDataSubtype             uint8=0x05  /* CF-Ack (no data)           */
    Dot11DataCfPollNoDataSubtype            uint8=0x06  /* CF-Poll (No data)          */
    Dot11DataCfAckPollNoDataSubtype        uint8=0x07  /* CF-Ack + CF-Poll (no data) */
    Dot11DataQosDataSubtype               uint8=0x08  /* QoS Data                   */
    Dot11DataQosDataCfAckSubtype        uint8=0x09  /* QoS Data + CF-Ack        */
    Dot11DataQosDataCfPollSubtype       uint8=0x0A  /* QoS Data + CF-Poll      */
    Dot11DataQosDataCfAckPollSubtype   uint8=0x0B  /* QoS Data + CF-Ack + CF-Poll    */
    Dot11DataQosNullSubtype               uint8=0x0C  /* QoS Null        */
    Dot11DataQosCfPollNoDataSubtype        uint8=0x0E  /* QoS CF-Poll (No Data)      */
    Dot11DataQosCfAckPollNoDataSubtype    uint8=0x0F  /* QoS CF-Ack + CF-Poll (No Data) */
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

// TODO: Update codes

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
    switch (a) {
        case Dot11ReasonReserved: {
            return ("Reserved")
        }
        case Dot11ReasonUnspecified: {
            return ("Unspecified")
        }
        case Dot11ReasonAuthExpired: {
            return ("Auth. expired")
        }
        case Dot11ReasonDeauthStLeaving: {
            return ("Deauth. st. leaving")
        }
        case Dot11ReasonInactivity: {
            return ("Inactivity")
        }
        case Dot11ReasonApFull: {
            return ("Ap. full")
        }
        case Dot11ReasonClass2FromNonAuth: {
            return ("Class2 from non auth.")
        }
        case Dot11ReasonClass3FromNonAss: {
            return ("Class3 from non ass.")
        }
        case Dot11ReasonDisasStLeaving: {
            return ("Disass st. leaving")
        }
        case Dot11ReasonStNotAuth: {
            return ("St. not auth.")
        }
        default: {
            return ("Unknown reason")
        }
    }
}

type Dot11Algorithm uint16 


const (
        Dot11AlgorithmOpen	                Dot11Algorithm = 0
	Dot11AlgorithmSharedKey                 Dot11Algorithm = 1
)

func (a Dot11Algorithm) String() string {
    switch (a) {
        case Dot11AlgorithmOpen: {
            return ("Open")
        }
        case Dot11AlgorithmSharedKey: {
            return ("Shared key")
        }
        default: {
            return ("Unknown algorithm")
        }
    }
}

type Dot11InformationElementId uint8 


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
        Dot11InformationElementIdQoSCapability	        Dot11InformationElementId = 46
        Dot11InformationElementIdERPInfo2	        Dot11InformationElementId = 47
        Dot11InformationElementIdRSNInfo	        Dot11InformationElementId = 48
        Dot11InformationElementIdESRates	        Dot11InformationElementId = 50
        Dot11InformationElementIdVendor 	        Dot11InformationElementId = 221
        Dot11InformationElementIdReserved 	        Dot11InformationElementId = 68
)

func (a Dot11InformationElementId) String() string {
    switch (a) {
        case Dot11InformationElementIdSSID: {
            return ("SSID")
        }
        case Dot11InformationElementIdRates: {
            return ("Rates")
        }
        case Dot11InformationElementIdFHSet: {
            return ("FHset")
        }
        case Dot11InformationElementIdDSSet: {
            return ("DSset")
        }
        case Dot11InformationElementIdCFSet: {
            return ("CFset")
        }
        case Dot11InformationElementIdTIM: {
            return ("TIM")
        }
        case Dot11InformationElementIdIBSSSet: {
            return ("IBSSset")
        }
        case Dot11InformationElementIdChallenge: {
            return ("Challenge")
        }
        case Dot11InformationElementIdERPInfo: {
            return ("ERPinfo")
        }
        case Dot11InformationElementIdQoSCapability: {
            return ("QoS capability")
        }
        case Dot11InformationElementIdERPInfo2: {
            return ("ERPinfo2")
        }
        case Dot11InformationElementIdRSNInfo: {
            return ("RSNinfo")
        }
        case Dot11InformationElementIdESRates: {
            return ("ESrates")
        }
        case Dot11InformationElementIdVendor: {
            return ("Vendor")
        }
        case Dot11InformationElementIdReserved: {
            return ("Reserved")
        }
        default: {
            return ("Unknown information element id")
        }
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
                    case Dot11ControlAcknowledgementSubtype: {
                        return LayerTypeDot11ControlAcknowledgement
                    }
                    case Dot11ControlContentionFreePeriodEndSubtype: {
                        return LayerTypeDot11ControlContentionFreePeriodEnd
                    }
                    case Dot11ControlContentionFreePeriodEndAckSubtype: {
                        return LayerTypeDot11ControlContentionFreePeriodEndAck
                    }
                }
                return gopacket.LayerTypePayload
            }
            case Dot11DataType: {
                switch (m.Subtype) {
                    case Dot11DataSubtype: {
                        return LayerTypeDot11DataFrame
                    }
                    case Dot11DataCfAckSubtype: {
                        return LayerTypeDot11DataCfAck
                    }
                    case Dot11DataCfPollSubtype: {
                        return LayerTypeDot11DataCfPoll
                    }
                    case Dot11DataCfAckPollSubtype: {
                        return LayerTypeDot11DataCfAckPoll
                    }
                    case Dot11DataNullFunctionSubtype: {
                        return LayerTypeDot11DataNull
                    }
                    case Dot11DataCfAckNoDataSubtype: {
                        return LayerTypeDot11DataCfAckNoData
                    }
                    case Dot11DataCfPollNoDataSubtype: {
                        return LayerTypeDot11DataCfPollNoData
                    }
                    case Dot11DataCfAckPollNoDataSubtype: {
                        return LayerTypeDot11DataCfAckPollNoData
                    }
                    case Dot11DataQosDataSubtype: {
                        return LayerTypeDot11DataQosData
                    }
                    case Dot11DataQosDataCfAckSubtype: {
                        return LayerTypeDot11DataQosDataCfAck
                    }
                    case Dot11DataQosDataCfPollSubtype: {
                        return LayerTypeDot11DataQosDataCfPoll
                    }
                    case Dot11DataQosDataCfAckPollSubtype: {
                        return LayerTypeDot11DataQosDataCfAckPoll
                    }
                    case Dot11DataQosNullSubtype: {
                        return LayerTypeDot11DataQosNull
                    }
                    case Dot11DataQosCfPollNoDataSubtype: {
                        return LayerTypeDot11DataQosCfPollNoData
                    }
                    case Dot11DataQosCfAckPollNoDataSubtype: {
                        return LayerTypeDot11DataQosCfAckPollNoData
                    }
                }
                return gopacket.LayerTypePayload
            }
        }

        // not implemented yet
	return gopacket.LayerTypePayload}

func (m *Dot11) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Subtype = ((uint8)(data[0]) & 0xF0) >> 4
    m.Type = ((uint8)(data[0]) & 0x000C) >> 2
    m.Proto = ((uint8)(data[0]) & 0x0003)
    m.Flags = Dot11Flags(data[1])
    m.DurationId=binary.LittleEndian.Uint16(data[2:4])
    m.Address1=net.HardwareAddr(data[4:10])

    offset := 10

    if (m.Type == Dot11ControlType) {
        switch(m.Subtype) { 
            case Dot11ControlBlockRequestToSendSubtype, Dot11ControlPowersavePollSubtype, Dot11ControlContentionFreePeriodEndSubtype, Dot11ControlContentionFreePeriodEndAckSubtype: {
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

type Dot11ControlFrame struct {
	BaseLayer
}

func (m *Dot11ControlFrame) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

func (m *Dot11ControlFrame) LayerType() gopacket.LayerType { return LayerTypeDot11ControlFrame }
func (m *Dot11ControlFrame) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlFrame }
func (m *Dot11ControlFrame) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
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
    return nil
}

func decodeDot11DataFrame(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataFrame{}
	return decodingLayerDecoder(d, data, p)
}


type Dot11DataCfAck struct {
	Dot11ControlFrame
}

func decodeDot11DataCfAck(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCfAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCfAck) LayerType() gopacket.LayerType { return LayerTypeDot11DataCfAck }
func (m *Dot11DataCfAck) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCfAck }
func (m *Dot11DataCfAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

type Dot11DataCfPoll struct {
	Dot11ControlFrame
}

func decodeDot11DataCfPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCfPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCfPoll) LayerType() gopacket.LayerType { return LayerTypeDot11DataCfPoll }
func (m *Dot11DataCfPoll) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCfPoll }
func (m *Dot11DataCfPoll) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

type Dot11DataCfAckPoll struct {
	Dot11ControlFrame
}

func decodeDot11DataCfAckPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCfAckPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCfAckPoll) LayerType() gopacket.LayerType { return LayerTypeDot11DataCfAckPoll }
func (m *Dot11DataCfAckPoll) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCfAckPoll }
func (m *Dot11DataCfAckPoll) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
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
    return nil
}

type Dot11DataCfAckNoData struct {
	Dot11ControlFrame
}

func decodeDot11DataCfAckNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCfAckNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCfAckNoData) LayerType() gopacket.LayerType { return LayerTypeDot11DataCfAckNoData }
func (m *Dot11DataCfAckNoData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCfAckNoData }
func (m *Dot11DataCfAckNoData) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

type Dot11DataCfPollNoData struct {
	Dot11ControlFrame
}

func decodeDot11DataCfPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCfPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCfPollNoData) LayerType() gopacket.LayerType { return LayerTypeDot11DataCfPollNoData }
func (m *Dot11DataCfPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCfPollNoData }
func (m *Dot11DataCfPollNoData) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

type Dot11DataCfAckPollNoData struct {
	Dot11ControlFrame
}

func decodeDot11DataCfAckPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataCfAckPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataCfAckPollNoData) LayerType() gopacket.LayerType { return LayerTypeDot11DataCfAckPollNoData }
func (m *Dot11DataCfAckPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataCfAckPollNoData }
func (m *Dot11DataCfAckPollNoData) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

type Dot11DataQos struct {
    Dot11ControlFrame
    TID uint8 /* Traffic Identifier */
    EOSP bool /* End of service period */
    AckPolicy uint8
    TXOP uint8


    /*
    fields_desc = [ BitField("TID",None,4),
                    BitField("EOSP",None,1),
                    BitField("Ack Policy",None,2),
                    BitField("Reserved",None,1),
                    ByteField("TXOP",None) ]
    */
}

func (m *Dot11DataQos) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.TID = ((uint8)(data[0]) & 0x0F) 
    m.EOSP = ((uint8)(data[0]) & 0x10) == 0x10
    m.AckPolicy = ((uint8)(data[0]) & 0x60) >> 5
    m.TXOP = (uint8)(data[1])
    m.BaseLayer = BaseLayer{Contents: data[0:2], Payload: data[2:]}
    return nil
}

func (d *Dot11DataQos) String() string {
    ack_policies:=map[uint8]string{0:"Normal Ack", 1:"No Ack", 2: "No Explicit Acknowledgement", 3:"Block Acknowledgement"}
    return fmt.Sprintf("Ack policy: %v[%v]", ack_policies[d.AckPolicy], d.AckPolicy)
}

type Dot11DataQosData struct {
	Dot11DataQos
}

func decodeDot11DataQosData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQosData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQosData) LayerType() gopacket.LayerType { return LayerTypeDot11DataQosData }
func (m *Dot11DataQosData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQosData }

func (m *Dot11DataQosData) NextLayerType() gopacket.LayerType { 
    return LayerTypeDot11DataFrame
}

type Dot11DataQosDataCfAck struct {
	Dot11DataQos
}

func decodeDot11DataQosDataCfAck(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQosDataCfAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQosDataCfAck) LayerType() gopacket.LayerType { return LayerTypeDot11DataQosDataCfAck }
func (m *Dot11DataQosDataCfAck) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQosDataCfAck }

func (m *Dot11DataQosDataCfAck) NextLayerType() gopacket.LayerType { 
    return LayerTypeDot11DataCfAck
}

func (d *Dot11DataQosDataCfAck) String() string {
    return fmt.Sprintf("Dot11DataQosDataCfAck %v", d.Dot11DataQos.String())
}

type Dot11DataQosDataCfPoll struct {
	Dot11DataQos
}

func decodeDot11DataQosDataCfPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQosDataCfPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQosDataCfPoll) LayerType() gopacket.LayerType { return LayerTypeDot11DataQosDataCfPoll }
func (m *Dot11DataQosDataCfPoll) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQosDataCfPoll }
func (m *Dot11DataQosDataCfPoll) NextLayerType() gopacket.LayerType { return LayerTypeDot11DataCfPoll } 
func (d *Dot11DataQosDataCfPoll) String() string {
    return fmt.Sprintf("Dot11DataQosDataCfAck %v", d.Dot11DataQos.String())
}

type Dot11DataQosDataCfAckPoll struct {
	Dot11DataQos
}

func decodeDot11DataQosDataCfAckPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQosDataCfAckPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQosDataCfAckPoll) LayerType() gopacket.LayerType { return LayerTypeDot11DataQosDataCfAckPoll }
func (m *Dot11DataQosDataCfAckPoll) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQosDataCfAckPoll }
func (m *Dot11DataQosDataCfAckPoll) NextLayerType() gopacket.LayerType { return LayerTypeDot11DataCfAckPoll }
func (d *Dot11DataQosDataCfAckPoll) String() string {
    return fmt.Sprintf("Dot11DataQosDataCfAckPoll %v", d.Dot11DataQos.String())
}

type Dot11DataQosNull struct {
	Dot11DataQos
}

func decodeDot11DataQosNull(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQosNull{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQosNull) LayerType() gopacket.LayerType { return LayerTypeDot11DataQosNull }
func (m *Dot11DataQosNull) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQosNull }
func (m *Dot11DataQosNull) NextLayerType() gopacket.LayerType { return LayerTypeDot11DataNull } 
func (d *Dot11DataQosNull) String() string {
    return fmt.Sprintf("Dot11DataQosNull %v", d.Dot11DataQos.String())
}

type Dot11DataQosCfPollNoData struct {
	Dot11DataQos
}

func decodeDot11DataQosCfPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQosCfPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQosCfPollNoData) LayerType() gopacket.LayerType { return LayerTypeDot11DataQosCfPollNoData }
func (m *Dot11DataQosCfPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQosCfPollNoData }
func (m *Dot11DataQosCfPollNoData) NextLayerType() gopacket.LayerType { return LayerTypeDot11DataCfPollNoData } 
func (d *Dot11DataQosCfPollNoData) String() string {
    return fmt.Sprintf("Dot11DataQosCfPollNoData %v", d.Dot11DataQos.String())
}

type Dot11DataQosCfAckPollNoData struct {
	Dot11DataQos
}

func decodeDot11DataQosCfAckPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11DataQosCfAckPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11DataQosCfAckPollNoData) LayerType() gopacket.LayerType { return LayerTypeDot11DataQosCfAckPollNoData }
func (m *Dot11DataQosCfAckPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeDot11DataQosCfAckPollNoData }
func (m *Dot11DataQosCfAckPollNoData) NextLayerType() gopacket.LayerType { return LayerTypeDot11DataCfAckPollNoData } 
func (d *Dot11DataQosCfAckPollNoData) String() string {
    return fmt.Sprintf("Dot11DataQosCfAckPollNoData %v", d.Dot11DataQos.String())
}

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
    // TODO: check for last element?
    /*    
    if (false) {
        Return NIL)
    } 
    */
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
    return nil
}

type Dot11ControlAcknowledgement struct {
	Dot11ControlFrame
}

func decodeDot11ControlAcknowledgement(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlAcknowledgement{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlAcknowledgement) LayerType() gopacket.LayerType { return LayerTypeDot11ControlAcknowledgement }
func (m *Dot11ControlAcknowledgement) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlAcknowledgement }
func (m *Dot11ControlAcknowledgement) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

type Dot11ControlContentionFreePeriodEnd struct {
	Dot11ControlFrame
}

func decodeDot11ControlContentionFreePeriodEnd(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlContentionFreePeriodEnd{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlContentionFreePeriodEnd) LayerType() gopacket.LayerType { return LayerTypeDot11ControlContentionFreePeriodEnd }
func (m *Dot11ControlContentionFreePeriodEnd) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlContentionFreePeriodEnd }
func (m *Dot11ControlContentionFreePeriodEnd) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

type Dot11ControlContentionFreePeriodEndAck struct {
	Dot11ControlFrame
}

func decodeDot11ControlContentionFreePeriodEndAck(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11ControlContentionFreePeriodEndAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11ControlContentionFreePeriodEndAck) LayerType() gopacket.LayerType { return LayerTypeDot11ControlContentionFreePeriodEndAck }
func (m *Dot11ControlContentionFreePeriodEndAck) CanDecode() gopacket.LayerClass { return LayerTypeDot11ControlContentionFreePeriodEndAck }
func (m *Dot11ControlContentionFreePeriodEndAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
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
    m.BaseLayer = BaseLayer{Contents: data[:4], Payload: data[4:]}
    return nil
}

type Dot11MgmtAssocResp struct {
	Dot11MgmtFrame
        CapabilityInfo uint16 
        Status uint16 
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
    m.Status=binary.LittleEndian.Uint16(data[2:4])
    m.AID=binary.LittleEndian.Uint16(data[4:6])
    m.BaseLayer = BaseLayer{Contents: data, Payload: data[6:]}
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
    m.BaseLayer = BaseLayer{Contents: data, Payload: data[10:]}
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
func (m *Dot11MgmtReassocResp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: data[0:]}
    return nil
}

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
func (m *Dot11MgmtProbeReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

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
func (m *Dot11MgmtProbeResp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

type Dot11MgmtMeasurementPilot struct {
	Dot11MgmtFrame
}

func decodeDot11MgmtMeasurementPilot(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtMeasurementPilot{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtMeasurementPilot) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtMeasurementPilot }
func (m *Dot11MgmtMeasurementPilot) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtMeasurementPilot }
func (m *Dot11MgmtMeasurementPilot) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

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
    m.BaseLayer = BaseLayer{Contents: data, Payload: data[12:]}
    return nil
}

func (d *Dot11MgmtBeacon) String() string {
    return fmt.Sprintf("Beacon timestamp=%.1f (seconds) interval=%v (ms) flags=%v", (float32(d.Timestamp) / 100000.0), d.Interval, d.Flags)
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
func (m *Dot11MgmtATIM) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

func (d *Dot11MgmtATIM) String() string {
    return fmt.Sprintf("802.11 ATIM")
}

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
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

type Dot11MgmtAuthentication struct {
	Dot11MgmtFrame
        Algorithm Dot11Algorithm
        Sequence uint16
        Statuscode uint16
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
    m.Statuscode=binary.LittleEndian.Uint16(data[4:6])
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

func (d *Dot11MgmtAuthentication) String() string {
    status_code :=map[uint16]string{
      0:"success", 
      1:"failure", 
      10:"cannot-support-all-cap",
      11:"inexist-asso", 
      12:"asso-denied", 
      13:"algo-unsupported",
      14:"bad-seq-num", 
      15:"challenge-failure",
      16:"timeout", 
      17:"AP-full",
      18:"rate-unsupported" }

    return fmt.Sprintf("802.11 Authentication (Algorithm: %v, Sequence: %v, Statuscode: %v[%v])", d.Algorithm, d.Statuscode, status_code[d.Statuscode], d.Statuscode)
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
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
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
func (m *Dot11MgmtAction) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

type Dot11MgmtActionNoAck struct {
	Dot11MgmtFrame
}

func decodeDot11MgmtActionNoAck(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtActionNoAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtActionNoAck) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtActionNoAck }
func (m *Dot11MgmtActionNoAck) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtActionNoAck }
func (m *Dot11MgmtActionNoAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

type Dot11MgmtArubaWlan struct {
	Dot11MgmtFrame
}

func decodeDot11MgmtArubaWlan(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtArubaWlan{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtArubaWlan) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtArubaWlan }
func (m *Dot11MgmtArubaWlan) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtArubaWlan }
func (m *Dot11MgmtArubaWlan) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}
