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
    DOT11_REGISTER_NUM int= 0x11000
    DOT11_MGT_REGISTER_NUM int= 0x11100
    DOT11_MGT_ASSOC_REQ_REGISTER_NUM int= DOT11_MGT_REGISTER_NUM + int(MGT_ASSOC_REQ)
)

const (
    MGT_FRAME            uint8=0x00  /* Frame type is management */
    CONTROL_FRAME        uint8=0x01  /* Frame type is control */
    DATA_FRAME           uint8=0x02  /* Frame type is Data */
    RESERVED_FRAME       uint8=0x03  /* Frame type is Reserved */
)

const (
    MGT_ASSOC_REQ          uint8=0x00  /* association request        */
    MGT_ASSOC_RESP         uint8=0x01  /* association response       */
    MGT_REASSOC_REQ        uint8=0x02  /* reassociation request      */
    MGT_REASSOC_RESP       uint8=0x03  /* reassociation response     */
    MGT_PROBE_REQ          uint8=0x04  /* Probe request              */
    MGT_PROBE_RESP         uint8=0x05  /* Probe response             */
    MGT_MEASUREMENT_PILOT  uint8=0x06  /* Measurement Pilot          */
    MGT_BEACON             uint8=0x08  /* Beacon frame               */
    MGT_ATIM               uint8=0x09  /* ATIM                       */
    MGT_DISASS             uint8=0x0A  /* Disassociation             */
    MGT_AUTHENTICATION     uint8=0x0B  /* Authentication             */
    MGT_DEAUTHENTICATION   uint8=0x0C  /* Deauthentication           */
    MGT_ACTION             uint8=0x0D  /* Action                     */
    MGT_ACTION_NO_ACK      uint8=0x0E  /* Action No Ack              */
    MGT_ARUBA_WLAN         uint8=0x0F  /* Aruba WLAN Specific        */

    CTRL_CONTROL_WRAPPER uint8=0x07  /* Control Wrapper        */
    CTRL_BLOCK_ACK_REQ   uint8=0x08  /* Block ack Request        */
    CTRL_BLOCK_ACK       uint8=0x09  /* Block ack          */
    CTRL_PS_POLL         uint8=0x0A  /* power-save poll               */
    CTRL_RTS             uint8=0x0B  /* request to send               */
    CTRL_CTS             uint8=0x0C  /* clear to send                 */
    CTRL_ACKNOWLEDGEMENT uint8=0x0D  /* acknowledgement               */
    CTRL_CFP_END         uint8=0x0E  /* contention-free period end    */
    CTRL_CFP_ENDACK      uint8=0x0F  /* contention-free period end/ack */

    DATA                        uint8=0x00  /* Data                       */
    DATA_CF_ACK                 uint8=0x01  /* Data + CF-Ack              */
    DATA_CF_POLL                uint8=0x02  /* Data + CF-Poll             */
    DATA_CF_ACK_POLL            uint8=0x03  /* Data + CF-Ack + CF-Poll    */
    DATA_NULL_FUNCTION          uint8=0x04  /* Null function (no data)    */
    DATA_CF_ACK_NOD             uint8=0x05  /* CF-Ack (no data)           */
    DATA_CF_POLL_NOD            uint8=0x06  /* CF-Poll (No data)          */
    DATA_CF_ACK_POLL_NOD        uint8=0x07  /* CF-Ack + CF-Poll (no data) */
    DATA_QOS_DATA               uint8=0x08  /* QoS Data                   */
    DATA_QOS_DATA_CF_ACK        uint8=0x09  /* QoS Data + CF-Ack        */
    DATA_QOS_DATA_CF_POLL       uint8=0x0A  /* QoS Data + CF-Poll      */
    DATA_QOS_DATA_CF_ACK_POLL   uint8=0x0B  /* QoS Data + CF-Ack + CF-Poll    */
    DATA_QOS_NULL               uint8=0x0C  /* QoS Null        */
    DATA_QOS_CF_POLL_NOD        uint8=0x0E  /* QoS CF-Poll (No Data)      */
    DATA_QOS_CF_ACK_POLL_NOD    uint8=0x0F  /* QoS CF-Ack + CF-Poll (No Data) */
)


type Dot11 struct {
	BaseLayer
        Subtype uint8
        Type uint8
        Proto uint8
        ToDS bool
        FromDS bool
        MF bool
        Retry bool
        PowerManagement bool
        MD bool
        Valid bool
        Wep bool
        Order bool
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
            case MGT_FRAME: {
                // same header for all management frames, 24 bytes
                switch (m.Subtype) {
                    case MGT_ASSOC_REQ: {
                        return LayerTypeDot11MgmtAssocReq
                    }
                    case MGT_ASSOC_RESP: {
                        return LayerTypeDot11MgmtAssocResp
                    }
                    case MGT_REASSOC_REQ: {
                        return LayerTypeDot11MgmtReassocReq
                    }
                    case MGT_REASSOC_RESP: {
                        return LayerTypeDot11MgmtReassocResp
                    }
                    case MGT_PROBE_REQ: {
                        return LayerTypeDot11MgmtProbeReq
                    }
                    case MGT_PROBE_RESP: {
                        return LayerTypeDot11MgmtProbeResp
                    }
                    case MGT_MEASUREMENT_PILOT: {
                        return LayerTypeDot11MgmtMeasurementPilot
                    }
                    case MGT_BEACON: {
                        return LayerTypeDot11MgmtBeacon
                    }
                    case MGT_ATIM: {
                        return LayerTypeDot11MgmtATIM
                    }
                    case MGT_DISASS: {
                        return LayerTypeDot11MgmtDisassociation
                    }
                    case MGT_AUTHENTICATION: {
                        return LayerTypeDot11MgmtAuthentication
                    }
                    case MGT_DEAUTHENTICATION: {
                        return LayerTypeDot11MgmtDeauthentication
                    }
                    case MGT_ACTION: {
                        return LayerTypeDot11MgmtAction
                    }
                    case MGT_ACTION_NO_ACK: {
                        return LayerTypeDot11MgmtActionNoAck
                    }
                    case MGT_ARUBA_WLAN: {
                        return LayerTypeDot11MgmtArubaWlan
                    }
                }
            }
            case CONTROL_FRAME: {
                switch (m.Subtype) {
                    case CTRL_BLOCK_ACK_REQ: {
                        return LayerTypeDot11ControlBlockAckReq
                    }
                    case CTRL_BLOCK_ACK: {
                        return LayerTypeDot11ControlBlockAck
                    }
                    case CTRL_RTS: {
                        return LayerTypeDot11ControlRequestToSend
                    }
                    case CTRL_CTS: {
                        return LayerTypeDot11ControlClearToSend
                    }
                    case CTRL_PS_POLL: {
                        return LayerTypeDot11ControlPowersavePoll
                    }
                    case CTRL_ACKNOWLEDGEMENT: {
                        return LayerTypeDot11ControlAcknowledgement
                    }
                    case CTRL_CFP_END: {
                        return LayerTypeDot11ControlContentionFreePeriodEnd
                    }
                    case CTRL_CFP_ENDACK: {
                        return LayerTypeDot11ControlContentionFreePeriodEndAck
                    }
                }
                return gopacket.LayerTypePayload
            }
            case DATA_FRAME: {
                switch (m.Subtype) {
                    case DATA: {
                        return LayerTypeDot11DataFrame
                    }
                    case DATA_CF_ACK: {
                        return LayerTypeDot11DataCfAck
                    }
                    case DATA_CF_POLL: {
                        return LayerTypeDot11DataCfPoll
                    }
                    case DATA_CF_ACK_POLL: {
                        return LayerTypeDot11DataCfAckPoll
                    }
                    case DATA_NULL_FUNCTION: {
                        return LayerTypeDot11DataNull
                    }
                    case DATA_CF_ACK_NOD: {
                        return LayerTypeDot11DataCfAckNoData
                    }
                    case DATA_CF_POLL_NOD: {
                        return LayerTypeDot11DataCfPollNoData
                    }
                    case DATA_CF_ACK_POLL_NOD: {
                        return LayerTypeDot11DataCfAckPollNoData
                    }
                    case DATA_QOS_DATA: {
                        return LayerTypeDot11DataQosData
                    }
                    case DATA_QOS_DATA_CF_ACK: {
                        return LayerTypeDot11DataQosDataCfAck
                    }
                    case DATA_QOS_DATA_CF_POLL: {
                        return LayerTypeDot11DataQosDataCfPoll
                    }
                    case DATA_QOS_DATA_CF_ACK_POLL: {
                        return LayerTypeDot11DataQosDataCfAckPoll
                    }
                    case DATA_QOS_NULL: {
                        return LayerTypeDot11DataQosNull
                    }
                    case DATA_QOS_CF_POLL_NOD: {
                        return LayerTypeDot11DataQosCfPollNoData
                    }
                    case DATA_QOS_CF_ACK_POLL_NOD: {
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
    m.ToDS = (((uint8)(data[1]) & 0x01)  == 0x01)
    m.FromDS = (((uint8)(data[1]) & 0x02) == 0x02)
    m.MF = (((uint8)(data[1]) & 0x04)  == 0x04)
    m.Retry = (((uint8)(data[1]) & 0x08) == 0x08)
    m.PowerManagement = (((uint8)(data[1]) & 0x10)  == 0x10)
    m.MD = (((uint8)(data[1]) & 0x20) == 0x20)
    m.Wep = (((uint8)(data[1]) & 0x40)  == 0x40)
    m.Order = (((uint8)(data[1]) & 0x80) == 0x80)
    m.DurationId=binary.LittleEndian.Uint16(data[2:4])
    m.Address1=net.HardwareAddr(data[4:10])

    offset := 10

    if (m.Type == CONTROL_FRAME) {
        switch(m.Subtype) { 
            case CTRL_RTS, CTRL_PS_POLL, CTRL_CFP_END, CTRL_CFP_ENDACK: {
                m.Address2=net.HardwareAddr(data[offset:offset+6])
                offset += 6
            }
        }
    } else {
        m.Address2=net.HardwareAddr(data[offset:offset+6])
        offset += 6
    }

    if (m.Type == MGT_FRAME || m.Type == DATA_FRAME) {
        m.Address3=net.HardwareAddr(data[offset:offset+6])
        offset += 6
    }

    if (m.Type != CONTROL_FRAME) {
        // Sequence
        offset +=2 
    }

    if (m.Type == DATA_FRAME && m.FromDS && m.ToDS) {
        m.Address4=net.HardwareAddr(data[offset:offset+6])
        offset += 6
    }

    // ChecksumIEEE(data)
    // 29:31 SequenceControl

    // Frame body
    switch(m.Type) {
        case MGT_FRAME: {
            m.BaseLayer = BaseLayer{Contents: data[0:offset], Payload: data[offset:len(data)-4]}
            offset = len(data)-4
        }
        case CONTROL_FRAME: {
            m.BaseLayer = BaseLayer{Contents: data[0:offset], Payload: data[offset:len(data)-4]}
            offset = len(data)-4
        }
        case DATA_FRAME: {
            m.BaseLayer = BaseLayer{Contents: data[0:offset], Payload: data[offset:len(data)-4]}
            offset = len(data)-4
        }
    }

    checksum := crc32.ChecksumIEEE(data[:offset])
    m.Valid = (checksum == binary.LittleEndian.Uint32(data[offset:offset+4]))
   
    return (nil)
}

func (m Dot11) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return nil
}

func (m *Dot11) String() string {
    text := fmt.Sprintf("802.11 Type: %v Subtype: %v Protocol: %v ", m.Type, m.Subtype, m.Proto)

    if (!m.Valid) {
        text += "bad-fcs "
    }
    if (m.Wep) {
        text += "wep "
    }
    if (m.Retry) {
        text += "Retry"
    }
    if (m.MD) {
        text += "More Data"
    }
    if (m.PowerManagement) {
        text += "Pwr Mgmt"
    }
    if (m.Order) {
        text += "Strictly Ordered "
    }

    text += fmt.Sprintf("Address1: %s ", m.Address1)
    text += fmt.Sprintf("Address2: %s ", m.Address2)
    text += fmt.Sprintf("Address3: %s ", m.Address3)
    text += fmt.Sprintf("Address4: %s ", m.Address4)
    return text
}


type Dot11MgmtFrame struct {
	BaseLayer
}

func (m *Dot11MgmtFrame) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

var LayerTypeDot11ControlFrame = gopacket.RegisterLayerType(103001, gopacket.LayerTypeMetadata{"LayerTypeDot11ControlFrame", gopacket.DecodeFunc(decodeDot11ControlFrame)})

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

var LayerTypeDot11DataFrame = gopacket.RegisterLayerType(105001, gopacket.LayerTypeMetadata{"LayerTypeDot11DataFrame", gopacket.DecodeFunc(decodeDot11DataFrame)})

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


var LayerTypeDot11DataCfAck = gopacket.RegisterLayerType(105002, gopacket.LayerTypeMetadata{"LayerTypeDot11DataCfAck", gopacket.DecodeFunc(decodeDot11DataCfAck)})

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

var LayerTypeDot11DataCfPoll = gopacket.RegisterLayerType(105003, gopacket.LayerTypeMetadata{"LayerTypeDot11DataCfPoll", gopacket.DecodeFunc(decodeDot11DataCfPoll)})

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

var LayerTypeDot11DataCfAckPoll = gopacket.RegisterLayerType(105043, gopacket.LayerTypeMetadata{"LayerTypeDot11DataCfAckPoll", gopacket.DecodeFunc(decodeDot11DataCfAckPoll)})

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

var LayerTypeDot11DataNull = gopacket.RegisterLayerType(105004, gopacket.LayerTypeMetadata{"LayerTypeDot11DataNull", gopacket.DecodeFunc(decodeDot11DataNull)})

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

var LayerTypeDot11DataCfAckNoData = gopacket.RegisterLayerType(105005, gopacket.LayerTypeMetadata{"LayerTypeDot11DataCfAckNoData", gopacket.DecodeFunc(decodeDot11DataCfAckNoData)})

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

var LayerTypeDot11DataCfPollNoData = gopacket.RegisterLayerType(105006, gopacket.LayerTypeMetadata{"LayerTypeDot11DataCfPollNoData", gopacket.DecodeFunc(decodeDot11DataCfPollNoData)})

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

var LayerTypeDot11DataCfAckPollNoData = gopacket.RegisterLayerType(105007, gopacket.LayerTypeMetadata{"LayerTypeDot11DataCfAckPollNoData", gopacket.DecodeFunc(decodeDot11DataCfAckPollNoData)})

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


var LayerTypeDot11DataQosData = gopacket.RegisterLayerType(105008, gopacket.LayerTypeMetadata{"LayerTypeDot11DataQosData", gopacket.DecodeFunc(decodeDot11DataQosData)})

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

func (d *Dot11DataQosData) String() string {
    return fmt.Sprintf("Dot11DataQosData %v", d.Dot11DataQos.String())
}

var LayerTypeDot11DataQosDataCfAck = gopacket.RegisterLayerType(105009, gopacket.LayerTypeMetadata{"LayerTypeDot11DataQosDataCfAck", gopacket.DecodeFunc(decodeDot11DataQosDataCfAck)})

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

var LayerTypeDot11DataQosDataCfPoll = gopacket.RegisterLayerType(105010, gopacket.LayerTypeMetadata{"LayerTypeDot11DataQosDataCfPoll", gopacket.DecodeFunc(decodeDot11DataQosDataCfPoll)})

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

var LayerTypeDot11DataQosDataCfAckPoll = gopacket.RegisterLayerType(105011, gopacket.LayerTypeMetadata{"LayerTypeDot11DataQosDataCfAckPoll", gopacket.DecodeFunc(decodeDot11DataQosDataCfAckPoll)})

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

var LayerTypeDot11DataQosNull = gopacket.RegisterLayerType(105012, gopacket.LayerTypeMetadata{"LayerTypeDot11DataQosNull", gopacket.DecodeFunc(decodeDot11DataQosNull)})

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

var LayerTypeDot11DataQosCfPollNoData = gopacket.RegisterLayerType(105013, gopacket.LayerTypeMetadata{"LayerTypeDot11DataQosCfPollNoData", gopacket.DecodeFunc(decodeDot11DataQosCfPollNoData)})

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

var LayerTypeDot11DataQosCfAckPollNoData = gopacket.RegisterLayerType(105014, gopacket.LayerTypeMetadata{"LayerTypeDot11DataQosCfAckPollNoData", gopacket.DecodeFunc(decodeDot11DataQosCfAckPollNoData)})

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

var LayerTypeDot11InformationElement = gopacket.RegisterLayerType(105015, gopacket.LayerTypeMetadata{"LayerTypeDot11InformationElement", gopacket.DecodeFunc(decodeDot11InformationElement)})

type Dot11InformationElement struct {
	BaseLayer
        Id uint8 
        Length uint8
        Oui []byte
        Info []byte
}

func (m *Dot11InformationElement) LayerType() gopacket.LayerType { return LayerTypeDot11InformationElement }
func (m *Dot11InformationElement) CanDecode() gopacket.LayerClass { return LayerTypeDot11InformationElement }

func (m *Dot11InformationElement) NextLayerType() gopacket.LayerType { 
    /*    
    if (false) {
        Return NIL)
    } 
    */
    return LayerTypeDot11InformationElement 
}

func (m *Dot11InformationElement) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Id = data[0]
    m.Length = data[1]
    offset := uint8(2)

    if (m.Id==221) {
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
    ids:=map[uint8]string{0:"SSID", 1:"Rates", 2: "FHset", 3:"DSset", 4:"CFset", 5:"TIM", 6:"IBSSset", 16:"challenge",
                                            42:"ERPinfo", 46:"QoS Capability", 47:"ERPinfo", 48:"RSNinfo", 50:"ESRates",221:"vendor",68:"reserved"}
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
        return fmt.Sprintf("802.11 Information Element (Vendor: ID: %v[%v], Length: %v, OUI: %X, Info: %X)", ids[d.Id], d.Id, d.Length, d.Oui, d.Info)
    } else {
        return fmt.Sprintf("802.11 Information Element (ID: %v[%v], Length: %v, Info: %X)", ids[d.Id], d.Id, d.Length, d.Info)
    }
}

func decodeDot11InformationElement(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11InformationElement{}
	return decodingLayerDecoder(d, data, p)
}


var LayerTypeDot11ControlClearToSend = gopacket.RegisterLayerType(104001, gopacket.LayerTypeMetadata{"LayerTypeDot11ControlClearToSend", gopacket.DecodeFunc(decodeDot11ControlClearToSend)})

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

var LayerTypeDot11ControlRequestToSend = gopacket.RegisterLayerType(104002, gopacket.LayerTypeMetadata{"LayerTypeDot11ControlRequestToSend", gopacket.DecodeFunc(decodeDot11ControlRequestToSend)})

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

var LayerTypeDot11ControlBlockAckReq = gopacket.RegisterLayerType(104003, gopacket.LayerTypeMetadata{"LayerTypeDot11ControlBlockAckReq", gopacket.DecodeFunc(decodeDot11ControlBlockAckReq)})

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

var LayerTypeDot11ControlBlockAck = gopacket.RegisterLayerType(104004, gopacket.LayerTypeMetadata{"LayerTypeDot11ControlBlockAck", gopacket.DecodeFunc(decodeDot11ControlBlockAck)})

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

var LayerTypeDot11ControlPowersavePoll = gopacket.RegisterLayerType(104005, gopacket.LayerTypeMetadata{"LayerTypeDot11ControlPowersavePoll", gopacket.DecodeFunc(decodeDot11ControlPowersavePoll)})

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

var LayerTypeDot11ControlAcknowledgement = gopacket.RegisterLayerType(104006, gopacket.LayerTypeMetadata{"LayerTypeDot11ControlAcknowledgement", gopacket.DecodeFunc(decodeDot11ControlAcknowledgement)})

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

var LayerTypeDot11ControlContentionFreePeriodEnd = gopacket.RegisterLayerType(104007, gopacket.LayerTypeMetadata{"LayerTypeDot11ControlContentionFreePeriodEnd", gopacket.DecodeFunc(decodeDot11ControlContentionFreePeriodEnd)})

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

var LayerTypeDot11ControlContentionFreePeriodEndAck = gopacket.RegisterLayerType(104008, gopacket.LayerTypeMetadata{"LayerTypeDot11ControlContentionFreePeriodEndAck", gopacket.DecodeFunc(decodeDot11ControlContentionFreePeriodEndAck)})

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



var LayerTypeDot11MgmtAssocReq = gopacket.RegisterLayerType(DOT11_MGT_ASSOC_REQ_REGISTER_NUM, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtAssocReq", gopacket.DecodeFunc(decodeDot11MgmtAssocReq)})

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

var LayerTypeDot11MgmtAssocResp = gopacket.RegisterLayerType(1059981, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtAssocResp", gopacket.DecodeFunc(decodeDot11MgmtAssocResp)})

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

var LayerTypeDot11MgmtReassocReq = gopacket.RegisterLayerType(1059999, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtReassocReq", gopacket.DecodeFunc(decodeDot11MgmtReassocReq)})

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


var LayerTypeDot11MgmtReassocResp = gopacket.RegisterLayerType(1059991, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtReassocResp", gopacket.DecodeFunc(decodeDot11MgmtReassocResp)})

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

var LayerTypeDot11MgmtProbeReq = gopacket.RegisterLayerType(1059992, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtProbeReq", gopacket.DecodeFunc(decodeDot11MgmtProbeReq)})

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

var LayerTypeDot11MgmtProbeResp = gopacket.RegisterLayerType(1059993, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtProbeResp", gopacket.DecodeFunc(decodeDot11MgmtProbeResp)})

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

var LayerTypeDot11MgmtMeasurementPilot = gopacket.RegisterLayerType(1059994, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtMeasurementPilot", gopacket.DecodeFunc(decodeDot11MgmtMeasurementPilot)})

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

var LayerTypeDot11MgmtBeacon = gopacket.RegisterLayerType(1059995, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtBeacon", gopacket.DecodeFunc(decodeDot11MgmtBeacon)})

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

var LayerTypeDot11MgmtATIM = gopacket.RegisterLayerType(1059996, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtATIM", gopacket.DecodeFunc(decodeDot11MgmtATIM)})

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

var LayerTypeDot11MgmtDisassociation = gopacket.RegisterLayerType(1059997, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtDisassociation", gopacket.DecodeFunc(decodeDot11MgmtDisassociation)})

type Dot11MgmtDisassociation struct {
	Dot11MgmtFrame
        Reason uint16 
}

func decodeDot11MgmtDisassociation(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtDisassociation{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtDisassociation) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtDisassociation }
func (m *Dot11MgmtDisassociation) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtDisassociation }
func (m *Dot11MgmtDisassociation) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Reason=binary.LittleEndian.Uint16(data[0:2])
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

func (d *Dot11MgmtDisassociation) String() string {
    reasons:=map[uint16]string{
        0:"reserved",
        1:"unspec", 
        2:"auth-expired",
        3:"deauth-ST-leaving",
        4:"inactivity", 
        5:"AP-full", 
        6:"class2-from-nonauth",
        7:"class3-from-nonass", 
        8:"disas-ST-leaving",
        9:"ST-not-auth"}
    return fmt.Sprintf("802.11 Disassociation (Reason: %v[%v])", reasons[d.Reason], d.Reason)
}


var LayerTypeDot11MgmtAuthentication = gopacket.RegisterLayerType(1054327, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtAuthentication", gopacket.DecodeFunc(decodeDot11MgmtAuthentication)})

type Dot11MgmtAuthentication struct {
	Dot11MgmtFrame
        Algorithm uint16
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
    m.Algorithm=binary.LittleEndian.Uint16(data[0:2])
    m.Sequence=binary.LittleEndian.Uint16(data[2:4])
    m.Statuscode=binary.LittleEndian.Uint16(data[4:6])
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

func (d *Dot11MgmtAuthentication) String() string {
    algorithms:=map[uint16]string{
        0:"open",
        1:"shared-key"}

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

    return fmt.Sprintf("802.11 Authentication (Algorithm: %v[%v], Sequence: %v, Statuscode: %v[%v])", algorithms[d.Algorithm], d.Algorithm, d.Statuscode, status_code[d.Statuscode], d.Statuscode)
}

var LayerTypeDot11MgmtDeauthentication = gopacket.RegisterLayerType(1054328, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtDeauthentication", gopacket.DecodeFunc(decodeDot11MgmtDeauthentication)})

type Dot11MgmtDeauthentication struct {
	Dot11MgmtFrame
        Reason uint16
}

func decodeDot11MgmtDeauthentication(data []byte, p gopacket.PacketBuilder) error {
	d := &Dot11MgmtDeauthentication{}
	return decodingLayerDecoder(d, data, p)
}

func (m *Dot11MgmtDeauthentication) LayerType() gopacket.LayerType { return LayerTypeDot11MgmtDeauthentication }
func (m *Dot11MgmtDeauthentication) CanDecode() gopacket.LayerClass { return LayerTypeDot11MgmtDeauthentication }
func (m *Dot11MgmtDeauthentication) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Reason=binary.LittleEndian.Uint16(data[0:2])
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

func (d *Dot11MgmtDeauthentication) String() string {
    reasons:=map[uint16]string{
        0:"reserved",
        1:"unspec", 
        2:"auth-expired",
        3:"deauth-ST-leaving",
        4:"inactivity", 
        5:"AP-full", 
        6:"class2-from-nonauth",
        7:"class3-from-nonass", 
        8:"disas-ST-leaving",
        9:"ST-not-auth"}
    return fmt.Sprintf("802.11 Deauthentication (Reason: %v[%v])", reasons[d.Reason], d.Reason)
}

var LayerTypeDot11MgmtAction = gopacket.RegisterLayerType(1054329, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtAction", gopacket.DecodeFunc(decodeDot11MgmtAction)})

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

var LayerTypeDot11MgmtActionNoAck = gopacket.RegisterLayerType(1054330, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtActionNoAck", gopacket.DecodeFunc(decodeDot11MgmtActionNoAck)})

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

var LayerTypeDot11MgmtArubaWlan = gopacket.RegisterLayerType(1054331, gopacket.LayerTypeMetadata{"LayerTypeDot11MgmtArubaWlan", gopacket.DecodeFunc(decodeDot11MgmtArubaWlan)})

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
