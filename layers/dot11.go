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


type IEEE802_11 struct {
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

func decodeIEEE802_11(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11 }
func (m *IEEE802_11) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11 }
func (m *IEEE802_11) NextLayerType() gopacket.LayerType {
        switch(m.Type) {
            case MGT_FRAME: {
                // same header for all management frames, 24 bytes
                switch (m.Subtype) {
                    case MGT_ASSOC_REQ: {
                        return LayerTypeIEEE802_11MgmtAssocReq
                    }
                    case MGT_ASSOC_RESP: {
                        return LayerTypeIEEE802_11MgmtAssocResp
                    }
                    case MGT_REASSOC_REQ: {
                        return LayerTypeIEEE802_11MgmtReassocReq
                    }
                    case MGT_REASSOC_RESP: {
                        return LayerTypeIEEE802_11MgmtReassocResp
                    }
                    case MGT_PROBE_REQ: {
                        return LayerTypeIEEE802_11MgmtProbeReq
                    }
                    case MGT_PROBE_RESP: {
                        return LayerTypeIEEE802_11MgmtProbeResp
                    }
                    case MGT_MEASUREMENT_PILOT: {
                        return LayerTypeIEEE802_11MgmtMeasurementPilot
                    }
                    case MGT_BEACON: {
                        return LayerTypeIEEE802_11MgmtBeacon
                    }
                    case MGT_ATIM: {
                        return LayerTypeIEEE802_11MgmtATIM
                    }
                    case MGT_DISASS: {
                        return LayerTypeIEEE802_11MgmtDisassociation
                    }
                    case MGT_AUTHENTICATION: {
                        return LayerTypeIEEE802_11MgmtAuthentication
                    }
                    case MGT_DEAUTHENTICATION: {
                        return LayerTypeIEEE802_11MgmtDeauthentication
                    }
                    case MGT_ACTION: {
                        return LayerTypeIEEE802_11MgmtAction
                    }
                    case MGT_ACTION_NO_ACK: {
                        return LayerTypeIEEE802_11MgmtActionNoAck
                    }
                    case MGT_ARUBA_WLAN: {
                        return LayerTypeIEEE802_11MgmtArubaWlan
                    }
                }
            }
            case CONTROL_FRAME: {
                switch (m.Subtype) {
                    case CTRL_BLOCK_ACK_REQ: {
                        return LayerTypeIEEE802_11ControlBlockAckReq
                    }
                    case CTRL_BLOCK_ACK: {
                        return LayerTypeIEEE802_11ControlBlockAck
                    }
                    case CTRL_RTS: {
                        return LayerTypeIEEE802_11ControlRequestToSend
                    }
                    case CTRL_CTS: {
                        return LayerTypeIEEE802_11ControlClearToSend
                    }
                    case CTRL_PS_POLL: {
                        return LayerTypeIEEE802_11ControlPowersavePoll
                    }
                    case CTRL_ACKNOWLEDGEMENT: {
                        return LayerTypeIEEE802_11ControlAcknowledgement
                    }
                    case CTRL_CFP_END: {
                        return LayerTypeIEEE802_11ControlContentionFreePeriodEnd
                    }
                    case CTRL_CFP_ENDACK: {
                        return LayerTypeIEEE802_11ControlContentionFreePeriodEndAck
                    }
                }
                return gopacket.LayerTypePayload
            }
            case DATA_FRAME: {
                switch (m.Subtype) {
                    case DATA: {
                        return LayerTypeIEEE802_11DataFrame
                    }
                    case DATA_CF_ACK: {
                        return LayerTypeIEEE802_11DataCfAck
                    }
                    case DATA_CF_POLL: {
                        return LayerTypeIEEE802_11DataCfPoll
                    }
                    case DATA_CF_ACK_POLL: {
                        return LayerTypeIEEE802_11DataCfAckPoll
                    }
                    case DATA_NULL_FUNCTION: {
                        return LayerTypeIEEE802_11DataNull
                    }
                    case DATA_CF_ACK_NOD: {
                        return LayerTypeIEEE802_11DataCfAckNoData
                    }
                    case DATA_CF_POLL_NOD: {
                        return LayerTypeIEEE802_11DataCfPollNoData
                    }
                    case DATA_CF_ACK_POLL_NOD: {
                        return LayerTypeIEEE802_11DataCfAckPollNoData
                    }
                    case DATA_QOS_DATA: {
                        return LayerTypeIEEE802_11DataQosData
                    }
                    case DATA_QOS_DATA_CF_ACK: {
                        return LayerTypeIEEE802_11DataQosDataCfAck
                    }
                    case DATA_QOS_DATA_CF_POLL: {
                        return LayerTypeIEEE802_11DataQosDataCfPoll
                    }
                    case DATA_QOS_DATA_CF_ACK_POLL: {
                        return LayerTypeIEEE802_11DataQosDataCfAckPoll
                    }
                    case DATA_QOS_NULL: {
                        return LayerTypeIEEE802_11DataQosNull
                    }
                    case DATA_QOS_CF_POLL_NOD: {
                        return LayerTypeIEEE802_11DataQosCfPollNoData
                    }
                    case DATA_QOS_CF_ACK_POLL_NOD: {
                        return LayerTypeIEEE802_11DataQosCfAckPollNoData
                    }
                }
                return gopacket.LayerTypePayload
            }
        }

        // not implemented yet
	return gopacket.LayerTypePayload}

func (m *IEEE802_11) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
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

func (m IEEE802_11) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return nil
}

func (m *IEEE802_11) String() string {
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


type IEEE802_11MgmtFrame struct {
	BaseLayer
}

func (m *IEEE802_11MgmtFrame) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

var LayerTypeIEEE802_11ControlFrame = gopacket.RegisterLayerType(103001, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11ControlFrame", gopacket.DecodeFunc(decodeIEEE802_11ControlFrame)})

type IEEE802_11ControlFrame struct {
	BaseLayer
}

func (m *IEEE802_11ControlFrame) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

func (m *IEEE802_11ControlFrame) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11ControlFrame }
func (m *IEEE802_11ControlFrame) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11ControlFrame }
func (m *IEEE802_11ControlFrame) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

func decodeIEEE802_11ControlFrame(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11ControlFrame{}
	return decodingLayerDecoder(d, data, p)
}

var LayerTypeIEEE802_11DataFrame = gopacket.RegisterLayerType(105001, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataFrame", gopacket.DecodeFunc(decodeIEEE802_11DataFrame)})

type IEEE802_11DataFrame struct {
	BaseLayer
}

func (m *IEEE802_11DataFrame) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

func (m *IEEE802_11DataFrame) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataFrame }
func (m *IEEE802_11DataFrame) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataFrame }
func (m *IEEE802_11DataFrame) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

func decodeIEEE802_11DataFrame(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataFrame{}
	return decodingLayerDecoder(d, data, p)
}


var LayerTypeIEEE802_11DataCfAck = gopacket.RegisterLayerType(105002, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataCfAck", gopacket.DecodeFunc(decodeIEEE802_11DataCfAck)})

type IEEE802_11DataCfAck struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11DataCfAck(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataCfAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataCfAck) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataCfAck }
func (m *IEEE802_11DataCfAck) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataCfAck }
func (m *IEEE802_11DataCfAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11DataCfPoll = gopacket.RegisterLayerType(105003, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataCfPoll", gopacket.DecodeFunc(decodeIEEE802_11DataCfPoll)})

type IEEE802_11DataCfPoll struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11DataCfPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataCfPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataCfPoll) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataCfPoll }
func (m *IEEE802_11DataCfPoll) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataCfPoll }
func (m *IEEE802_11DataCfPoll) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11DataCfAckPoll = gopacket.RegisterLayerType(105043, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataCfAckPoll", gopacket.DecodeFunc(decodeIEEE802_11DataCfAckPoll)})

type IEEE802_11DataCfAckPoll struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11DataCfAckPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataCfAckPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataCfAckPoll) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataCfAckPoll }
func (m *IEEE802_11DataCfAckPoll) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataCfAckPoll }
func (m *IEEE802_11DataCfAckPoll) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11DataNull = gopacket.RegisterLayerType(105004, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataNull", gopacket.DecodeFunc(decodeIEEE802_11DataNull)})

type IEEE802_11DataNull struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11DataNull(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataNull{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataNull) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataNull }
func (m *IEEE802_11DataNull) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataNull }
func (m *IEEE802_11DataNull) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11DataCfAckNoData = gopacket.RegisterLayerType(105005, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataCfAckNoData", gopacket.DecodeFunc(decodeIEEE802_11DataCfAckNoData)})

type IEEE802_11DataCfAckNoData struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11DataCfAckNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataCfAckNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataCfAckNoData) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataCfAckNoData }
func (m *IEEE802_11DataCfAckNoData) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataCfAckNoData }
func (m *IEEE802_11DataCfAckNoData) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11DataCfPollNoData = gopacket.RegisterLayerType(105006, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataCfPollNoData", gopacket.DecodeFunc(decodeIEEE802_11DataCfPollNoData)})

type IEEE802_11DataCfPollNoData struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11DataCfPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataCfPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataCfPollNoData) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataCfPollNoData }
func (m *IEEE802_11DataCfPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataCfPollNoData }
func (m *IEEE802_11DataCfPollNoData) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11DataCfAckPollNoData = gopacket.RegisterLayerType(105007, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataCfAckPollNoData", gopacket.DecodeFunc(decodeIEEE802_11DataCfAckPollNoData)})

type IEEE802_11DataCfAckPollNoData struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11DataCfAckPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataCfAckPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataCfAckPollNoData) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataCfAckPollNoData }
func (m *IEEE802_11DataCfAckPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataCfAckPollNoData }
func (m *IEEE802_11DataCfAckPollNoData) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

type IEEE802_11DataQos struct {
    IEEE802_11ControlFrame
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

func (m *IEEE802_11DataQos) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.TID = ((uint8)(data[0]) & 0x0F) 
    m.EOSP = ((uint8)(data[0]) & 0x10) == 0x10
    m.AckPolicy = ((uint8)(data[0]) & 0x60) >> 5
    m.TXOP = (uint8)(data[1])
    m.BaseLayer = BaseLayer{Contents: data[0:2], Payload: data[2:]}
    return nil
}

func (d *IEEE802_11DataQos) String() string {
    ack_policies:=map[uint8]string{0:"Normal Ack", 1:"No Ack", 2: "No Explicit Acknowledgement", 3:"Block Acknowledgement"}
    return fmt.Sprintf("Ack policy: %v[%v]", ack_policies[d.AckPolicy], d.AckPolicy)
}


var LayerTypeIEEE802_11DataQosData = gopacket.RegisterLayerType(105008, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataQosData", gopacket.DecodeFunc(decodeIEEE802_11DataQosData)})

type IEEE802_11DataQosData struct {
	IEEE802_11DataQos
}

func decodeIEEE802_11DataQosData(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataQosData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataQosData) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataQosData }
func (m *IEEE802_11DataQosData) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataQosData }

func (m *IEEE802_11DataQosData) NextLayerType() gopacket.LayerType { 
    return LayerTypeIEEE802_11DataFrame
}

func (d *IEEE802_11DataQosData) String() string {
    return fmt.Sprintf("IEEE802_11DataQosData %v", d.IEEE802_11DataQos.String())
}

var LayerTypeIEEE802_11DataQosDataCfAck = gopacket.RegisterLayerType(105009, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataQosDataCfAck", gopacket.DecodeFunc(decodeIEEE802_11DataQosDataCfAck)})

type IEEE802_11DataQosDataCfAck struct {
	IEEE802_11DataQos
}

func decodeIEEE802_11DataQosDataCfAck(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataQosDataCfAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataQosDataCfAck) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataQosDataCfAck }
func (m *IEEE802_11DataQosDataCfAck) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataQosDataCfAck }

func (m *IEEE802_11DataQosDataCfAck) NextLayerType() gopacket.LayerType { 
    return LayerTypeIEEE802_11DataCfAck
}

func (d *IEEE802_11DataQosDataCfAck) String() string {
    return fmt.Sprintf("IEEE802_11DataQosDataCfAck %v", d.IEEE802_11DataQos.String())
}

var LayerTypeIEEE802_11DataQosDataCfPoll = gopacket.RegisterLayerType(105010, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataQosDataCfPoll", gopacket.DecodeFunc(decodeIEEE802_11DataQosDataCfPoll)})

type IEEE802_11DataQosDataCfPoll struct {
	IEEE802_11DataQos
}

func decodeIEEE802_11DataQosDataCfPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataQosDataCfPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataQosDataCfPoll) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataQosDataCfPoll }
func (m *IEEE802_11DataQosDataCfPoll) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataQosDataCfPoll }
func (m *IEEE802_11DataQosDataCfPoll) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataCfPoll } 
func (d *IEEE802_11DataQosDataCfPoll) String() string {
    return fmt.Sprintf("IEEE802_11DataQosDataCfAck %v", d.IEEE802_11DataQos.String())
}

var LayerTypeIEEE802_11DataQosDataCfAckPoll = gopacket.RegisterLayerType(105011, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataQosDataCfAckPoll", gopacket.DecodeFunc(decodeIEEE802_11DataQosDataCfAckPoll)})

type IEEE802_11DataQosDataCfAckPoll struct {
	IEEE802_11DataQos
}

func decodeIEEE802_11DataQosDataCfAckPoll(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataQosDataCfAckPoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataQosDataCfAckPoll) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataQosDataCfAckPoll }
func (m *IEEE802_11DataQosDataCfAckPoll) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataQosDataCfAckPoll }
func (m *IEEE802_11DataQosDataCfAckPoll) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataCfAckPoll }
func (d *IEEE802_11DataQosDataCfAckPoll) String() string {
    return fmt.Sprintf("IEEE802_11DataQosDataCfAckPoll %v", d.IEEE802_11DataQos.String())
}

var LayerTypeIEEE802_11DataQosNull = gopacket.RegisterLayerType(105012, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataQosNull", gopacket.DecodeFunc(decodeIEEE802_11DataQosNull)})

type IEEE802_11DataQosNull struct {
	IEEE802_11DataQos
}

func decodeIEEE802_11DataQosNull(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataQosNull{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataQosNull) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataQosNull }
func (m *IEEE802_11DataQosNull) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataQosNull }
func (m *IEEE802_11DataQosNull) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataNull } 
func (d *IEEE802_11DataQosNull) String() string {
    return fmt.Sprintf("IEEE802_11DataQosNull %v", d.IEEE802_11DataQos.String())
}

var LayerTypeIEEE802_11DataQosCfPollNoData = gopacket.RegisterLayerType(105013, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataQosCfPollNoData", gopacket.DecodeFunc(decodeIEEE802_11DataQosCfPollNoData)})

type IEEE802_11DataQosCfPollNoData struct {
	IEEE802_11DataQos
}

func decodeIEEE802_11DataQosCfPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataQosCfPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataQosCfPollNoData) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataQosCfPollNoData }
func (m *IEEE802_11DataQosCfPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataQosCfPollNoData }
func (m *IEEE802_11DataQosCfPollNoData) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataCfPollNoData } 
func (d *IEEE802_11DataQosCfPollNoData) String() string {
    return fmt.Sprintf("IEEE802_11DataQosCfPollNoData %v", d.IEEE802_11DataQos.String())
}

var LayerTypeIEEE802_11DataQosCfAckPollNoData = gopacket.RegisterLayerType(105014, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11DataQosCfAckPollNoData", gopacket.DecodeFunc(decodeIEEE802_11DataQosCfAckPollNoData)})

type IEEE802_11DataQosCfAckPollNoData struct {
	IEEE802_11DataQos
}

func decodeIEEE802_11DataQosCfAckPollNoData(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11DataQosCfAckPollNoData{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11DataQosCfAckPollNoData) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataQosCfAckPollNoData }
func (m *IEEE802_11DataQosCfAckPollNoData) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11DataQosCfAckPollNoData }
func (m *IEEE802_11DataQosCfAckPollNoData) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11DataCfAckPollNoData } 
func (d *IEEE802_11DataQosCfAckPollNoData) String() string {
    return fmt.Sprintf("IEEE802_11DataQosCfAckPollNoData %v", d.IEEE802_11DataQos.String())
}

var LayerTypeIEEE802_11InformationElement = gopacket.RegisterLayerType(105015, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11InformationElement", gopacket.DecodeFunc(decodeIEEE802_11InformationElement)})

type IEEE802_11InformationElement struct {
	BaseLayer
        Id uint8 
        Length uint8
        Oui []byte
        Info []byte
}

func (m *IEEE802_11InformationElement) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11InformationElement }
func (m *IEEE802_11InformationElement) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11InformationElement }

func (m *IEEE802_11InformationElement) NextLayerType() gopacket.LayerType { 
    /*    
    if (false) {
        Return NIL)
    } 
    */
    return LayerTypeIEEE802_11InformationElement 
}

func (m *IEEE802_11InformationElement) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
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

func (d *IEEE802_11InformationElement) String() string {
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

func decodeIEEE802_11InformationElement(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11InformationElement{}
	return decodingLayerDecoder(d, data, p)
}


var LayerTypeIEEE802_11ControlClearToSend = gopacket.RegisterLayerType(104001, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11ControlClearToSend", gopacket.DecodeFunc(decodeIEEE802_11ControlClearToSend)})

type IEEE802_11ControlClearToSend struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11ControlClearToSend(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11ControlClearToSend{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11ControlClearToSend) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11ControlClearToSend }
func (m *IEEE802_11ControlClearToSend) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11ControlClearToSend }
func (m *IEEE802_11ControlClearToSend) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11ControlRequestToSend = gopacket.RegisterLayerType(104002, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11ControlRequestToSend", gopacket.DecodeFunc(decodeIEEE802_11ControlRequestToSend)})

type IEEE802_11ControlRequestToSend struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11ControlRequestToSend(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11ControlRequestToSend{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11ControlRequestToSend) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11ControlRequestToSend }
func (m *IEEE802_11ControlRequestToSend) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11ControlRequestToSend }
func (m *IEEE802_11ControlRequestToSend) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11ControlBlockAckReq = gopacket.RegisterLayerType(104003, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11ControlBlockAckReq", gopacket.DecodeFunc(decodeIEEE802_11ControlBlockAckReq)})

type IEEE802_11ControlBlockAckReq struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11ControlBlockAckReq(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11ControlBlockAckReq{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11ControlBlockAckReq) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11ControlBlockAckReq }
func (m *IEEE802_11ControlBlockAckReq) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11ControlBlockAckReq }
func (m *IEEE802_11ControlBlockAckReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11ControlBlockAck = gopacket.RegisterLayerType(104004, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11ControlBlockAck", gopacket.DecodeFunc(decodeIEEE802_11ControlBlockAck)})

type IEEE802_11ControlBlockAck struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11ControlBlockAck(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11ControlBlockAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11ControlBlockAck) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11ControlBlockAck }
func (m *IEEE802_11ControlBlockAck) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11ControlBlockAck }
func (m *IEEE802_11ControlBlockAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11ControlPowersavePoll = gopacket.RegisterLayerType(104005, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11ControlPowersavePoll", gopacket.DecodeFunc(decodeIEEE802_11ControlPowersavePoll)})

type IEEE802_11ControlPowersavePoll struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11ControlPowersavePoll(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11ControlPowersavePoll{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11ControlPowersavePoll) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11ControlPowersavePoll }
func (m *IEEE802_11ControlPowersavePoll) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11ControlPowersavePoll }
func (m *IEEE802_11ControlPowersavePoll) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11ControlAcknowledgement = gopacket.RegisterLayerType(104006, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11ControlAcknowledgement", gopacket.DecodeFunc(decodeIEEE802_11ControlAcknowledgement)})

type IEEE802_11ControlAcknowledgement struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11ControlAcknowledgement(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11ControlAcknowledgement{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11ControlAcknowledgement) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11ControlAcknowledgement }
func (m *IEEE802_11ControlAcknowledgement) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11ControlAcknowledgement }
func (m *IEEE802_11ControlAcknowledgement) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11ControlContentionFreePeriodEnd = gopacket.RegisterLayerType(104007, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11ControlContentionFreePeriodEnd", gopacket.DecodeFunc(decodeIEEE802_11ControlContentionFreePeriodEnd)})

type IEEE802_11ControlContentionFreePeriodEnd struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11ControlContentionFreePeriodEnd(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11ControlContentionFreePeriodEnd{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11ControlContentionFreePeriodEnd) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11ControlContentionFreePeriodEnd }
func (m *IEEE802_11ControlContentionFreePeriodEnd) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11ControlContentionFreePeriodEnd }
func (m *IEEE802_11ControlContentionFreePeriodEnd) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}

var LayerTypeIEEE802_11ControlContentionFreePeriodEndAck = gopacket.RegisterLayerType(104008, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11ControlContentionFreePeriodEndAck", gopacket.DecodeFunc(decodeIEEE802_11ControlContentionFreePeriodEndAck)})

type IEEE802_11ControlContentionFreePeriodEndAck struct {
	IEEE802_11ControlFrame
}

func decodeIEEE802_11ControlContentionFreePeriodEndAck(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11ControlContentionFreePeriodEndAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11ControlContentionFreePeriodEndAck) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11ControlContentionFreePeriodEndAck }
func (m *IEEE802_11ControlContentionFreePeriodEndAck) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11ControlContentionFreePeriodEndAck }
func (m *IEEE802_11ControlContentionFreePeriodEndAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    return nil
}



var LayerTypeIEEE802_11MgmtAssocReq = gopacket.RegisterLayerType(DOT11_MGT_ASSOC_REQ_REGISTER_NUM, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtAssocReq", gopacket.DecodeFunc(decodeIEEE802_11MgmtAssocReq)})

type IEEE802_11MgmtAssocReq struct {
	IEEE802_11MgmtFrame
        CapabilityInfo uint16 
        ListenInterval uint16 
}

func decodeIEEE802_11MgmtAssocReq(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtAssocReq{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtAssocReq) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtAssocReq }
func (m *IEEE802_11MgmtAssocReq) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtAssocReq }
func (m *IEEE802_11MgmtAssocReq) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11InformationElement }
func (m *IEEE802_11MgmtAssocReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.CapabilityInfo=binary.LittleEndian.Uint16(data[0:2])
    m.ListenInterval=binary.LittleEndian.Uint16(data[2:4])
    m.BaseLayer = BaseLayer{Contents: data[:4], Payload: data[4:]}
    return nil
}

var LayerTypeIEEE802_11MgmtAssocResp = gopacket.RegisterLayerType(1059981, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtAssocResp", gopacket.DecodeFunc(decodeIEEE802_11MgmtAssocResp)})

type IEEE802_11MgmtAssocResp struct {
	IEEE802_11MgmtFrame
        CapabilityInfo uint16 
        Status uint16 
        AID uint16 
}

func decodeIEEE802_11MgmtAssocResp(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtAssocResp{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtAssocResp) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtAssocResp }
func (m *IEEE802_11MgmtAssocResp) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtAssocResp }
func (m *IEEE802_11MgmtAssocResp) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11InformationElement }
func (m *IEEE802_11MgmtAssocResp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.CapabilityInfo=binary.LittleEndian.Uint16(data[0:2])
    m.Status=binary.LittleEndian.Uint16(data[2:4])
    m.AID=binary.LittleEndian.Uint16(data[4:6])
    m.BaseLayer = BaseLayer{Contents: data, Payload: data[6:]}
    return nil
}

var LayerTypeIEEE802_11MgmtReassocReq = gopacket.RegisterLayerType(1059999, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtReassocReq", gopacket.DecodeFunc(decodeIEEE802_11MgmtReassocReq)})

type IEEE802_11MgmtReassocReq struct {
	IEEE802_11MgmtFrame
        CapabilityInfo uint16
        ListenInterval uint16
        CurrentApAddress net.HardwareAddr
}

func decodeIEEE802_11MgmtReassocReq(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtReassocReq{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtReassocReq) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtReassocReq }
func (m *IEEE802_11MgmtReassocReq) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtReassocReq }
func (m *IEEE802_11MgmtReassocReq) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11InformationElement }
func (m *IEEE802_11MgmtReassocReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.CapabilityInfo=binary.LittleEndian.Uint16(data[0:2])
    m.ListenInterval=binary.LittleEndian.Uint16(data[2:4])
    m.CurrentApAddress=net.HardwareAddr(data[4:10])
    m.BaseLayer = BaseLayer{Contents: data, Payload: data[10:]}
    return nil
}


var LayerTypeIEEE802_11MgmtReassocResp = gopacket.RegisterLayerType(1059991, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtReassocResp", gopacket.DecodeFunc(decodeIEEE802_11MgmtReassocResp)})

type IEEE802_11MgmtReassocResp struct {
	IEEE802_11MgmtFrame
}

func decodeIEEE802_11MgmtReassocResp(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtReassocResp{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtReassocResp) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtReassocResp }
func (m *IEEE802_11MgmtReassocResp) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtReassocResp }
func (m *IEEE802_11MgmtReassocResp) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11InformationElement }
func (m *IEEE802_11MgmtReassocResp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: data[0:]}
    return nil
}

var LayerTypeIEEE802_11MgmtProbeReq = gopacket.RegisterLayerType(1059992, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtProbeReq", gopacket.DecodeFunc(decodeIEEE802_11MgmtProbeReq)})

type IEEE802_11MgmtProbeReq struct {
	IEEE802_11MgmtFrame
}

func decodeIEEE802_11MgmtProbeReq(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtProbeReq{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtProbeReq) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtProbeReq }
func (m *IEEE802_11MgmtProbeReq) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtProbeReq }
func (m *IEEE802_11MgmtProbeReq) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11InformationElement }
func (m *IEEE802_11MgmtProbeReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeIEEE802_11MgmtProbeResp = gopacket.RegisterLayerType(1059993, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtProbeResp", gopacket.DecodeFunc(decodeIEEE802_11MgmtProbeResp)})

type IEEE802_11MgmtProbeResp struct {
	IEEE802_11MgmtFrame
}

func decodeIEEE802_11MgmtProbeResp(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtProbeResp{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtProbeResp) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtProbeResp }
func (m *IEEE802_11MgmtProbeResp) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtProbeResp }
func (m *IEEE802_11MgmtProbeResp) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11InformationElement }
func (m *IEEE802_11MgmtProbeResp) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeIEEE802_11MgmtMeasurementPilot = gopacket.RegisterLayerType(1059994, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtMeasurementPilot", gopacket.DecodeFunc(decodeIEEE802_11MgmtMeasurementPilot)})

type IEEE802_11MgmtMeasurementPilot struct {
	IEEE802_11MgmtFrame
}

func decodeIEEE802_11MgmtMeasurementPilot(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtMeasurementPilot{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtMeasurementPilot) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtMeasurementPilot }
func (m *IEEE802_11MgmtMeasurementPilot) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtMeasurementPilot }
func (m *IEEE802_11MgmtMeasurementPilot) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeIEEE802_11MgmtBeacon = gopacket.RegisterLayerType(1059995, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtBeacon", gopacket.DecodeFunc(decodeIEEE802_11MgmtBeacon)})

type IEEE802_11MgmtBeacon struct {
	IEEE802_11MgmtFrame
        Timestamp uint64 
        Interval uint16
        Flags uint16
}

func decodeIEEE802_11MgmtBeacon(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtBeacon{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtBeacon) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtBeacon }
func (m *IEEE802_11MgmtBeacon) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtBeacon }
func (m *IEEE802_11MgmtBeacon) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Timestamp=binary.LittleEndian.Uint64(data[0:8])
    m.Interval=binary.LittleEndian.Uint16(data[8:10])
    m.Flags=binary.LittleEndian.Uint16(data[10:12])
    m.BaseLayer = BaseLayer{Contents: data, Payload: data[12:]}
    return nil
}

func (d *IEEE802_11MgmtBeacon) String() string {
    return fmt.Sprintf("Beacon timestamp=%.1f (seconds) interval=%v (ms) flags=%v", (float32(d.Timestamp) / 100000.0), d.Interval, d.Flags)
}

func (m *IEEE802_11MgmtBeacon) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11InformationElement }

var LayerTypeIEEE802_11MgmtATIM = gopacket.RegisterLayerType(1059996, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtATIM", gopacket.DecodeFunc(decodeIEEE802_11MgmtATIM)})

type IEEE802_11MgmtATIM struct {
	IEEE802_11MgmtFrame
}

func decodeIEEE802_11MgmtATIM(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtATIM{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtATIM) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtATIM }
func (m *IEEE802_11MgmtATIM) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtATIM }
func (m *IEEE802_11MgmtATIM) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

func (d *IEEE802_11MgmtATIM) String() string {
    return fmt.Sprintf("802.11 ATIM")
}

var LayerTypeIEEE802_11MgmtDisassociation = gopacket.RegisterLayerType(1059997, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtDisassociation", gopacket.DecodeFunc(decodeIEEE802_11MgmtDisassociation)})

type IEEE802_11MgmtDisassociation struct {
	IEEE802_11MgmtFrame
        Reason uint16 
}

func decodeIEEE802_11MgmtDisassociation(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtDisassociation{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtDisassociation) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtDisassociation }
func (m *IEEE802_11MgmtDisassociation) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtDisassociation }
func (m *IEEE802_11MgmtDisassociation) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Reason=binary.LittleEndian.Uint16(data[0:2])
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

func (d *IEEE802_11MgmtDisassociation) String() string {
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


var LayerTypeIEEE802_11MgmtAuthentication = gopacket.RegisterLayerType(1054327, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtAuthentication", gopacket.DecodeFunc(decodeIEEE802_11MgmtAuthentication)})

type IEEE802_11MgmtAuthentication struct {
	IEEE802_11MgmtFrame
        Algorithm uint16
        Sequence uint16
        Statuscode uint16
}

func decodeIEEE802_11MgmtAuthentication(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtAuthentication{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtAuthentication) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtAuthentication }
func (m *IEEE802_11MgmtAuthentication) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtAuthentication }
func (m *IEEE802_11MgmtAuthentication) NextLayerType() gopacket.LayerType { return LayerTypeIEEE802_11InformationElement }
func (m *IEEE802_11MgmtAuthentication) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Algorithm=binary.LittleEndian.Uint16(data[0:2])
    m.Sequence=binary.LittleEndian.Uint16(data[2:4])
    m.Statuscode=binary.LittleEndian.Uint16(data[4:6])
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

func (d *IEEE802_11MgmtAuthentication) String() string {
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

var LayerTypeIEEE802_11MgmtDeauthentication = gopacket.RegisterLayerType(1054328, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtDeauthentication", gopacket.DecodeFunc(decodeIEEE802_11MgmtDeauthentication)})

type IEEE802_11MgmtDeauthentication struct {
	IEEE802_11MgmtFrame
        Reason uint16
}

func decodeIEEE802_11MgmtDeauthentication(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtDeauthentication{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtDeauthentication) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtDeauthentication }
func (m *IEEE802_11MgmtDeauthentication) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtDeauthentication }
func (m *IEEE802_11MgmtDeauthentication) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.Reason=binary.LittleEndian.Uint16(data[0:2])
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

func (d *IEEE802_11MgmtDeauthentication) String() string {
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

var LayerTypeIEEE802_11MgmtAction = gopacket.RegisterLayerType(1054329, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtAction", gopacket.DecodeFunc(decodeIEEE802_11MgmtAction)})

type IEEE802_11MgmtAction struct {
	IEEE802_11MgmtFrame
}

func decodeIEEE802_11MgmtAction(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtAction{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtAction) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtAction }
func (m *IEEE802_11MgmtAction) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtAction }
func (m *IEEE802_11MgmtAction) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeIEEE802_11MgmtActionNoAck = gopacket.RegisterLayerType(1054330, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtActionNoAck", gopacket.DecodeFunc(decodeIEEE802_11MgmtActionNoAck)})

type IEEE802_11MgmtActionNoAck struct {
	IEEE802_11MgmtFrame
}

func decodeIEEE802_11MgmtActionNoAck(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtActionNoAck{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtActionNoAck) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtActionNoAck }
func (m *IEEE802_11MgmtActionNoAck) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtActionNoAck }
func (m *IEEE802_11MgmtActionNoAck) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}

var LayerTypeIEEE802_11MgmtArubaWlan = gopacket.RegisterLayerType(1054331, gopacket.LayerTypeMetadata{"LayerTypeIEEE802_11MgmtArubaWlan", gopacket.DecodeFunc(decodeIEEE802_11MgmtArubaWlan)})

type IEEE802_11MgmtArubaWlan struct {
	IEEE802_11MgmtFrame
}

func decodeIEEE802_11MgmtArubaWlan(data []byte, p gopacket.PacketBuilder) error {
	d := &IEEE802_11MgmtArubaWlan{}
	return decodingLayerDecoder(d, data, p)
}

func (m *IEEE802_11MgmtArubaWlan) LayerType() gopacket.LayerType { return LayerTypeIEEE802_11MgmtArubaWlan }
func (m *IEEE802_11MgmtArubaWlan) CanDecode() gopacket.LayerClass { return LayerTypeIEEE802_11MgmtArubaWlan }
func (m *IEEE802_11MgmtArubaWlan) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
    m.BaseLayer = BaseLayer{Contents: data, Payload: nil}
    return nil
}
