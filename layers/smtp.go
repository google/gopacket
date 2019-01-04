// Copyright 2019 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"fmt"
	"github.com/google/gopacket"
	"io"
	"regexp"
	"strconv"
	"strings"
)

func decodeSMTP(data []byte, p gopacket.PacketBuilder) error {
	f := &SMTP{}
	err := f.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(f)
	p.SetApplicationLayer(f)
	return nil

}

// SMTPCommandType defines the different commands for SMTP
type SMTPCommandType int32

// All SMTP commands
const (
	SMTPCommandTypeUnknown SMTPCommandType = -1
	SMTPCommandTypeMSG     SMTPCommandType = -2 // special type to signal that payload contains message data

	// basic commands
	SMTPCommandTypeHELO     SMTPCommandType = 1
	SMTPCommandTypeMAILFROM SMTPCommandType = 2
	SMTPCommandTypeRCPTTO   SMTPCommandType = 3
	SMTPCommandTypeDATA     SMTPCommandType = 4
	SMTPCommandTypeRSET     SMTPCommandType = 5
	SMTPCommandTypeVRFY     SMTPCommandType = 6
	SMTPCommandTypeNOOP     SMTPCommandType = 7
	SMTPCommandTypeQUIT     SMTPCommandType = 8

	// extended smtp command
	SMTPCommandTypeEHLO     SMTPCommandType = 9
	SMTPCommandTypeAUTH     SMTPCommandType = 10
	SMTPCommandTypeSTARTTLS SMTPCommandType = 11
	SMTPCommandTypeSIZE     SMTPCommandType = 12
	SMTPCommandTypeHELP     SMTPCommandType = 13
)

// GetSMTPCommand get a SMTPCommandType from string
func GetSMTPCommand(command string) (SMTPCommandType, error) {
	switch strings.ToUpper(command) {
	case "HELO":
		return SMTPCommandTypeHELO, nil
	case "MAILFROM":
		return SMTPCommandTypeMAILFROM, nil
	case "RCPTTO":
		return SMTPCommandTypeRCPTTO, nil
	case "DATA":
		return SMTPCommandTypeDATA, nil
	case "RSET":
		return SMTPCommandTypeRSET, nil
	case "VRFY":
		return SMTPCommandTypeVRFY, nil
	case "NOOP":
		return SMTPCommandTypeNOOP, nil
	case "QUIT":
		return SMTPCommandTypeQUIT, nil
	case "EHLO":
		return SMTPCommandTypeEHLO, nil
	case "AUTH":
		return SMTPCommandTypeAUTH, nil
	case "STARTTLS":
		return SMTPCommandTypeSTARTTLS, nil
	case "SITE":
		return SMTPCommandTypeSIZE, nil
	case "HELP":
		return SMTPCommandTypeHELP, nil
	default:
		return SMTPCommandTypeUnknown, fmt.Errorf("Unknown SMTP command: '%s'", command)
	}
}

// SMTPResponse smtp response type, containing status code and parameter
type SMTPResponse struct {
	ResponseCode int
	Parameter    string
}

// SMTPCommand represents a smtp command
type SMTPCommand struct {
	Command   SMTPCommandType
	Parameter string
}

// SMTP represents a smtp dialog
type SMTP struct {
	BaseLayer

	IsEncrypted   bool
	IsResponse    bool
	ResponseLines []SMTPResponse
	Command       SMTPCommand
}

// LayerType returns gopacket.LayerTypeSMTP
func (smtp *SMTP) LayerType() gopacket.LayerType { return LayerTypeSMTP }

// Payload returns the base layer payload (nil)
func (smtp *SMTP) Payload() []byte { return smtp.BaseLayer.Payload }

// CanDecode returns gopacket.LayerTypeSMTP
func (smtp *SMTP) CanDecode() gopacket.LayerClass { return LayerTypeSMTP }

// NextLayerType returns gopacket.LayerTypeZero
func (smtp *SMTP) NextLayerType() gopacket.LayerType {
	if len(smtp.BaseLayer.Payload) > 0 {
		return gopacket.LayerTypeFragment
	} else {
		return gopacket.LayerTypeZero
	}
}

// DecodeFromBytes decodes the SMTP layer from bytes
func (smtp *SMTP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	smtp.BaseLayer = BaseLayer{Contents: data[:len(data)]}

	// Clean leading new line
	data = bytes.Trim(data, "\n")
	buffer := bytes.NewBuffer(data)

	var line []byte
	var err error
	var isLastLine bool
	for {
		// Read next line
		line, err = buffer.ReadBytes(byte('\n'))
		if err != nil {
			if err == io.EOF {
				isLastLine = true
			} else {
				return err
			}
		}

		// check if smtp is encrypted
		tlsType := TLSType(line[0])
		if tlsType.String() == "Unknown" { // try to parse line if not encrypted
			parseErr := smtp.parseLine(line)
			if parseErr != nil {
				return err
			}
		} else { // smtp seams to be encrypted, stop here
			smtp.IsEncrypted = true
			break
		}

		if isLastLine {
			break
		}
	}

	return nil
}

// command example: EHLO mail.example.com
// command example: STARTTLS
// response example: 250-mail.example.com
// response example: 220 ready for tls
//
// parseLine parse the smtp line
func (smtp *SMTP) parseLine(line []byte) error {
	var convErr, cmdErr error

	// Trim the new line delimiters
	lineTrimmed := bytes.Trim(line, "\r\n")

	re := regexp.MustCompile("^([0-9]{3})[ -](.*)") // check if line is response
	if result := re.FindStringSubmatch(string(lineTrimmed)); result != nil {
		response := SMTPResponse{
			Parameter: result[2],
		}
		response.ResponseCode, convErr = strconv.Atoi(result[1])
		if convErr != nil {
			return convErr
		}

		smtp.IsResponse = true
		smtp.ResponseLines = append(smtp.ResponseLines, response)
	} else {
		commandSplit := strings.SplitN(string(lineTrimmed), " ", 2)
		command := SMTPCommand{}
		command.Command, cmdErr = GetSMTPCommand(strings.Replace(commandSplit[0], " ", "", -1))
		if cmdErr != nil { // no valid command, treating it as the content of DATA, adding it to payload
			smtp.Command = SMTPCommand{
				Command: SMTPCommandTypeMSG,
			}
			smtp.BaseLayer.Payload = append(smtp.BaseLayer.Payload, line...)
		} else {
			if len(commandSplit) >= 2 {
				command.Parameter = commandSplit[1]
			}
			smtp.Command = command
		}
	}

	return nil
}
