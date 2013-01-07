// Copyright 2012 Google, Inc. All rights reserved.

package layers

import (
	"fmt"
	"strconv"
)

type TCPPort uint16
type UDPPort uint16
type RUDPPort uint8
type SCTPPort uint16
type UDPLitePort uint16

var RUDPPortNames = map[RUDPPort]string{}
var UDPLitePortNames = map[UDPLitePort]string{}

// {TCP,UDP,SCTP}PortNames can be found in iana_ports.go

func (a TCPPort) String() string {
	if name, ok := TCPPortNames[a]; ok {
		return fmt.Sprintf("%d(%s)", a, name)
	}
	return strconv.Itoa(int(a))
}
func (a UDPPort) String() string {
	if name, ok := UDPPortNames[a]; ok {
		return fmt.Sprintf("%d(%s)", a, name)
	}
	return strconv.Itoa(int(a))
}
func (a RUDPPort) String() string {
	if name, ok := RUDPPortNames[a]; ok {
		return fmt.Sprintf("%d(%s)", a, name)
	}
	return strconv.Itoa(int(a))
}
func (a SCTPPort) String() string {
	if name, ok := SCTPPortNames[a]; ok {
		return fmt.Sprintf("%d(%s)", a, name)
	}
	return strconv.Itoa(int(a))
}
func (a UDPLitePort) String() string {
	if name, ok := UDPLitePortNames[a]; ok {
		return fmt.Sprintf("%d(%s)", a, name)
	}
	return strconv.Itoa(int(a))
}
