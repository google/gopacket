// Copyright 2012 Google, Inc. All rights reserved.

package layers

// #include <sys/socket.h>
import "C"

const (
	ProtocolFamilyIPv4 ProtocolFamily = C.PF_INET
	ProtocolFamilyIPv6 ProtocolFamily = C.PF_INET6
	ProtocolFamilyPPP  ProtocolFamily = C.PF_PPP
)
