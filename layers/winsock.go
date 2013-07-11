// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build windows,cgo

package layers

// #include <WinSock.h>
import "C"

const (
	ProtocolFamilyIPv4 ProtocolFamily = C.AF_INET
	// BSDs use different values for INET6... glory be.  These values taken from
	// tcpdump 4.3.0.
	ProtocolFamilyIPv6BSD     ProtocolFamily = 24
	ProtocolFamilyIPv6FreeBSD ProtocolFamily = 28
	ProtocolFamilyIPv6Darwin  ProtocolFamily = 30
	ProtocolFamilyIPv6Linux   ProtocolFamily = 10
)
