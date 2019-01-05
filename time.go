// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import "fmt"

// TimestampResolution represents the resolution of timestamps in Base^Exponent.
type TimestampResolution struct {
	Base, Exponent int
}

func (t TimestampResolution) String() string {
	return fmt.Sprintf("%d^%d", t.Base, t.Exponent)
}

// TimestampResolutionInvalid represents an invalid timestamp resolution
var TimestampResolutionInvalid = TimestampResolution{}

// TimestampResolutionMillisecond is a resolution of 10^-6s
var TimestampResolutionMillisecond = TimestampResolution{10, -6}

// TimestampResolutionNanosecond is a resolution of 10^-9s
var TimestampResolutionNanosecond = TimestampResolution{10, -9}

// TimestampResolutionNTP is the resolution of NTP timestamps which is 2^-32 ≈ 233 picoseconds
var TimestampResolutionNTP = TimestampResolution{2, -32}

// TimestampResolutionCaptureInfo is the resolution used in CaptureInfo, which his currently nanosecond
var TimestampResolutionCaptureInfo = TimestampResolutionNanosecond

// PacketSourceResolution is an interface for packet data sources that
// support reporting the timestamp resolution of the aqcuired timestamps.
// Returned timestamps will always have NanosecondTimestampResolution due
// to the use of time.Time, but scaling might have occured if acquired
// timestamps have a different resolution.
type PacketSourceResolution interface {
	// Resolution returns the timestamp resolution of acquired timestamps before scaling to NanosecondTimestampResolution.
	Resolution() TimestampResolution
}
