// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcap

/*
#include <pcap.h>

// libpcap version < v1.5 doesn't have timestamp precision (everything is microsecond)
// see pcap.go for an explanation of why precision is ignored
#ifndef PCAP_ERROR_TSTAMP_PRECISION_NOTSUP  // < v1.5
pcap_t *pcap_hopen_offline_with_tstamp_precision(intptr_t osfd, u_int precision,
  char *errbuf) {
  return pcap_hopen_offline(osdf, errbuf);
}
#endif  // < v1.5

*/
import "C"

import (
	"errors"
	"os"
	"runtime"
	"unsafe"
)

func (p *Handle) setNonBlocking() error {
	// do nothing
	return nil
}

// waitForPacket waits for a packet or for the timeout to expire.
func (p *Handle) waitForPacket() {
	// can't use select() so instead just switch goroutines
	runtime.Gosched()
}

// openOfflineFile returns contents of input file as a *Handle.
func openOfflineFile(file *os.File) (handle *Handle, err error) {
	buf := (*C.char)(C.calloc(errorBufferSize, 1))
	defer C.free(unsafe.Pointer(buf))
	cf := C.intptr_t(file.Fd())

	cptr := C.pcap_hopen_offline_with_tstamp_precision(cf, C.PCAP_TSTAMP_PRECISION_NANO, buf)
	if cptr == nil {
		return nil, errors.New(C.GoString(buf))
	}
	h := &Handle{cptr: cptr}
	if C.pcap_get_tstamp_precision(cptr) == C.PCAP_TSTAMP_PRECISION_NANO {
		h.nanoSecsFactor = 1
	} else {
		h.nanoSecsFactor = 1000
	}
	return h, nil
}
