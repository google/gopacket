// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
//
// +build !windows

package pcap

/*
#include <stdlib.h>
#include <pcap.h>

// pcap_wait returns when the next packet is available or the timeout expires.
// Since it uses pcap_get_selectable_fd, it will not work in Windows.
int pcap_wait(pcap_t *p, int usec) {
	fd_set fds;
	int fd;
	struct timeval tv;

	fd = pcap_get_selectable_fd(p);
	if(fd < 0) {
		return fd;
	}

	FD_ZERO(&fds);
	FD_SET(fd, &fds);

	tv.tv_sec = 0;
	tv.tv_usec = usec;

	if(usec != 0) {
		return select(fd+1, &fds, NULL, NULL, &tv);
	}

	// block indefinitely if no timeout provided
	return select(fd+1, &fds, NULL, NULL, NULL);
}

// libpcap version < v1.5 doesn't have timestamp precision (everything is microsecond)
// see pcap.go for an explanation of why precision is ignored
#ifndef PCAP_ERROR_TSTAMP_PRECISION_NOTSUP  // < v1.5
pcap_t *pcap_fopen_offline_with_tstamp_precision(FILE *fp, u_int precision,
  char *errbuf) {
  return pcap_fopen_offline(fp, errbuf);
}
#endif  // < v1.5

*/
import "C"

import (
	"errors"
	"os"
	"unsafe"
)

func (p *Handle) setNonBlocking() error {
	buf := (*C.char)(C.calloc(errorBufferSize, 1))
	defer C.free(unsafe.Pointer(buf))

	// Change the device to non-blocking, we'll use pcap_wait to wait until the
	// handle is ready to read.
	if v := C.pcap_setnonblock(p.cptr, 1, buf); v == -1 {
		return errors.New(C.GoString(buf))
	}

	return nil
}

// waitForPacket waits for a packet or for the timeout to expire.
func (p *Handle) waitForPacket() {
	// need to wait less than the read timeout according to pcap documentation.
	// timeoutMillis rounds up to at least one millisecond so we can safely
	// subtract up to a millisecond.
	usec := timeoutMillis(p.timeout) * 1000
	usec -= 100

	C.pcap_wait(p.cptr, usec)
}

// openOfflineFile returns contents of input file as a *Handle.
func openOfflineFile(file *os.File) (handle *Handle, err error) {
	buf := (*C.char)(C.calloc(errorBufferSize, 1))
	defer C.free(unsafe.Pointer(buf))
	cmode := C.CString("rb")
	defer C.free(unsafe.Pointer(cmode))
	cf := C.fdopen(C.int(file.Fd()), cmode)

	cptr := C.pcap_fopen_offline_with_tstamp_precision(cf, C.PCAP_TSTAMP_PRECISION_NANO, buf)
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
