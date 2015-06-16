// +build darwin dragonfly freebsd netbsd openbsd

// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package bpf_sniffer

import (
	"github.com/google/gopacket"
	"golang.org/x/sys/unix"

	"fmt"
	"syscall"
	"time"
	"unsafe"
)

const wordSize = int(unsafe.Sizeof(uintptr(0)))

func bpf_wordalign(x int) int {
	return (((x) + (wordSize - 1)) &^ (wordSize - 1))
}

type TimedFrame struct {
	RawFrame  []byte
	Timestamp time.Time
}

type BpfSniffer struct {
	sniffDeveiceName string
	bpfDeviceName string
	fd       int
	stopChan chan bool
	readChan chan TimedFrame
}

func NewBpfSniffer(name string) *BpfSniffer {
	return &BpfSniffer{
		sniffDeviceName: name,
		stopChan: make(chan bool, 0),
		readChan: make(chan TimedFrame, 0),
	}
}

func (b *BpfSniffer) pickBpfDevice() {
	for i := 0; i < 99; i++ {
		b.bpfDeviceName = fmt.Sprintf("/dev/bpf%d", i)
		b.fd, err = syscall.Open(b.bpfDeviceName, syscall.O_RDWR, 0)
		if err == nil {
			break
		}
	}
}

// Init is used to initialize a BPF device for promiscuous sniffing.
// It also starts a goroutine to continuously read frames.
func (b *BpfSniffer) Init() error {
	var err error
	enable := 1

	b.pickBpfDevice()

	err = syscall.SetBpfInterface(b.fd, b.sniffDeviceName)
	if err != nil {
		return err
	}

	// turning Immediate mode off should make the snffer
	// block when no packets are available.
	err = syscall.SetBpfImmediate(b.fd, enable)
	if err != nil {
		return err
	}

	// preserves the link level source address...
	// higher level protocol analyzers will not need this
	err = syscall.SetBpfHeadercmpl(b.fd, enable)
	if err != nil {
		return err
	}

	// forces the interface into promiscuous mode
	err = syscall.SetBpfPromisc(b.fd, enable)
	if err != nil {
		return err
	}

	go b.readFrames()
	return nil
}

func (b *BpfSniffer) Stop() {
	b.stopChan <- true
}

func (b *BpfSniffer) readFrames() {
	bufLen, err := syscall.BpfBuflen(b.fd)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, bufLen)
	var n int
	for {
		select {
		case <-b.stopChan:
			return
		default:
			n, err = syscall.Read(b.fd, buf)
			if err != nil {
				continue
			} else {
				p := int(0)
				for p < n {
					hdr := (*unix.BpfHdr)(unsafe.Pointer(&buf[p]))
					frameStart := p + int(hdr.Hdrlen)
					b.readChan <- TimedFrame{
						RawFrame:  buf[frameStart : frameStart+int(hdr.Caplen)],
						Timestamp: time.Unix(int64(hdr.Tstamp.Sec), int64(hdr.Tstamp.Usec)*1000),
					}
					p += bpf_wordalign(int(hdr.Hdrlen) + int(hdr.Caplen))
				}
			}
		}
	}
}

func (b *BpfSniffer) ReadTimedFrame() TimedFrame {
	timedFrame := <-b.readChan
	return timedFrame
}

func (b *BpfSniffer) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	timedFrame := b.ReadTimedFrame()
	captureInfo := gopacket.CaptureInfo{
		Timestamp:     timedFrame.Timestamp,
		CaptureLength: len(timedFrame.RawFrame),
		Length:        len(timedFrame.RawFrame),
	}
	return timedFrame.RawFrame, captureInfo, nil
}
