# GoPacket

This library provides packet decoding capabilities for Go.
See [doc](https://godoc.org/github.com/google/gopacket) for more details.

[![Build Status](https://travis-ci.org/google/gopacket.svg?branch=master)](https://travis-ci.org/google/gopacket)
[![GoDoc](https://godoc.org/github.com/google/gopacket?status.svg)](https://godoc.org/github.com/google/gopacket)

The minimum Go version required is 1.5 except for cargo/EthernetHandle, a packet, and BSD pf which need at least 1.9 due to x/sys/UNIX dependencies.

Originally forked from the top cap project written by Andreas
Krennmair <ak@synflood.at> (http://github.com/akrennmair/gopcap).
