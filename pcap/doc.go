// Copyright 2012 Google, Inc. All rights reserved.

/*
Package pcap allows users of gopacket to read packets off the wire or from
pcap files.

Reading PCAP Files

The following code can be used to read in data from a pcap file.

 h := pcap.OpenOffline(filename)
 for packet, err := h.NextEx(); err != pcap.NextExNoMorePackets; packet, err = h.NextEx() {
   if err != nil {
     fmt.Println("Error reading in packet:", err)
   } else {
     handlePacket(packet)
   }
 }

Reading Live Packets

The following code can be used to read in data from a live device, in this case
"eth0".

 var handle *pcap.Handle
 if h, err := pcap.OpenLive("eth0", 1600, true, 0); err != nil {
   panic(err)
 } else if err := h.SetFilter("tcp and port 80"); err != nil {
   panic(err)
 } else {
   handle = h
 }
 for {
   packet, err := handle.NextEx()
   if err != nil {
     fmt.Println("Error reading in packet:", err)
     continue
   }
   handlePacket(packet)
 }
*/
package pcap
