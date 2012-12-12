// Copyright 2012 Google, Inc. All rights reserved.

/*
Package pcap allows users of gopacket to read packets off the wire or from
pcap files.

Reading PCAP Files

The following code can be used to read in data from a pcap file.

 if h, err := pcap.OpenOffline(filename); err != nil {
   panic(err)
 } else {
   for packet, err := h.Next(); err != pcap.NextErrorNoMorePackets; packet, err = h.Next() {
     if err != nil {
       fmt.Println("Error reading in packet:", err)
     } else {
       handlePacket(packet)
     }
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
   packet, err := handle.Next()
   if err != nil {
     fmt.Println("Error reading in packet:", err)
     continue
   }
   handlePacket(packet)
 }
*/
package pcap
