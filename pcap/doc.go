// Copyright 2012 Google, Inc. All rights reserved.

/*
Package pcap allows users of gopacket to read packets off the wire or from
pcap files.

Reading PCAP Files

The following code can be used to read in data from a pcap file.

 if handle, err := pcap.OpenOffline(filename); err != nil {
   panic(err)
 } else {
   for packet, err := handle.Next(); err != io.EOF; packet, err = handle.Next() {
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

 if handle, err := pcap.OpenLive("eth0", 1600, true, 0); err != nil {
   panic(err)
 } else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {  // optional
   panic(err)
 } else {
   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for {
     packet, err := packetSource.NextPacket()
     if err != {
       fmt.Println("ERROR:", err)
       continue
     }
     handlePacket(packet)  // Do something with a packet here.
   }
 }

Changing Packet Decoding Behavior

You have a few options for changing the behavior of packet decoding on a handle.
The first is to modify the DecodeOptions of the handle:

 handle, _ := pcap.OpenLive(...)
 // See gopacket.DecodeOptions for more options you can set here.
 handle.DecodeOptions.Lazy = true

The second option is to change the default decoder used to decode each packet.
By default, we set the decoder based on the link type of the handler, so you
should very rarely need to do this.  However, if you want, you can:

 handle, _ := pcap.OpenLive(...)
 // Force the handle to decode every packet as if it were PPP
 handle.Decoder = gopacket.LinkTypePPP
*/
package pcap
