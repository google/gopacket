// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

/*
Package pcap allows users of gopacket to read packets off the wire or from
pcap files.

This package is meant to be used with its parent,
http://code.google.com/p/gopacket, although it can also be used independently
if you just want to get packet data from the wire.

Reading PCAP Files

The following code can be used to read in data from a pcap file.

 if handle, err := pcap.OpenOffline("/path/to/my/file"); err != nil {
   panic(err)
 } else {
   packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
   for packet := range packetSource.Packets() {
     handlePacket(packet)  // Do something with a packet here.
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
   for packet := range packetSource.Packets() {
     handlePacket(packet)  // Do something with a packet here.
   }
 }

Unactivated Handles

Newer PCAP functionality requires the concept of an 'unactivated' PCAP handle.
Instead of constantly adding new arguments to pcap_open_live, users now call
pcap_create to create a handle, set it up with a bunch of optional function
calls, then call pcap_activate to activate it.  This library mirrors that
mechanism, for those that want to expose/use these new features:

  unactivated, err := pcap.Create(deviceName)
  if err != nil {
    log.Fatal(err)
  }
  defer unactivated.CleanUp()

  // Call various functions on unactivated to set it up the way you'd like:
  if err = unactivated.SetTimeout(time.Minute); err != nil {
    log.Fatal(err)
  } else if err = unactivated.SetTimestampSource("foo"); err != nil {
    log.Fatal(err)
  }

  // Finally, create the actual handle by calling Activate:
  handle, err := unactivated.Activate()  // after this, unactivated is no longer valid
  if err != nil {
    log.Fatal(err)
  }
  defer handle.Close()

  // Now use your handle as you see fit.

PCAP Timeouts

pcap.OpenLive and pcap.SetTimeout both take timeouts.
If you don't care about timeouts, just pass in BlockForever,
which should do what you expect with minimal fuss.

A timeout of 0 is not recommended.  Some platforms, like Macs
(http://www.manpages.info/macosx/pcap.3.html) say:
  The read timeout is used to arrange that the read not necessarily return
  immediately when a packet is seen, but that it wait for some amount of time
  to allow more packets to arrive and to read multiple packets from the OS
  kernel in one operation.
This means that if you only capture one packet, the kernel might decide to wait
'timeout' for more packets to batch with it before returning.  A timeout of
0, then, means 'wait forever for more packets', which is... not good.

To get around this, we've introduced the following behavior:  if a negative
timeout is passed in, we set the positive timeout in the handle, then loop
internally in ReadPacketData/ZeroCopyReadPacketData when we see timeout
errors.
*/
package pcap
