// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

/*
Package gopacket provides packet decoding for the Go language.

gopacket contains 3 sub-packages with additional functionality you may find
useful:

 * layers: You'll probably use this every time.  This contains of the logic
     built into gopacket for decoding packet protocols.  Note that all example
     code below assumes that you have imported both gopacket and
     gopacket/layers.
 * pcap: C bindings to use libpcap to pull packets off the wire.
 * pfring: C bindings to use PF_RING to pull packets off the wire.

Basic Usage

gopacket takes in packet data as a []byte and decodes it into a packet with
a non-zero number of "layers".  Each layer corresponds to a protocol
within the bytes.  Once a packet has been decoded, the layers of the packet
can be requested from the packet.

 // Decode a packet
 packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Default)
 // Get the TCP layer from this packet
 if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
   fmt.Println("This is a TCP packet!")
   // Get actual TCP data from this layer
   tcp, _ := tcpLayer.(*layers.TCP)
   fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
 }
 // Iterate over all layers, printing out each layer type
 for layer := range packet.Layers() {
   fmt.Println("PACKET LAYER:", layer.LayerType())
 }

Packets can be decoded from a number of starting points.  Many of our base
types implement Decoder, which allow us to decode packets for which
we don't have full data.

 // Decode an ethernet packet
 ethP := gopacket.NewPacket(p1, layers.LayerTypeEthernet, gopacket.Default)
 // Decode an IPv6 header and everything it contains
 ipP := gopacket.NewPacket(p2, layers.LayerTypeIPv6, gopacket.Default)
 // Decode a TCP header and its payload
 tcpP := gopacket.NewPacket(p3, layers.LayerTypeTCP, gopacket.Default)

Reading Packets From A Source

Most of the time, you won't just have a []byte of packet data lying around.
Instead, you'll want to read packets in from somewhere (file, interface, etc)
and process them.  To do that, you'll want to build a PacketSource.

First, you'll need to construct an object that implements the PacketDataSource
interface.  There are implementations of this interface bundled with gopacket
in the gopacket/pcap and gopacket/pfring subpackages... see their documentation
for more information on their usage.  Once you have a PacketDataSource, you can
pass it into NewPacketSource, along with a Decoder of your choice, to create
a PacketSource.

Once you have a PacketSource, you can read packets from it in multiple ways.
See the docs for PacketSource for more details.  The easiest method is the
Packets function, which returns a channel, then asynchronously writes new
packets into that channel, closing the channel if the packetSource hits an
end-of-file.

  packetSource := ...  // construct using pcap or pfring
  for packet := range packetSource.Packets() {
    handlePacket(packet)  // do something with each packet
  }

You can change the decoding options of the packetSource by setting fields in
packetSource.DecodeOptions... see the following sections for more details.

Lazy Decoding

gopacket optionally decodes packet data lazily, meaning it
only decodes a packet layer when it needs to to handle a function call.

 // Create a packet, but don't actually decode anything yet
 packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Lazy)
 // Now, decode the packet up to the first IPv4 layer found but no further.
 // If no IPv4 layer was found, the whole packet will be decoded looking for
 // it.
 ip4 := packet.Layer(layers.LayerTypeIPv4)
 // Decode all layers and return them.  The layers up to the first IPv4 layer
 // are already decoded, and will not require decoding a second time.
 layers := packet.Layers()

Lazily-decoded packets are not concurrency-safe.  Since layers have not all been
decoded, each call to Layer() or Layers() has the potential to mutate the packet
in order to decode the next layer.  If a packet is used
in multiple goroutines concurrently, don't use gopacket.Lazy.  Then gopacket
will decode the packet fully, and all future function calls won't mutate the
object.

NoCopy Decoding

By default, gopacket will copy the slice passed to NewPacket and store the
copy within the packet, so future mutations to the bytes underlying the slice
don't affect the packet and its layers.  If you can guarantee that the
underlying slice bytes won't be changed, you can use NoCopy to tell
gopacket.NewPacket, and it'll use the passed-in slice itself.

 // This channel returns new byte slices, each of which points to a new
 // memory location that's guaranteed immutable for the duration of the
 // packet.
 for data := range myByteSliceChannel {
   p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
   doSomethingWithPacket(p)
 }

The fastest method of decoding is to use both Lazy and NoCopy, but note from
the many caveats above that for some implementations they may be dangerous
either or both may be dangerous.

Pointers To Known Layers

During decoding, certain layers are stored in the packet as well-known
layer types.  For example, IPv4 and IPv6 are both considered NetworkLayer
layers, while TCP and UDP are both TransportLayer layers.  We support 4
layers, corresponding to the 4 layers of the TCP/IP layering scheme (roughly
anagalous to layers 2, 3, 4, and 7 of the OSI model).  To access these,
you can use the packet.LinkLayer, packet.NetworkLayer,
packet.TransportLayer, and packet.ApplicationLayer functions.  Each of
these functions returns a corresponding interface
(gopacket.{Link,Network,Transport,Application}Layer).  The first three
provide methods for getting src/dst addresses for that particular layer,
while the final layer provides a Payload function to get payload data.
This is helpful, for example, to get payloads for all packets regardless
of their underlying data type:

 // Get packets from some source
 for packet := range someSource {
   if app := packet.ApplicationLayer(); app != nil {
     if strings.Contains(string(app.Payload()), "magic string") {
       fmt.Println("Found magic string in a packet!")
     }
   }
 }

A particularly useful layer is ErrorLayer, which is set whenever there's
an error parsing part of the packet.

 packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Default)
 if err := packet.ErrorLayer(); err != nil {
   fmt.Println("Error decoding some part of the packet:", err)
 }

Note that we don't return an error from NewPacket because we may have decoded
a number of layers successfully before running into our erroneous layer.  You
may still be able to get your Ethernet and IPv4 layers correctly, even if
your TCP layer is malformed.

Flow And Endpoint

gopacket has two useful objects, Flow and Endpoint, for communicating in a protocol
independent manner the fact that a packet is coming from A and going to B.
The general layer types LinkLayer, NetworkLayer, and TransportLayer all provide
methods for extracting their flow information, without worrying about the type
of the underlying Layer.

A Flow is a simple object made up of a set of two Endpoints, one source and one
destination.  It details the sender and receiver of the Layer of the Packet.

An Endpoint is a hashable representation of a source or destination.  For
example, for LayerTypeIPv4, an Endpoint contains the IP address bytes for a v4
IP packet.  A Flow can be broken into Endpoints, and Endpoints can be combined
into Flows:

 packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Lazy)
 netFlow := packet.NetworkLayer().NetworkFlow()
 src, dst := netFlow.Endpoints()
 reverseFlow := gopacket.NewFlow(dst, src)

Both Endpoint and Flow objects can be used as map keys, and the equality
operator can compare them, so you can easily group together all packets
based on endpoint criteria:

 flows := map[gopacket.Endpoint]chan gopacket.Packet
 packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Lazy)
 // Send all TCP packets to channels based on their destination port.
 if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
   flows[tcp.TransportFlow().Dst()] <- packet
 }
 // Look for all packets with the same source and destination network address
 if net := packet.NetworkLayer(); net != nil {
   src, dst := net.NetworkFlow().Endpoints()
   if src == dst {
     fmt.Println("Fishy packet has same network source and dst: %s", src)
   }
 }
 // Find all packets coming from UDP port 1000 to UDP port 500
 interestingFlow := gopacket.NewFlow(layers.NewUDPPortEndpoint(1000), layers.NewUDPPortEndpoint(500))
 if t := packet.NetworkLayer(); t != nil && t.TransportFlow() == interestingFlow {
   fmt.Println("Found that UDP flow I was looking for!")
 }

Implementing Your Own Decoder

If your network has some strange encapsulation, you can implement your own
decoder.  In this example, we handle Ethernet packets which are encapsulated
in a 4-byte header.

 // Create a layer type, should be unique and high, so it doesn't conflict,
 // giving it a name and a decoder to use.
 var MyLayerType = gopacket.RegisterLayerType(12345, "MyLayerType", gopacket.DecodeFunc(decodeMyLayer))

 // Implement my layer
 type MyLayer struct {
   StrangeHeader []byte
   payload []byte
 }
 func (m MyLayer) LayerType() LayerType { return MyLayerType }
 func (m MyLayer) LayerContents() []byte { return m.StrangeHeader }
 func (m MyLayer) LayerPayload() []byte { return m.payload }

 // Now implement a decoder... this one strips off the first 4 bytes of the
 // packet.
 func decodeMyLayer(data []byte, p gopacket.PacketBuilder) error {
   // Create my layer
   p.AddLayer(&MyLayer{data[:4], data[4:]})
   // Determine how to handle the rest of the packet
   return p.NextDecoder(layers.LayerTypeEthernet)
 }

 // Finally, decode your packets:
 p := gopacket.NewPacket(data, MyLayerType, gopacket.Lazy)

See the docs for Decoder and PacketBuilder for more details on how coding
decoders works, or look at RegisterLayerType and RegisterEndpointType to see how
to add layer/endpoint types to gopacket.

A Final Note

If you use gopacket, you'll almost definitely want to make sure gopacket/layers
is imported, since when imported it sets all the LayerType variables and fills
in a lot of interesting variables/maps (DecodersByLayerName, etc).  Therefore,
it's recommended that even if you don't use any layers functions directly, you still import with:

  import (
    _ "code.google.com/p/gopacket/layers"
  )
*/
package gopacket
