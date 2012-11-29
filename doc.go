// Copyright (c) 2012 Google, Inc. All rights reserved.

// Package gopacket provides packet decoding for the Go language.
//
// gopacket takes in packet data as a []byte, and decodes it into a packet with
// a non-zero number of "layers", with each layer corresponding a protocol
// within the bytes.  Once a packet has been decoded, the layers of that packet
// can be requested from the packet.
//  // Decode a packet
//  packet := gopacket.NewPacket(myPacketData, gopacket.LinkTypeEthernet, gopacket.Eager)
//  // Get the TCP layer from this packet
//  if tcpLayer := packet.Layer(gopacket.LayerTypeTCP); tcpLayer != nil {
//    fmt.Println("This is a TCP packet!")
//    // Get actual TCP data from this layer
//    tcp, _ := tcpLayer.(*gopacket.TCP)
//    fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
//  }
//  // Iterate over all layers, printing out each layer type
//  for layer := range packet.Layers() {
//    fmt.Println("PACKET LAYER:", layer.LayerType())
//  }
// Packets can be decoded from a number of starting points.  Many of our base
// types implement PacketDecoder, which allow us to decode packets for which
// we don't have full data.
//  // Decode an ethernet packet
//  ethP := gopacket.NewPacket(p1, gopacket.LinkTypeEthernet, gopacket.Eager)
//  // Decode an IPv6 header and everything it contains
//  ipP := gopacket.NewPacket(p2, gopacket.EthernetTypeIPv6, gopacket.Eager)
//  // Decode a TCP header and its payload
//  tcpP := gopacket.NewPacket(p3, gopacket.IPProtocolTCP, gopacket.Eager)
//
// gopacket provides a number of features which users might find useful:
//
// === Pointers To Known Layers ===
//
// During decoding, certain layers are stored in the packet as well-known
// layer types.  For example, IPv4 and IPv6 are both considered NetworkLayer
// layers, while TCP and UDP are both TransportLayer layers.  We support 4
// layers, corresponding to the 4 layers of the TCP/IP layering scheme (roughly
// anagalous to layers 2, 3, 4, and 7 of the OSI model).  To access these,
// you can use the packet.LinkLayer(), packet.NetworkLayer(),
// packet.TransportLayer(), and packet.ApplicationLayer() functions.  Each of
// these functions returns a corresponding interface
// (gopacket.{Link,Network,Transport,Application}Layer).  The first three
// provide methods for getting src/dst addresses for that particular layer,
// while the final layer provides a Payload() function to get payload data.
// This is helpful, for example, to get payloads for all packets regardless
// of their underlying data type:
//  // Get packets from some source
//  for packet := range someSource {
//    if app := packet.ApplicationLayer(); app != nil {
//      if strings.Index(string(app.Payload()), "magic string") {
//        fmt.Println("Found magic string in a packet!")
//      }
//    }
//  }
//
// === Lazy Decoding ===
//
// gopacket optionally decodes packet data lazily, meaning it
// only decodes a packet layer when it needs to to handle a function call.
//  // Create a packet, but don't actually decode anything yet (use
//  // gopacket.Eager instead if you don't want lazy decoding)
//  packet := gopacket.NewPacket(myPacketData, gopacket.LinkTypeEthernet, gopacket.Lazy)
//  // Now, decode the packet up to the first IPv4 layer found but no further.
//  // If no IPv4 layer was found, the whole packet will be decoded looking for
//  // it.
//  ip4 := packet.Layer(gopacket.LayerTypeIPv4)
//  // Decode all layers and return them.  The layers up to the first IPv4 layer
//  // are already decoded, and will not require decoding a second time.
//  layers := packet.Layers()
// Lazily-decoded packets are not concurrency-safe.  If a packet is used
// in multiple goroutines concurrently, use gopacket.Eager decoding to fully
// decode the packet, then pass it around.
//
// === Flow Keys ===
//
// Since gopacket has abstract types for NetworkLayer and TransportLayer, and
// both of these return addresses for their sources and destinations, it's able
// to create a flow key to map a packet to a flow.
//  // Create a flow map
//  flows := map[gopacket.FlowKey]*someFlowObject
//  // Create the packet
//  packet := gopacket.NewPacket(myPacketData, gopacket.LinkTypeEthernet, gopacket.Lazy)
//  // Add the packet to a flow
//  flows[packet.FlowKey()].addPacketToFlow(packet)
package gopacket
