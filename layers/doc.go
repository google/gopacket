// Copyright 2012 Google, Inc. All rights reserved.

/*
Package layers provides decoding layers for many common protocols.

The layers package contains decode implementations for a number of different
types of packet layers.  Users of gopacket will almost always want to also use
layers to actually decode packet data into useful pieces.

To see the set of protocols that gopacket/layers is currently able to decode,
look at the set of LayerTypes defined in the Variables sections.

The layers package also defines endpoints for many of the common packet layers
that have source/destination addresses associated with them, for example IPv4/6
(IPs) and TCP/UDP (ports).

Finally, layers contains a number of useful enumerations (IPProtocol,
EthernetType, LinkType, PPPType, etc...).  Many of these implement the
gopacket.Decoder interface, so they can be passed into gopacket as decoders.

Most common protocol layers are named using acronyms or other industry-common
names (IPv4, TCP, PPP).  Some of the less common ones have their names expanded
(CiscoDiscoveryProtocol).

For certain protocols, sub-parts of the protocol are split out into their own
layers (SCTP, for example).  This is done mostly in cases where portions of the
protocol may fulfill the capabilities of interesting layers (SCTPData implements
ApplicationLayer, while base SCTP implements TransportLayer), or possibly
because splitting a protocol into a few layers makes decoding easier.
*/
package layers
