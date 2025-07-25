package packet

import (
	"ValiantProxy/gophertunnel/minecraft/protocol"
)

// NetworkStackLatency is sent by the server (and the client, on development builds) to measure the latency
// over the entire Minecraft stack, rather than the RakNet latency. It has other usages too, such as the
// ability to be used as some kind of acknowledgement packet, to know when the client has received a certain
// other packet.
type NetworkStackLatency struct {
	// Timestamp is the timestamp of the network stack latency packet. The client will, if NeedsResponse is
	// set to true, send a NetworkStackLatency packet with this same timestamp packet in response.
	Timestamp int64
	// NeedsResponse specifies if the sending side of this packet wants a response to the packet, meaning that
	// the other side should send a NetworkStackLatency packet back.
	NeedsResponse bool
}

// ID ...
func (*NetworkStackLatency) ID() uint32 {
	return IDNetworkStackLatency
}

func (pk *NetworkStackLatency) Marshal(io protocol.IO) {
	io.Int64(&pk.Timestamp)
	io.Bool(&pk.NeedsResponse)
}
