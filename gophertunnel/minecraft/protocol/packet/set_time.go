package packet

import (
	"ValiantProxy/gophertunnel/minecraft/protocol"
)

// SetTime is sent by the server to update the current time client-side. The client actually advances time
// client-side by itself, so this packet does not need to be sent each tick. It is merely a means of
// synchronising time between server and client.
type SetTime struct {
	// Time is the current time. The time is not limited to 24000 (time of day), but continues progressing
	// after that.
	Time int32
}

// ID ...
func (*SetTime) ID() uint32 {
	return IDSetTime
}

func (pk *SetTime) Marshal(io protocol.IO) {
	io.Varint32(&pk.Time)
}
