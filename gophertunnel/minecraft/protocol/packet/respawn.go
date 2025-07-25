package packet

import (
	"ValiantProxy/gophertunnel/minecraft/protocol"

	"github.com/go-gl/mathgl/mgl32"
)

const (
	RespawnStateSearchingForSpawn = iota
	RespawnStateReadyToSpawn
	RespawnStateClientReadyToSpawn
)

// Respawn is sent by the server to make a player respawn client-side. It is sent in response to a
// PlayerAction packet with ActionType PlayerActionRespawn.
// As of 1.13, the server sends two of these packets with different states, and the client sends one of these
// back in order to complete the respawn.
type Respawn struct {
	// Position is the position on which the player should be respawned. The position might be in a different
	// dimension, in which case the client should first be sent a ChangeDimension packet.
	Position mgl32.Vec3
	// State is the 'state' of the respawn. It is one of the constants that may be found above, and the value
	// the packet contains depends on whether the server or client sends it.
	State byte
	// EntityRuntimeID is the entity runtime ID of the player that the respawn packet concerns. This is
	// apparently for the server to recognise which player sends this packet.
	EntityRuntimeID uint64
}

// ID ...
func (*Respawn) ID() uint32 {
	return IDRespawn
}

func (pk *Respawn) Marshal(io protocol.IO) {
	io.Vec3(&pk.Position)
	io.Uint8(&pk.State)
	io.Varuint64(&pk.EntityRuntimeID)
}
