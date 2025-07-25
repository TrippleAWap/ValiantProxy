package packet

import (
	"ValiantProxy/gophertunnel/minecraft/protocol"

	"github.com/go-gl/mathgl/mgl32"
)

const (
	_ = iota + 1
	_
	InteractActionLeaveVehicle
	InteractActionMouseOverEntity
	InteractActionNPCOpen
	InteractActionOpenInventory
)

// Interact is sent by the client when it interacts with another entity in some way. It used to be used for
// normal entity and block interaction, but this is no longer the case now.
type Interact struct {
	// Action type is the ID of the action that was executed by the player. It is one of the constants that
	// may be found above.
	ActionType byte
	// TargetEntityRuntimeID is the runtime ID of the entity that the player interacted with. This is empty
	// for the InteractActionOpenInventory action type.
	TargetEntityRuntimeID uint64
	// Position associated with the ActionType above. For the InteractActionMouseOverEntity, this is the
	// position relative to the entity moused over over which the player hovered with its mouse/touch. For the
	// InteractActionLeaveVehicle, this is the position that the player spawns at after leaving the vehicle.
	Position mgl32.Vec3
}

// ID ...
func (*Interact) ID() uint32 {
	return IDInteract
}

func (pk *Interact) Marshal(io protocol.IO) {
	io.Uint8(&pk.ActionType)
	io.Varuint64(&pk.TargetEntityRuntimeID)
	if pk.ActionType == InteractActionMouseOverEntity || pk.ActionType == InteractActionLeaveVehicle {
		io.Vec3(&pk.Position)
	}
}
