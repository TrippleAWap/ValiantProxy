package packet

import (
	"ValiantProxy/gophertunnel/minecraft/protocol"
)

// TakeItemActor is sent by the server when a player picks up an item entity. It makes the item entity
// disappear to viewers and shows the pick-up animation.
type TakeItemActor struct {
	// ItemEntityRuntimeID is the entity runtime ID of the item that is being taken by another entity. It will
	// disappear to viewers after showing the pick-up animation.
	ItemEntityRuntimeID uint64
	// TakerEntityRuntimeID is the runtime ID of the entity that took the item, which is usually a player, but
	// could be another entity like a zombie too.
	TakerEntityRuntimeID uint64
}

// ID ...
func (*TakeItemActor) ID() uint32 {
	return IDTakeItemActor
}

func (pk *TakeItemActor) Marshal(io protocol.IO) {
	io.Varuint64(&pk.ItemEntityRuntimeID)
	io.Varuint64(&pk.TakerEntityRuntimeID)
}
