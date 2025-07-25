package packet

import "ValiantProxy/gophertunnel/minecraft/protocol"

// CreatePhoto is a packet that allows players to export photos from their portfolios into items in their inventory.
// This packet only works on the Education Edition version of Minecraft.
type CreatePhoto struct {
	// EntityUniqueID is the unique ID of the entity.
	EntityUniqueID int64
	// PhotoName is the name of the photo.
	PhotoName string
	// ItemName is the name of the photo as an item.
	ItemName string
}

// ID ...
func (*CreatePhoto) ID() uint32 {
	return IDCreatePhoto
}

func (pk *CreatePhoto) Marshal(io protocol.IO) {
	io.Int64(&pk.EntityUniqueID)
	io.String(&pk.PhotoName)
	io.String(&pk.ItemName)
}
