package packet

import (
	"ValiantProxy/gophertunnel/minecraft/protocol"

	"github.com/google/uuid"
)

// ResourcePacksInfo is sent by the server to inform the client on what resource packs the server has. It
// sends a list of the resource packs it has and basic information on them like the version and description.
type ResourcePacksInfo struct {
	// TexturePackRequired specifies if the client must accept the texture packs the server has in order to
	// join the server. If set to true, the client gets the option to either download the resource packs and
	// join, or quit entirely. Behaviour packs never have to be downloaded.
	TexturePackRequired bool
	// HasAddons specifies if any of the resource packs contain addons in them. If set to true, only clients
	// that support addons will be able to download them.
	HasAddons bool
	// HasScripts specifies if any of the resource packs contain scripts in them. If set to true, only clients
	// that support scripts will be able to download them.
	HasScripts bool
	// ForceDisableVibrantVisuals specifies if the vibrant visuals feature should be forcibly disabled on the server.
	// If set to true, the server will ensure that vibrant visuals are not enabled, regardless of the client's settings.
	ForceDisableVibrantVisuals bool
	// WorldTemplateUUID is the UUID of the template that has been used to generate the world. Templates can
	// be downloaded from the marketplace or installed via '.mctemplate' files. If the world was not generated
	// from a template, this field is empty.
	WorldTemplateUUID uuid.UUID
	// WorldTemplateVersion is the version of the world template that has been used to generate the world. If
	// the world was not generated from a template, this field is empty.
	WorldTemplateVersion string
	// TexturePacks is a list of texture packs that the client needs to download before joining the server.
	// The order of these texture packs is not relevant in this packet. It is however important in the
	// ResourcePackStack packet.
	TexturePacks []protocol.TexturePackInfo
}

// ID ...
func (*ResourcePacksInfo) ID() uint32 {
	return IDResourcePacksInfo
}

func (pk *ResourcePacksInfo) Marshal(io protocol.IO) {
	io.Bool(&pk.TexturePackRequired)
	io.Bool(&pk.HasAddons)
	io.Bool(&pk.HasScripts)
	io.Bool(&pk.ForceDisableVibrantVisuals)
	io.UUID(&pk.WorldTemplateUUID)
	io.String(&pk.WorldTemplateVersion)
	protocol.SliceUint16Length(io, &pk.TexturePacks)
}
