package packet

import "ValiantProxy/gophertunnel/minecraft/protocol"

const (
	CameraShakeTypePositional uint8 = iota
	CameraShakeTypeRotational
)

const (
	CameraShakeActionAdd = iota
	CameraShakeActionStop
)

// CameraShake is sent by the server to make the camera shake client-side. This feature was added for map-
// making partners.
type CameraShake struct {
	// Intensity is the intensity of the shaking. The client limits this value to 4, so anything higher may
	// not work.
	Intensity float32
	// Duration is the number of seconds the camera will shake for.
	Duration float32
	// Type is the type of shake, and is one of the constants listed above. The different type affects how
	// the shake looks in game.
	Type uint8
	// Action is the action to be performed, and is one of the constants listed above. Currently the
	// different actions will either add or stop shaking the client.
	Action uint8
}

// ID ...
func (*CameraShake) ID() uint32 {
	return IDCameraShake
}

func (pk *CameraShake) Marshal(io protocol.IO) {
	io.Float32(&pk.Intensity)
	io.Float32(&pk.Duration)
	io.Uint8(&pk.Type)
	io.Uint8(&pk.Action)
}
