package minecraft

import (
	"ValiantProxy/gophertunnel/minecraft/protocol/packet"
	"bytes"
	"fmt"
)

func ParseData(data []byte) (*packetData, error) {
	buf := bytes.NewBuffer(data)
	header := &packet.Header{}
	if err := header.Read(buf); err != nil {
		// We don't return this as an error as it's not in the hand of the user to control this. Instead,
		// we return to reading a new packet.
		return nil, fmt.Errorf("read packet header: %w", err)
	}
	return &packetData{h: header, full: data, payload: buf}, nil
}

func (p *packetData) Header() *packet.Header {
	return p.h
}

func (p *packetData) Full() []byte {
	return p.full
}

func (p *packetData) Payload() *bytes.Buffer {
	return p.payload
}

func (p *packetData) Decode(pool *packet.Pool) (pks packet.Packet, err error) {
	pkFunc, ok := (*pool)[p.h.PacketID]
	var pk packet.Packet
	if !ok {
		pk = &packet.Unknown{PacketID: p.h.PacketID}
	} else {
		pk = pkFunc()
	}

	defer func() {
		if recoveredErr := recover(); recoveredErr != nil {
			err = fmt.Errorf("decode packet %T: %w", pk, recoveredErr.(error))
		}
	}()

	r := DefaultProtocol.NewReader(p.payload, 0, true)
	pk.Marshal(r)
	if p.payload.Len() != 0 {
		err = fmt.Errorf("decode packet %T: %v unread bytes left: 0x%x", pk, p.payload.Len(), p.payload.Bytes())
	}
	return pk, err
}
