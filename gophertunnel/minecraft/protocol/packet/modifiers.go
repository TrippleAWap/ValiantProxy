package packet

import (
	"bytes"
	"fmt"

	"ValiantProxy/gophertunnel/minecraft/protocol"
)

func (decoder *Decoder) DecodeData(data []byte) (packets [][]byte, err error) {
	if len(data) == 0 {
		return nil, nil
	}
	if data[0] != header {
		return nil, fmt.Errorf("decode batch: invalid header %x, expected %x", data[0], header)
	}
	data = data[1:]
	if decoder.encrypt != nil {
		decoder.encrypt.decrypt(data)
		if err := decoder.encrypt.verify(data); err != nil {
			// The packet did not have a correct checksum.
			return nil, fmt.Errorf("verify batch: %w", err)
		}
		data = data[:len(data)-8]
	}

	if decoder.decompress {
		if data[0] == 0xff {
			data = data[1:]
		} else {
			compression, ok := CompressionByID(uint16(data[0]))
			if !ok {
				return nil, fmt.Errorf("decompress batch: unknown compression algorithm %v", data[0])
			}
			data, err = compression.Decompress(data[1:])
			if err != nil {
				return nil, fmt.Errorf("decompress batch: %w", err)
			}
		}
	}

	b := bytes.NewBuffer(data)
	for b.Len() != 0 {
		var length uint32
		if err := protocol.Varuint32(b, &length); err != nil {
			return nil, fmt.Errorf("decode batch: read packet length: %w", err)
		}
		packets = append(packets, b.Next(int(length)))
	}
	if len(packets) > maximumInBatch && decoder.checkPacketLimit {
		return nil, fmt.Errorf("decode batch: number of packets %v exceeds max=%v", len(packets), maximumInBatch)
	}
	return packets, nil
}
