package main

import (
	"ValiantProxy/gophertunnel/minecraft/protocol/login"
	"ValiantProxy/gophertunnel/minecraft/protocol/packet"
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"strings"
)

type saltClaims struct {
	Salt string `json:"salt"`
}

func enableEncryption(pk *packet.ServerToClientHandshake, privateKey *ecdsa.PrivateKey) ([32]byte, string, error) {
	var keyBytes [32]byte
	tok, err := jwt.ParseSigned(string(pk.JWT), []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return keyBytes, "", fmt.Errorf("parse server token: %w", err)
	}
	//lint:ignore S1005 Double assignment is done explicitly to prevent panics.
	raw, _ := tok.Headers[0].ExtraHeaders["x5u"]
	kStr, _ := raw.(string)

	pub := new(ecdsa.PublicKey)
	if err := login.ParsePublicKey(kStr, pub); err != nil {
		return keyBytes, "", fmt.Errorf("parse server public key: %w", err)
	}

	var c saltClaims
	if err := tok.Claims(pub, &c); err != nil {
		return keyBytes, "", fmt.Errorf("verify claims: %w", err)
	}
	c.Salt = strings.TrimRight(c.Salt, "=")
	salt, err := base64.RawStdEncoding.DecodeString(c.Salt)
	if err != nil {
		return keyBytes, "", fmt.Errorf("decode ServerToClientHandshake salt: %w", err)
	}

	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, privateKey.D.Bytes())
	// Make sure to pad the shared secret up to 96 bytes.
	sharedSecret := append(bytes.Repeat([]byte{0}, 48-len(x.Bytes())), x.Bytes()...)

	keyBytes = sha256.Sum256(append(salt, sharedSecret...))
	return keyBytes, c.Salt, nil
}

func WritePacket(enc *packet.Encoder, p packet.Packet) error {
	buf := bytes.NewBuffer(make([]byte, 0, 256))
	hdr := packet.Header{
		PacketID: p.ID(),
	}
	if err := hdr.Write(buf); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	return enc.Encode([][]byte{buf.Bytes()})
}
