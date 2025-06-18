package main

import (
	"ValiantProxy/gophertunnel/minecraft/protocol/login"
	"ValiantProxy/gophertunnel/minecraft/protocol/packet"
	"ValiantProxy/gophertunnel/minecraft/text"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var buf = bytes.NewBuffer(make([]byte, 0, 1024*1024*3)) // 3MB buffer

// exemptedResourcePack is a resource pack that is exempted from being downloaded. These packs may be directly
// applied by sending them in the ResourcePackStack packet.
type exemptedResourcePack struct {
	uuid    string
	version string
}

// exemptedPacks is a list of all resource packs that do not need to be downloaded, but may always be applied
// in the ResourcePackStack packet.
var exemptedPacks = []exemptedResourcePack{
	{
		uuid:    "0fba4063-dba1-4281-9b89-ff9390653530",
		version: "1.0.0",
	},
}

// Conn represents a Minecraft (Bedrock Edition) connection over a specific net.Conn transport layer. Its
// methods (Read, Write etc.) are safe to be called from multiple goroutines simultaneously, but ReadPacket
// must not be called on multiple goroutines simultaneously.
type Conn struct {
	// once is used to ensure the Conn is closed only a single time. It protects the channel below from being
	// closed multiple times.
	once       sync.Once
	ctx        context.Context
	cancelFunc context.CancelCauseFunc

	conn        net.Conn
	log         *slog.Logger
	authEnabled bool

	proto         Protocol
	acceptedProto []Protocol
	pool          packet.Pool
	enc           *packet.Encoder
	dec           *packet.Decoder
	compression   packet.Compression
	readerLimits  bool

	disconnectOnUnknownPacket bool
	disconnectOnInvalidPacket bool

	identityData login.IdentityData
	clientData   login.ClientData

	privateKey *ecdsa.PrivateKey
	salt       []byte

	// packets is a channel of byte slices containing serialised packets that are coming in from the other
	// side of the connection.
	packets chan *packetData

	deferredPacketMu sync.Mutex
	// deferredPackets is a list of packets that were pushed back during the login sequence because they
	// were not used by the connection yet. These packets are read the first when calling to Read or
	// ReadPacket after being connected.
	deferredPackets []*packetData
	readDeadline    <-chan time.Time

	sendMu sync.Mutex
	// bufferedSend is a slice of byte slices containing packets that are 'written'. They are buffered until
	// they are sent each 20th of a second.
	bufferedSend [][]byte
	hdr          *packet.Header

	loggedIn bool

	shieldID atomic.Int32

	additional  chan packet.Packet
	expectedIDs atomic.Value
}

// newConn creates a new Minecraft connection for the net.Conn passed, reading and writing compressed
// Minecraft packets to that net.Conn.
// newConn accepts a private key which will be used to identify the connection. If a nil key is passed, the
// key is generated.
func newConn(netConn net.Conn, key *ecdsa.PrivateKey, proto Protocol, flushRate time.Duration, limits bool) *Conn {
	conn := &Conn{
		enc:          packet.NewEncoder(netConn),
		dec:          packet.NewDecoder(netConn),
		salt:         make([]byte, 16),
		packets:      make(chan *packetData, 8),
		additional:   make(chan packet.Packet, 16),
		conn:         netConn,
		privateKey:   key,
		hdr:          &packet.Header{},
		proto:        proto,
		readerLimits: limits,
	}

	if c, ok := netConn.(interface{ Context() context.Context }); ok {
		conn.ctx, conn.cancelFunc = context.WithCancelCause(c.Context())
	} else {
		conn.ctx, conn.cancelFunc = context.WithCancelCause(context.Background())
	}

	conn.expectedIDs.Store([]uint32{packet.IDRequestNetworkSettings})

	if !limits {
		conn.dec.DisableBatchPacketLimit()
	}
	_, _ = rand.Read(conn.salt)

	if flushRate <= 0 {
		return conn
	}
	go func() {
		ticker := time.NewTicker(flushRate)
		defer ticker.Stop()
		for range ticker.C {
			if err := conn.Flush(); err != nil {
				_ = conn.close(err)
				return
			}
		}
	}()
	return conn
}

// IdentityData returns the identity data of the connection. It holds the UUID, XUID and username of the
// connected client.
func (conn *Conn) IdentityData() login.IdentityData {
	return conn.identityData
}

// ClientData returns the client data the client connected with. Note that this client data may be changed
// during the session, so the data should only be used directly after connection, and should be updated after
// that by the caller.
func (conn *Conn) ClientData() login.ClientData {
	return conn.clientData
}

// Authenticated returns true if the connection was authenticated through XBOX Live services.
func (conn *Conn) Authenticated() bool {
	return conn.IdentityData().XUID != ""
}

// WritePacket encodes the packet passed and writes it to the Conn. The encoded data is buffered until the
// next 20th of a second, after which the data is flushed and sent over the connection.
func (conn *Conn) WritePacket(pk packet.Packet) error {
	select {
	case <-conn.ctx.Done():
		return conn.closeErr("write packet")
	default:
	}
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()

	defer func() {
		buf.Reset()
	}()

	conn.hdr.PacketID = pk.ID()
	_ = conn.hdr.Write(buf)

	pk.Marshal(conn.proto.NewWriter(buf, conn.shieldID.Load()))

	conn.bufferedSend = append(conn.bufferedSend, append([]byte(nil), buf.Bytes()...))
	return nil
}

// ReadPacket reads a packet from the Conn, depending on the packet ID that is found in front of the packet
// data. If a read deadline is set, an error is returned if the deadline is reached before any packet is
// received. ReadPacket must not be called on multiple goroutines simultaneously.
//
// If the packet read was not implemented, a *packet.Unknown is returned, containing the raw payload of the
// packet read.
func (conn *Conn) ReadPacket() (pk packet.Packet, err error) {
	if len(conn.additional) > 0 {
		return <-conn.additional, nil
	}
	if data, ok := conn.takeDeferredPacket(); ok {
		pk, err := data.decode(conn)
		if err != nil {
			conn.log.Error("read packet: " + err.Error())
			return conn.ReadPacket()
		}
		if len(pk) == 0 {
			return conn.ReadPacket()
		}
		for _, additional := range pk[1:] {
			conn.additional <- additional
		}
		return pk[0], nil
	}

	select {
	case <-conn.ctx.Done():
		return nil, conn.closeErr("read packet")
	case <-conn.readDeadline:
		return nil, conn.wrap(context.DeadlineExceeded, "read packet")
	case data := <-conn.packets:
		pk, err := data.decode(conn)
		if err != nil {
			conn.log.Error("read packet: " + err.Error())
			return conn.ReadPacket()
		}
		if len(pk) == 0 {
			return conn.ReadPacket()
		}
		for _, additional := range pk[1:] {
			conn.additional <- additional
		}
		return pk[0], nil
	}
}

// Write writes a slice of serialised packet data to the Conn. The data is buffered until the next 20th of a
// tick, after which it is flushed to the connection. Write returns the amount of bytes written n.
func (conn *Conn) Write(b []byte) (n int, err error) {
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()

	conn.bufferedSend = append(conn.bufferedSend, b)
	return len(b), nil
}

// ReadBytes reads a packet from the connection without decoding it directly.
// For direct reading, consider using ReadPacket() which decodes the packet.
func (conn *Conn) ReadBytes() ([]byte, error) {
	if data, ok := conn.takeDeferredPacket(); ok {
		return data.full, nil
	}
	select {
	case <-conn.ctx.Done():
		return nil, conn.closeErr("read")
	case <-conn.readDeadline:
		return nil, conn.wrap(context.DeadlineExceeded, "read")
	case data := <-conn.packets:
		return data.full, nil
	}
}

// Read reads a packet from the connection into the byte slice passed, provided the byte slice is big enough
// to carry the full packet.
// It is recommended to use ReadPacket() and ReadBytes() rather than Read() in cases where reading is done directly.
func (conn *Conn) Read(b []byte) (n int, err error) {
	if data, ok := conn.takeDeferredPacket(); ok {
		if len(b) < len(data.full) {
			return 0, conn.wrap(errBufferTooSmall, "read")
		}
		return copy(b, data.full), nil
	}
	select {
	case <-conn.ctx.Done():
		return 0, conn.closeErr("read")
	case <-conn.readDeadline:
		return 0, conn.wrap(context.DeadlineExceeded, "read")
	case data := <-conn.packets:
		if len(b) < len(data.full) {
			return 0, conn.wrap(errBufferTooSmall, "read")
		}
		return copy(b, data.full), nil
	}
}

// Flush flushes the packets currently buffered by the connections to the underlying net.Conn, so that they
// are directly sent.
func (conn *Conn) Flush() error {
	select {
	case <-conn.ctx.Done():
		return conn.closeErr("flush")
	default:
	}
	conn.sendMu.Lock()
	defer conn.sendMu.Unlock()

	if len(conn.bufferedSend) > 0 {
		if err := conn.enc.Encode(conn.bufferedSend); err != nil && !errors.Is(err, net.ErrClosed) {
			// Should never happen.
			panic(fmt.Errorf("error encoding packet batch: %w", err))
		}
		// First manually clear out conn.bufferedSend so that re-using the slice after resetting its length to
		// 0 doesn't result in an 'invisible' memory leak.
		for i := range conn.bufferedSend {
			conn.bufferedSend[i] = nil
		}
		// Slice the conn.bufferedSend to a length of 0 so we don't have to re-allocate space in this slice
		// every time.
		conn.bufferedSend = conn.bufferedSend[:0]
	}
	return nil
}

// Close closes the Conn and its underlying connection. Before closing, it also calls Flush() so that any
// packets currently pending are sent out.
func (conn *Conn) Close() error {
	return conn.close(net.ErrClosed)
}

// LocalAddr returns the local address of the underlying connection.
func (conn *Conn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}

// RemoteAddr returns the remote address of the underlying connection.
func (conn *Conn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadline of the connection. It is equivalent to calling SetReadDeadline
// and SetWriteDeadline at the same time.
func (conn *Conn) SetDeadline(t time.Time) error {
	return conn.SetReadDeadline(t)
}

// SetReadDeadline sets the read deadline of the Conn to the time passed. The time must be after time.Now().
// Passing an empty time.Time to the method (time.Time{}) results in the read deadline being cleared.
func (conn *Conn) SetReadDeadline(t time.Time) error {
	empty := time.Time{}
	if t == empty {
		conn.readDeadline = make(chan time.Time)
	} else if t.Before(time.Now()) {
		panic(fmt.Errorf("error setting read deadline: time passed is before time.Now()"))
	} else {
		conn.readDeadline = time.After(time.Until(t))
	}
	return nil
}

// SetWriteDeadline is a stub function to implement net.Conn. It has no functionality.
func (conn *Conn) SetWriteDeadline(time.Time) error {
	return nil
}

// Latency returns a rolling average of latency between the sending and the receiving end of the connection.
// The latency returned is updated continuously and is half the round trip time (RTT).
func (conn *Conn) Latency() time.Duration {
	if c, ok := conn.conn.(interface {
		Latency() time.Duration
	}); ok {
		return c.Latency()
	}
	panic(fmt.Sprintf("connection type %T has no Latency() time.Duration method", conn.conn))
}

// Context returns the connection's context. The context is canceled when the connection is closed,
// allowing for cancellation of operations that are tied to the lifecycle of the connection.
func (conn *Conn) Context() context.Context {
	return conn.ctx
}

// takeDeferredPacket locks the deferred packets lock and takes the next packet from the list of deferred
// packets. If none was found, it returns false, and if one was found, the data and true is returned.
func (conn *Conn) takeDeferredPacket() (*packetData, bool) {
	conn.deferredPacketMu.Lock()
	defer conn.deferredPacketMu.Unlock()

	if len(conn.deferredPackets) == 0 {
		return nil, false
	}
	data := conn.deferredPackets[0]
	// Explicitly clear out the packet at offset 0. When we slice it to remove the first element, that element
	// will not be garbage collectable, because the array it's in is still referenced by the slice. Doing this
	// makes sure garbage collecting the packet is possible.
	conn.deferredPackets[0] = nil
	conn.deferredPackets = conn.deferredPackets[1:]
	return data, true
}

// deferPacket defers a packet so that it is obtained in the next ReadPacket call
func (conn *Conn) deferPacket(pk *packetData) {
	conn.deferredPacketMu.Lock()
	conn.deferredPackets = append(conn.deferredPackets, pk)
	conn.deferredPacketMu.Unlock()
}

// receive receives an incoming serialised packet from the underlying connection. If the connection is not yet
// logged in, the packet is immediately handled.
func (conn *Conn) receive(data []byte) error {
	pkData, err := parseData(data)
	if err != nil {
		return err
	}
	return conn.handle(pkData)
}

// handle tries to handle the incoming packetData.
func (conn *Conn) handle(pkData *packetData) error {
	for _, id := range conn.expectedIDs.Load().([]uint32) {
		if id == pkData.h.PacketID {
			pks, err := pkData.decode(conn)
			if err != nil {
				return err
			}
			return conn.handleMultiple(pks)
		}
	}
	return nil
}

// handleMultiple handles multiple packets and returns an error if at least one of those packets could not be handled
// successfully.
func (conn *Conn) handleMultiple(pks []packet.Packet) error {
	var err error
	for _, pk := range pks {
		if e := conn.handlePacket(pk); e != nil {
			err = fmt.Errorf("handle %T: %w", pk, e)
			break
		}
	}
	return err
}

// handlePacket handles an incoming packet. It returns an error if any of the data found in the packet was not
// valid or if handling failed for any other reason.
func (conn *Conn) handlePacket(pk packet.Packet) error {
	defer func() {
		_ = conn.Flush()
	}()
	fmt.Printf("\t%T\n", pk)
	switch pk := pk.(type) {
	// Internal packets destined for the server.
	case *packet.RequestNetworkSettings:
		return conn.handleRequestNetworkSettings(pk)
	case *packet.Login:
		return conn.handleLogin(pk)

	case *packet.NetworkSettings:
		return conn.handleNetworkSettings(pk)
	case *packet.ServerToClientHandshake:
		return conn.handleServerToClientHandshake(pk)
	}
	return nil
}

// handleRequestNetworkSettings handles an incoming RequestNetworkSettings packet. It returns an error if the protocol
// version is not supported, otherwise sending back a NetworkSettings packet.
func (conn *Conn) handleRequestNetworkSettings(pk *packet.RequestNetworkSettings) error {
	conn.expect(packet.IDLogin)
	if err := conn.WritePacket(&packet.NetworkSettings{
		CompressionThreshold: 512,
		CompressionAlgorithm: conn.compression.EncodeCompression(),
	}); err != nil {
		return fmt.Errorf("send NetworkSettings: %w", err)
	}
	_ = conn.Flush()
	conn.enc.EnableCompression(conn.compression)
	conn.dec.EnableCompression()
	return nil
}

// handleNetworkSettings handles an incoming NetworkSettings packet, enabling compression for future packets.
func (conn *Conn) handleNetworkSettings(pk *packet.NetworkSettings) error {
	alg, ok := packet.CompressionByID(pk.CompressionAlgorithm)
	if !ok {
		return fmt.Errorf("unknown compression algorithm %v", pk.CompressionAlgorithm)
	}
	conn.enc.EnableCompression(alg)
	conn.dec.EnableCompression()
	return nil
}

// handleLogin handles an incoming login packet. It verifies and decodes the login request found in the packet
// and returns an error if it couldn't be done successfully.
func (conn *Conn) handleLogin(pk *packet.Login) error {
	// The next expected packet is a response from the client to the handshake.
	conn.expect(packet.IDClientToServerHandshake)
	var (
		err        error
		authResult login.AuthResult
	)
	conn.identityData, conn.clientData, authResult, err = login.Parse(pk.ConnectionRequest)
	if err != nil {
		return fmt.Errorf("parse login request: %w", err)
	}

	// Make sure the player is logged in with XBOX Live when necessary.
	if !authResult.XBOXLiveAuthenticated && conn.authEnabled {
		_ = conn.WritePacket(&packet.Disconnect{Message: text.Colourf("<red>You must be logged in with XBOX Live to join.</red>")})
		return fmt.Errorf("client was not authenticated to XBOX Live")
	}
	if err := conn.enableEncryption(authResult.PublicKey); err != nil {
		return fmt.Errorf("enable encryption: %w", err)
	}
	return nil
}

// handleServerToClientHandshake handles an incoming ServerToClientHandshake packet. It initialises encryption
// on the client side of the connection, using the hash and the public key from the server exposed in the
// packet.
func (conn *Conn) handleServerToClientHandshake(pk *packet.ServerToClientHandshake) error {
	tok, err := jwt.ParseSigned(string(pk.JWT), []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return fmt.Errorf("parse server token: %w", err)
	}
	//lint:ignore S1005 Double assignment is done explicitly to prevent panics.
	raw, _ := tok.Headers[0].ExtraHeaders["x5u"]
	kStr, _ := raw.(string)

	pub := new(ecdsa.PublicKey)
	if err := login.ParsePublicKey(kStr, pub); err != nil {
		return fmt.Errorf("parse server public key: %w", err)
	}

	var c saltClaims
	if err := tok.Claims(pub, &c); err != nil {
		return fmt.Errorf("verify claims: %w", err)
	}
	c.Salt = strings.TrimRight(c.Salt, "=")
	salt, err := base64.RawStdEncoding.DecodeString(c.Salt)
	if err != nil {
		return fmt.Errorf("decode ServerToClientHandshake salt: %w", err)
	}

	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, conn.privateKey.D.Bytes())
	// Make sure to pad the shared secret up to 96 bytes.
	sharedSecret := append(bytes.Repeat([]byte{0}, 48-len(x.Bytes())), x.Bytes()...)

	keyBytes := sha256.Sum256(append(salt, sharedSecret...))

	// Finally we enable encryption for the enc and dec using the secret pubKey bytes we produced.
	conn.enc.EnableEncryption(keyBytes)
	conn.dec.EnableEncryption(keyBytes)

	// We write a ClientToServerHandshake packet (which has no payload) as a response.
	_ = conn.WritePacket(&packet.ClientToServerHandshake{})
	return nil
}

// enableEncryption enables encryption on the server side over the connection. It sends an unencrypted
// handshake packet to the client and enables encryption after that.
func (conn *Conn) enableEncryption(clientPublicKey *ecdsa.PublicKey) error {
	signer, _ := jose.NewSigner(jose.SigningKey{Key: conn.privateKey, Algorithm: jose.ES384}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"x5u": login.MarshalPublicKey(&conn.privateKey.PublicKey)},
	})
	// We produce an encoded JWT using the header and payload above, then we send the JWT in a ServerToClient-
	// Handshake packet so that the client can initialise encryption.
	serverJWT, err := jwt.Signed(signer).Claims(saltClaims{Salt: base64.RawStdEncoding.EncodeToString(conn.salt)}).Serialize()
	if err != nil {
		return fmt.Errorf("compact serialise server JWT: %w", err)
	}
	if err := conn.WritePacket(&packet.ServerToClientHandshake{JWT: []byte(serverJWT)}); err != nil {
		return fmt.Errorf("send ServerToClientHandshake: %w", err)
	}
	// Flush immediately as we'll enable encryption after this.
	_ = conn.Flush()

	// We first compute the shared secret.
	x, _ := clientPublicKey.Curve.ScalarMult(clientPublicKey.X, clientPublicKey.Y, conn.privateKey.D.Bytes())

	sharedSecret := append(bytes.Repeat([]byte{0}, 48-len(x.Bytes())), x.Bytes()...)

	keyBytes := sha256.Sum256(append(conn.salt, sharedSecret...))

	// Finally we enable encryption for the encoder and decoder using the secret key bytes we produced.
	conn.enc.EnableEncryption(keyBytes)
	conn.dec.EnableEncryption(keyBytes)

	return nil
}

// expect sets the packet IDs that are next expected to arrive.
func (conn *Conn) expect(packetIDs ...uint32) {
	conn.expectedIDs.Store(packetIDs)
}

func (conn *Conn) close(cause error) error {
	var err error
	conn.once.Do(func() {
		err = conn.Flush()
		conn.cancelFunc(cause)
		_ = conn.conn.Close()
	})
	return err
}

// closeErr returns an adequate connection closed error for the op passed. If the connection was closed
// through a Disconnect packet, the message is contained.
func (conn *Conn) closeErr(op string) error {
	select {
	case <-conn.ctx.Done():
		return conn.wrap(context.Cause(conn.ctx), op)
	default:
		return conn.wrap(net.ErrClosed, op)
	}
}

var errBufferTooSmall = errors.New("a message sent was larger than the buffer used to receive the message into")

// wrap wraps the error passed into a net.OpError with the op as operation and returns it, or nil if the error
// passed is nil.
func (conn *Conn) wrap(err error, op string) error {
	if err == nil {
		return nil
	}
	return &net.OpError{
		Op:     op,
		Net:    "minecraft",
		Source: conn.LocalAddr(),
		Addr:   conn.RemoteAddr(),
		Err:    err,
	}
}

// DisconnectError is an error returned by operations from Conn when the connection is closed by the other
// end through a packet.Disconnect. It is wrapped in a net.OpError and may be obtained using
// errors.Unwrap(net.OpError).
type DisconnectError string

// Error returns the message held in the packet.Disconnect.
func (d DisconnectError) Error() string {
	return string(d)
}
