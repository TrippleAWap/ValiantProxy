package minecraft

import (
	"ValiantProxy/gophertunnel/minecraft/internal"
	"ValiantProxy/gophertunnel/minecraft/protocol"
	"ValiantProxy/gophertunnel/minecraft/protocol/packet"
	"ValiantProxy/gophertunnel/minecraft/resource"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// ListenConfig holds settings that may be edited to change behaviour of a Listener.
type ListenConfig struct {
	// ErrorLog is a log.Logger that errors that occur during packet handling of
	// clients are written to. By default, errors are not logged.
	ErrorLog *slog.Logger

	// AuthenticationDisabled specifies if authentication of players that join is disabled. If set to true, no
	// verification will be done to ensure that the player connecting is authenticated using their XBOX Live
	// account.
	AuthenticationDisabled bool

	// MaximumPlayers is the maximum amount of players accepted in the server. If non-zero, players that
	// attempt to join while the server is full will be kicked during login. If zero, the maximum player count
	// will be dynamically updated each time a player joins, so that an unlimited amount of players is
	// accepted into the server.
	MaximumPlayers int

	// AllowUnknownPackets specifies if connections of this Listener are allowed to send packets not present
	// in the packet pool. If false (by default), such packets lead to the connection being closed immediately.
	// If set to true, the packets will be returned as a packet.Unknown.
	AllowUnknownPackets bool

	// AllowInvalidPackets specifies if invalid packets (either too few bytes or too many bytes) should be
	// allowed. If false (by default), such packets lead to the connection being closed immediately. If true,
	// packets with too many bytes will be returned while packets with too few bytes will be skipped.
	AllowInvalidPackets bool

	// StatusProvider is the ServerStatusProvider of the Listener. When set to nil, the default provider,
	// ListenerStatusProvider, is used as provider.
	StatusProvider ServerStatusProvider

	// AcceptedProtocols is a slice of Protocol accepted by a Listener created with this ListenConfig. The current
	// Protocol is always added to this slice. Clients with a protocol version that is not present in this slice will
	// be disconnected.
	AcceptedProtocols []Protocol
	// Compression is the packet.Compression to use for packets sent over this Conn. If set to nil, the compression
	// will default to packet.flateCompression.
	Compression packet.Compression // TODO: Change this to snappy once Windows crashes are resolved.
	// FlushRate is the rate at which packets sent are flushed. Packets are buffered for a duration up to
	// FlushRate and are compressed/encrypted together to improve compression ratios. The lower this
	// time.Duration, the lower the latency but the less efficient both network and cpu wise.
	// The default FlushRate (when set to 0) is time.Second/20. If FlushRate is set negative, packets
	// will not be flushed automatically. In this case, calling `(*Conn).Flush()` is required after any
	// calls to `(*Conn).Write()` or `(*Conn).WritePacket()` to send the packets over network.
	FlushRate time.Duration

	// ResourcePacks is a slice of resource packs that the listener may hold. Each client will be asked to
	// download these resource packs upon joining.
	// Use Listener.AddResourcePack() to add a resource pack and Listener.RemoveResourcePack() to remove a resource pack
	// after having called ListenConfig.Listen(). Note that these methods will not update resource packs for active connections.
	ResourcePacks []*resource.Pack
	// TexturePacksRequired specifies if clients that join must accept the texture pack in order for them to
	// be able to join the server. If they don't accept, they can only leave the server.
	TexturePacksRequired bool

	// PacketFunc is called whenever a packet is read from or written to a connection returned when using
	// Listener.Accept. It includes packets that are otherwise covered in the connection sequence, such as the
	// Login packet. The function is called with the header of the packet and its raw payload, the address
	// from which the packet originated, and the destination address.
	PacketFunc func(header packet.Header, payload []byte, src, dst net.Addr)
}

// Listener implements a Minecraft listener on top of an unspecific net.Listener. It abstracts away the
// login sequence of connecting clients and provides the implements the net.Listener interface to provide a
// consistent API.
type Listener struct {
	cfg      ListenConfig
	listener NetworkListener

	packs   []*resource.Pack
	packsMu sync.RWMutex

	// playerCount is the amount of players connected to the server. If MaximumPlayers is non-zero and equal
	// to the playerCount, no more players will be accepted.
	playerCount atomic.Int32

	incoming chan *Conn
	close    chan struct{}

	key *ecdsa.PrivateKey
}

// Listen announces on the local network address. The network is typically "raknet".
// If the host in the address parameter is empty or a literal unspecified IP address, Listen listens on all
// available unicast and anycast IP addresses of the local system.
func (cfg ListenConfig) Listen(network string, address string) (*Listener, error) {
	if cfg.ErrorLog == nil {
		cfg.ErrorLog = slog.New(internal.DiscardHandler{})
	}
	cfg.ErrorLog = cfg.ErrorLog.With("src", "listener")
	if cfg.StatusProvider == nil {
		cfg.StatusProvider = NewStatusProvider("Minecraft Server", "Gophertunnel")
	}
	if cfg.Compression == nil {
		cfg.Compression = packet.DefaultCompression
	}
	if cfg.FlushRate == 0 {
		cfg.FlushRate = time.Second / 20
	}

	n, ok := networkByID(network, cfg.ErrorLog)
	if !ok {
		return nil, fmt.Errorf("listen: no network under id %v", network)
	}

	netListener, err := n.Listen(address)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA key: %w", err)
	}
	listener := &Listener{
		cfg:      cfg,
		listener: netListener,
		packs:    slices.Clone(cfg.ResourcePacks),
		incoming: make(chan *Conn),
		close:    make(chan struct{}),
		key:      key,
	}

	// Actually start listening.
	go listener.listen()
	return listener, nil
}

// Listen announces on the local network address. The network must be "tcp", "tcp4", "tcp6", "unix",
// "unixpacket" or "raknet". A Listener is returned which may be used to accept connections.
// If the host in the address parameter is empty or a literal unspecified IP address, Listen listens on all
// available unicast and anycast IP addresses of the local system.
// Listen has the default values for the fields of Listener filled out. To use different values for these
// fields, call &Listener{}.Listen() instead.
func Listen(network, address string) (*Listener, error) {
	var lc ListenConfig
	return lc.Listen(network, address)
}

// Accept accepts a fully connected (on Minecraft layer) connection which is ready to receive and send
// packets. It is recommended to cast the net.Conn returned to a *minecraft.Conn so that it is possible to
// use the Conn.ReadPacket() and Conn.WritePacket() methods.
// Accept returns an error if the listener is closed.
func (listener *Listener) Accept() (net.Conn, error) {
	conn, ok := <-listener.incoming
	if !ok {
		return nil, &net.OpError{Op: "accept", Net: "minecraft", Addr: listener.Addr(), Err: net.ErrClosed}
	}
	return conn, nil
}

// Disconnect disconnects a Minecraft Conn passed by first sending a disconnect with the message passed, and
// closing the connection after. If the message passed is empty, the client will be immediately sent to the
// server list instead of a disconnect screen.
func (listener *Listener) Disconnect(conn *Conn, message string) error {
	_ = conn.WritePacket(&packet.Disconnect{
		HideDisconnectionScreen: message == "",
		Message:                 message,
	})
	return conn.close(conn.closeErr(message))
}

// AddResourcePack adds a new resource pack to the listener's resource packs.
// Note: This method will not update resource packs for active connections.
func (listener *Listener) AddResourcePack(pack *resource.Pack) {
	listener.packsMu.Lock()
	defer listener.packsMu.Unlock()
	listener.packs = append(listener.packs, pack)
}

// RemoveResourcePack removes a resource pack from the listener's configuration by its UUID.
// Note: This method will not update resource packs for active connections.
func (listener *Listener) RemoveResourcePack(uuid string) {
	listener.packsMu.Lock()
	listener.packs = slices.DeleteFunc(listener.packs, func(pack *resource.Pack) bool {
		return pack.UUID().String() == uuid
	})
	listener.packsMu.Unlock()
}

// Addr returns the address of the underlying listener.
func (listener *Listener) Addr() net.Addr {
	return listener.listener.Addr()
}

// Close closes the listener and the underlying net.Listener. Pending calls to Accept will fail immediately.
func (listener *Listener) Close() error {
	return listener.listener.Close()
}

// updatePongData updates the pong data of the listener using the current only players, maximum players and
// server name of the listener, provided the listener isn't currently hijacking the pong of another server.
func (listener *Listener) updatePongData() {
	s := listener.status()
	listener.listener.PongData([]byte(fmt.Sprintf("MCPE;%v;%v;%v;%v;%v;%v;%v;%v;%v;%v;%v;%v;",
		s.ServerName, protocol.CurrentProtocol, protocol.CurrentVersion, s.PlayerCount, s.MaxPlayers,
		listener.listener.ID(), s.ServerSubName, "Creative", 1, listener.Addr().(*net.UDPAddr).Port, listener.Addr().(*net.UDPAddr).Port, 0,
	)))
}

// listen starts listening for incoming connections and packets. When a player is fully connected, it submits
// it to the accepted connections channel so that a call to Accept can pick it up.
func (listener *Listener) listen() {
	listener.updatePongData()
	go func() {
		ticker := time.NewTicker(time.Second * 4)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				listener.updatePongData()
			case <-listener.close:
				return
			}
		}
	}()
	defer func() {
		close(listener.close)
		close(listener.incoming)
		_ = listener.Close()
	}()
	for {
		netConn, err := listener.listener.Accept()
		if err != nil {
			// The underlying listener was closed, meaning we should return immediately so this listener can
			// close too.
			return
		}
		listener.createConn(netConn)
	}
}

// createConn creates a connection for the net.Conn passed and adds it to the listener, so that it may be
// accepted once its login sequence is complete.
func (listener *Listener) createConn(netConn net.Conn) {
	listener.packsMu.RLock()
	packs := slices.Clone(listener.packs)
	listener.packsMu.RUnlock()

	conn := newConn(netConn, listener.key, listener.cfg.ErrorLog, proto{}, listener.cfg.FlushRate, true)
	conn.acceptedProto = append(listener.cfg.AcceptedProtocols, proto{})
	conn.compression = listener.cfg.Compression
	conn.pool = conn.proto.Packets(true)

	conn.packetFunc = listener.cfg.PacketFunc
	conn.texturePacksRequired = listener.cfg.TexturePacksRequired
	conn.resourcePacks = packs
	conn.gameData.WorldName = listener.status().ServerName
	conn.authEnabled = !listener.cfg.AuthenticationDisabled
	conn.disconnectOnUnknownPacket = !listener.cfg.AllowUnknownPackets
	conn.disconnectOnInvalidPacket = !listener.cfg.AllowInvalidPackets

	if listener.playerCount.Load() == int32(listener.cfg.MaximumPlayers) && listener.cfg.MaximumPlayers != 0 {
		// The server was full. We kick the player immediately and close the connection.
		_ = conn.WritePacket(&packet.PlayStatus{Status: packet.PlayStatusLoginFailedServerFull})
		_ = conn.close(conn.closeErr("server full"))
		return
	}
	listener.playerCount.Add(1)
	listener.updatePongData()

	go listener.handleConn(conn)
}

// status returns the current ServerStatus of the Listener.
func (listener *Listener) status() ServerStatus {
	status := listener.cfg.StatusProvider.ServerStatus(int(listener.playerCount.Load()), listener.cfg.MaximumPlayers)
	if status.MaxPlayers == 0 {
		status.MaxPlayers = status.PlayerCount + 1
	}
	return status
}

// handleConn handles an incoming connection of the Listener. It will first attempt to get the connection to
// log in, after which it will expose packets received to the user.
func (listener *Listener) handleConn(conn *Conn) {
	defer func() {
		_ = conn.Close()
		listener.playerCount.Add(-1)
		listener.updatePongData()
	}()
	for {
		// We finally arrived at the packet decoding loop. We constantly decode packets that arrive
		// and push them to the Conn so that they may be processed.
		packets, err := conn.dec.Decode()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				conn.log.Error(err.Error())
			}
			return
		}
		for _, data := range packets {
			loggedInBefore := conn.loggedIn
			if err := conn.receive(data); err != nil {
				conn.log.Error(err.Error())
				return
			}
			if !loggedInBefore && conn.loggedIn {
				select {
				case <-listener.close:
					// The listener was closed while this one was logged in, so the incoming channel will be
					// closed. Just return so the connection is closed and cleaned up.
					return
				case listener.incoming <- conn:
					// The connection was previously not logged in, but was after receiving this packet,
					// meaning the connection is fully completely now. We add it to the channel so that
					// a call to Accept() can receive it.
				}
			}
		}
	}
}
