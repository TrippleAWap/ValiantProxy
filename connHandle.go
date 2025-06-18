package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"ValiantProxy/go-raknet"
	"ValiantProxy/gophertunnel/minecraft"
	"ValiantProxy/gophertunnel/minecraft/protocol/login"
	"ValiantProxy/gophertunnel/minecraft/protocol/packet"
	"ValiantProxy/gophertunnel/minecraft/text"
)

func handleConnection(conn net.Conn) {
	id, ok := connections[conn.RemoteAddr().(*net.UDPAddr).IP.String()]
	if !ok {
		connections[conn.RemoteAddr().(*net.UDPAddr).IP.String()] = 1
		id = 1
	} else {
		id = id + 1
		connections[conn.RemoteAddr().(*net.UDPAddr).IP.String()] = id
	}
	fmt.Printf("Handling connection from %s (connId: %d)\n", conn.RemoteAddr().String(), id)
	defer func() {
		log.Printf("Connection from %s closed (connId: %d)\n", conn.RemoteAddr().String(), id)
		_ = sendMessage(fmt.Sprintf("Connection from %s closed (connId: %d)", conn.RemoteAddr().String(), id))
		connections[conn.RemoteAddr().(*net.UDPAddr).IP.String()]--
		if connections[conn.RemoteAddr().(*net.UDPAddr).IP.String()] == 0 {
			delete(connections, conn.RemoteAddr().(*net.UDPAddr).IP.String())
		}
	}()
	// dial connection to server
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	serverConn, err := raknet.DialContext(ctx, os.Getenv("REMOTE_ADDR"))
	if err != nil {
		fmt.Println(err)
		return
	}

	decode := true
	var stopDecoding sync.Once

	clientDec := packet.NewDecoder(conn)
	serverDec := packet.NewDecoder(serverConn)

	// client->server
	go func() {
		pool := packet.NewClientPool()
		buf := make([]byte, 1024*1024*3)
		maxPacket := len(buf)
		minPackets := 12
		defer func() {
			err := recover()
			if err != nil {
				log.Printf("panic in client decoder:\t%v\n", err)
			}
			_ = conn.Close()
			_ = serverConn.Close()
		}()
		window := NewSlidingWindowRateLimiter(time.Millisecond*200, 50)
		ticker := time.NewTicker(time.Millisecond * 20)
		defer ticker.Stop()
		timeout := time.Second * 5
		lastPacket := time.Now()
		go func() {
			for {
				select {
				case <-ticker.C:
					if time.Since(lastPacket) > timeout {
						log.Printf("No packets sent to server in %s, closing connection %s\n", time.Since(lastPacket), conn.RemoteAddr().String())
						_ = sendMessage(fmt.Sprintf("No packets sent to server in %s, closing connection %s", time.Since(lastPacket), conn.RemoteAddr().String()))
						_ = conn.Close()
						_ = serverConn.Close()
						return
					}
				}
			}
		}()
		for {
			// clone buf;
			lastBuf := make([]byte, len(buf))
			copy(lastBuf, buf)
			n, err := conn.Read(buf)
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") {
					return
				}
				log.Printf("Error reading from connection %s:\t%v\n", conn.RemoteAddr().String(), err)
				return
			}
			if false {
				log.Printf("Read %d bytes from %s\n", n, conn.RemoteAddr().String())
				fmt.Printf("\t[")
				var displayed []string
				for _, byteValue := range buf[:n] {
					displayed = append(displayed, fmt.Sprintf("0x%X", byteValue))
				}
				fmt.Printf("%s]\n", strings.Join(displayed, ","))
			}
			if n < minPackets && !(n == 8 && buf[2] == 0xC1) {
				fmt.Printf("%s:\tpacket too small: %d < %d\n", conn.RemoteAddr().String(), n, minPackets)
				return
			}
			if n > maxPacket {
				fmt.Printf("%s:\tpacket too large: %d > %d\n", conn.RemoteAddr().String(), n, maxPacket)
				return
			}
			if !window.Allow() {
				fmt.Printf("%s:\ttoo many packets: %d > %d\n", conn.RemoteAddr().String(), window.requests.Len(), window.maxRequests)
				return
			}
			lastPacket = time.Now()
			lastBuf = nil
			addPacket(buf[:n])
			if !decode {
				nW, err := serverConn.Write(buf[:n])
				if err != nil {
					if strings.Contains(err.Error(), "use of closed network connection") {
						return
					}
					fmt.Println("\t", err)
					return
				}
				if nW != n {
					fmt.Printf("\tfailed to write all bytes to server, wrote %d bytes expected %d\n", nW, n)
					return
				}
				continue
			}
			packets, err := clientDec.DecodeData(buf[:n])
			if err != nil {
				fmt.Println(err)
				return
			}
			if len(packets) == 0 {
				continue
			}
			for _, packetV := range packets {
				pk, err := minecraft.ParseData(packetV)
				if err != nil {
					fmt.Println(err)
					return
				}
				packetV, err := pk.Decode(&pool)
				if err != nil {
					fmt.Println(err)
					return
				}
				switch pk.Header().PacketID {
				case packet.IDLogin:
					packetVV, ok := packetV.(*packet.Login)
					if !ok {
						fmt.Printf("\tinvalid packet type, expected *packet.Login found %T\n", packetV)
						return
					}
					if checkCode, err := validateLogin(packetVV); err != nil {
						_ = sendMessage(fmt.Sprintf("login check failed:\n    %v:    %v\n    disconnecting %v with check code 0x%X", conn.RemoteAddr().String(), err, conn.RemoteAddr().String(), checkCode))
						log.Printf("login check failed:\n\t%v:\t%v\n", conn.RemoteAddr(), err)
						fmt.Printf("\tdisconnecting %v with check code 0x%X\n", conn.RemoteAddr(), checkCode)
						fmt.Printf("\tblocking connection for %s\n", listener.Conf.BlockDuration)
						listener.Block(conn.RemoteAddr())
						// ts aint working wth.
						clientEnc := packet.NewEncoder(conn)
						if err := WritePacket(clientEnc, &packet.Disconnect{
							Message: text.Colourf("<red>You've been disconnected for failing to log in correctly.</red>\n<aqua>Check code: <bold>%v</aqua></bold>", checkCode),
						}); err != nil {
							fmt.Printf("\t%v\n", err)
							return
						}
						time.Sleep(time.Second)
						return
					}
					identityData, clientData, _, err := login.Parse(packetVV.ConnectionRequest)
					if err != nil {
						fmt.Printf("\tparse login request: %v\n", err)
						return
					}
					log.Printf("login successful from %s\n", conn.RemoteAddr().String())
					fmt.Printf("\tidentity: %s (%s)\n", identityData.DisplayName, identityData.XUID)
					fmt.Printf("\tdevice: %s (%s)\n", clientData.DeviceModel, clientData.DeviceID)
					fmt.Printf("\tpfid: %s\n", clientData.PlayFabID)
					_ = sendMessage(strings.Join([]string{
						fmt.Sprintf("login successful from %s", conn.RemoteAddr().String()),
						fmt.Sprintf("\tidentity: %s (%s)", identityData.DisplayName, identityData.XUID),
						fmt.Sprintf("\tdevice: %s (%s)", clientData.DeviceModel, clientData.DeviceID),
						fmt.Sprintf("\tpfid: %s", clientData.PlayFabID),
					}, "\n"))
					go func() {
						time.Sleep(time.Second * 5)
						timeout = time.Second * 2
					}()
					maxPacket = 1024 * 1024
				}
			}
			nW, err := serverConn.Write(buf[:n])
			if err != nil {
				fmt.Println("\t", err)
				return
			}
			if nW != n {
				fmt.Printf("\tfailed to write all bytes to server, wrote %d bytes expected %d\n", nW, n)
				return
			}
		}
	}()
	// server->client
	buf := make([]byte, 1024*1024*3)
	for {
		n, err := serverConn.Read(buf)
		if err != nil {
			if strings.Contains(err.Error(), " use of closed network connection") {
				return
			}
			log.Printf("Error reading from server connection %s:\t%v\n", conn.RemoteAddr().String(), err)
			return
		}
		if !decode {
			nW, err := conn.Write(buf[:n])
			if err != nil {
				fmt.Println("\t", err)
				return
			}
			if nW != n {
				fmt.Printf("\tfailed to write all bytes to clients, wrote %d bytes expected %d\n", nW, n)
				return
			}
			//fmt.Printf("\twrote %d bytes to client\n", nW)
			continue
		}
		packets, err := serverDec.DecodeData(buf[:n])
		if err != nil {
			fmt.Println(err)
			return
		}
		if len(packets) == 0 {
			continue
		}
		//log.Printf("read %d packets from server\n", len(packets))
		for _, packetV := range packets {
			pk, err := minecraft.ParseData(packetV)
			if err != nil {
				fmt.Println(err)
				return
			}
			//fmt.Printf("\t%x\n", pk.Header().PacketID)
			switch pk.Header().PacketID {
			case packet.IDNetworkSettings:
				clientDec.EnableCompression()
				serverDec.EnableCompression()
			// we don't have the client key so if we want to do this we have to make our own "secrets" and then "decode" clients, "encode" with our secret,
			// and then "decode" the server's response with our secret and "encode" and send it back to the client.
			case packet.IDServerToClientHandshake:
				stopDecoding.Do(func() {
					decode = false
				})
			default:
				panic(fmt.Sprintf("unhandled default case %T", pk))
			}
		}
		nW, err := conn.Write(buf[:n])
		if err != nil {
			fmt.Println("\t", err)
			return
		}
		if nW != n {
			fmt.Printf("\tfailed to write all bytes to clients, wrote %d bytes expected %d\n", nW, n)
			return
		}
		//fmt.Printf("\twrote %d bytes to client\n", nW)
	}
}
