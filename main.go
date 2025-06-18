package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"

	"ValiantProxy/go-raknet"
)

func init() {
	if err := godotenv.Load(); err != nil {
		panic(err)
	}
	fmt.Printf("\033[1;95m")
}

var (
	connections = make(map[string]byte)
	listener    *raknet.Listener
)

func main() {
	defer func() {
		fmt.Print("\033[0m")
	}()
	listenerV, err := raknet.ListenConfig{
		BlockDuration: time.Hour,
	}.Listen(os.Getenv("LOCAL_ADDR"))
	if err != nil {
		log.Fatal(err)
	}
	listener = listenerV
	log.Printf("Server started on %s\n", listener.Addr().String())
	fmt.Printf("\tRemote Address: %s\n", os.Getenv("REMOTE_ADDR"))
	ctx, canc := context.WithTimeout(context.Background(), time.Second*5)
	defer canc()
	s := time.Now()
	pong, err := raknet.PingContext(ctx, os.Getenv("REMOTE_ADDR"))
	if checkError(err) {
		return
	}
	latency := time.Since(s).Truncate(time.Millisecond)
	pongData, err := parsePong(pong)
	if checkError(err) {
		return
	}
	expectedProtocol = pongData.ProtocolId
	if checkError(sendMessage(fmt.Sprintf("**ValiantProxy is now online!**\n-# **Remote Address**: %s\n-# **Version**: %s [%d]\n-# **Latency**: %s\n-# **Players**: %d/%d",
		os.Getenv("REMOTE_ADDR"), pongData.ProtocolVersion, pongData.ProtocolId, latency.String(), pongData.PlayerCount, pongData.MaxPlayerCount))) {
		return
	}
	fmt.Printf("\t%s\n", pong)

	go func() {
		pongTicker := time.NewTicker(time.Second * 5)
		defer pongTicker.Stop()
		for {
			select {
			case <-pongTicker.C:
				ctx, canc := context.WithTimeout(context.Background(), time.Second*5)
				pong, err = raknet.PingContext(ctx, os.Getenv("REMOTE_ADDR"))
				canc()
				if err != nil {
					fmt.Printf("Error pinging remote server: %s\n", err)
					printLastPackets()
					continue
				}
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Second * 3)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				listener.PongData(pong)
			}
		}
	}()
	MaxConnectionsString := os.Getenv("MAX_CONNECTIONS_ALLOWED")
	MaxConnectionsV, err := strconv.Atoi(MaxConnectionsString)
	if err != nil {
		log.Printf("Error parsing MAX_CONNECTIONS_ALLOWED: %s\n", err)
		return
	}
	MaxConnections := byte(MaxConnectionsV)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %s\n", err)
			continue
		}
		i, _ := connections[conn.RemoteAddr().(*net.UDPAddr).IP.String()]
		if i >= MaxConnections {
			fmt.Printf("\033[1;91m%s attempted to connect %d times, disconnecting...\033[0m\n", conn.RemoteAddr().String(), i+1)
			_ = conn.Close()
			continue
		}
		go handleConnection(conn)
	}
}
