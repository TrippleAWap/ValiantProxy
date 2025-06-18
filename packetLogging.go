package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type PacketEntry struct {
	time time.Time
	data []byte
}

var lastPackets = make([]PacketEntry, 0, 100)

func addPacket(data []byte) {
	lastPackets = append(lastPackets, PacketEntry{time.Now(), data})
	if len(lastPackets) > 100 {
		lastPackets = lastPackets[1:]
	}
}

func printLastPackets() {
	if len(lastPackets) == 0 {
		return
	}
	fmt.Printf("Last %d packets:\n", len(lastPackets))
	for _, packet := range lastPackets {
		fmt.Printf("%s: %s\n", packet.time.Format(time.RFC3339), packet.data)
	}
	uid := time.Now().Format("2006-01-02_15-04-05")
	lastPacketsF, err := os.Create("lastPackets_" + uid + ".json")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer lastPacketsF.Close()
	if err := json.NewEncoder(lastPacketsF).Encode(lastPackets); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Last packets saved to lastPackets_%s.json\n", uid)
	lastPackets = lastPackets[:0]
}
