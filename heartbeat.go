package main

import (
	"fmt"
	"log"
	"net"
	"time"
	"bytes"
	"encoding/binary"
)

const HeartbeatPort = 48689;

type SenderHeartbeat struct {
	_ [27]byte;
	SignalPresent byte;
	SignalWidth uint16;
	SignalHeight uint16;
	SignalFPS uint16;
	EncodedWidth uint16;
	EncodedHeight uint16;
	_ [2]byte;
	Uptime uint32;
	_ [6]byte;
	ReceiverPresent uint8;
}

func BroadcastWakeups(ifname string, senderip string) {
	packet := []byte{
		0x54, 0x46, 0x36, 0x7a,
		0x60, 0x02, // Source (sender / receiver) 0x6002 / 0x6301
		0x00, 0x00, // Padding
		0x00, 0x00, // Heartbeat counter

		0x00, 0x03, 0x03, 0x01, 0x00, 0x26, 0x00, 0x00, 0x00, // Magic sequence
		0x00, 0x00, 0x00, 0x00, // Uptime
	}

	for {
		saddr,err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", senderip, HeartbeatPort))
		if err != nil {
			log.Fatalf("Unable to resolve addr, %s", err.Error())
		}
		laddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", HeartbeatPort))
		if err != nil {
			log.Fatalf("Unable to resolve addr, %s", err.Error())
		}
		conn, err := net.DialUDP("udp", laddr, saddr)
		if err != nil {
			log.Fatalf("Unable to keep broadcasting the keepalives, %s", err.Error())
		}
		_, err = conn.Write(packet)
		if err != nil {
			log.Fatalf("Unable to keep broadcasting the keepalives, %s", err.Error())
		}
		conn.Close()
		time.Sleep(time.Second)
		log.Println("Heartbeat sent")
	}
}

func ProcessHeartbeat(data []byte) {
	heartbeat := SenderHeartbeat{}
	buffer := bytes.NewBuffer(data)
	err := binary.Read(buffer, binary.BigEndian, &heartbeat)
	if err == nil {
		log.Printf("[signal present: %t] %dx%d@%.1f - %dx%d",
		heartbeat.SignalPresent == 3,
		heartbeat.SignalWidth, heartbeat.SignalHeight,
		float32(heartbeat.SignalFPS)/10.0,
		heartbeat.EncodedWidth, heartbeat.EncodedHeight)
	}
}
