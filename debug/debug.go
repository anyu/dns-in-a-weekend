package debug

import (
	"encoding/hex"
	"fmt"
	"net"
)

func debug() {
	destination := "8.8.8.8:53"

	conn, err := net.Dial("udp", destination)
	if err != nil {
		fmt.Printf("Error creating UDP connection: %v\n", err)
		return
	}
	defer conn.Close()

	decodedBytes, err := hex.DecodeString("3c5f0100000100000000000003777777076578616d706c6503636f6d0000010001")
	if err != nil {
		fmt.Printf("Error decoding hex string: %v\n", err)
		return
	}

	_, err = conn.Write(decodedBytes)
	if err != nil {
		fmt.Printf("Error sending data: %v\n", err)
		return
	}
}
