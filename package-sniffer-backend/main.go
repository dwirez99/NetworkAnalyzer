package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
)

type PacketData struct {
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	Protocol  string `json:"protocol"`
	Length    int    `json:"length"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func liveCaptureHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket Upgrade Error:", err)
		return
	}
	defer conn.Close()

	// GET INTERFACE FROM ENV (Default to eth0 if missing)
	iface := os.Getenv("NETWORK_INTERFACE")
	if iface == "" {
		iface = "eth0"
	}
	log.Println("Starting capture on device:", iface)

	// List all available devices for debugging
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("Error finding devices:", err)
	} else {
		log.Println("Available devices:")
		for _, device := range devices {
			log.Printf("  - %s: %s\n", device.Name, device.Description)
		}
	}

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Println("Error opening device:", err)
		conn.WriteJSON(map[string]string{"error": "Could not open network device: " + iface})
		return
	}
	defer handle.Close()

	log.Println("Successfully opened device:", iface)
	log.Println("Link type:", handle.LinkType())

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	log.Println("Starting packet capture loop...")
	packetCount := 0
	for packet := range packetSource.Packets() {
		packetCount++
		if packetCount%100 == 0 {
			log.Printf("Captured %d packets so far...\n", packetCount)
		}
		data := processPacket(packet)
		if data != nil {
			if err := conn.WriteJSON(data); err != nil {
				log.Println("Error writing to WebSocket:", err)
				break
			}
		}
	}
	log.Println("Packet capture loop ended")
}

func uploadPcapHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	file, header, err := r.FormFile("pcapfile")
	if err != nil {
		http.Error(w, "Error retrieving file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	tempFilename := "./temp_" + header.Filename
	f, _ := os.Create(tempFilename)
	io.Copy(f, file)
	f.Close()
	defer os.Remove(tempFilename)

	handle, err := pcap.OpenOffline(tempFilename)
	if err != nil {
		http.Error(w, "Error opening pcap file", http.StatusInternalServerError)
		return
	}
	defer handle.Close()

	var results []PacketData
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		data := processPacket(packet)
		if data != nil {
			results = append(results, *data)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func processPacket(packet gopacket.Packet) *PacketData {
	// Try IPv4 first
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return &PacketData{
			Timestamp: packet.Metadata().Timestamp.Format(time.RFC3339),
			SrcIP:     ip.SrcIP.String(),
			DstIP:     ip.DstIP.String(),
			Protocol:  ip.Protocol.String(),
			Length:    packet.Metadata().Length,
		}
	}

	// Try IPv6
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer != nil {
		ip, _ := ipv6Layer.(*layers.IPv6)
		return &PacketData{
			Timestamp: packet.Metadata().Timestamp.Format(time.RFC3339),
			SrcIP:     ip.SrcIP.String(),
			DstIP:     ip.DstIP.String(),
			Protocol:  ip.NextHeader.String(),
			Length:    packet.Metadata().Length,
		}
	}

	return nil
}

func main() {
	// Log environment variables
	iface := os.Getenv("NETWORK_INTERFACE")
	log.Println("NETWORK_INTERFACE env var:", iface)

	http.HandleFunc("/live", liveCaptureHandler)
	http.HandleFunc("/upload", uploadPcapHandler)
	fmt.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
