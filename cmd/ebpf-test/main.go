package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/free5gc/anlf/pkg/ebpf"
)

func main() {
	ifaceName := flag.String("iface", "upfgtp", "Interface name to attach XDP")
	interval := flag.Duration("interval", 1*time.Second, "Read interval")
	flag.Parse()

	log.Printf("Starting eBPF test tool")
	log.Printf("Interface: %s", *ifaceName)
	log.Printf("Read interval: %v", *interval)

	mgr, err := ebpf.NewManager()
	if err != nil {
		log.Fatalf("Failed to create manager: %v", err)
	}

	log.Printf("Loading eBPF program...")
	if err := mgr.Load(); err != nil {
		log.Fatalf("Failed to load eBPF: %v", err)
	}
	defer mgr.Close()

	log.Printf("Attaching XDP to interface %s...", *ifaceName)
	if err := mgr.AttachXDP(*ifaceName); err != nil {
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	log.Printf("✓ XDP attached successfully")

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("Monitoring traffic... (Ctrl+C to stop)")
	fmt.Println()

	for {
		select {
		case <-ticker.C:
			metrics, err := mgr.ReadMetrics()
			if err != nil {
				log.Printf("Error reading metrics: %v", err)
				continue
			}

			if len(metrics) == 0 {
				fmt.Printf("[%s] No traffic detected\n", time.Now().Format("15:04:05"))
				continue
			}

			fmt.Printf("\n=== Metrics at %s ===\n", time.Now().Format("15:04:05"))
			for ipNet, m := range metrics {
				ip := ebpf.IPFromNetByteOrder(ipNet)
				fanOut := ebpf.CountBits(m.DstBitmap)

				fmt.Printf("\nUE IP: %s\n", ip)
				fmt.Printf("  Packets: %d, Bytes: %d\n", m.PacketCount, m.ByteCount)
				fmt.Printf("  TCP: %d, UDP: %d, ICMP: %d\n", m.TcpCount, m.UdpCount, m.IcmpCount)
				fmt.Printf("  TCP Flags - SYN: %d, RST: %d\n", m.SynCount, m.RstCount)
				fmt.Printf("  New Flows: %d\n", m.NewFlowCount)
				fmt.Printf("  Fan-Out (unique dsts): %d/64\n", fanOut)
			}

		case <-sigChan:
			fmt.Println("\nShutting down...")
			return
		}
	}
}
