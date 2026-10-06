package netfallback

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/example/linux-agent/internal/models"
	"github.com/example/linux-agent/internal/util"
)

const (
	tcpEstablished = "01"
	tcpListen      = "0A"
)

type Collector struct {
	interval time.Duration
	events   chan models.ConnectionEvent
	hostname string
}

func NewCollector(interval time.Duration, hostname string) *Collector {
	return &Collector{
		interval: interval,
		events:   make(chan models.ConnectionEvent, 4096),
		hostname: hostname,
	}
}

func (c *Collector) Start(ctx context.Context) {
	log.Println("[netfallback] collector started (parsing /proc/net/*)")
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	c.collect()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collect()
		}
	}
}

func (c *Collector) Events() <-chan models.ConnectionEvent {
	return c.events
}

func (c *Collector) Close() {}

func (c *Collector) collect() {
	// 🚀 ОПТИМИЗАЦИЯ: Сканируем /proc ОДИН РАЗ за цикл, а не для каждого соединения!
	inodeMap := util.BuildInodeMap()
	
	listeningPorts := c.collectListeningPorts()
	files := []struct {
		path  string
		proto models.Protocol
		v6    bool
	}{
		{"/proc/net/tcp", models.ProtoTCP, false},
		{"/proc/net/tcp6", models.ProtoTCP, true},
		{"/proc/net/udp", models.ProtoUDP, false},
		{"/proc/net/udp6", models.ProtoUDP, true},
	}

	now := time.Now()
	seen := make(map[string]bool)
	for _, f := range files {
		c.parseProcNet(f.path, f.proto, f.v6, now, listeningPorts, seen, inodeMap)
	}
}

func (c *Collector) collectListeningPorts() map[uint16]bool {
	listening := make(map[uint16]bool)
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Scan()
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 4 || fields[3] != tcpListen {
				continue
			}
			parts := strings.Split(fields[1], ":")
			if len(parts) != 2 {
				continue
			}
			port64, _ := strconv.ParseUint(parts[1], 16, 16)
			listening[uint16(port64)] = true
		}
		file.Close()
	}
	return listening
}

func (c *Collector) parseProcNet(path string, proto models.Protocol, v6 bool, now time.Time, listeningPorts map[uint16]bool, seen map[string]bool, inodeMap map[string]util.ProcInfo) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		state := fields[3]
		if proto == models.ProtoTCP && state != tcpEstablished {
			continue
		}

		localAddr := fields[1]
		remoteAddr := fields[2]
		srcIP, srcPort := parseAddr(localAddr, v6)
		dstIP, dstPort := parseAddr(remoteAddr, v6)

		if srcPort == 0 {
			continue
		}
		if proto == models.ProtoUDP && dstPort == 0 {
			continue
		}

		inode := fields[9]

		// Включаем inode в ключ дедупликации.
		// Это предотвратит потерю событий, если два разных процесса (разные inode/PID)
		// используют одинаковые src/dst IP:Port (например, за NAT).
		key := fmt.Sprintf("%s:%d->%s:%d:%s", srcIP, srcPort, dstIP, dstPort, inode)
		if seen[key] {
			continue
		}
		seen[key] = true

		direction := models.DirectionOutbound
		if listeningPorts[srcPort] {
			direction = models.DirectionInbound
		}

		var pid uint32
		var procName string
		if info, ok := inodeMap[inode]; ok {
			pid = info.PID
			procName = info.Name
		} else {
			procName = "unknown"
		}

		evt := models.ConnectionEvent{
			Hostname:  c.hostname,
			Timestamp: now,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Protocol:  proto,
			Direction: direction,
			PID:       pid,
			Comm:      procName,
		}

		select {
		case c.events <- evt:
		default:
		}
	}
}

func parseAddr(s string, v6 bool) (net.IP, uint16) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return nil, 0
	}
	portHex := parts[1]
	port64, _ := strconv.ParseUint(portHex, 16, 16)
	port := uint16(port64)

	ipHex := parts[0]
	ipBytes, err := hex.DecodeString(ipHex)
	if err != nil {
		return nil, 0
	}

	var ip net.IP
	if v6 {
		ip = make(net.IP, 16)
		for i := 0; i < 4; i++ {
			ip[i*4+0] = ipBytes[i*4+3]
			ip[i*4+1] = ipBytes[i*4+2]
			ip[i*4+2] = ipBytes[i*4+1]
			ip[i*4+3] = ipBytes[i*4+0]
		}
	} else {
		ip = make(net.IP, 4)
		ip[0] = ipBytes[3]
		ip[1] = ipBytes[2]
		ip[2] = ipBytes[1]
		ip[3] = ipBytes[0]
	}
	return ip, port
}
