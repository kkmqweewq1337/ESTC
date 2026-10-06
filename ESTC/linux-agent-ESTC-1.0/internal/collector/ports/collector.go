package ports

import (
	"bufio"
	"context"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/example/linux-agent/internal/models"
	"github.com/example/linux-agent/internal/util"
)

type Collector struct {
	interval time.Duration
	events   chan []models.ListeningPort
}

func NewCollector(interval time.Duration) *Collector {
	return &Collector{
		interval: interval,
		events:   make(chan []models.ListeningPort, 64),
	}
}

func (c *Collector) Start(ctx context.Context) {
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

func (c *Collector) Events() <-chan []models.ListeningPort {
	return c.events
}

func (c *Collector) collect() {
	now := time.Now()
	
	// 🚀 ОПТИМИЗАЦИЯ: Сканируем /proc ОДИН РАЗ за цикл
	inodeMap := util.BuildInodeMap()

	var result []models.ListeningPort
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

	for _, f := range files {
		ports := parseProcNet(f.path, f.proto, f.v6, now, inodeMap)
		result = append(result, ports...)
	}

	select {
	case c.events <- result:
	default:
	}
}

func parseProcNet(path string, proto models.Protocol, v6 bool, now time.Time, inodeMap map[string]util.ProcInfo) []models.ListeningPort {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var result []models.ListeningPort
	scanner := bufio.NewScanner(file)
	scanner.Scan()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		state := fields[3]
		if proto == models.ProtoTCP && state != "0A" {
			continue
		}

		localAddr := fields[1]
		ip, port := parseAddr(localAddr, v6)
		if port == 0 {
			continue
		}

		inode := fields[9]
		
		// 🚀 Мгновенный lookup в памяти
		var pid uint32
		var procName string
		if info, ok := inodeMap[inode]; ok {
			pid = info.PID
			procName = info.Name
		} else {
			procName = "unknown"
		}

		result = append(result, models.ListeningPort{
			Timestamp: now,
			IP:        ip,
			Port:      port,
			Protocol:  proto,
			PID:       pid,
			Process:   procName,
		})
	}
	return result
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
