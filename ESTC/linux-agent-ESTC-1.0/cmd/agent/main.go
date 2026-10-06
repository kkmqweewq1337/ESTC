package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/example/linux-agent/internal/models"
	"github.com/example/linux-agent/internal/util"
	ebpfcol "github.com/example/linux-agent/internal/collector/ebpf"
	"github.com/example/linux-agent/internal/collector/netfallback"
	dockercol "github.com/example/linux-agent/internal/collector/docker"
	portscol "github.com/example/linux-agent/internal/collector/ports"
	systemdcol "github.com/example/linux-agent/internal/collector/systemd"
	"github.com/example/linux-agent/internal/sender"
)

const AgentVersion = "1.0.0"

type networkCollector interface {
	Events() <-chan models.ConnectionEvent
	Close()
}

func main() {
	chDSN := flag.String("clickhouse", "clickhouse://estc_agent:@localhost:9000/ESTC", "ClickHouse DSN")
	caCert := flag.String("ca-cert", "", "Path to CA certificate")
	clientCert := flag.String("client-cert", "", "Path to client certificate")
	clientKey := flag.String("client-key", "", "Path to client private key")
	collectInterval := flag.Duration("interval", 30*time.Second, "Collection interval for systemd/docker/ports")
	flushInterval := flag.Duration("flush", 5*time.Second, "eBPF events flush interval")
	heartbeatInterval := flag.Duration("heartbeat", 30*time.Second, "Heartbeat interval")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	log.Println("Starting ESTC-1.0.0")

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown_host"
		log.Printf("WARNING: failed to get hostname: %v, using %s", err, hostname)
	}
	hostIP := getOutboundIP()
	if hostIP == nil {
		hostIP = net.IPv4zero
		log.Printf("WARNING: failed to get outbound IP, using %s", hostIP)
	}

	senderCfg := sender.Config{
		DSN:            *chDSN,
		CACertPath:     *caCert,
		ClientCertPath: *clientCert,
		ClientKeyPath:  *clientKey,
	}
	snd, err := sender.NewSender(senderCfg)
	if err != nil {
		log.Fatalf("ClickHouse init: %v", err)
	}
	defer snd.Close()

	util.InitHostNetns()

	startTime := time.Now()
	log.Printf("Agent started on %s (%s)", hostname, hostIP)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()
	}()

	if err := snd.InitTables(ctx); err != nil {
		log.Fatalf("ClickHouse init tables: %v", err)
	}
	log.Println("ClickHouse connected, tables initialized")

	connCh := make(chan []models.ConnectionEvent, 16)
	portsCh := make(chan []models.ListeningPort, 16)
	sysdCh := make(chan []models.SystemdUnit, 16)
	dockCh := make(chan []models.DockerContainer, 16)

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); sendWorker(ctx, connCh, "connections", snd.SendConnections) }()
	go func() { defer wg.Done(); sendWorker(ctx, portsCh, "listening ports", snd.SendPorts) }()
	go func() { defer wg.Done(); sendWorker(ctx, sysdCh, "systemd units", snd.SendSystemdUnits) }()
	go func() { defer wg.Done(); sendWorker(ctx, dockCh, "docker containers", snd.SendDockerContainers) }()

	sendHeartbeat(ctx, snd, hostname, hostIP, startTime)

	// Heartbeat goroutine (оставляем синхронным, так как это 1 строка раз в 30с)
	go func() {
		ticker := time.NewTicker(*heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sendHeartbeat(ctx, snd, hostname, hostIP, startTime)
			}
		}
	}()

	// Проверка поддержки eBPF
	supported, kernelVer, reason := util.CheckEBPFSupport()
	log.Printf("Kernel: %s, eBPF support: %v (%s)", kernelVer, supported, reason)

	var netCol networkCollector
	var netColType string
	if !supported {
		log.Printf("WARNING: Kernel %s does not support eBPF: %s", kernelVer, reason)
		log.Println("WARNING: Using /proc/net fallback collector")
		fallbackCol := netfallback.NewCollector(*collectInterval, hostname)
		go fallbackCol.Start(ctx)
		netCol = fallbackCol
		netColType = "proc-net"
	} else {
		ebpfCol, err := ebpfcol.NewCollector()
		if err != nil {
			log.Printf("WARNING: eBPF load failed even on supported kernel: %v", err)
			log.Println("WARNING: Falling back to /proc/net parser")
			fallbackCol := netfallback.NewCollector(*collectInterval, hostname)
			go fallbackCol.Start(ctx)
			netCol = fallbackCol
			netColType = "proc-net"
		} else {
			defer ebpfCol.Close()
			netCol = ebpfCol
			netColType = "ebpf"
			log.Println("eBPF collector started successfully")
		}
	}
	log.Printf("Network collector mode: %s", netColType)

	sysdCol, err := systemdcol.NewCollector(*collectInterval)
	if err != nil {
		log.Printf("WARNING: systemd collector init failed: %v (continuing without)", err)
	} else {
		defer sysdCol.Close()
		go sysdCol.Start(ctx)
		log.Println("systemd collector started")
	}

	dockCol, err := dockercol.NewCollector(*collectInterval)
	if err != nil {
		log.Printf("WARNING: docker collector init failed: %v (continuing without)", err)
	} else {
		defer dockCol.Close()
		go dockCol.Start(ctx)
		log.Println("Docker collector started")
	}

	portsCol := portscol.NewCollector(*collectInterval)
	go portsCol.Start(ctx)
	log.Println("Ports collector started")

	// Основной цикл обработки событий
	connBatch := make([]models.ConnectionEvent, 0, 10000)
	flushTicker := time.NewTicker(*flushInterval)
	defer flushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Graceful shutdown: отправляем оставшиеся события перед выходом
			if len(connBatch) > 0 {
				select {
				case connCh <- connBatch:
				default:
					log.Println("Warning: connection channel full on shutdown, dropping remaining batch")
				}
			}

			// Закрываем каналы, чтобы воркеры могли завершиться после отправки остатков
			close(connCh)
			close(portsCh)
			close(sysdCh)
			close(dockCh)
			// Ждем, пока все данные улетят в ClickHouse
			log.Println("Waiting for background senders to finish...")
			wg.Wait()
			log.Println("Agent stopped gracefully")
			return

		case evt, ok := <-netCol.Events():
			if !ok {
				log.Println("Network collector channel closed")
				return
			}
			evt.Hostname = hostname
			connBatch = append(connBatch, evt)

			if len(connBatch) >= 10000 {
				select {
				case connCh <- connBatch:
				default:
					log.Printf("WARNING: connection channel full, dropping %d events", len(connBatch))
				}
				connBatch = connBatch[:0]
			}

		case <-flushTicker.C:
			if len(connBatch) > 0 {
				select {
				case connCh <- connBatch:
				default:
					log.Printf("WARNING: connection channel full, dropping %d events", len(connBatch))
				}
				connBatch = connBatch[:0]
			}

		case units, ok := <-sysdCol.Events():
			if !ok { continue }
			for i := range units { units[i].Hostname = hostname }
			select {
			case sysdCh <- units:
			default:
				log.Printf("WARNING: systemd channel full, dropping %d units", len(units))
			}

		case containers, ok := <-dockCol.Events():
			if !ok { continue }
			for i := range containers { containers[i].Hostname = hostname }
			select {
			case dockCh <- containers:
			default:
				log.Printf("WARNING: docker channel full, dropping %d containers", len(containers))
			}

		case ports, ok := <-portsCol.Events():
			if !ok { continue }
			for i := range ports { ports[i].Hostname = hostname }
			select {
			case portsCh <- ports:
			default:
				log.Printf("WARNING: ports channel full, dropping %d ports", len(ports))
			}
		}
	}
}

func sendWorker[T any](ctx context.Context, ch <-chan []T, name string, sendFunc func(context.Context, []T) error) {
	for batch := range ch {
		if err := sendFunc(ctx, batch); err != nil {
			log.Printf("[ch] send %s: %v", name, err)
		} else {
			log.Printf("[ch] sent %d %s", len(batch), name)
		}
	}
}

func getOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

func sendHeartbeat(ctx context.Context, snd *sender.Sender, hostname string, ip net.IP, startTime time.Time) {
	uptime := int64(time.Since(startTime).Seconds())
	hb := models.Heartbeat{
		Hostname:  hostname,
		IP:        ip,
		Timestamp: time.Now(),
		Status:    "alive",
		Version:   AgentVersion,
		Uptime:    uptime,
	}
	if err := snd.SendHeartbeat(ctx, hb); err != nil {
		log.Printf("WARNING: heartbeat send error: %v", err)
	} else {
		log.Printf("WARNING: heartbeat sent for %s (%s), uptime: %ds", hostname, ip, uptime)
	}
}
