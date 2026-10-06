package sender

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
	"os"
	"crypto/tls"
	"crypto/x509"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/example/linux-agent/internal/models"
)

type Config struct {
        DSN            string
	CACertPath     string // Путь к CA сертификату
	ClientCertPath string // Путь к клиентскому сертификату
	ClientKeyPath  string // Путь к приватному ключу клиента
}
type Sender struct {
	conn driver.Conn
}

func NewSender(cfg Config) (*Sender, error) {
	opts, err := clickhouse.ParseDSN(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse DSN: %w", err)
	}

	// Если переданы все три пути, включаем mTLS
	if cfg.CACertPath != "" && cfg.ClientCertPath != "" && cfg.ClientKeyPath != "" {
		log.Printf("🔒 Configuring mTLS for ClickHouse (CA: %s)", cfg.CACertPath)

		// 1. Загружаем клиентский сертификат и ключ
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertPath, cfg.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}

		// 2. Загружаем CA, чтобы агент доверял серверу ClickHouse
		caCert, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		// 3. Настраиваем TLS
		opts.TLS = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      caCertPool,
			MinVersion:   tls.VersionTLS12,
			// ServerName: "your-clickhouse-domain.com", // Раскомментировать, если имя в сертификате не совпадает с хостом в DSN
		}
		log.Println("✅ mTLS configured successfully")
	} else {
		log.Println("⚠️  Connecting to ClickHouse without mTLS (standard connection)")
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}

	return &Sender{conn: conn}, nil
}

func (s *Sender) InitTables(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS connections (
			hostname   String,
			timestamp  DateTime,
			src_ip     IPv4,
			dst_ip     IPv4,
			src_port   UInt16,
			dst_port   UInt16,
			protocol   Enum8('TCP'=6, 'UDP'=17),
			direction  Enum8('outbound'=0, 'inbound'=1),
			pid        UInt32,
			comm       LowCardinality(String),
                        service_comm  LowCardinality(String),
			is_docker_src UInt8,
			is_docker_dst UInt8
		) ENGINE = MergeTree()
		ORDER BY (hostname, timestamp, protocol, direction)
		TTL timestamp + INTERVAL 30 DAY`,

		`CREATE TABLE IF NOT EXISTS listening_ports (
			hostname   String,
			timestamp  DateTime,
			ip         IPv4,
			port       UInt16,
			protocol   Enum8('TCP'=6, 'UDP'=17),
			pid        UInt32,
			process    LowCardinality(String)
		) ENGINE = MergeTree()
		ORDER BY (hostname, timestamp, port, protocol)
		TTL timestamp + INTERVAL 30 DAY`,

		`CREATE TABLE IF NOT EXISTS systemd_units (
			hostname     String,
			timestamp    DateTime,
			name         LowCardinality(String),
			type         LowCardinality(String),
			load_state   LowCardinality(String),
			active_state LowCardinality(String),
			sub_state    LowCardinality(String)
		) ENGINE = MergeTree()
		ORDER BY (hostname, timestamp, name)
		TTL timestamp + INTERVAL 30 DAY`,

		`CREATE TABLE IF NOT EXISTS docker_containers (
			hostname   String,
			timestamp  DateTime,
			id         String,
			name       LowCardinality(String),
			image      LowCardinality(String),
			state      LowCardinality(String),
			status     String,
			ports      String
		) ENGINE = MergeTree()
		ORDER BY (hostname, timestamp, name)
		TTL timestamp + INTERVAL 30 DAY`,

		`CREATE TABLE IF NOT EXISTS agent_heartbeat (
			hostname   LowCardinality(String),
			ip         IPv4,
			timestamp  DateTime,
			status     LowCardinality(String),
			version    String,
			uptime     Int64
		) ENGINE = MergeTree()
		ORDER BY (hostname, timestamp)
		TTL timestamp + INTERVAL 7 DAY`,
	}

	for _, q := range queries {
		if err := s.conn.Exec(ctx, q); err != nil {
			return fmt.Errorf("exec %q: %w", q[:40], err)
		}
	}
	return nil
}

func (s *Sender) SendConnections(ctx context.Context, events []models.ConnectionEvent) error {
	if len(events) == 0 {
		return nil
	}
	batch, err := s.conn.PrepareBatch(ctx, "INSERT INTO connections")
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}

	successCount := 0
	for _, e := range events {
		// 1. Безопасное преобразование IP
		srcIP := e.SrcIP.To4()
		dstIP := e.DstIP.To4()

		if srcIP == nil || dstIP == nil {
			log.Printf("[ch] DROP: invalid IP format (src=%v, dst=%v)", e.SrcIP, e.DstIP)
			continue
		}

		// 2. Исправлено: передаем СТРОКИ для Enum8, это самый надежный способ в clickhouse-go/v2
		err := batch.Append(
			e.Hostname,                  // 1: String
			e.Timestamp,                 // 2: DateTime
			srcIP,                       // 3: IPv4
			dstIP,                       // 4: IPv4
			e.SrcPort,                   // 5: UInt16
			e.DstPort,                   // 6: UInt16
			e.Protocol.String(),         // 7: Enum8 ('TCP' или 'UDP')
			e.Direction.String(),        // 8: Enum8 ('outbound' или 'inbound')
			e.PID,                       // 9: UInt32
			e.Comm,                      // 10: LowCardinality(String)
			e.ServiceComm,               // 11: LowCardinality(String)
			uint8(boolToInt(e.IsDockerSrc)), // 12: UInt8
			uint8(boolToInt(e.IsDockerDst)), // 13: UInt8
                )
		if err != nil {
			log.Printf("[ch] ERROR append connection: %v | Event: %+v", err, e)
			continue
		}
		successCount++
	}

	if successCount == 0 {
		log.Println("[ch] No valid connections to send after filtering")
		return nil
	}

	if err := batch.Send(); err != nil {
		return fmt.Errorf("batch send: %w", err)
	}

	log.Printf("[ch] successfully sent %d/%d connections", successCount, len(events))
	return nil
}

func (s *Sender) SendPorts(ctx context.Context, ports []models.ListeningPort) error {
	if len(ports) == 0 {
		return nil
	}
	batch, err := s.conn.PrepareBatch(ctx, "INSERT INTO listening_ports")
	if err != nil {
		return err
	}
	for _, p := range ports {
		ip4 := p.IP.To4()
		if ip4 == nil {
			ip4 = net.IPv4zero.To4()
		}
		err := batch.Append(
			p.Hostname,
			p.Timestamp,
			ip4,
			p.Port,
			p.Protocol.String(),
			p.PID,
			p.Process,
		)
		if err != nil {
			log.Printf("[ch] append port: %v", err)
			continue
		}
	}
	return batch.Send()
}

func (s *Sender) SendSystemdUnits(ctx context.Context, units []models.SystemdUnit) error {
	if len(units) == 0 {
		return nil
	}
	batch, err := s.conn.PrepareBatch(ctx, "INSERT INTO systemd_units")
	if err != nil {
		return err
	}
	for _, u := range units {
		err := batch.Append(
			u.Hostname,    // 1
			u.Timestamp,   // 2
			u.Name,        // 3
			u.Type,        // 4
			u.LoadState,   // 5
			u.ActiveState, // 6
			u.SubState,    // 7
		)
		if err != nil {
			log.Printf("[ch] append unit: %v", err)
			continue
		}
	}
	return batch.Send()
}

func (s *Sender) SendDockerContainers(ctx context.Context, containers []models.DockerContainer) error {
	if len(containers) == 0 {
		return nil
	}
	batch, err := s.conn.PrepareBatch(ctx, "INSERT INTO docker_containers")
	if err != nil {
		return err
	}
	for _, c := range containers {
		err := batch.Append(
			c.Hostname, // 1
			c.Timestamp,// 2
			c.ID,       // 3
			c.Name,     // 4
			c.Image,    // 5
			c.State,    // 6
			c.Status,   // 7
			c.Ports,    // 8
		)
		if err != nil {
			log.Printf("[ch] append container: %v", err)
			continue
		}
	}
	return batch.Send()
}

func (s *Sender) SendHeartbeat(ctx context.Context, hb models.Heartbeat) error {
	batch, err := s.conn.PrepareBatch(ctx, "INSERT INTO agent_heartbeat")
	if err != nil {
		return err
	}

	ip4 := hb.IP.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero.To4()
	}

	err = batch.Append(
		hb.Hostname,
		ip4,
		hb.Timestamp,
		hb.Status,
		hb.Version,
		hb.Uptime,
	)
	if err != nil {
		return err
	}

	return batch.Send()
}

func (s *Sender) Close() error {
	return s.conn.Close()
}

func boolToInt(b bool) int {
	if b { return 1 }
	return 0
}
