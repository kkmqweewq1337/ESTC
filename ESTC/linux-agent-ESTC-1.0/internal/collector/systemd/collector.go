package systemd

import (
	"context"
	"log"
	"time"

	"github.com/example/linux-agent/internal/models"
	"github.com/godbus/dbus/v5"
)

const (
	systemdDest   = "org.freedesktop.systemd1"
	systemdPath   = "/org/freedesktop/systemd1"
	systemdIface  = "org.freedesktop.systemd1.Manager"
	unitIface     = "org.freedesktop.systemd1.Unit"
)

type Collector struct {
	conn     *dbus.Conn
	interval time.Duration
	events   chan []models.SystemdUnit
}

func NewCollector(interval time.Duration) (*Collector, error) {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	return &Collector{
		conn:     conn,
		interval: interval,
		events:   make(chan []models.SystemdUnit, 64),
	}, nil
}

func (c *Collector) Start(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// первый сбор сразу
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

func (c *Collector) Events() <-chan []models.SystemdUnit {
	return c.events
}

func (c *Collector) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

func (c *Collector) collect() {
	obj := c.conn.Object(systemdDest, systemdPath)

	// ListUnits() → array of struct (name, description, load_state, active_state,
	//   sub_state, following, unit_path, job_id, job_type, job_path)
	var units [][]dbus.Variant
	err := obj.Call(systemdIface+".ListUnits", 0).Store(&units)
	if err != nil {
		log.Printf("[systemd] ListUnits error: %v", err)
		return
	}

	now := time.Now()
	result := make([]models.SystemdUnit, 0, len(units))

	for _, u := range units {
		if len(u) < 5 {
			continue
		}
		su := models.SystemdUnit{
			Timestamp:   now,
			Name:        u[0].Value().(string),
			LoadState:   u[2].Value().(string),
			ActiveState: u[3].Value().(string),
			SubState:    u[4].Value().(string),
		}
		// Определяем тип юнита по расширению
		su.Type = unitType(su.Name)
		result = append(result, su)
	}

	select {
	case c.events <- result:
	default:
	}
}

func unitType(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[i+1:]
		}
	}
	return "unknown"
}
