package docker

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/example/linux-agent/internal/models"
)

type Collector struct {
	cli      *client.Client
	interval time.Duration
	events   chan []models.DockerContainer
}

func NewCollector(interval time.Duration) (*Collector, error) {
	cli, err := client.NewClientWithOpts(
	client.WithHost("unix:///var/run/docker.sock"),
	client.FromEnv,
	client.WithAPIVersionNegotiation(),
	)

	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	return &Collector{
		cli:      cli,
		interval: interval,
		events:   make(chan []models.DockerContainer, 64),
	}, nil
}

func (c *Collector) Start(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	c.collect(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.collect(ctx)
		}
	}
}

func (c *Collector) Events() <-chan []models.DockerContainer {
	return c.events
}

func (c *Collector) Close() {
	if c.cli != nil {
		c.cli.Close()
	}
}

func (c *Collector) collect(ctx context.Context) {
	containers, err := c.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		log.Printf("[docker] ContainerList error: %v", err)
		return
	}

	now := time.Now()
	result := make([]models.DockerContainer, 0, len(containers))

	for _, cnt := range containers {
		name := ""
		if len(cnt.Names) > 0 {
			name = strings.TrimPrefix(cnt.Names[0], "/")
		}

		ports := formatPorts(cnt.Ports)

		result = append(result, models.DockerContainer{
			Timestamp: now,
			ID:        cnt.ID[:12],
			Name:      name,
			Image:     cnt.Image,
			State:     cnt.State,
			Status:    cnt.Status,
			Ports:     ports,
		})
	}

	select {
	case c.events <- result:
	default:
	}
}

// Используем types.Port для совместимости с разными версиями Docker SDK
func formatPorts(ports []types.Port) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		if p.PublicPort != 0 {
			parts = append(parts, fmt.Sprintf("%s:%d->%d/%s", p.IP, p.PublicPort, p.PrivatePort, p.Type))
		} else {
			parts = append(parts, fmt.Sprintf("%d/%s", p.PrivatePort, p.Type))
		}
	}
	return strings.Join(parts, ", ")
}
