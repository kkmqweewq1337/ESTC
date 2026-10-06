package models

import (
	"net"
	"time"
)

// Direction определяет направление соединения
type Direction uint8

const (
	DirectionOutbound Direction = 0
	DirectionInbound  Direction = 1
)

func (d Direction) String() string {
	if d == DirectionInbound {
		return "inbound"
	}
	return "outbound"
}

// Protocol определяет тип протокола
type Protocol uint8

const (
	ProtoTCP Protocol = 6
	ProtoUDP Protocol = 17
)

func (p Protocol) String() string {
	if p == ProtoUDP {
		return "UDP"
	}
	return "TCP"
}

// ConnectionEvent — событие соединения от eBPF
type ConnectionEvent struct {
	Hostname  string      // Имя хоста, с которого пришло событие
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  Protocol
	Direction Direction
	PID       uint32
	Comm      string // имя процесса (до 16 байт)
	ServiceComm string  // Новое поле: имя процесса сервиса
	IsDockerSrc  bool       // Является ли источник Docker/приватной сетью
	IsDockerDst  bool       // Является ли назначение Docker/приватной сетью
}

// ListeningPort — открытый (слушающий) порт
type ListeningPort struct {
	Hostname  string      // Имя хоста
	Timestamp time.Time
	IP        net.IP
	Port      uint16
	Protocol  Protocol
	PID       uint32
	Process   string
}

// SystemdUnit — состояние юнита systemd
type SystemdUnit struct {
	Hostname    string // Имя хоста
	Timestamp   time.Time
	Name        string
	Type        string // service, socket, timer …
	LoadState   string // loaded, not-found …
	ActiveState string // active, inactive, failed …
	SubState    string // running, dead, exited …
}

// DockerContainer — состояние Docker контейнера
type DockerContainer struct {
	Hostname  string // Имя хоста
	Timestamp time.Time
	ID        string
	Name      string
	Image     string
	State     string // running, exited …
	Status    string // "Up 5 hours"
	Ports     string // "0.0.0.0:8080->80/tcp"
}

// Heartbeat — сигнал о том, что агент жив
type Heartbeat struct {
	Hostname  string
	IP        net.IP
	Timestamp time.Time
	Status    string // "alive", "degraded", "error"
	Version   string // версия агента
	Uptime    int64  // время работы в секундах
}
