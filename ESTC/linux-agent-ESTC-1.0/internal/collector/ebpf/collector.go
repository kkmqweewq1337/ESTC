package ebpf

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/example/linux-agent/internal/models"
	"github.com/example/linux-agent/internal/util"
)

type bpfEvent struct {
	TimestampNs uint64      // 0-7 (8 байт)
	SrcIP       uint32      // 8-11 (4 байта)
	DstIP       uint32      // 12-15 (4 байта)
	SrcPort     uint16      // 16-17 (2 байта)
	DstPort     uint16      // 18-19 (2 байта)
	Protocol    uint8       // 20 (1 байт)
	Direction   uint8       // 21 (1 байт)
	_           [2]byte     // 22-23 (2 байта padding для выравнивания PID)
	PID         uint32      // 24-27 (4 байта)
	Comm        [16]byte    // 28-43 (16 байт)
	ServicePort uint16      // 44-45 (2 байта)
	ServiceComm [16]byte    // 46-61 (16 байт)
	_           [2]byte     // 62-63 (2 байта padding для выравнивания NetnsIno)
	NetnsIno    uint32      // 64-67 (4 байта)
}

type Collector struct {
	objs      *conntrackObjects
	links     []link.Link
	ringBuf   *ringbuf.Reader
	eventsCh  chan models.ConnectionEvent
	closeChan chan struct{}
}

func NewCollector() (*Collector, error) {
	var objs conntrackObjects
	if err := loadConntrackObjects(&objs, nil); err != nil {
		return nil, err
	}

	var links []link.Link

	attachKprobe := func(symbol string, prog *ebpf.Program) error {
		l, err := link.Kprobe(symbol, prog, nil)
		if err != nil {
			return err
		}
		links = append(links, l)
		return nil
	}

	attachKretprobe := func(symbol string, prog *ebpf.Program) error {
		l, err := link.Kretprobe(symbol, prog, nil)
		if err != nil {
			return err
		}
		links = append(links, l)
		return nil
	}

	if err := attachKprobe("inet_listen", objs.InetListen); err != nil {
		return nil, err
	}
	if err := attachKprobe("inet_csk_listen_stop", objs.InetCskListenStop); err != nil {
		return nil, err
	}
	if err := attachKprobe("tcp_v4_connect", objs.TcpV4ConnectEntry); err != nil {
		return nil, err
	}
	if err := attachKretprobe("tcp_v4_connect", objs.TcpV4ConnectExit); err != nil {
		return nil, err
	}
	if err := attachKretprobe("inet_csk_accept", objs.InetCskAccept); err != nil {
		return nil, err
	}
	if err := attachKprobe("udp_sendmsg", objs.UdpSendmsg); err != nil {
		return nil, err
	}
	if err := attachKprobe("udp_queue_rcv_skb", objs.UdpQueueRcvSkb); err != nil {
		return nil, err
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return nil, err
	}

	c := &Collector{
		objs:      &objs,
		links:     links,
		ringBuf:   reader,
		eventsCh:  make(chan models.ConnectionEvent, 10000),
		closeChan: make(chan struct{}),
	}

	go c.readEvents()

	log.Println(" eBPF programs attached successfully")
	return c, nil
}

func (c *Collector) readEvents() {
	defer close(c.eventsCh)

	for {
		select {
		case <-c.closeChan:
			return
		default:
			record, err := c.ringBuf.Read()
			if err != nil {
				log.Printf("⚠️ [ebpf] ringbuf read error: %v", err)
				return
			}

			var rawEvent bpfEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &rawEvent); err != nil {
				log.Printf("⚠️ [ebpf] failed to parse event: %v", err)
				continue
			}

			// ИСПРАВЛЕНО #1: Конвертируем uint32 IP в net.IP (little-endian, как в ядре на x86)
			srcIP := uint32ToIP(rawEvent.SrcIP)
			dstIP := uint32ToIP(rawEvent.DstIP)

			// ИСПРАВЛЕНО #2: Используем time.Now() вместо bpf_ktime_get_ns()
			// bpf_ktime_get_ns() возвращает monotonic time (с boot), а не realtime!
			isLocalContainer := util.IsContainerNetns(rawEvent.NetnsIno)
			evt := models.ConnectionEvent{
				Timestamp:   time.Now(),
				SrcIP:       srcIP,
				DstIP:       dstIP,
				SrcPort:     rawEvent.SrcPort,
				DstPort:     rawEvent.DstPort,
				Protocol:    models.Protocol(rawEvent.Protocol),
				Direction:   models.Direction(rawEvent.Direction),
				PID:         rawEvent.PID,
				Comm:        sanitizeComm(rawEvent.Comm[:]),
				ServiceComm: sanitizeComm(rawEvent.ServiceComm[:]),
				IsDockerSrc: isLocalContainer && rawEvent.Direction == 0,
				IsDockerDst: isLocalContainer && rawEvent.Direction == 1,
			}

			select {
			case c.eventsCh <- evt:
			case <-c.closeChan:
				return
			}
		}
	}
}

func (c *Collector) Events() <-chan models.ConnectionEvent {
	return c.eventsCh
}

func (c *Collector) Close() {
	close(c.closeChan)
	if c.ringBuf != nil {
		c.ringBuf.Close()
	}
	for _, l := range c.links {
		l.Close()
	}
	if c.objs != nil {
		c.objs.Close()
	}
	log.Println("✅ eBPF collector closed")
}

// uint32ToIP конвертирует uint32 (little-endian, как хранится в ядре на x86) в net.IP
func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}
func sanitizeComm(b []byte) string {
	var cleaned []byte
	for _, char := range b {
		if char == 0 {
			break
		}
		if char >= 32 && char <= 126 {
			cleaned = append(cleaned, char)
		}
	}
	// Возвращаем пустую строку, а не "unknown"
	return string(cleaned)
}
