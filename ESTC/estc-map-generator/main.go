package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
        "text/template"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
        chHost     = getEnv("CLICKHOUSE_HOST", "127.0.0.1")
        chPort     = getEnv("CLICKHOUSE_PORT", "8443")
        chDB       = getEnv("CLICKHOUSE_DB", "ESTC")
        chUser     = getEnv("CLICKHOUSE_USER", "estc_agent")
        chPass     = url.QueryEscape(getRequiredEnv("CLICKHOUSE_PASS"))
        outputDir  = getEnv("MAP_OUTPUT_DIR", "/opt/sds-docker/network_map/map/")
        caCertPath = getEnv("CH_CA_CERT", "/opt/sds-docker/network_map/certs/ca.crt")
        clientCert = getEnv("CH_CLIENT_CERT", "/opt/sds-docker/network_map/certs/client.crt")
        clientKey  = getEnv("CH_CLIENT_KEY", "/opt/sds-docker/network_map/certs/client.key")
)

var (
        subnetRe = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}$`)
        dbNameRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
)

const (
	NODE_R           = 36
	CONTAINER_R      = 22
	CONTAINER_RADIUS = 90
	PER_NODE_ARC     = 160
	RING_STEP        = 200
	RADIUS_MIN       = 400
	RADIUS_MAX       = 1600
	DEFAULT_WINDOW   = "24h"
	MAX_HOURS        = 168
)

var TIME_WINDOWS = []struct {
	Key   string
	Hours int
}{
	{"1h", 1}, {"4h", 4}, {"8h", 8}, {"16h", 16},
	{"24h", 24}, {"2d", 48}, {"4d", 96}, {"7d", 168},
}

type Connection struct {
	Ts                                  int64
	Hostname, SrcIP, DstIP              string
	DstPort                             int
	ProcessName, Direction, ServiceComm string
	IsDockerSrc, IsDockerDst            bool
}
type Heartbeat struct {
	Ts           int64
	Hostname, IP string
}
type Service struct {
	Ts                       int64
	Host, Type, Name, Status string
}
type PortProcess struct {
	Ts      int64
	Host    string
	Port    int
	Process string
}
type ResolvedConn struct {
	Src, Dst, DstIP, DstSubnet, Port, Service, Direction string
}
type Coord struct{ X, Y float64 }

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func getRequiredEnv(key string) string {
        if v, ok := os.LookupEnv(key); ok && v != "" {
                return v
        }
        fmt.Printf("ERROR: Environment variable %s is not set or is empty.\n", key)
        fmt.Println("Please set it before running the program.")
        os.Exit(1)
        return ""
}

var xmlInvalidRe = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\x{D800}-\x{DFFF}\x{FDD0}-\x{FDEF}\x{FFFE}-\x{FFFF}]`)
var safeNameRe = regexp.MustCompile(`[^\w\.\-\_\:\s\/\(\)\[\]]+`)

func cleanXML(s string) string { return xmlInvalidRe.ReplaceAllString(s, "") }
func cleanName(s string) string {
	if s == "" {
		return "unknown"
	}
	s = cleanXML(s)
	s = safeNameRe.ReplaceAllString(s, "")
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	return s
}
func escapeHTML(s string) string { return html.EscapeString(cleanXML(s)) }
func jsStr(s string) string {
	s = cleanXML(s)
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "\\'")
	s = strings.ReplaceAll(s, "\\", "\\\\")
	return s
}
func normalizeHostname(hostname string) string {
	if hostname == "" {
		return "unknown"
	}
	return strings.ToLower(strings.Split(hostname, ".")[0])
}
func mapPath(subnet, windowKey string) string {
	return filepath.Join(outputDir, fmt.Sprintf("map_%s_%s.svg", subnet, windowKey))
}

func createHTTPClient() (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, err
	}
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert}, RootCAs: caCertPool,
		}},
		Timeout: 180 * time.Second,
	}, nil
}

func chQuery(client *http.Client, sql string) ([][]string, error) {
	reqURL := fmt.Sprintf("https://%s:%s/?user=%s&password=%s&default_format=TSV", chHost, chPort, chUser, chPass)
	req, _ := http.NewRequest("POST", reqURL, strings.NewReader(sql))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ERROR: ClickHouse %d - %s", resp.StatusCode, string(body))
	}
	var result [][]string
	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			result = append(result, strings.Split(line, "\t"))
		}
	}
	return result, scanner.Err()
}

func fetchConnections(client *http.Client, hours int) ([]Connection, error) {
        sql := fmt.Sprintf(`SELECT toUnixTimestamp(timestamp), hostname, toString(src_ip), toString(dst_ip), dst_port, comm, direction, service_comm, is_docker_src, is_docker_dst FROM %s.connections WHERE timestamp >= now() - INTERVAL %d HOUR AND toString(src_ip) NOT LIKE '127.0.%%' AND toString(dst_ip) NOT LIKE '127.0.%%' AND src_ip != '0.0.0.0' AND dst_ip != '0.0.0.0' AND dst_port > 0`, chDB, hours)
	rows, err := chQuery(client, sql)
	if err != nil {
		return nil, err
	}
	var conns []Connection
	for _, r := range rows {
		if len(r) < 10 {
			continue
		}
		ts, _ := strconv.ParseInt(r[0], 10, 64)
		port, _ := strconv.Atoi(r[4])
		conns = append(conns, Connection{Ts: ts, Hostname: r[1], SrcIP: r[2], DstIP: r[3], DstPort: port, ProcessName: r[5], Direction: r[6], ServiceComm: r[7], IsDockerSrc: r[8] == "1", IsDockerDst: r[9] == "1"})
	}
	return conns, nil
}

func fetchHeartbeats(client *http.Client, hours int) ([]Heartbeat, error) {
        sql := fmt.Sprintf(`SELECT toUnixTimestamp(timestamp), hostname, toString(ip) FROM %s.agent_heartbeat WHERE timestamp >= now() - INTERVAL %d HOUR AND ip != '0.0.0.0' AND toString(ip) NOT LIKE '127.%%'`, chDB, hours)
 	rows, err := chQuery(client, sql)
	if err != nil {
		return nil, err
	}
	var hbs []Heartbeat
	for _, r := range rows {
		if len(r) < 3 {
			continue
		}
		ts, _ := strconv.ParseInt(r[0], 10, 64)
		hbs = append(hbs, Heartbeat{Ts: ts, Hostname: normalizeHostname(r[1]), IP: r[2]})
	}
	return hbs, nil
}

func fetchServices(client *http.Client, hours int) ([]Service, error) {
        sql := fmt.Sprintf(`SELECT max(toUnixTimestamp(timestamp)) as ts, hostname, type, name, argMax(status, timestamp) as status FROM (SELECT timestamp, hostname, 'docker' as type, name, state as status FROM %s.docker_containers WHERE timestamp >= now() - INTERVAL %d HOUR AND name != '' UNION ALL SELECT timestamp, hostname, 'systemd' as type, name, active_state as status FROM %s.systemd_units WHERE timestamp >= now() - INTERVAL %d HOUR AND name != '' AND (name LIKE '%%.service' OR name LIKE '%%.timer' OR name LIKE '%%.socket')) GROUP BY hostname, type, name`, chDB, hours, chDB, hours)
	rows, err := chQuery(client, sql)
	if err != nil {
		return nil, err
	}
	var svcs []Service
	for _, r := range rows {
		if len(r) < 5 {
			continue
		}
		ts, _ := strconv.ParseInt(r[0], 10, 64)
		svcs = append(svcs, Service{Ts: ts, Host: normalizeHostname(r[1]), Type: r[2], Name: r[3], Status: r[4]})
	}
	return svcs, nil
}

func fetchPortToProcess(client *http.Client, hours int) ([]PortProcess, error) {
        sql := fmt.Sprintf(`SELECT toUnixTimestamp(timestamp), hostname, port, process FROM %s.listening_ports WHERE timestamp >= now() - INTERVAL %d HOUR AND process NOT IN ('', 'unknown')`, chDB, hours)
 	rows, err := chQuery(client, sql)
	if err != nil {
		return nil, err
	}
	var ports []PortProcess
	for _, r := range rows {
		if len(r) < 4 {
			continue
		}
		ts, _ := strconv.ParseInt(r[0], 10, 64)
		port, _ := strconv.Atoi(r[2])
		ports = append(ports, PortProcess{Ts: ts, Host: normalizeHostname(r[1]), Port: port, Process: r[3]})
	}
	return ports, nil
}

var ianaPortMap = map[int]string{
	80: "http", 443: "https", 8000: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
	3000: "grafana/node", 5000: "registry", 3306: "mysql", 5432: "postgres", 1433: "mssql", 1521: "oracle",
	27017: "mongodb", 6379: "redis", 9042: "cassandra", 11211: "memcached", 9200: "elasticsearch", 9300: "es-transport",
	5672: "rabbitmq", 15672: "rabbitmq-mgmt", 9092: "kafka", 4222: "nats", 9090: "prometheus", 9100: "node_exporter",
	8123: "clickhouse-http", 9000: "clickhouse-native", 9440: "clickhouse-mtls", 22: "ssh", 3389: "rdp",
	53: "dns", 123: "ntp", 161: "snmp", 514: "syslog", 6514: "syslog-tls", 389: "ldap", 636: "ldaps",
	2049: "nfs", 139: "netbios", 445: "smb", 21: "ftp", 873: "rsync",
}
var noiseWords = map[string]bool{"docker-proxy": true, "proxy": true, "unknown": true, "sh": true, "bash": true, "exe": true, "systemd": true, "init": true, "node": true, "nodejs": true, "python": true, "python3": true, "java": true, "ruby": true, "php": true, "perl": true}

func getAutomatedServiceName(processName string, port int, isDocker bool) string {
	name := strings.ToLower(cleanName(processName))
	if noiseWords[name] || name == "" {
		name = ""
	}
	if name != "" && len(name) > 3 {
		parts := strings.Split(name, "-")
		parts = strings.Split(parts[0], ".")
		return parts[0]
	}
	if svc, ok := ianaPortMap[port]; ok {
		return svc
	}
	if isDocker {
		return fmt.Sprintf("ctr_%d", port)
	}
	return fmt.Sprintf("port_%d", port)
}

var proxyNames = map[string]bool{"nginx": true, "apache": true, "apache2": true, "httpd": true, "haproxy": true, "caddy": true, "traefik": true, "envoy": true, "varnish": true, "squid": true, "pound": true, "lighttpd": true, "cherokee": true, "gunicorn": true, "uvicorn": true, "uwsgi": true, "mod_wsgi": true, "passenger": true}
var webPorts = map[string]bool{"80": true, "443": true, "8080": true, "8443": true}

func isProxy(serviceName string) bool {
	if serviceName == "" {
		return false
	}
	name := strings.ToLower(serviceName)
	parts := strings.Split(name, "/")
	name = parts[len(parts)-1]
	parts = strings.Split(name, ":")
	name = strings.TrimSpace(parts[0])
	for proxy := range proxyNames {
		if name == proxy || strings.HasPrefix(name, proxy+"-") || strings.HasPrefix(name, proxy+"/") {
			return true
		}
	}
	return false
}

func detectProxies(conns []ResolvedConn, localHosts map[string]bool) map[string]bool {
	nodeInboundPorts := make(map[string]map[string]bool)
	nodeOutboundPorts := make(map[string]map[string]bool)
	nodeOutboundHosts := make(map[string]map[string]bool)
	nodeServices := make(map[string]map[string]bool)
	for _, c := range conns {
		dst, src, dir, svc, port := c.Dst, c.Src, c.Direction, strings.ToLower(c.Service), c.Port
		if dir == "1" || dir == "inbound" {
			if nodeInboundPorts[dst] == nil {
				nodeInboundPorts[dst] = make(map[string]bool)
			}
			nodeInboundPorts[dst][port] = true
		} else {
			if nodeOutboundPorts[src] == nil {
				nodeOutboundPorts[src] = make(map[string]bool)
			}
			nodeOutboundPorts[src][port] = true
			if nodeOutboundHosts[src] == nil {
				nodeOutboundHosts[src] = make(map[string]bool)
			}
			nodeOutboundHosts[src][dst] = true
		}
		if svc != "" && svc != "unknown" && !strings.HasPrefix(svc, "port:") {
			if nodeServices[dst] == nil {
				nodeServices[dst] = make(map[string]bool)
			}
			nodeServices[dst][svc] = true
			if nodeServices[src] == nil {
				nodeServices[src] = make(map[string]bool)
			}
			nodeServices[src][svc] = true
		}
	}
	proxyNodes := make(map[string]bool)
	allNodes := make(map[string]bool)
	for n := range nodeInboundPorts {
		allNodes[n] = true
	}
	for n := range nodeServices {
		allNodes[n] = true
	}
	for node := range allNodes {
		inboundPorts, outboundPorts, outboundHosts, services := nodeInboundPorts[node], nodeOutboundPorts[node], nodeOutboundHosts[node], nodeServices[node]
		isKnownProxy := false
		for svc := range services {
			if isProxy(svc) {
				isKnownProxy = true
				break
			}
		}
		hasWebInbound := false
		for port := range inboundPorts {
			if webPorts[port] {
				hasWebInbound = true
				break
			}
		}
		hasOutbound := len(outboundHosts) >= 2
		hasBackendOutbound := false
		for port := range outboundPorts {
			if !webPorts[port] {
				hasBackendOutbound = true
				break
			}
		}
		if isKnownProxy || (hasWebInbound && hasOutbound && hasBackendOutbound) {
			proxyNodes[node] = true
		}
	}
	return proxyNodes
}

func cutoffFor(hours int, nowUnix int64) int64 { return nowUnix - int64(hours*3600) }

type WindowData struct {
	Conns                   []Connection
	IPToHost, HostToPrimary map[string]string
	LocalHosts              map[string]bool
	Services                map[string][]Service
	PortProc                map[string]string
}

func buildWindowData(subnet string, hours int, nowUnix int64, allConns []Connection, allHb []Heartbeat, allSvc []Service, allPorts []PortProcess) WindowData {
	cut := cutoffFor(hours, nowUnix)
	var conns []Connection
	for _, c := range allConns {
		if c.Ts >= cut {
			conns = append(conns, c)
		}
	}
	var hb []Heartbeat
	for _, h := range allHb {
		if h.Ts >= cut {
			hb = append(hb, h)
		}
	}
	var svc []Service
	for _, s := range allSvc {
		if s.Ts >= cut {
			svc = append(svc, s)
		}
	}
	var ports []PortProcess
	for _, p := range allPorts {
		if p.Ts >= cut {
			ports = append(ports, p)
		}
	}
	ipToHost := make(map[string]string)
	hostToIPs := make(map[string][]string)
	for _, h := range hb {
		ipToHost[h.IP] = h.Hostname
		hostToIPs[h.Hostname] = append(hostToIPs[h.Hostname], h.IP)
	}
	hostToPrimary := make(map[string]string)
	for host, ips := range hostToIPs {
		if len(ips) > 0 {
			sort.Strings(ips)
			hostToPrimary[host] = ips[0]
		}
	}
	localHosts := make(map[string]bool)
	for _, h := range hb {
		if strings.HasPrefix(h.IP, subnet+".") {
			localHosts[h.Hostname] = true
		}
	}
	services := make(map[string][]Service)
	seen := make(map[string]bool)
	for _, s := range svc {
		key := fmt.Sprintf("%s|%s|%s", s.Host, s.Type, s.Name)
		if !seen[key] {
			seen[key] = true
			services[s.Host] = append(services[s.Host], s)
		}
	}
	portProc := make(map[string]string)
	for _, p := range ports {
		portProc[fmt.Sprintf("%s|%d", p.Host, p.Port)] = p.Process
	}
	return WindowData{Conns: conns, IPToHost: ipToHost, HostToPrimary: hostToPrimary, LocalHosts: localHosts, Services: services, PortProc: portProc}
}

func resolveConnections(conns []Connection, data WindowData) ([]ResolvedConn, map[string]string) {
	containerToHost := make(map[string]string)
	var resolved []ResolvedConn
	for _, c := range conns {
		srcHost := normalizeHostname(c.Hostname)
		dstIP := c.DstIP
		dstHostRaw, ok := data.IPToHost[dstIP]
		var dstHost string
		if ok {
			dstHost = dstHostRaw
		} else if strings.HasPrefix(dstIP, "192.168.") || strings.HasPrefix(dstIP, "10.") || strings.HasPrefix(dstIP, "172.") {
			dstHost = "U-" + dstIP
		} else {
			dstHost = "E-" + dstIP
		}
		if !data.LocalHosts[srcHost] && !data.LocalHosts[dstHost] {
			continue
		}
		if srcHost == dstHost {
			continue
		}
		dstIPResolved := data.HostToPrimary[dstHost]
		if dstIPResolved == "" {
			dstIPResolved = c.DstIP
		}
		parts := strings.Split(dstIPResolved, ".")
		var dstSubnet string
		if len(parts) == 4 && !strings.HasPrefix(dstIPResolved, "127.") && !strings.HasPrefix(dstIPResolved, "U-") && !strings.HasPrefix(dstIPResolved, "E-") {
			dstSubnet = strings.Join(parts[:3], ".")
		}
		rawService := c.ServiceComm
		if rawService == "" {
			rawService = c.ProcessName
		}
		if rawService == "" {
			rawService = data.PortProc[fmt.Sprintf("%s|%d", dstHost, c.DstPort)]
		}
		service := getAutomatedServiceName(rawService, c.DstPort, c.IsDockerDst)
		nodeID := dstHost
		if c.IsDockerDst {
			nodeID = fmt.Sprintf("CTR::%s||%s", service, c.DstIP)
			containerToHost[nodeID] = srcHost
		}
		resolved = append(resolved, ResolvedConn{Src: srcHost, Dst: nodeID, DstIP: dstIP, DstSubnet: dstSubnet, Port: strconv.Itoa(c.DstPort), Service: service, Direction: c.Direction})
	}
	seen := make(map[string]bool)
	var uniq []ResolvedConn
	for _, r := range resolved {
		key := fmt.Sprintf("%s|%s", r.Src, r.Dst)
		if !seen[key] {
			seen[key] = true
			uniq = append(uniq, r)
		}
	}
	return uniq, containerToHost
}

func layoutHosts(hosts []string, cx, cy float64) (map[string]Coord, map[string]float64) {
	n := len(hosts)
	if n == 0 {
		return make(map[string]Coord), make(map[string]float64)
	}
	capacity := func(r float64) int { return int(math.Max(1, (2*math.Pi*r)/PER_NODE_ARC)) }
	type Ring struct {
		R     float64
		Count int
	}
	var rings []Ring
	remaining := n
	r := float64(RADIUS_MIN)
	for remaining > 0 {
		if r > RADIUS_MAX {
			rings = append(rings, Ring{RADIUS_MAX, remaining})
			break
		}
		cap := capacity(r)
		take := int(math.Min(float64(cap), float64(remaining)))
		rings = append(rings, Ring{r, take})
		remaining -= take
		r += RING_STEP
	}
	coords := make(map[string]Coord)
	angles := make(map[string]float64)
	idx := 0
	for ringI, ring := range rings {
		step := 2 * math.Pi / float64(ring.Count)
		offset := 0.0
		if ringI%2 != 0 {
			offset = math.Pi / float64(ring.Count)
		}
		for i := 0; i < ring.Count; i++ {
			h := hosts[idx]
			angle := float64(i)*step - math.Pi/2 + offset
			angles[h] = angle
			coords[h] = Coord{X: cx + ring.R*math.Cos(angle), Y: cy + ring.R*math.Sin(angle)}
			idx++
		}
	}
	return coords, angles
}

type EdgeData struct {
	X1, Y1, X2, Y2, Mx, My                          float64
	Color, Marker, Label                            string
	LabelWidth, LabelX                              float64
	Src, Dst, DstSubnet, TargetURL, ContainerHostID string
	Clickable, IsContainer                          bool
}
type NodeData struct {
	X, Y                                      float64
	ID, DisplayName, Stroke, Fill, NodeIDAttr string
	IsHost, IsProxy, HasContainers            bool
	ContainerCount                            int
}
type ContainerData struct {
	X, Y                                       float64
	HostID, ID, DisplayName, CtrIP, NodeIDAttr string
	IsProxy                                    bool
}
type HostingLineData struct {
	HostID         string
	X1, Y1, X2, Y2 float64
}
type RenderData struct {
	ViewW, ViewH, LegendY, CenterX, CenterY                              float64
	Subnet, WindowKey, Timestamp, ServicesJSON                           string
	HostsCount, ContainersCount, ConnsCount, InboundCount, OutboundCount int
	TimeWindows                                                          []struct {
		Key   string
		Hours int
	}
	HostingLines []HostingLineData
	Edges        []EdgeData
	Nodes        []NodeData
	Containers   []ContainerData
}

const svgTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {{.ViewW}} {{.ViewH}}" style="background:#15171c;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;" preserveAspectRatio="xMidYMid meet">
  <style>
    .node { transition: opacity 0.15s ease; cursor: pointer; }
    .node.active { stroke-width: 3 !important; }
    .edge-line { transition: opacity 0.15s ease; cursor: pointer; }
    .edge-hit { cursor: pointer; }
    .edge-info { opacity: 0; transition: opacity 0.15s ease; pointer-events: none; }
    .hosting-line { stroke-dasharray: 4,4; opacity: 0; transition: opacity 0.3s ease; }
    .hosting-line.visible { opacity: 0.3; }
    .container-node { opacity: 0; transition: opacity 0.3s ease; pointer-events: none; }
    .container-node.visible { opacity: 1; pointer-events: auto; }
    .expand-btn { cursor: pointer; }
    .expand-btn:hover circle { stroke: #79c0ff; }
    .edge-line.hidden { opacity: 0 !important; pointer-events: none; }
    .edge-hit.hidden { pointer-events: none; }
    .time-tabs a rect:hover { stroke: #39c0ed; }
    .back-btn rect:hover { stroke: #39c0ed; fill: #252a33; }
    .svc-panel { position: fixed !important; display: none !important; background: #1c2128 !important; border: 2px solid #39c0ed !important; border-radius: 10px !important; color: #c9d1d9 !important; font-size: 15px !important; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif !important; box-shadow: 0 8px 32px rgba(0,0,0,0.85) !important; max-height: 80vh !important; flex-direction: column !important; z-index: 10000 !important; width: 600px !important; min-width: 600px !important; max-width: 700px !important; padding: 0 !important; pointer-events: auto !important; overflow: hidden !important; }
    .svc-panel.open { display: flex !important; }
    .svc-panel .hd { color: #39c0ed; font-weight: 600; font-size: 16px; padding: 12px 16px 10px; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; flex-shrink: 0; gap: 12px; }
    .svc-panel .hd .close { cursor: pointer; color: #888; font-size: 24px; font-weight: bold; line-height: 1; }
    .svc-panel .hd .close:hover { color: #c9d1d9; }
    .svc-panel .body { overflow-y: auto; padding: 8px 14px 12px; flex: 1; }
    .svc-row { display: flex; align-items: center; gap: 10px; padding: 6px 0; line-height: 1.5; }
    .svc-row.hidden { display: none !important; }
    .svc-search { padding: 8px 14px; border-bottom: 1px solid #30363d; background: #161b22; }
    .svc-search input { width: 100%; padding: 8px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 13px; outline: none; box-sizing: border-box; }
    .svc-search input:focus { border-color: #39c0ed; box-shadow: 0 0 0 2px rgba(57, 192, 237, 0.2); }
    .svc-search input::placeholder { color: #6e7681; }
    .svc-badge { display: inline-block; width: 22px; height: 22px; line-height: 22px; text-align: center; border-radius: 4px; font-size: 12px; font-weight: 700; flex-shrink: 0; }
    .svc-badge.D { background: #0d419d; color: #79c0ff; }
    .svc-badge.S { background: #1a4d2e; color: #7ee787; }
    .svc-name { flex: 1; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-size: 13px; }
    .svc-status { font-size: 11px; text-transform: uppercase; flex-shrink: 0; font-weight: 600; }
    .svc-empty { color: #888; font-size: 14px; padding: 8px 0; }
  </style>
  <defs>
    <marker id="arrow-out" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L0,8 L8,4 z" fill="#39c0ed" /></marker>
    <marker id="arrow-in" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L0,8 L8,4 z" fill="#7ee787" /></marker>
    <marker id="arrow-proxy" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L0,8 L8,4 z" fill="#a855f7" /></marker>
  </defs>
  <g id="viewport">
  <text x="{{.CenterX}}" y="35" fill="#f0f6fc" font-size="22" font-weight="600" text-anchor="middle">Network Topology — {{.Subnet}}.0 · {{.WindowKey}}</text>
  {{template "timeTabs" .}}
  <text x="{{.CenterX}}" y="122" fill="#8b949e" font-size="12" text-anchor="middle">{{.Timestamp}} · Hosts: {{.HostsCount}} · Containers: {{.ContainersCount}} · Connections: {{.ConnsCount}}</text>
  <g transform="translate(20, {{.LegendY}})">
    <rect x="0" y="0" width="280" height="90" rx="6" fill="#1c2128" stroke="#30363d" stroke-width="1" opacity="0.9"/>
    <line x1="15" y1="18" x2="40" y2="18" stroke="#39c0ed" stroke-width="2" marker-end="url(#arrow-out)"/>
    <text x="50" y="22" fill="#39c0ed" font-size="11">Outbound ({{.OutboundCount}})</text>
    <line x1="15" y1="38" x2="40" y2="38" stroke="#7ee787" stroke-width="2" marker-end="url(#arrow-in)"/>
    <text x="50" y="42" fill="#7ee787" font-size="11">Inbound ({{.InboundCount}})</text>
    <line x1="15" y1="58" x2="40" y2="58" stroke="#a855f7" stroke-width="2" marker-end="url(#arrow-proxy)"/>
    <text x="50" y="62" fill="#a855f7" font-size="11">Reverse Proxy</text>
    <line x1="15" y1="78" x2="40" y2="78" stroke="#8b949e" stroke-width="2" stroke-dasharray="4,4"/>
    <text x="50" y="82" fill="#8b949e" font-size="11">Hosted by (Docker)</text>
  </g>
  {{range .HostingLines}}
  <line class="hosting-line" data-host="{{.HostID}}" x1="{{.X1}}" y1="{{.Y1}}" x2="{{.X2}}" y2="{{.Y2}}" stroke="#8b949e" stroke-width="1.5" />
  {{end}}
  {{range .Edges}}
  {{if .Clickable}}<a href="{{.TargetURL}}" onclick="navigateTo('{{.TargetURL}}'); return false;">{{end}}
  <g class="edge-group">
    <line class="edge-hit{{if .IsContainer}} hidden{{end}}" data-src="{{.Src}}" data-dst="{{.Dst}}"{{if .IsContainer}} data-container-host="{{.ContainerHostID}}"{{end}} x1="{{.X1}}" y1="{{.Y1}}" x2="{{.X2}}" y2="{{.Y2}}" stroke="transparent" stroke-width="14"></line>
    <path class="edge-line{{if .IsContainer}} hidden{{end}}" data-src="{{.Src}}" data-dst="{{.Dst}}"{{if .IsContainer}} data-container-host="{{.ContainerHostID}}"{{end}} d="M{{.X1}},{{.Y1}} Q{{.Mx}},{{.My}} {{.X2}},{{.Y2}}" fill="none" stroke="{{.Color}}" stroke-width="1.5" marker-end="{{.Marker}}" opacity="0.6" onmouseover="highlightEdge(this,true)" onmouseout="highlightEdge(this,false)"{{if .Clickable}} style="cursor:pointer;"{{end}}></path>
    <g class="edge-info" transform="translate({{.Mx}},{{.My}})" style="opacity:0;pointer-events:none;">
      <rect x="{{.LabelX}}" y="-11" width="{{.LabelWidth}}" height="22" rx="4" fill="#1c2128" stroke="{{.Color}}" stroke-width="1" />
      <text x="0" y="4" fill="#c9d1d9" font-size="10" font-weight="500" text-anchor="middle">{{escapeHTML .Label}}</text>
    </g>
    <title>{{.Src}} → {{.Dst}}&#10;Port: {{escapeHTML .Label}}{{if .Clickable}}&#10;Click: go to subnet {{.DstSubnet}}{{end}}</title>
  </g>
  {{if .Clickable}}</a>{{end}}
  {{end}}
  {{range .Nodes}}
  <g class="node-group" id="node-{{.NodeIDAttr}}">
    <circle class="node" data-name="{{.ID}}" cx="{{.X}}" cy="{{.Y}}" r="36" fill="{{.Fill}}" stroke="{{.Stroke}}" stroke-width="2" onclick="togglePanel(this, '{{.ID}}', 'panel')" onmouseover="highlightNode('{{.ID}}', true)" onmouseout="highlightNode('{{.ID}}', false)" />
    <text x="{{.X}}" y="{{.Y}}" fill="#c9d1d9" font-size="10" font-weight="600" text-anchor="middle" pointer-events="none">{{.DisplayName}}</text>
    {{if .IsProxy}}
    <circle cx="{{add .X 36}}" cy="{{sub .Y 36}}" r="9" fill="#a855f7" stroke="#1c2128" stroke-width="2" pointer-events="none" />
    <text x="{{add .X 36}}" y="{{sub .Y 33}}" fill="#ffffff" font-size="10" font-weight="bold" text-anchor="middle" pointer-events="none">P</text>
    {{end}}
    {{if .HasContainers}}
    <g class="expand-btn" onclick="toggleContainers('{{.ID}}')" transform="translate({{add .X 36}},{{add .Y 36}})">
      <circle cx="0" cy="0" r="12" fill="#1c2128" stroke="#39c0ed" stroke-width="1.5" />
      <text id="expand-icon-{{.NodeIDAttr}}" x="0" y="4" fill="#39c0ed" font-size="14" font-weight="bold" text-anchor="middle" pointer-events="none">+</text>
      <text x="0" y="-16" fill="#8b949e" font-size="8" text-anchor="middle" pointer-events="none">{{.ContainerCount}} ctr</text>
    </g>
    {{end}}
  </g>
  {{end}}
  {{range .Containers}}
  <g class="container-node" data-host="{{.HostID}}" data-name="{{.ID}}" id="container-{{.NodeIDAttr}}">
    <rect class="node" data-name="{{.ID}}" x="{{sub .X 45}}" y="{{sub .Y 22}}" width="90" height="44" rx="5" fill="#1a2332" stroke="#0d419d" stroke-width="1.5" onmouseover="highlightNode('{{.ID}}', true)" onmouseout="highlightNode('{{.ID}}', false)" />
    {{if .IsProxy}}
    <circle cx="{{add .X 45}}" cy="{{sub .Y 22}}" r="9" fill="#a855f7" stroke="#1c2128" stroke-width="2" pointer-events="none" />
    <text x="{{add .X 45}}" y="{{sub .Y 19}}" fill="#ffffff" font-size="10" font-weight="bold" text-anchor="middle" pointer-events="none">P</text>
    {{end}}
    <text x="{{.X}}" y="{{sub .Y 4}}" fill="#79c0ff" font-size="10" font-weight="600" text-anchor="middle" pointer-events="none">{{.DisplayName}}</text>
    <text x="{{.X}}" y="{{add .Y 12}}" fill="#8b949e" font-size="9" text-anchor="middle" pointer-events="none">{{.CtrIP}}</text>
  </g>
  {{end}}
  </g>
  <foreignObject x="0" y="0" width="100%" height="100%" style="pointer-events: none; overflow: visible;">
    <div xmlns="http://www.w3.org/1999/xhtml" style="width: 100%; height: 100%; position: relative;">
      <div id="svc-panel" class="svc-panel"></div>
    </div>
  </foreignObject>
  <script type="text/javascript"><![CDATA[
  (function() {
    var SERVICES = {{.ServicesJSON}};
    var EDGE_INDEX = {};
    var NODE_INDEX = {};
    function buildIndexes() {
      document.querySelectorAll('.edge-line').forEach(function(l) {
        var s = l.getAttribute('data-src'), d = l.getAttribute('data-dst');
        (EDGE_INDEX[s] = EDGE_INDEX[s] || []).push(l);
        (EDGE_INDEX[d] = EDGE_INDEX[d] || []).push(l);
      });
      document.querySelectorAll('.node').forEach(function(n) {
        NODE_INDEX[n.getAttribute('data-name')] = n;
      });
    }
    var panelEl = document.getElementById('svc-panel');
    var panelHost = null;
    function statusColor(s) {
      s = (s || '').toLowerCase();
      if (s.indexOf('up') === 0 || s.indexOf('active') === 0 || s.indexOf('running') === 0 || s.indexOf('healthy') === 0) return '#7ee787';
      if (s === 'failed' || s === 'exited' || s === 'dead') return '#ff7b72';
      return '#8b949e';
    }
    function escapeHtml(s) {
      return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    function buildPanelHTML(host, svcs) {
      var docker = 0, sysd = 0; var rows = '';
      if (!svcs || !svcs.length) { rows = '<div class="svc-empty">No services detected</div>'; }
      else {
        for (var i = 0; i < svcs.length; i++) {
          var t = svcs[i][0], name = svcs[i][1], status = svcs[i][2];
          if (t === 'docker') docker++; else sysd++;
          var badgeCls = (t === 'docker') ? 'D' : 'S';
          var sc = statusColor(status);
          rows += '<div class="svc-row" data-name="' + escapeHtml(name).toLowerCase() + '"><span class="svc-badge ' + badgeCls + '">' + badgeCls + '</span><span class="svc-name" title="' + escapeHtml(name) + '">' + escapeHtml(name) + '</span><span class="svc-status" style="color:' + sc + '">' + escapeHtml(status) + '</span></div>';
        }
      }
      return '<div class="hd"><span>' + escapeHtml(host) + '</span><span style="font-size:10px;color:#666;">' + docker + 'D · ' + sysd + 'S</span><span class="close" onclick="closePanel()">×</span></div><div class="svc-search"><input type="text" id="svc-search-input" placeholder="Search services..." oninput="filterServices(this.value)"></div><div class="body">' + rows + '</div>';
    }
    function filterServices(query) {
      var rows = document.querySelectorAll('.svc-row');
      var q = query.toLowerCase().trim();
      if (!q) { rows.forEach(function(row) { row.classList.remove('hidden'); }); return; }
      rows.forEach(function(row) {
        var name = row.getAttribute('data-name');
        if (name && name.indexOf(q) !== -1) { row.classList.remove('hidden'); } else { row.classList.add('hidden'); }
      });
    }
    window.togglePanel = function(nodeEl, nodeName, panelId) {
      if (!panelEl) { console.error("Panel element not found!"); return; }
      if (event) event.stopPropagation();
      if (panelHost === nodeName) { closePanel(); return; }
      panelEl.innerHTML = buildPanelHTML(nodeName, SERVICES[nodeName] || []);
      panelEl.classList.add('open');
      panelEl.style.width = '600px'; panelEl.style.maxWidth = '700px';
      var rect = nodeEl.getBoundingClientRect();
      var left = rect.right + 20; var top = rect.top - 50;
      if (left + 600 > window.innerWidth) left = rect.left - 620;
      if (left < 10) left = 10; if (top < 10) top = 10;
      panelEl.style.left = left + 'px'; panelEl.style.top = top + 'px';
      setTimeout(function() { var searchInput = document.getElementById('svc-search-input'); if (searchInput) searchInput.focus(); }, 50);
      panelHost = nodeName; highlightNode(nodeName, true);
    };
    window.closePanel = function() {
      if (!panelEl) return;
      panelEl.classList.remove('open'); panelEl.innerHTML = '';
      if (panelHost) { highlightNode(panelHost, false); panelHost = null; }
    };
    window.highlightNode = function(nodeName, active) {
      if (!active && panelHost && panelHost !== nodeName) return;
      if (active) {
        document.querySelectorAll('.edge-line').forEach(function(l) { if (!l.classList.contains('hidden')) { l.style.opacity = '0.1'; l.style.strokeWidth = '1.5'; } });
        document.querySelectorAll('.node').forEach(function(n) { n.style.opacity = '0.2'; });
        var self = NODE_INDEX[nodeName];
        if (self) { self.style.opacity = '1'; self.classList.add('active'); }
        var related = EDGE_INDEX[nodeName] || [];
        related.forEach(function(l) {
          if (l.classList.contains('hidden')) return;
          l.style.opacity = '1'; l.style.strokeWidth = '3';
          var info = l.parentElement.querySelector('.edge-info');
          if (info) info.style.opacity = '1';
        });
        related.forEach(function(l) {
          var s = l.getAttribute('data-src'), d = l.getAttribute('data-dst');
          var other = (s === nodeName) ? d : s;
          var on = NODE_INDEX[other];
          if (on) on.style.opacity = '1';
        });
      } else {
        document.querySelectorAll('.edge-line').forEach(function(l) { if (!l.classList.contains('hidden')) { l.style.opacity = '0.6'; l.style.strokeWidth = '1.5'; } var info = l.parentElement.querySelector('.edge-info'); if (info) info.style.opacity = '0'; });
        document.querySelectorAll('.node').forEach(function(n) { n.style.opacity = '1'; n.classList.remove('active'); });
      }
    };
    window.highlightEdge = function(line, active) {
      var s = line.getAttribute('data-src'), d = line.getAttribute('data-dst');
      var ns = NODE_INDEX[s], nd = NODE_INDEX[d];
      if (active) { if (ns) ns.style.opacity = '1'; if (nd) nd.style.opacity = '1'; }
      else { if (!panelHost) { if (ns) ns.style.opacity = '1'; if (nd) nd.style.opacity = '1'; } }
      var info = line.parentElement.querySelector('.edge-info');
      if (info) info.style.opacity = active ? '1' : '0';
    };
    var expandedHosts = {};
    window.toggleContainers = function(hostName) {
      if (event) event.stopPropagation();
      var isExpanded = expandedHosts[hostName];
      var safeHost = hostName.replace(/"/g, '\\"');
      document.querySelectorAll('.container-node[data-host="' + safeHost + '"]').forEach(function(c) { c.classList.toggle('visible', !isExpanded); });
      document.querySelectorAll('.hosting-line[data-host="' + safeHost + '"]').forEach(function(l) { l.classList.toggle('visible', !isExpanded); });
      document.querySelectorAll('.edge-line, .edge-hit').forEach(function(el) { if (el.getAttribute('data-container-host') === hostName) { el.classList.toggle('hidden', isExpanded); } });
      var nodes = document.querySelectorAll('.node-group');
      nodes.forEach(function(g) {
        var circle = g.querySelector('.node');
        if (circle && circle.getAttribute('data-name') === hostName) { var icon = g.querySelector('.expand-btn text'); if (icon) icon.textContent = isExpanded ? '+' : '−'; }
      });
      expandedHosts[hostName] = !isExpanded;
    };
    window.navigateTo = function(url) {
      if (event) event.stopPropagation();
      var u = new URL(url, window.location.href);
      var token = new URLSearchParams(window.location.search).get('token');
      if (token && !u.searchParams.has('token')) u.searchParams.set('token', token);
      u.searchParams.set('nocache', Date.now());
      window.location.href = u.toString();
    };
    document.addEventListener('click', function(evt) {
      var t = evt.target;
      if (t.closest('#svc-panel')) return;
      if (t.closest('.node-group') || t.closest('.edge-group')) return;
      if (panelHost) closePanel();
    });
    document.addEventListener('keydown', function(evt) {
      if (evt.key === 'Escape') {
        var searchInput = document.getElementById('svc-search-input');
        if (searchInput && document.activeElement === searchInput) { searchInput.value = ''; filterServices(''); evt.stopPropagation(); }
        else if (panelHost) { closePanel(); }
      }
    });
    var svgEl = document.querySelector('svg');
    var vp = document.getElementById('viewport');
    var scale = 1, tx = 0, ty = 0;
    function upd() { vp.setAttribute('transform', 'translate(' + tx + ',' + ty + ') scale(' + scale + ')'); }
    svgEl.addEventListener('wheel', function(ev) {
      ev.preventDefault();
      var d = ev.deltaY > 0 ? -0.15 : 0.15;
      var ns = Math.max(0.2, Math.min(6, scale + d));
      if (ns !== scale) {
        var pt = svgEl.createSVGPoint(); pt.x = ev.clientX; pt.y = ev.clientY;
        var sp = pt.matrixTransform(svgEl.getScreenCTM().inverse());
        var f = ns / scale;
        tx = sp.x - f * (sp.x - tx); ty = sp.y - f * (sp.y - ty);
        scale = ns; upd();
      }
    }, {passive: false});
    var panning = false, startX = 0, startY = 0;
    svgEl.addEventListener('mousedown', function(ev) {
      if (ev.target.closest('a') || ev.target.closest('[onclick]')) return;
      panning = true; startX = ev.clientX - tx; startY = ev.clientY - ty; svgEl.style.cursor = 'grabbing';
    });
    svgEl.addEventListener('mousemove', function(ev) {
      if (!panning) return; ev.preventDefault();
      tx = ev.clientX - startX; ty = ev.clientY - startY; upd();
    });
    svgEl.addEventListener('mouseup', function() { panning = false; svgEl.style.cursor = 'default'; });
    svgEl.addEventListener('mouseleave', function() { panning = false; svgEl.style.cursor = 'default'; });
    buildIndexes();
  })();
  ]]></script>
</svg>
{{define "timeTabs"}}
  <g class="time-tabs">
    <g class="back-btn" onclick="history.back(); return false;" style="cursor:pointer;">
      <rect x="{{sub .CenterX 205}}" y="78" width="70" height="24" rx="6" fill="#1c2128" stroke="#30363d" stroke-width="1"/>
      <text x="{{sub .CenterX 170}}" y="94" fill="#8b949e" font-size="11" font-weight="600" text-anchor="middle">← Back</text>
    </g>
    {{$x := (sub .CenterX 127)}}
    {{$tabW := 52.0}}
    {{$gap := 6.0}}
    {{range $i, $tw := .TimeWindows}}
      {{if eq $tw.Key $.WindowKey}}
        <rect x="{{$x}}" y="78" width="{{$tabW}}" height="24" rx="6" fill="#39c0ed" opacity="0.95"/>
        <text x="{{add $x 26}}" y="94" fill="#0b0d10" font-size="11" font-weight="700" text-anchor="middle" pointer-events="none">{{$tw.Key}}</text>
      {{else}}
        <a href="./map_{{$.Subnet}}_{{$tw.Key}}.svg" onclick="navigateTo('./map_{{$.Subnet}}_{{$tw.Key}}.svg'); return false;">
          <rect x="{{$x}}" y="78" width="{{$tabW}}" height="24" rx="6" fill="#1c2128" stroke="#30363d" stroke-width="1"/>
          <text x="{{add $x 26}}" y="94" fill="#8b949e" font-size="11" font-weight="600" text-anchor="middle">{{$tw.Key}}</text>
        </a>
      {{end}}
      {{$x = (add $x (add $tabW $gap))}}
    {{end}}
  </g>
{{end}}`

var svgTmpl *template.Template

func init() {
        funcMap := template.FuncMap{
                "add":        func(a, b float64) float64 { return a + b },
                "sub":        func(a, b float64) float64 { return a - b },
                "escapeHTML": func(s string) string { return html.EscapeString(s) },
        }
        svgTmpl = template.Must(template.New("map").Funcs(funcMap).Parse(svgTemplate))
}


func renderSVG(subnet, windowKey string, conns []ResolvedConn, services map[string][]Service, localHosts map[string]bool, containerToHost map[string]string, hosts []string) error {
	coords, _ := layoutHosts(hosts, 0, 0)
	minX, maxX, minY, maxY := 0.0, 0.0, 0.0, 0.0
	first := true
	for _, c := range coords {
		if first {
			minX, maxX, minY, maxY = c.X, c.X, c.Y, c.Y
			first = false
		} else {
			if c.X < minX {
				minX = c.X
			}
			if c.X > maxX {
				maxX = c.X
			}
			if c.Y < minY {
				minY = c.Y
			}
			if c.Y > maxY {
				maxY = c.Y
			}
		}
	}
	margin := 320.0
	canvasW := math.Max(1800, (maxX-minX)+2*margin)
	canvasH := math.Max(1200, (maxY-minY)+2*margin+200)
	centerX := canvasW / 2
	centerY := canvasH/2 + 60
	cx0 := (minX + maxX) / 2
	cy0 := (minY + maxY) / 2
	finalCoords := make(map[string]Coord)
	for h, c := range coords {
		finalCoords[h] = Coord{X: centerX + (c.X - cx0), Y: centerY + (c.Y - cy0)}
	}
	hostContainers := make(map[string][]string)
	for cont, host := range containerToHost {
		hostContainers[host] = append(hostContainers[host], cont)
	}
	containerCoords := make(map[string]Coord)
	for host, contList := range hostContainers {
		hc, ok := finalCoords[host]
		if !ok {
			hc = Coord{X: centerX, Y: centerY}
		}
		outDX := hc.X - centerX
		outDY := hc.Y - centerY
		outLen := math.Hypot(outDX, outDY)
		if outLen == 0 {
			outLen = 1.0
		}
		ox, oy := outDX/outLen, outDY/outLen
		px, py := -oy, ox
		n := len(contList)
		spread := math.Min(CONTAINER_RADIUS, 30+float64(n)*14)
		for i, c := range contList {
			t := 0.0
			if n > 1 {
				t = (float64(i) - (float64(n-1) / 2)) / math.Max(1, float64(n-1)/2)
			}
			base := CONTAINER_RADIUS + float64(i%2)*16
			containerCoords[c] = Coord{X: hc.X + ox*base + px*t*spread, Y: hc.Y + oy*base + py*t*spread}
		}
	}
	data := RenderData{
		ViewW: canvasW, ViewH: canvasH, LegendY: canvasH - 100,
		CenterX: centerX, CenterY: centerY, Subnet: subnet, WindowKey: windowKey,
		Timestamp:  time.Now().Format("2006-01-02 15:04:05"),
		HostsCount: len(hosts), ContainersCount: len(containerToHost),
		ConnsCount: len(conns), TimeWindows: TIME_WINDOWS,
	}
	servicesCompact := make(map[string][][]string)
	for host, svcs := range services {
		if len(svcs) > 0 {
			sort.Slice(svcs, func(i, j int) bool {
				if svcs[i].Type == "docker" && svcs[j].Type != "docker" {
					return true
				}
				if svcs[i].Type != "docker" && svcs[j].Type == "docker" {
					return false
				}
				return svcs[i].Status == "running" || svcs[i].Status == "active"
			})
			limit := 100
			if len(svcs) < limit {
				limit = len(svcs)
			}
			var compact [][]string
			for i := 0; i < limit; i++ {
				compact = append(compact, []string{svcs[i].Type, svcs[i].Name, svcs[i].Status})
			}
			servicesCompact[host] = compact
		}
	}
	svcJSON, _ := json.Marshal(servicesCompact)
	data.ServicesJSON = string(svcJSON)
	proxyNodes := detectProxies(conns, localHosts)
	for cont, host := range containerToHost {
		hc, hOk := finalCoords[host]
		cc, cOk := containerCoords[cont]
		if hOk && cOk {
			data.HostingLines = append(data.HostingLines, HostingLineData{
				HostID: jsStr(host), X1: hc.X, Y1: hc.Y, X2: cc.X, Y2: cc.Y,
			})
		}
	}
	webProxyPorts := map[int]bool{
		80: true, 443: true, 8000: true, 8008: true, 8080: true, 8081: true,
		8082: true, 8088: true, 8090: true, 8099: true, 8443: true, 8888: true,
		8889: true, 9080: true, 1080: true, 1081: true, 3128: true, 3129: true,
		3130: true, 4000: true, 4001: true, 15001: true, 15006: true, 15021: true,
		15090: true, 8001: true, 8444: true, 1936: true, 8404: true, 2019: true,
	}
	skippedNoCoords := 0
	drawnInbound := 0
	drawnTotal := 0
	edgeIdx := 0
	for _, c := range conns {
		srcCoord, srcOk := finalCoords[c.Src]
		if !srcOk {
			srcCoord, srcOk = containerCoords[c.Src]
		}
		dstCoord, dstOk := finalCoords[c.Dst]
		if !dstOk {
			dstCoord, dstOk = containerCoords[c.Dst]
		}
		if !srcOk || !dstOk {
			skippedNoCoords++
			continue
		}
		dist := math.Hypot(dstCoord.X-srcCoord.X, dstCoord.Y-srcCoord.Y)
		if dist < 1 {
			continue
		}
		srcR := 25.0
		if _, isCtr := containerCoords[c.Src]; !isCtr {
			srcR = NODE_R
		}
		dstR := 25.0
		if _, isCtr := containerCoords[c.Dst]; !isCtr {
			dstR = NODE_R
		}
		sx2 := srcCoord.X + (dstCoord.X-srcCoord.X)*srcR/dist
		sy2 := srcCoord.Y + (dstCoord.Y-srcCoord.Y)*srcR/dist
		dx2 := dstCoord.X - (dstCoord.X-srcCoord.X)*dstR/dist
		dy2 := dstCoord.Y - (dstCoord.Y-srcCoord.Y)*dstR/dist
		portInt, _ := strconv.Atoi(c.Port)
		isProxyDst := proxyNodes[c.Dst]
		isProxySrc := proxyNodes[c.Src]
		isActualProxyDst := isProxyDst && webProxyPorts[portInt]
		dir := strings.TrimSpace(c.Direction)
		if dir == "1" || dir == "inbound" {
			data.InboundCount++
			drawnInbound++
		} else {
			data.OutboundCount++
		}
		var color, marker string
		if dir == "1" || dir == "inbound" {
			color, marker = "#7ee787", "url(#arrow-in)"
		} else if isActualProxyDst {
			color, marker = "#a855f7", "url(#arrow-proxy)"
		} else if isProxySrc {
			color, marker = "#39c0ed", "url(#arrow-out)"
		} else {
			color, marker = "#39c0ed", "url(#arrow-out)"
		}
		offset := float64((edgeIdx%5 - 2) * 12)
		mx := (sx2+dx2)/2 + (dy2-sy2)*offset/dist
		my := (sy2+dy2)/2 - (dx2-sx2)*offset/dist
		isCtrEdge := false
		ctrHost := ""
		if _, ok := containerCoords[c.Src]; ok {
			isCtrEdge = true
			ctrHost = containerToHost[c.Src]
		} else if _, ok := containerCoords[c.Dst]; ok {
			isCtrEdge = true
			ctrHost = containerToHost[c.Dst]
		}
		label := fmt.Sprintf("%s:%s", c.Port, c.Service)
		lw := math.Max(50, float64(len(label)*7+16))
		labelX := -lw / 2.0
		clickable := false
		targetURL := ""
		if c.DstSubnet != "" && c.DstSubnet != subnet {
			targetPath := mapPath(c.DstSubnet, windowKey)
			if _, err := os.Stat(targetPath); err == nil {
				clickable = true
				targetURL = fmt.Sprintf("./map_%s_%s.svg", c.DstSubnet, windowKey)
			}
		}
		data.Edges = append(data.Edges, EdgeData{
			X1: sx2, Y1: sy2, X2: dx2, Y2: dy2, Mx: mx, My: my,
			Color: color, Marker: marker, Label: label, LabelWidth: lw, LabelX: labelX,
			Src: jsStr(c.Src), Dst: jsStr(c.Dst), DstSubnet: c.DstSubnet,
			Clickable: clickable, TargetURL: targetURL, IsContainer: isCtrEdge,
			ContainerHostID: jsStr(ctrHost),
		})
		drawnTotal++
		edgeIdx++
	}
	fmt.Printf("DEBUG: Total resolved: %d | Skipped (no coords): %d | Drawn total: %d | Drawn inbound: %d\n",
		len(conns), skippedNoCoords, drawnTotal, drawnInbound)
	for _, h := range hosts {
		c := finalCoords[h]
		isHost := localHosts[h]
		stroke, fill := "#39c0ed", "#1a2332"
		if !isHost {
			stroke, fill = "#ffc107", "#2a2215"
		}
		id := jsStr(h)
		displayName := cleanName(h)
		if len(displayName) > 14 {
			displayName = displayName[:12] + "…"
		}
		nodeIDAttr := strings.NewReplacer("::", "-", "||", "-", " ", "-", "/", "-").Replace(h)
		contCount := len(hostContainers[h])
		data.Nodes = append(data.Nodes, NodeData{
			X: c.X, Y: c.Y, ID: id, DisplayName: displayName,
			Stroke: stroke, Fill: fill, IsHost: isHost, IsProxy: proxyNodes[h],
			NodeIDAttr: nodeIDAttr, HasContainers: contCount > 0, ContainerCount: contCount,
		})
	}
	for cont, host := range containerToHost {
		c, ok := containerCoords[cont]
		if !ok {
			continue
		}
		parts := strings.Split(cont, "||")
		svcName := cont
		ctrIP := "unknown"
		if len(parts) == 2 {
			svcName = strings.Replace(parts[0], "CTR::", "", 1)
			ctrIP = parts[1]
		}
		displayName := svcName
		if len(displayName) > 14 {
			displayName = displayName[:14]
		}
		data.Containers = append(data.Containers, ContainerData{
			X: c.X, Y: c.Y, HostID: jsStr(host), ID: jsStr(cont),
			DisplayName: escapeHTML(displayName), CtrIP: escapeHTML(ctrIP),
			NodeIDAttr: strings.NewReplacer("::", "-", "||", "-", " ", "-", "/", "-").Replace(cont),
			IsProxy:    isProxy(svcName),
		})
	}
	outPath := mapPath(subnet, windowKey)
	file, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("ERROR: Сreate file: %w", err)
	}
	defer file.Close()
	if err := svgTmpl.Execute(file, data); err != nil {
		return fmt.Errorf("ERROR: Template execution - %w", err)
	}
	return nil
}

func main() {
	subnet := flag.String("subnet", "172.20.44", "Target subnet")
	window := flag.String("window", "", "Specific window (e.g., 24h)")
	flag.Parse()
        if !subnetRe.MatchString(*subnet) {
                fmt.Printf("ERROR: Invalid subnet format '%s'.\n", *subnet)
                fmt.Println("   Expected a three-octet format, e.g 172.20.44")
                os.Exit(1)
        }

        if !dbNameRe.MatchString(chDB) {
                fmt.Printf("ERROR: Invalid database name format '%s'.\n", chDB)
                fmt.Println("   Only Latin letters, digits, and the '_'. character are allowed")
                os.Exit(1)
        }

	fmt.Printf("Subnet: %s\n", *subnet)
	fmt.Println("  Initializing mTLS client...")
	client, err := createHTTPClient()
	if err != nil {
		fmt.Printf("ERROR: Initializing mTLS: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("   mTLS client create")

        os.MkdirAll(outputDir, 0755)
        var generated []string
        nowUnix := time.Now().Unix()

        for _, tw := range TIME_WINDOWS {
                if *window != "" && *window != tw.Key {
                        continue
                }

                fmt.Printf("  Processing %s window (fetching up to %d hours of data)...\n", tw.Key, tw.Hours)

                conns, err := fetchConnections(client, tw.Hours)
                if err != nil {
                        fmt.Printf("ERROR: Connections - %v\n", err)
                        continue // Пропускаем это окно, но не ломаем весь цикл
                }

                hbs, err := fetchHeartbeats(client, tw.Hours)
                if err != nil {
                        fmt.Printf("ERROR: Heartbeats - %v\n", err)
                        continue
                }

                svc, err := fetchServices(client, tw.Hours)
                if err != nil {
                        fmt.Printf("ERROR: Services - %v\n", err)
                        continue
                }

                ports, err := fetchPortToProcess(client, tw.Hours)
                if err != nil {
                        fmt.Printf("ERROR: Ports - %v\n", err)
                        continue
                }

                // buildWindowData теперь получает уже отфильтрованные данные, 
                // но внутренняя проверка по времени (cutoff) останется как дополнительный рубеж защиты.
                data := buildWindowData(*subnet, tw.Hours, nowUnix, conns, hbs, svc, ports)
                resolved, containerToHost := resolveConnections(data.Conns, data)

                fmt.Printf("  [%3s] connections=%4d hosts=%d containers=%d\n", tw.Key, len(resolved), len(data.LocalHosts), len(containerToHost))

                hostSet := make(map[string]bool)
                for _, c := range resolved {
                        if _, isCtr := containerToHost[c.Src]; !isCtr {
                                hostSet[c.Src] = true
                        }
                        if _, isCtr := containerToHost[c.Dst]; !isCtr {
                                hostSet[c.Dst] = true
                        }
                }
                for host := range data.Services {
                        if _, isCtr := containerToHost[host]; !isCtr {
                                hostSet[host] = true
                        }
                }
                for _, host := range containerToHost {
                        hostSet[host] = true
                }

                var hosts []string
                for h := range hostSet {
                        hosts = append(hosts, h)
                }

                err = renderSVG(*subnet, tw.Key, resolved, data.Services, data.LocalHosts, containerToHost, hosts)
                if err != nil {
                        fmt.Printf("ERROR: Rendering %s: %v\n", tw.Key, err)
                        continue
                }

                outPath := mapPath(*subnet, tw.Key)
                info, _ := os.Stat(outPath)
                fmt.Printf("%s (%.1f KB)\n", outPath, float64(info.Size())/1024)
                generated = append(generated, tw.Key)
        }
        if len(generated) > 0 {
		defaultFile := mapPath(*subnet, DEFAULT_WINDOW)
		aliasFile := filepath.Join(outputDir, fmt.Sprintf("map_%s.svg", *subnet))
		os.Remove(aliasFile)
		os.Symlink(defaultFile, aliasFile)
		fmt.Printf(" alias: %s → %s\n", aliasFile, DEFAULT_WINDOW)
		fmt.Printf(" OK: %d map for %s\n", len(generated), *subnet)
	} else {
		fmt.Println("WARNING: Nothing generated.")
		os.Exit(1)
	}
}
