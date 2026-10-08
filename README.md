# ESTC Linux Agent
# IMAGE
<img width="1187" height="918" alt="image" src="https://github.com/user-attachments/assets/2afc3a53-9ccc-44a4-9386-f39b9f30e9b9" /><img width="1187" height="918" alt="image" src="https://github.com/user-attachments/assets/30ee16c6-616a-454c-bcb0-930e5e4edb16" /># ESTC Linux Agent
<img width="1187" height="918" alt="image" src="https://github.com/user-attachments/assets/9b72accf-673a-43ed-8706-78142264d453" />
<img width="877" height="782" alt="image" src="https://github.com/user-attachments/assets/c682ceab-cf33-40bb-8fd0-44431391c662" />

#      ENG

**Tech Stack:** Go 1.22+, eBPF (CO-RE), ClickHouse
**License:** GPL

ESTC - eBPF System Telemetry Collection

The ESTC Linux Agent is
a high-performance telemetry agent
operating at the Linux kernel level via eBPF. The agent
collects real-time metadata on network connections, system service status, and
containers with a computational overhead of less than 1%.

---

## Key Features

### 1. Network Telemetry (Network Tracking)
* Interception of all outgoing and incoming TCP/UDP connections via kprobes.
* Precise determination of traffic direction (inbound/outbound).
* Association of network connections with process IDs and names (PID/comm).
* Traffic tagging: automatic identification of whether the source or destination belongs to a container environment.

### 2. Service and Port Discovery (Listening Ports)
* Scanning and tracking of ports in the LISTEN state.
* Mapping open ports to the name of the owning process.

### 3. Infrastructure Monitoring (Docker & Systemd)
* Tracking Docker container lifecycles and port mappings.
* Monitoring systemd unit states (load_state, active_state, sub_state) to assess service availability on the host.

### 4. Agent Observability (Heartbeat)
* Regular transmission of availability signals (alive).
* Reporting of basic host metadata: hostname, IP address, agent version, and uptime. ---

## Architecture and Data Flow

The agent implements a three-tier data processing architecture:

1. **Kernel-space**
The agent loads eBPF programs attached to kernel tracepoints and kprobes. When a network event occurs, the program extracts the necessary data and passes it to user-space via an eBPF Ring Buffer.
2. **User-space**
* Loading and managing eBPF objects. 
* Reading events from the Ring Buffer. 
* Data enrichment: resolving inodes to PIDs/process names and determining container association via network namespace analysis. 
* Periodic polling of the Docker API and D-Bus (systemd). 
* Data batching and asynchronous transmission.
3. **Transport Layer**
* Protocol: HTTPS. 
* Security: Mutual authentication (mTLS). The agent authenticates with ClickHouse (port 9440) using client certificates. Server validation is performed via a CA certificate. The communication channel is fully cryptographically secured.

---

## Performance Optimizations

The agent's architecture is designed for stable operation in high-load production environments. The following technical solutions have been implemented:

* **Asynchronous Pipeline:** Data collection (reading the eBPF ring buffer) and transmission to the database are decoupled by buffered channels. Latency on the ClickHouse side does not block reading or cause eBPF ring buffer overflows.
* **O(1) Container Resolution:** Elimination of synchronous `netlink.RouteGet` calls in the hot path. Socket-to-container association is determined by an in-memory comparison of the `netns_ino` (network namespace inode).
* **Optimized `/proc` scanning:** Instead of executing thousands of `readlink` system calls for each connection, the agent performs a single scan of `/proc` per collection cycle, building an in-memory `inode -> PID` mapping.
* **Safe `sk_buff` reading:** In the eBPF program for incoming UDP traffic, header reading is performed via `skb->head + network_header`. This ensures compliance with eBPF verifier checks and correct handling of non-linear buffers (non-linear skbs).
* **Graceful Fallback:** Automatic fallback to parsing `/proc/net/*` files if the kernel lacks eBPF support.

---

## System Requirements

* **Operating System:** Linux.
* **Kernel:**
* `>= 5.8`: Recommended. Full eBPF CO-RE and BTF support. 
* `4.9 - 5.7`: Limited eBPF support (no BTF). 
* `< 4.9`: Automatic fallback mode (`/proc/net`).
* **Dependencies:** Read access to `/var/run/docker.sock` (optional; required only for collecting Docker metrics).

---

## Configuration and Startup

The agent is configured via command-line arguments.

| Flag          | Default Value | Description
| | |
| `-clickhouse` | `clickhouse://default:@localhost:9000/ESTC`
| | | DSN string for connecting to ClickHouse.
| `-ca-cert`    | `""`          | Path to the CA certificate (required for mTLS).
| `-client-cert`| `""`                  | Path to the client certificate (required for mTLS).
| `-client-key` | `""`                  | Path to the client private key (required for mTLS).
| `-interval`   | `30s`                 | Metric collection interval (systemd, Docker, listening ports).
| `-flush`      | `5s`                  | Interval for flushing eBPF event batches to the database.
| `-heartbeat`  | `30s`                 | Heartbeat sending interval.

---

## ClickHouse Data Schema

Upon initial startup, the agent automatically creates the necessary tables. The `MergeTree` engine is used. Data retention policy (TTL): 30 days for metrics, 7 days for heartbeats.

1. **`connections`**
Network connections. Columns: `hostname`, `timestamp`, `src_ip` (IPv4), `dst_ip` (IPv4), `src_port`, `dst_port`, `protocol` (Enum8), `direction` (Enum8), `pid`, `comm`, `service_comm`, `is_docker_src`, `is_docker_dst`.
2. **`listening_ports`**
Open (listening) ports. Columns: `hostname`, `timestamp`, `ip` (IPv4), `port`, `protocol` (Enum8), `pid`, `process`.
3. **`systemd_units`**
Systemd service states. Columns: `hostname`, `timestamp`, `name`, `type`, `load_state`, `active_state`, `sub_state`.
4. **`docker_containers`**
Docker container states. Columns: `hostname`, `timestamp`, `id`, `name`, `image`, `state`, `status`, `ports`.
5. **`agent_heartbeat`**
Agent status. Columns: `hostname`, `ip` (IPv4), `timestamp`, `status`, `version`, `uptime`.

#      RUS
**Стек технологий:** Go 1.22+, eBPF (CO-RE), ClickHouse
**Лицензия:** GPL

ESTC - eBPF System Telemetry Collection

ESTC Linux Agent —
        это высокопроизводительный агент телеметрии
        работающий на уровне ядра Linux посредством eBPF. Агент осуществляет
        сбор метаданных о сетевых соединениях, состоянии системных сервисов и
        контейнеров в реальном времени с вычислительными накладными расходами (overhead) менее 1%.

---

## Основные возможности

### 1. Сетевая телеметрия (Network Tracking)
* Перехват всех исходящих и входящих TCP/UDP соединений через kprobes.
* Точное определение направления трафика (inbound/outbound).
* Связь сетевого соединения с идентификатором и именем процесса (PID/comm).
* Маркировка трафика: автоматическое определение принадлежности источника или получателя к контейнерной среде.

### 2. Обнаружение сервисов и портов (Listening Ports)
* Сканирование и отслеживание портов, находящихся в состоянии LISTEN.
* Сопоставление открытого порта с именем владеющего процесса.

### 3. Мониторинг инфраструктуры (Docker & Systemd)
* Отслеживание жизненного цикла Docker-контейнеров и маппинг их портов.
* Мониторинг состояний systemd-юнитов (load_state, active_state, sub_state) для оценки доступности сервисов на хосте.

### 4. Наблюдаемость агента (Heartbeat)
* Регулярная отправка сигналов доступности (alive).
* Передача базовых метаданных хоста: hostname, IP-адрес, версия агента, uptime.

---

## Архитектура и поток данных

Агент реализует трехуровневую архитектуру обработки данных:

1. **Kernel-space (Ядро)**
   Агент загружает eBPF-программы, прикрепляемые к kernel tracepoints и kprobes. При возникновении сетевого события программа извлекает необходимые данные и передает их в user-space через eBPF Ring Buffer.
2. **User-space (Пользовательское пространство)**
   * Загрузка и управление eBPF-объектами.
   * Чтение событий из Ring Buffer.
   * Обогащение данных: преобразование inode в PID/имя процесса, определение принадлежности к контейнеру через анализ network namespace.
   * Периодический опрос Docker API и D-Bus (systemd).
   * Агрегация данных в батчи и асинхронная отправка.
3. **Transport Layer (Транспорт)**
   * Протокол: HTTPS.
   * Безопасность: Двусторонняя аутентификация (mTLS). Агент аутентифицируется на стороне ClickHouse (порт 9440) с использованием клиентских сертификатов. Валидация сервера осуществляется через CA-сертификат. Канал связи полностью криптографически защищен.

---

## Оптимизации производительности

Архитектура агента спроектирована для стабильной работы в высоконагруженных продакшен-средах. Реализованы следующие технические решения:

* **Асинхронный конвейер (Pipeline):** Сбор данных (чтение eBPF ringbuf) и отправка в базу данных разделены буферизированными каналами. Задержки на стороне ClickHouse не приводят к блокировке чтения и переполнению eBPF ring buffer.
* **O(1) определение контейнеров:** Отказ от синхронных вызовов `netlink.RouteGet` в горячем пути. Принадлежность сокета к контейнеру определяется мгновенным сравнением `netns_ino` (inode сетевого пространства имен) в памяти.
* **Оптимизированное сканирование `/proc`:** Вместо выполнения тысяч системных вызовов `readlink` для каждого соединения, агент выполняет единое сканирование `/proc` один раз за цикл сбора, строя в памяти карту соответствия `inode -> PID`.
* **Безопасное чтение `sk_buff`:** В eBPF-программе для входящего UDP-трафика чтение заголовков выполняется через `skb->head + network_header`. Это гарантирует прохождение проверок eBPF-верификатора и корректную работу с нелинейными буферами (non-linear skbs).
* **Graceful Fallback:** Автоматический переход на парсинг файлов `/proc/net/*` при отсутствии поддержки eBPF в ядре.

---

## Системные требования

* **Операционная система:** Linux.
* **Ядро:**
  * `>= 5.8`: Рекомендуется. Полная поддержка eBPF CO-RE и BTF.
  * `4.9 - 5.7`: Ограниченная поддержка eBPF (без BTF).
  * `< 4.9`: Автоматический переход в режим fallback (`/proc/net`).
* **Зависимости:** Доступ на чтение к `/var/run/docker.sock` (опционально, требуется только для сбора метрик Docker).

---

## Конфигурация и запуск

Агент конфигурируется через аргументы командной строки.

| Флаг          | Значение по умолчанию | Описание
|               |                       |
| `-clickhouse` | `clickhouse://default:@localhost:9000/ESTC`
|               |                       | DSN-строка для подключения к ClickHouse.
| `-ca-cert`    | `""`                  | Путь к CA-сертификату (обязательно для mTLS).
| `-client-cert`| `""`                  | Путь к клиентскому сертификату (обязательно для mTLS).
| `-client-key` | `""`                  | Путь к приватному ключу клиента (обязательно для mTLS).
| `-interval`   | `30s`                 | Интервал сбора метрик (systemd, docker, listening ports).
| `-flush`      | `5s`                  | Интервал принудительного сброса (flush) батчей eBPF-событий в БД.
| `-heartbeat`  | `30s`                 | Интервал отправки heartbeat-сигналов.

**Пример запуска:**
```bash
./estc \
  -clickhouse="clickhouse://user:pass@ch-server:9440/monitoring?secure=true" \
  -ca-cert="/etc/estc/ca.crt" \
  -client-cert="/etc/estc/client.crt" \
\n  -client-key="/etc/estc/client.key" \
  -interval=30s \
  -flush=5s
```

## Схема данных в ClickHouse

При первом запуске агент автоматически создает необходимые таблицы. Используется движок `MergeTree`. Политика хранения данных (TTL): 30 дней для метрик, 7 дней для heartbeat.

1. **`connections`**
   Сетевые соединения. Столбцы: `hostname`, `timestamp`, `src_ip` (IPv4), `dst_ip` (IPv4), `src_port`, `dst_port`, `protocol` (Enum8), `direction` (Enum8), `pid`, `comm`, `service_comm`, `is_docker_src`, `is_docker_dst`.
2. **`listening_ports`**
   Открытые (слушающие) порты. Столбцы: `hostname`, `timestamp`, `ip` (IPv4), `port`, `protocol` (Enum8), `pid`, `process`.
3. **`systemd_units`**
   Состояния systemd-сервисов. Столбцы: `hostname`, `timestamp`, `name`, `type`, `load_state`, `active_state`, `sub_state`.
4. **`docker_containers`**
   Состояние Docker-контейнеров. Столбцы: `hostname`, `timestamp`, `id`, `name`, `image`, `state`, `status`, `ports`.
5. **`agent_heartbeat`**
   Статус агента. Столбцы: `hostname`, `ip` (IPv4), `timestamp`, `status`, `version`, `uptime`.
