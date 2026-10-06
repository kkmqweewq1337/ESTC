-- Создаем базу данных, если её ещё нет
CREATE DATABASE IF NOT EXISTS ESTC;

-- ============================================================
-- Создание пользователя и назначение прав
-- ============================================================
-- Создаем пользователя estc_agent со стандартным паролем
CREATE USER IF NOT EXISTS estc_agent IDENTIFIED WITH plaintext_password BY 'PASS_PASS';

-- Выдаем права на создание таблиц (необходимо для работы функции InitTables в Go-агенте)
GRANT CREATE TABLE ON ESTC.* TO estc_agent;

-- Выдаем права на вставку данных (основная задача агента)
GRANT INSERT ON ESTC.* TO estc_agent;

-- Выдаем права на чтение (может понадобиться агенту для проверок или будущих фич)
GRANT SELECT ON ESTC.* TO estc_agent;


-- ============================================================
-- 1. Таблица сетевых соединений (основная)
-- ============================================================
CREATE TABLE IF NOT EXISTS ESTC.connections (
    hostname      LowCardinality(String),
    timestamp     DateTime,
    src_ip        IPv4,
    dst_ip        IPv4,
    src_port      UInt16,
    dst_port      UInt16,
    protocol      Enum8('TCP' = 6, 'UDP' = 17),
    direction     Enum8('outbound' = 0, 'inbound' = 1),
    pid           UInt32,
    comm          LowCardinality(String),
    service_comm  LowCardinality(String),
    is_docker_src UInt8,
    is_docker_dst UInt8
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, timestamp, protocol, direction)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- 2. Таблица слушающих портов
-- ============================================================
CREATE TABLE IF NOT EXISTS ESTC.listening_ports (
    hostname   LowCardinality(String),
    timestamp  DateTime,
    ip         IPv4,
    port       UInt16,
    protocol   Enum8('TCP' = 6, 'UDP' = 17),
    pid        UInt32,
    process    LowCardinality(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, timestamp, port, protocol)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- 3. Таблица systemd юнитов
-- ============================================================
CREATE TABLE IF NOT EXISTS ESTC.systemd_units (
    hostname     LowCardinality(String),
    timestamp    DateTime,
    name         LowCardinality(String),
    type         LowCardinality(String),
    load_state   LowCardinality(String),
    active_state LowCardinality(String),
    sub_state    LowCardinality(String)
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, timestamp, name)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- 4. Таблица Docker контейнеров
-- ============================================================
CREATE TABLE IF NOT EXISTS ESTC.docker_containers (
    hostname  LowCardinality(String),
    timestamp DateTime,
    id        String,
    name      LowCardinality(String),
    image     LowCardinality(String),
    state     LowCardinality(String),
    status    String,
    ports     String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, timestamp, name)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ============================================================
-- 5. Таблица heartbeat (сигналы жизни агента)
-- Храним меньше, так как записей очень много, а история не так важна
-- ============================================================
CREATE TABLE IF NOT EXISTS ESTC.agent_heartbeat (
    hostname  LowCardinality(String),
    ip        IPv4,
    timestamp DateTime,
    status    LowCardinality(String),
    version   String,
    uptime    Int64
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (hostname, timestamp)
TTL timestamp + INTERVAL 7 DAY
SETTINGS index_granularity = 8192;
