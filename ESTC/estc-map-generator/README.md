
# Build
go clean -cache
go build -o estc-map-generator main.go

# RUN
CLICKHOUSE_PASS="PASS_PASS" ./estc-map-generator --subnet="IP(172.16.1)" --window 1h (4h,8h,16h,24h,2h,4h,7h)

# VAR
CLICKHOUSE_PASS="PASS_PASS"
CLICKHOUSE_HOST="127.0.0.1"
CLICKHOUSE_PORT="8443"
CLICKHOUSE_DB="ESTC"
CLICKHOUSE_USER="estc_agent"
MAP_OUTPUT_DIR="/opt/sds-docker/network_map/map/"
CH_CA_CERT="/opt/sds-docker/network_map/certs/ca.crt"
CH_CLIENT_CERT="/opt/sds-docker/network_map/certs/client.crt"
CH_CLIENT_KEY="/opt/sds-docker/network_map/certs/client.key"
