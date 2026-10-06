# Else ClickHouse local:
clickhouse-client --multiquery < init_estc.sql

# Else remote:
clickhouse-client --host "IPADDRES" --port 9000 --multiquery < init_estc.sql

# HTTP INIT
curl -X POST 'http://"IPADDRESS":8123/' --data-binary @init_estc.sql

# CHANGE PASS
ALTER USER estc_agent IDENTIFIED WITH plaintext_password BY 'PASS';
