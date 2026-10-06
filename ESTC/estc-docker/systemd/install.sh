#!/bin/bash
# Load estc agent
PASS_WEB_estc='PASS_PASS'
PASS_USER_CLICKHOUSE='PASS_PASS'
IP_ADDRESS='localhost'
BD_NAME='ESTC'
mkdir /tmp/estc-agent && cd /tmp/estc-agent

wget --http-user=admin \
     --http-password=$PASS_WEB_estc \
     https://"$IP_ADDRESS"/agent/estc

cp ./estc /usr/bin/. && chmod 0655 /usr/bin/estc

# Load certs


mkdir -p /etc/estc/certs

wget --http-user=admin \
     --http-password=$PASS_WEB_estc \
     https://"$IP_ADDRESS"/certs/ca.crt
wget --http-user=admin \
     --http-password=$PASS_WEB_estc \
     https://"$IP_ADDRESS"/certs/client.crt
wget --http-user=admin \
     --http-password=$PASS_WEB_estc \
     https://"$IP_ADDRESS"/certs/client.key

cp ca.crt /etc/estc/certs/. && cp client.crt /etc/estc/certs/. && cp client.key /etc/estc/certs/.
chmod 0600 /etc/estc/certs/*.key
chmod 0644 /etc/estc/certs/*.crt

# Create service
cat << 'EOF' > /etc/systemd/system/estc-agent.service
[Unit]
Description=estc agent 1.0.0
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/estc
ExecStart=/usr/bin/estc -clickhouse "clickhouse://estc_agent:$PASS_USER_CLICKHOUSE@$IP_ADDRESS:9440/$BD_NAME" -ca-cert /etc/estc/certs/ca.crt -client-cert /etc/estc/certs/client.crt -client-key /etc/estc/certs/client.key
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
# Reload systemd and run agent

systemctl daemon-reload
systemctl enable estc-agent.service
systemctl start estc-agent.service

cd /

sleep 5

rm -rf /tmp/estc-agent

exit 0
