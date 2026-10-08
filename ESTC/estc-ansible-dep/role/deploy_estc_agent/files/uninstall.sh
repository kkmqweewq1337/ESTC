#!/bin/bash
# Uninstall
echo "stop agent"
systemctl stop estc-agent.service > /dev/null 2>&1
echo "rm service"
rm -rf /etc/systemd/system/estc-agent.service
systemctl daemon-reload
echo "rm estc agent and dir /etc/estc"
rm -rf /usr/bin/estc
rm -rf /etc/estc
