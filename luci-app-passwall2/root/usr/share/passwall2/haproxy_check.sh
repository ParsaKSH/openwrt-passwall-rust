#!/bin/sh
# HAProxy external-check command (haproxy passes: <proxy_addr> <proxy_port> <server_addr> <server_port>)
exec /usr/bin/passwall2 haproxy-check "$@"
