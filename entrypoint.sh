#!/bin/sh

set -eu

echo "time=$(date -u +"%Y-%m-%dT%H:%M:%SZ") level=info msg=\"entrypoint start\""

# --- GENERATE CONFIG ---
echo "time=$(date -u +"%Y-%m-%dT%H:%M:%SZ") level=info msg=\"ensure wireguard config\""
WG_CONF_PATH=$(/app/wg-keeper-node init --print-path)
if [ -z "$WG_CONF_PATH" ]; then
    echo "time=$(date -u +"%Y-%m-%dT%H:%M:%SZ") level=error msg=\"wireguard config path is empty\""
    exit 1
fi

# --- SAFE DOWN ---
echo "time=$(date -u +"%Y-%m-%dT%H:%M:%SZ") level=info msg=\"try bring down existing interface\""
if wg-quick down "$WG_CONF_PATH" 2>/dev/null; then
    echo "time=$(date -u +"%Y-%m-%dT%H:%M:%SZ") level=info msg=\"existing interface down\""
else
    echo "time=$(date -u +"%Y-%m-%dT%H:%M:%SZ") level=info msg=\"interface not active\""
fi

# --- WG UP WITH CHECK ---
echo "time=$(date -u +"%Y-%m-%dT%H:%M:%SZ") level=info msg=\"bring up wireguard\""
if wg-quick up "$WG_CONF_PATH" >/dev/null 2>&1; then
    echo "time=$(date -u +"%Y-%m-%dT%H:%M:%SZ") level=info msg=\"wireguard started\""
else
    echo "time=$(date -u +"%Y-%m-%dT%H:%M:%SZ") level=error msg=\"wireguard start failed\""
    exit 1
fi

# --- START APP ---
echo "time=$(date -u +"%Y-%m-%dT%H:%M:%SZ") level=info msg=\"starting wg-keeper-node\""
exec /app/wg-keeper-node