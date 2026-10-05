#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="system-update"
SERVICE_UNIT="/etc/systemd/system/${SERVICE_NAME}.service"

INSTALL_DIR="/opt/system-update"
PYZ_NAME="system-update-linux-x86_64.pyz"
PYZ_PATH="${INSTALL_DIR}/system-update.pyz"
WRAPPER="${INSTALL_DIR}/system-update"
CONFIG_DIR="/etc/system-update"
CONFIG_FILE="${CONFIG_DIR}/config.json"
STATE_DIR="/var/lib/system-update"
LOG_DIR="/var/log/system-update"
RUN_USER="root"
RUN_GROUP="root"

log_info()  { printf "\033[1;34m[*]\033[0m %s\n" "$*"; }
log_ok()    { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
log_err()   { printf "\033[1;31m[!]\033[0m %s\n" "$*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    log_err "This script must be run as root (sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_info "Installing system-update agent..."

mkdir -p "${INSTALL_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${STATE_DIR}"
mkdir -p "${LOG_DIR}"
log_ok "Created directories"

chmod 755 "${INSTALL_DIR}"
chmod 700 "${CONFIG_DIR}"
chmod 700 "${STATE_DIR}"
chmod 750 "${LOG_DIR}"

SOURCE_PYZ="${SCRIPT_DIR}/../../packages/${PYZ_NAME}"
if [ -f "${SOURCE_PYZ}" ]; then
    cp -f "${SOURCE_PYZ}" "${PYZ_PATH}"
    chmod 644 "${PYZ_PATH}"
    log_ok "Copied pyz bundle to ${PYZ_PATH}"
fi

cat > "${WRAPPER}" <<'WRAP_EOF'
#!/usr/bin/env bash
INSTALL_DIR="/opt/system-update"
CONFIG_FILE="/etc/system-update/config.json"
PYZ_PATH="${INSTALL_DIR}/system-update.pyz"
if [ -x "${INSTALL_DIR}/python/bin/python3" ]; then
    exec "${INSTALL_DIR}/python/bin/python3" "${PYZ_PATH}" --config "${CONFIG_FILE}" "$@"
elif command -v python3 >/dev/null 2>&1; then
    exec python3 "${PYZ_PATH}" --config "${CONFIG_FILE}" "$@"
elif command -v python >/dev/null 2>&1; then
    exec python "${PYZ_PATH}" --config "${CONFIG_FILE}" "$@"
else
    echo "ERROR: No python interpreter found" >&2
    exit 1
fi
WRAP_EOF
chmod 755 "${WRAPPER}"
log_ok "Installed wrapper script at ${WRAPPER}"

if [ -d "${SCRIPT_DIR}/python-runtime" ]; then
    cp -r "${SCRIPT_DIR}/python-runtime" "${INSTALL_DIR}/python"
    chmod -R a+rX "${INSTALL_DIR}/python"
    log_ok "Copied bundled python runtime"
fi

if [ ! -f "${CONFIG_FILE}" ]; then
    MACHINE_ID="$(cat /etc/machine-id 2>/dev/null || hostname 2>/dev/null || echo 'unknown')"
    cat > "${CONFIG_FILE}" <<CONF_EOF
{
    "server_url": "https://update.example.com",
    "tenant_id": "default",
    "machine_id": "${MACHINE_ID}",
    "log_level": "INFO",
    "log_file": "${LOG_DIR}/agent.log",
    "check_interval_sec": 3600,
    "state_dir": "${STATE_DIR}",
    "self_monitor_exclude": [
        "systemd",
        "system-update",
        "python3",
        "python",
        "bash"
    ],
    "tls": {
        "verify_tls": true,
        "ca_bundle": null,
        "client_cert": null,
        "client_key": null,
        "allow_insecure_http": false,
        "proxy": null
    }
}
CONF_EOF
    chmod 600 "${CONFIG_FILE}"
    log_ok "Wrote default config to ${CONFIG_FILE}"
else
    log_info "Config already exists at ${CONFIG_FILE} - preserving"
fi

chown -R "${RUN_USER}:${RUN_GROUP}" "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}" 2>/dev/null || true
log_ok "Applied ownership"

cat > "${SERVICE_UNIT}" <<UNIT_EOF
[Unit]
Description=System Update Service
Documentation=man:system-update(1)
After=network-online.target nss-lookup.target time-sync.target
Wants=network-online.target nss-lookup.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_GROUP}
ExecStart=${WRAPPER} run
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
StartLimitBurst=5
StartLimitIntervalSec=60
TimeoutStopSec=30
OOMScoreAdjust=-900
EnvironmentFile=-/etc/default/system-update
WorkingDirectory=${INSTALL_DIR}
ReadWritePaths=${STATE_DIR} ${LOG_DIR} ${CONFIG_DIR}
ReadOnlyPaths=${INSTALL_DIR}
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=false
SystemCallArchitectures=native
NoNewPrivileges=false
LogsDirectory=system-update
StateDirectory=system-update
ConfigurationDirectory=system-update

[Install]
WantedBy=multi-user.target
UNIT_EOF

chmod 644 "${SERVICE_UNIT}"
log_ok "Installed systemd unit at ${SERVICE_UNIT}"

cat > "/etc/default/system-update" <<DEFAULTS_EOF
# Environment overrides for ${SERVICE_NAME}.service
# HTTPS_PROXY=http://proxy.example.com:8080
# NO_PROXY=localhost,127.0.0.1
DEFAULTS_EOF
chmod 644 "/etc/default/system-update"

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}.service"
    log_ok "Enabled ${SERVICE_NAME}.service on boot"

    if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        systemctl restart "${SERVICE_NAME}.service"
        log_ok "Restarted running service"
    else
        systemctl start "${SERVICE_NAME}.service"
        log_ok "Started ${SERVICE_NAME}.service"
    fi
else
    log_info "systemctl not found in this environment (container/chroot); service unit installed but not started"
fi

cat <<EOF

$(tput setaf 2)========================================$(tput sgr0)
$(tput setaf 2)Installation complete$(tput sgr0)
$(tput setaf 2)========================================$(tput sgr0)
Service unit:   ${SERVICE_UNIT}
Install dir:    ${INSTALL_DIR}
Wrapper:        ${WRAPPER}
Config dir:     ${CONFIG_DIR}
Config file:    ${CONFIG_FILE}
State dir:      ${STATE_DIR}
Log dir:        ${LOG_DIR}

Admin commands:
  sudo systemctl status   ${SERVICE_NAME}.service
  sudo systemctl start    ${SERVICE_NAME}.service
  sudo systemctl stop     ${SERVICE_NAME}.service
  sudo systemctl restart  ${SERVICE_NAME}.service
  sudo systemctl enable   ${SERVICE_NAME}.service
  sudo systemctl disable  ${SERVICE_NAME}.service
  sudo journalctl -u      ${SERVICE_NAME}.service -f

Uninstall:
  sudo systemctl stop ${SERVICE_NAME}.service
  sudo systemctl disable ${SERVICE_NAME}.service
  sudo rm -f ${SERVICE_UNIT}
  sudo systemctl daemon-reload
  sudo rm -rf ${INSTALL_DIR} ${CONFIG_DIR} ${STATE_DIR} /etc/default/system-update
EOF
