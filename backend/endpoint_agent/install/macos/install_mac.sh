#!/usr/bin/env bash
set -euo pipefail

LABEL="com.system.update"
PLIST_PATH="/Library/LaunchDaemons/${LABEL}.plist"

INSTALL_DIR="/Library/Application Support/SystemUpdate"
PYZ_NAME="system-update-macos-universal2.pyz"
PYZ_PATH="${INSTALL_DIR}/system-update.pyz"
WRAPPER="${INSTALL_DIR}/system-update"
CONFIG_DIR="/Library/Preferences/SystemUpdate"
CONFIG_FILE="${CONFIG_DIR}/config.json"
STATE_DIR="/Library/Application Support/SystemUpdate/State"
LOG_DIR="/Library/Logs/SystemUpdate"
RUN_USER="root"
RUN_GROUP="wheel"

log_info()  { printf "\033[1;34m[*]\033[0m %s\n" "$*"; }
log_ok()    { printf "\033[1;32m[+]\033[0m %s\n" "$*"; }
log_err()   { printf "\033[1;31m[!]\033[0m %s\n" "$*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    log_err "This script must be run as root (sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_info "Installing System Update LaunchDaemon (${LABEL})..."

mkdir -p "${INSTALL_DIR}"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${STATE_DIR}"
mkdir -p "${LOG_DIR}"
log_ok "Created directories"

chmod 755 "${INSTALL_DIR}"
chmod 755 "${CONFIG_DIR}"
chmod 700 "${STATE_DIR}"
chmod 755 "${LOG_DIR}"

SOURCE_PYZ="${SCRIPT_DIR}/../../packages/${PYZ_NAME}"
if [ -f "${SOURCE_PYZ}" ]; then
    cp -f "${SOURCE_PYZ}" "${PYZ_PATH}"
    chmod 644 "${PYZ_PATH}"
    log_ok "Copied pyz bundle to ${PYZ_PATH}"
fi

cat > "${WRAPPER}" <<'WRAP_EOF'
#!/usr/bin/env bash
INSTALL_DIR="/Library/Application Support/SystemUpdate"
CONFIG_FILE="/Library/Preferences/SystemUpdate/config.json"
PYZ_PATH="${INSTALL_DIR}/system-update.pyz"
if [ -x "${INSTALL_DIR}/python/bin/python3" ]; then
    exec "${INSTALL_DIR}/python/bin/python3" "${PYZ_PATH}" --config "${CONFIG_FILE}" "$@"
elif [ -x /usr/local/bin/python3 ]; then
    exec /usr/local/bin/python3 "${PYZ_PATH}" --config "${CONFIG_FILE}" "$@"
elif [ -x /opt/homebrew/bin/python3 ]; then
    exec /opt/homebrew/bin/python3 "${PYZ_PATH}" --config "${CONFIG_FILE}" "$@"
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
    cp -R "${SCRIPT_DIR}/python-runtime" "${INSTALL_DIR}/python"
    chmod -R a+rX "${INSTALL_DIR}/python"
    xattr -rd com.apple.quarantine "${INSTALL_DIR}/python" 2>/dev/null || true
    log_ok "Copied bundled python runtime"
fi

if [ ! -f "${CONFIG_FILE}" ]; then
    MACHINE_ID="$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' '/IOPlatformUUID/{print $4; exit}' || true)"
    if [ -z "${MACHINE_ID}" ]; then
        MACHINE_ID="$(hostname -s 2>/dev/null || scutil --get LocalHostName 2>/dev/null || echo 'unknown')"
    fi
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
        "launchd",
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

chown -R "${RUN_USER}:${RUN_GROUP}" "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}"
log_ok "Applied ownership (${RUN_USER}:${RUN_GROUP})"

cat > "${PLIST_PATH}" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${WRAPPER}</string>
        <string>run</string>
    </array>

    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>

    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>Crashed</key>
        <true/>
        <key>NetworkState</key>
        <true/>
    </dict>

    <key>ThrottleInterval</key>
    <integer>5</integer>

    <key>ExitTimeOut</key>
    <integer>30</integer>
    <key>StartCalendarInterval</key>
    <dict/>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/stderr.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    </dict>

    <key>ProcessType</key>
    <string>Background</string>

    <key>LowPriorityIO</key>
    <false/>

    <key>Nice</key>
    <integer>0</integer>
</dict>
</plist>
PLIST_EOF

chmod 644 "${PLIST_PATH}"
chown root:wheel "${PLIST_PATH}"
log_ok "Installed LaunchDaemon plist at ${PLIST_PATH}"

if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
    launchctl bootout system "${PLIST_PATH}" 2>/dev/null || true
    sleep 1
fi

launchctl bootstrap system "${PLIST_PATH}"
launchctl enable "system/${LABEL}"
launchctl kickstart -k "system/${LABEL}"
log_ok "Loaded and started ${LABEL} via launchctl"

sleep 1
if launchctl print "system/${LABEL}" >/dev/null 2>&1; then
    log_ok "Verified: ${LABEL} is registered with launchd"
fi

cat <<EOF

$(tput setaf 2)========================================$(tput sgr0)
$(tput setaf 2)Installation complete$(tput sgr0)
$(tput setaf 2)========================================$(tput sgr0)
LaunchDaemon:   ${PLIST_PATH}
Label:          ${LABEL}
Install dir:    ${INSTALL_DIR}
Wrapper:        ${WRAPPER}
Config dir:     ${CONFIG_DIR}
Config file:    ${CONFIG_FILE}
State dir:      ${STATE_DIR}
Log dir:        ${LOG_DIR}

Admin commands:
  sudo launchctl print system/${LABEL}
  sudo launchctl kickstart -k system/${LABEL}
  sudo launchctl stop system/${LABEL}
  sudo launchctl start system/${LABEL}

Uninstall:
  sudo launchctl bootout system ${PLIST_PATH}
  sudo rm -f ${PLIST_PATH}
  sudo rm -rf "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_DIR}" "${LOG_DIR}"
EOF
