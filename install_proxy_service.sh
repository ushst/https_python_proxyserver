#!/usr/bin/env bash
set -euo pipefail

DEFAULT_SERVICE_NAME="https-python-proxy"
DEFAULT_SERVICE_USER="proxy"
DEFAULT_PYTHON_BIN="$(command -v python3 || true)"
DEFAULT_WORKING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SERVICE_NAME=${SERVICE_NAME:-$DEFAULT_SERVICE_NAME}
SERVICE_USER=${SERVICE_USER:-$DEFAULT_SERVICE_USER}
SERVICE_GROUP=${SERVICE_GROUP:-}
PYTHON_BIN=${PYTHON_BIN:-$DEFAULT_PYTHON_BIN}
WORKING_DIR=${WORKING_DIR:-$DEFAULT_WORKING_DIR}
ENV_FILE=${ENV_FILE:-}
AUTO_START=1

usage() {
  cat <<USAGE
Usage: sudo $0 [options]

Options:
  -n NAME       Systemd service name (default: ${SERVICE_NAME})
  -u USER       System user to run the service under (default: ${SERVICE_USER})
  -g GROUP      System group for the service (default: same as USER)
  -p PATH       Path to python executable (default: detected python3)
  -w DIR        Working directory of the application (default: repository root)
  -e FILE       Path to .env file to load (default: DIR/.env if exists)
  -N            Do not enable and start the service automatically
  -h            Show this help message

Environment variables (take precedence over defaults but can be overridden by options):
  SERVICE_NAME, SERVICE_USER, SERVICE_GROUP, PYTHON_BIN, WORKING_DIR, ENV_FILE
USAGE
}

while getopts ":n:u:g:p:w:e:Nh" opt; do
  case "$opt" in
    n) SERVICE_NAME=$OPTARG ;;
    u) SERVICE_USER=$OPTARG ;;
    g) SERVICE_GROUP=$OPTARG ;;
    p) PYTHON_BIN=$OPTARG ;;
    w) WORKING_DIR=$OPTARG ;;
    e) ENV_FILE=$OPTARG ;;
    N) AUTO_START=0 ;;
    h)
      usage
      exit 0
      ;;
    :)
      echo "Option -$OPTARG requires an argument" >&2
      usage >&2
      exit 1
      ;;
    \?)
      echo "Unknown option: -$OPTARG" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z $SERVICE_GROUP ]]; then
  SERVICE_GROUP=$SERVICE_USER
fi

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root. Use sudo." >&2
  exit 1
fi

if [[ -z $PYTHON_BIN ]]; then
  echo "Unable to detect python3 executable. Use -p to specify." >&2
  exit 1
fi

if [[ ! -x $PYTHON_BIN ]]; then
  echo "Python executable '$PYTHON_BIN' is not executable." >&2
  exit 1
fi

if [[ ! -d $WORKING_DIR ]]; then
  echo "Working directory '$WORKING_DIR' does not exist." >&2
  exit 1
fi

if ! id "$SERVICE_USER" &>/dev/null; then
  echo "Warning: user '$SERVICE_USER' does not exist. The service may fail to start." >&2
fi

if ! getent group "$SERVICE_GROUP" &>/dev/null; then
  echo "Warning: group '$SERVICE_GROUP' does not exist. The service may fail to start." >&2
fi

if ! command -v systemctl &>/dev/null; then
  echo "systemctl command not found. This script requires systemd." >&2
  exit 1
fi

SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

SELECTED_ENV_FILE=""
if [[ -n $ENV_FILE ]]; then
  SELECTED_ENV_FILE=$ENV_FILE
elif [[ -f ${WORKING_DIR}/.env ]]; then
  SELECTED_ENV_FILE=${WORKING_DIR}/.env
fi

{
  cat <<SERVICE
[Unit]
Description=HTTPS Python Proxy Server (${SERVICE_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${WORKING_DIR}
Environment="PYTHONUNBUFFERED=1"
SERVICE

  if [[ -n $SELECTED_ENV_FILE ]]; then
    if [[ -f $SELECTED_ENV_FILE ]]; then
      printf 'EnvironmentFile=%q\n' "$SELECTED_ENV_FILE"
    else
      echo "Warning: environment file '$SELECTED_ENV_FILE' does not exist." >&2
    fi
  fi

  printf 'ExecStart=%q %q\n' "$PYTHON_BIN" "$WORKING_DIR/proxy_async.py"

  cat <<'SERVICE'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE
} > "$SERVICE_PATH"

chmod 644 "$SERVICE_PATH"

systemctl daemon-reload

if [[ $AUTO_START -eq 1 ]]; then
  systemctl enable --now "$SERVICE_NAME"
  echo "Service '$SERVICE_NAME' installed and started."
else
  echo "Service '$SERVICE_NAME' installed. Start it with: systemctl start $SERVICE_NAME"
fi
