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
COPY_TO_OPT=1
DEPLOY_DIR=${DEPLOY_DIR:-}

DEFAULT_SSL_CERT="/etc/letsencrypt/live/example.com/fullchain.pem"
DEFAULT_SSL_KEY="/etc/letsencrypt/live/example.com/privkey.pem"

usage() {
  cat <<USAGE
Usage: sudo $0 [options]

Options:
  -n NAME       Systemd service name (default: ${SERVICE_NAME})
  -u USER       System user to run the service under (default: ${SERVICE_USER})
  -g GROUP      System group for the service (default: same as USER)
  -p PATH       Path to python executable (default: detected python3)
  -w DIR        Source application directory to install from (default: script directory)
  -o DIR        Target deployment directory (default: /opt/<basename of source DIR>)
  -e FILE       Path to .env file to load (default: DIR/.env if exists)
  -C            Do not copy project to /opt; run directly from DIR
  -N            Do not enable and start the service automatically
  -h            Show this help message

Environment variables (take precedence over defaults but can be overridden by options):
  SERVICE_NAME, SERVICE_USER, SERVICE_GROUP, PYTHON_BIN, WORKING_DIR, DEPLOY_DIR, ENV_FILE
USAGE
}

trim_whitespace() {
  local s=$1
  # shellcheck disable=SC2001
  s=$(echo "$s" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
  printf '%s' "$s"
}

strip_quotes() {
  local s=$1
  if [[ $s == \"*\" && $s == *\" ]]; then
    s=${s:1:${#s}-2}
  elif [[ $s == \'*\' && $s == *\' ]]; then
    s=${s:1:${#s}-2}
  fi
  printf '%s' "$s"
}

get_env_var() {
  local key=$1
  local file=$2
  local line value

  line=$(
    awk -F= -v wanted="$key" '
      /^[[:space:]]*#/ {next}
      {
        left=$1
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", left)
        sub(/^export[[:space:]]+/, "", left)
        if (left == wanted) {
          print $0
        }
      }
    ' "$file" | tail -n1
  )

  if [[ -z $line ]]; then
    return 1
  fi

  value=${line#*=}
  value=$(trim_whitespace "$value")
  value=$(strip_quotes "$value")
  printf '%s' "$value"
}

resolve_path() {
  local p=$1
  if [[ -z $p ]]; then
    printf '%s' ""
    return 0
  fi
  if [[ $p == /* ]]; then
    printf '%s' "$p"
  else
    printf '%s/%s' "$WORKING_DIR" "$p"
  fi
}

can_user_read_file() {
  local user=$1
  local path=$2
  if command -v runuser &>/dev/null; then
    runuser -u "$user" -- test -r "$path"
    return $?
  fi
  su -s /bin/sh "$user" -c "test -r \"\$1\"" -- "$path"
}

prompt_yes_no() {
  local message=$1
  local answer
  while true; do
    read -r -p "$message [y/N]: " answer || return 1
    case "${answer,,}" in
      y|yes) return 0 ;;
      n|no|"") return 1 ;;
      *) echo "Please answer yes or no." ;;
    esac
  done
}

grant_user_read_access() {
  local user=$1
  local original_path=$2
  local resolved_path
  local current
  local -a dir_list=()

  ensure_setfacl_available_or_install() {
    local install_cmd=""

    if command -v setfacl &>/dev/null; then
      return 0
    fi

    if command -v apt-get &>/dev/null; then
      install_cmd="apt-get update && apt-get install -y acl"
    elif command -v dnf &>/dev/null; then
      install_cmd="dnf install -y acl"
    elif command -v yum &>/dev/null; then
      install_cmd="yum install -y acl"
    elif command -v zypper &>/dev/null; then
      install_cmd="zypper install -y acl"
    elif command -v pacman &>/dev/null; then
      install_cmd="pacman -Sy --noconfirm acl"
    elif command -v apk &>/dev/null; then
      install_cmd="apk add acl"
    fi

    if [[ -z $install_cmd ]]; then
      echo "setfacl command not found and package manager is unknown." >&2
      echo "Install ACL tools manually, then run the script again." >&2
      return 1
    fi

    if prompt_yes_no "setfacl is missing. Install ACL tools now?"; then
      if ! sh -c "$install_cmd"; then
        echo "Failed to install ACL tools using: $install_cmd" >&2
        return 1
      fi
      if ! command -v setfacl &>/dev/null; then
        echo "ACL tools were installed, but setfacl is still unavailable." >&2
        return 1
      fi
      return 0
    fi

    echo "Install ACL tools manually:" >&2
    echo "  sudo $install_cmd" >&2
    return 1
  }

  if ! ensure_setfacl_available_or_install; then
    return 1
  fi

  resolved_path=$(readlink -f "$original_path")
  if [[ -z $resolved_path ]]; then
    resolved_path=$original_path
  fi

  collect_dirs() {
    local p=$1
    local d
    d=$(dirname "$p")
    while [[ $d != "/" && -n $d ]]; do
      dir_list+=("$d")
      d=$(dirname "$d")
    done
  }

  collect_dirs "$original_path"
  collect_dirs "$resolved_path"

  for current in "${dir_list[@]}"; do
    setfacl -m "u:${user}:x" "$current"
  done

  setfacl -m "u:${user}:r" "$resolved_path"
  if [[ $original_path != "$resolved_path" ]]; then
    setfacl -m "u:${user}:r" "$original_path" 2>/dev/null || true
  fi
}

ensure_user_can_read_or_prompt() {
  local user=$1
  local path=$2
  local label=$3

  if can_user_read_file "$user" "$path"; then
    return 0
  fi

  echo "User '$user' cannot read $label '$path'." >&2
  if prompt_yes_no "Grant read access for '$user' to '$path'?"; then
    if ! grant_user_read_access "$user" "$path"; then
      echo "Failed to grant access for '$user' to '$path'." >&2
      exit 1
    fi
    if ! can_user_read_file "$user" "$path"; then
      echo "Access update was attempted, but '$user' still cannot read '$path'." >&2
      exit 1
    fi
    echo "Access granted for '$user' to '$path'."
    return 0
  fi

  echo "Installation cancelled." >&2
  exit 1
}

sync_project_tree() {
  local src=$1
  local dst=$2

  mkdir -p "$dst"
  if command -v rsync &>/dev/null; then
    rsync -a --delete "$src"/ "$dst"/
  else
    cp -a "$src"/. "$dst"/
  fi
}

while getopts ":n:u:g:p:w:o:e:CNh" opt; do
  case "$opt" in
    n) SERVICE_NAME=$OPTARG ;;
    u) SERVICE_USER=$OPTARG ;;
    g) SERVICE_GROUP=$OPTARG ;;
    p) PYTHON_BIN=$OPTARG ;;
    w) WORKING_DIR=$OPTARG ;;
    o) DEPLOY_DIR=$OPTARG ;;
    e) ENV_FILE=$OPTARG ;;
    C) COPY_TO_OPT=0 ;;
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

SOURCE_DIR=$(readlink -f "$WORKING_DIR")
if [[ -z $SOURCE_DIR ]]; then
  SOURCE_DIR=$WORKING_DIR
fi

if [[ $COPY_TO_OPT -eq 1 ]]; then
  if [[ -z $DEPLOY_DIR ]]; then
    DEPLOY_DIR="/opt/$(basename "$SOURCE_DIR")"
  fi
  TARGET_DIR=$(readlink -m "$DEPLOY_DIR")
  if [[ -z $TARGET_DIR ]]; then
    TARGET_DIR=$DEPLOY_DIR
  fi

  if [[ $SOURCE_DIR != "$TARGET_DIR" ]]; then
    echo "Deploying project from '$SOURCE_DIR' to '$TARGET_DIR'..."
    sync_project_tree "$SOURCE_DIR" "$TARGET_DIR"
  fi
  WORKING_DIR=$TARGET_DIR
else
  WORKING_DIR=$SOURCE_DIR
fi

if [[ -n $ENV_FILE ]]; then
  ENV_FILE_ABS=""
  if [[ $ENV_FILE == /* ]]; then
    ENV_FILE_ABS=$(readlink -m "$ENV_FILE")
  else
    ENV_FILE_ABS=$(readlink -m "$SOURCE_DIR/$ENV_FILE")
  fi

  if [[ $COPY_TO_OPT -eq 1 && $ENV_FILE_ABS == "$SOURCE_DIR"/* ]]; then
    ENV_FILE="$WORKING_DIR/${ENV_FILE_ABS#"$SOURCE_DIR"/}"
  else
    ENV_FILE=$ENV_FILE_ABS
  fi
fi

if ! id "$SERVICE_USER" &>/dev/null; then
  echo "User '$SERVICE_USER' does not exist." >&2
  exit 1
fi

if ! getent group "$SERVICE_GROUP" &>/dev/null; then
  echo "Group '$SERVICE_GROUP' does not exist." >&2
  exit 1
fi

chown -R "${SERVICE_USER}:${SERVICE_GROUP}" "$WORKING_DIR"

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

SSL_CERT_VALUE=$DEFAULT_SSL_CERT
SSL_KEY_VALUE=$DEFAULT_SSL_KEY
if [[ -n $SELECTED_ENV_FILE ]]; then
  if [[ -f $SELECTED_ENV_FILE ]]; then
    if cert_from_env=$(get_env_var "SSL_CERT" "$SELECTED_ENV_FILE"); then
      SSL_CERT_VALUE=$cert_from_env
    fi
    if key_from_env=$(get_env_var "SSL_KEY" "$SELECTED_ENV_FILE"); then
      SSL_KEY_VALUE=$key_from_env
    fi
  else
    echo "Environment file '$SELECTED_ENV_FILE' does not exist." >&2
    exit 1
  fi
fi

SSL_CERT_PATH=$(resolve_path "$SSL_CERT_VALUE")
SSL_KEY_PATH=$(resolve_path "$SSL_KEY_VALUE")

if [[ ! -f $SSL_CERT_PATH ]]; then
  echo "SSL certificate file '$SSL_CERT_PATH' does not exist." >&2
  exit 1
fi
if [[ ! -f $SSL_KEY_PATH ]]; then
  echo "SSL private key file '$SSL_KEY_PATH' does not exist." >&2
  exit 1
fi

ensure_user_can_read_or_prompt "$SERVICE_USER" "$SSL_CERT_PATH" "certificate"
ensure_user_can_read_or_prompt "$SERVICE_USER" "$SSL_KEY_PATH" "key"

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
