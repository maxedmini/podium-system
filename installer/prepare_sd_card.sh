#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOOT_PAYLOAD_DIR="$SCRIPT_DIR/boot"

display_id=""
boot_volume=""
pi_username="event"
podium_user=""
pi_hostname=""
server_host=""
server_port="5001"
server_url=""
repo_url="https://github.com/maxedmini/podium-system.git"
branch="main"
repo_dir=""
eject_after=0

usage() {
  cat <<EOF
Usage:
  $(basename "$0") --display 1 [options]

Options:
  --display N         Required. Display id: 1, 2, or 3.
  --boot-volume PATH  Boot volume mount path. Defaults to /Volumes/bootfs or /Volumes/boot.
  --pi-username USER  Raspberry Pi OS username. Default: event
  --podium-user USER  User that owns the podium install. Defaults to --pi-username.
  --hostname NAME     Pi hostname. Default: podium-N
  --server-host HOST  Server hostname. Default: hostname for display 1, otherwise podium-1.local
  --server-port PORT  Server port. Default: 5001
  --server-url URL    Full display URL override.
  --repo-url URL      Git repository URL.
  --branch NAME       Git branch to install. Default: main
  --repo-dir PATH     Install path on the Pi. Default: /home/<user>/podium-system
  --eject             Eject the SD card after writing files.
EOF
}

find_boot_volume() {
  for candidate in /Volumes/bootfs /Volumes/boot; do
    if [ -d "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --display)
      display_id="${2:-}"
      shift 2
      ;;
    --boot-volume)
      boot_volume="${2:-}"
      shift 2
      ;;
    --pi-username)
      pi_username="${2:-}"
      shift 2
      ;;
    --podium-user)
      podium_user="${2:-}"
      shift 2
      ;;
    --hostname)
      pi_hostname="${2:-}"
      shift 2
      ;;
    --server-host)
      server_host="${2:-}"
      shift 2
      ;;
    --server-port)
      server_port="${2:-}"
      shift 2
      ;;
    --server-url)
      server_url="${2:-}"
      shift 2
      ;;
    --repo-url)
      repo_url="${2:-}"
      shift 2
      ;;
    --branch)
      branch="${2:-}"
      shift 2
      ;;
    --repo-dir)
      repo_dir="${2:-}"
      shift 2
      ;;
    --eject)
      eject_after=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

case "$display_id" in
  1|2|3)
    ;;
  *)
    echo "--display must be 1, 2, or 3" >&2
    exit 1
    ;;
esac

if [ -z "$boot_volume" ]; then
  boot_volume="$(find_boot_volume)" || {
    echo "Could not find a mounted Raspberry Pi boot volume. Use --boot-volume." >&2
    exit 1
  }
fi

if [ ! -d "$boot_volume" ]; then
  echo "Boot volume does not exist: $boot_volume" >&2
  exit 1
fi

if [ -z "$podium_user" ]; then
  podium_user="$pi_username"
fi

if [ -z "$pi_hostname" ]; then
  pi_hostname="podium-$display_id"
fi

if [ -z "$server_host" ]; then
  if [ "$display_id" = "1" ]; then
    server_host="$pi_hostname.local"
  else
    server_host="podium-1.local"
  fi
fi

if [ -z "$server_url" ]; then
  server_url="http://${server_host}:${server_port}/display/${display_id}"
fi

if [ -z "$repo_dir" ]; then
  repo_dir="/home/${podium_user}/podium-system"
fi

cp "$BOOT_PAYLOAD_DIR/podium-firstboot.sh" "$boot_volume/podium-firstboot.sh"

cat >"$boot_volume/firstrun.sh" <<'EOF'
#!/bin/bash
set -e
bash /boot/firmware/podium-firstboot.sh || bash /boot/podium-firstboot.sh
EOF

cat >"$boot_volume/podium.env" <<EOF
DISPLAY_ID=$display_id
PI_USERNAME=$pi_username
PODIUM_USER=$podium_user
PI_HOSTNAME=$pi_hostname
SERVER_HOST=$server_host
SERVER_PORT=$server_port
SERVER_URL=$server_url
REPO_URL=$repo_url
BRANCH=$branch
REPO_DIR=$repo_dir
EOF

chmod +x "$boot_volume/firstrun.sh" "$boot_volume/podium-firstboot.sh" || true

echo "Prepared $boot_volume"
echo "  display:    $display_id"
echo "  hostname:   $pi_hostname"
echo "  server url: $server_url"
echo "  repo:       $repo_url ($branch)"

if [ "$eject_after" -eq 1 ]; then
  diskutil eject "$boot_volume"
fi
