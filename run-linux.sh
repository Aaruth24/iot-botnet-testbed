#!/usr/bin/env bash
# One-command launcher for Linux. Brings up the full Dockerized testbed and
# prints the dashboard URL. Safe to re-run.
set -euo pipefail
cd "$(dirname "$0")"

green() { printf '\033[32m%s\033[0m\n' "$1"; }
red()   { printf '\033[31m%s\033[0m\n' "$1"; }

echo "=== Docker IoT Security Testbed — Linux launcher ==="

# 1. Docker present?
if ! command -v docker >/dev/null 2>&1; then
  red "Docker is not installed."
  echo "Install it, then re-run this script:"
  echo "  Ubuntu/Debian : sudo apt update && sudo apt install -y docker.io docker-compose-plugin"
  echo "  Fedora        : sudo dnf install -y docker docker-compose-plugin"
  echo "  Arch          : sudo pacman -S docker docker-compose"
  echo "  Then          : sudo systemctl enable --now docker && sudo usermod -aG docker \$USER  (log out/in)"
  echo ""
  echo "No Docker? You can still run the offline demo with no install:"
  echo "  xdg-open demo/testbed-demo.html"
  exit 1
fi

# 2. Compose plugin present?
if ! docker compose version >/dev/null 2>&1; then
  red "The 'docker compose' plugin is missing."
  echo "Install docker-compose-plugin (see your distro above), then re-run."
  exit 1
fi

# 3. Daemon running?
if ! docker info >/dev/null 2>&1; then
  red "The Docker daemon is not running or you lack permission."
  echo "Try:  sudo systemctl start docker    (or run this script with sudo)"
  exit 1
fi

green "Docker OK — building and starting the testbed (first build downloads images; give it a few minutes)."
docker compose up --build -d

echo ""
green "Testbed is up."
echo "  Dashboard : http://localhost:8080"
echo "  Logs      : docker compose logs -f ids orchestrator"
echo "  Experiment: docker compose exec redis redis-cli set control:run_experiment 1"
echo "  Stop      : docker compose down"
echo ""
echo "Tip: open the dashboard and click 'Run full experiment'."
