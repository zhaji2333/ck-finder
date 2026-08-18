#!/usr/bin/env bash
# ck-finder Linux 工具链安装脚本（Debian/Ubuntu）
# 用法: bash scripts/install_tools.sh
set -euo pipefail

echo "==> 系统依赖"
sudo apt update
sudo apt install -y git curl ca-certificates build-essential golang nmap

echo "==> Node.js 22"
if ! command -v node >/dev/null || [[ "$(node -v | cut -d. -f1 | tr -d 'v')" -lt 22 ]]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
  sudo apt install -y nodejs
fi
node -v

echo "==> ProjectDiscovery 工具链"
GOBIN=/usr/local/bin go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
GOBIN=/usr/local/bin go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
GOBIN=/usr/local/bin go install github.com/projectdiscovery/httpx/cmd/httpx@latest
GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "==> 验证"
for bin in subfinder dnsx httpx nuclei nmap; do
  if command -v "$bin" >/dev/null; then echo "  ✅ $bin"; else echo "  ❌ $bin 缺失"; fi
done

echo "==> 完成。运行 npm run dev -- doctor 复查。"
