#!/usr/bin/env bash

set -e
export DEBIAN_FRONTEND=noninteractive

APP_DIR="/opt/myapp"
STATE_FILE="${APP_DIR}/.project_type"
APP_NAME=$(tr -dc a-z </dev/urandom | head -c 6)

# 环境变量
export ARGO_PORT=${ARGO_PORT:-'8001'}
export ARGO_DOMAIN=${ARGO_DOMAIN}
export ARGO_AUTH=${ARGO_AUTH}
export SUB_URL=${SUB_URL}
export TOKEN=${TOKEN}

# 必须 root
[[ $EUID -ne 0 ]] && echo "Please run as root." && exit 1

# 清理旧进程
pkill -f '\.npm/' >/dev/null 2>&1 || true

# 卸载
if [[ "$1" == "-u" || "$1" == "u" || "$1" == "uninstall" ]]; then

    echo "Stopping service..."

    pkill -f '\.npm/' >/dev/null 2>&1 || true

    pm2 delete all 2>/dev/null || true
    pm2 save >/dev/null 2>&1 || true
    pm2 unstartup systemd -u root --hp /root >/dev/null 2>&1 || true

    rm -rf "${APP_DIR}"

    echo "Done."
    exit 0
fi

PROJECT_TYPE="nodejs"

echo "Installing dependencies..."

apt-get update -qq

apt-get install -y -qq \
curl \
wget \
ca-certificates \
gnupg >/dev/null 2>&1

mkdir -p "${APP_DIR}"

echo "${PROJECT_TYPE}" > "${STATE_FILE}"

cd "${APP_DIR}"

########################################################
# 安装 Node.js
########################################################

if ! command -v node >/dev/null 2>&1; then

    echo "Installing Node.js..."

    curl -fsSL https://deb.nodesource.com/setup_current.x | bash - >/dev/null 2>&1

    apt-get install -y -qq nodejs >/dev/null 2>&1

else

    echo "Node.js already installed."

fi

########################################################
# 安装 PM2
########################################################

if ! command -v pm2 >/dev/null 2>&1; then

    echo "Installing PM2..."

    npm install -g pm2 >/dev/null 2>&1

else

    echo "PM2 already installed."

fi

########################################################
# 下载项目文件
########################################################

echo "Downloading project..."

# 修改成你的 GitHub 地址
wget -q -O index.js https://raw.githubusercontent.com/vmsu0/patch/main/sub/index.js

########################################################
# 初始化 npm
########################################################

echo "Initializing npm..."

npm init -y >/dev/null 2>&1

########################################################
# 安装混淆器
########################################################

echo "Installing javascript-obfuscator..."

npm install axios ws javascript-obfuscator >/dev/null 2>&1

########################################################
# 写入 .env
########################################################

echo "Writing .env..."

cat > "${APP_DIR}/.env" <<EOF
ARGO_PORT=${ARGO_PORT}
ARGO_DOMAIN=${ARGO_DOMAIN}
ARGO_AUTH=${ARGO_AUTH}
TOKEN=${TOKEN}
SUB_URL=${SUB_URL}
EOF

########################################################
# 混淆 index.js
########################################################

echo "Obfuscating index.js..."

npx javascript-obfuscator index.js \
    --output ${APP_NAME}.js \
    --compact true \
    --control-flow-flattening true \
    --control-flow-flattening-threshold 0.5 \
    --dead-code-injection true \
    --dead-code-injection-threshold 0.2 \
    --string-array true \
    --string-array-threshold 0.75 \
    --rename-globals false \
    >/dev/null 2>&1

rm -f index.js

########################################################
# 启动 PM2
########################################################

echo "Starting service..."

set -a
source "${APP_DIR}/.env"
set +a

pm2 start ${APP_NAME}.js --name "${APP_NAME}" >/dev/null 2>&1

########################################################
# 开机启动
########################################################

pm2 startup systemd -u root --hp /root >/dev/null 2>&1
pm2 save >/dev/null 2>&1

########################################################
# 完成
########################################################

echo ""
echo "========================================="
echo "Install Complete"
echo "========================================="
echo ""
echo "Application : ${APP_NAME}"
echo "Port        : ${ARGO_PORT}"
echo "Argo Domain : ${ARGO_DOMAIN}"
echo "Subscription URL :"
echo "http://<你的服务器IP>:${ARGO_PORT}"
echo ""
echo "如果配置了 Argo："
echo "https://${ARGO_DOMAIN}${TOKEN:+/$TOKEN}"
echo ""
