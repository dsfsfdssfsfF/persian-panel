#!/bin/bash

set -e

echo "🇮🇷 Starting PERSIAN PANEL..."

# Default environment variables
export PORT="${PORT:-2053}"
export DOMAIN="${DOMAIN:-localhost}"
export PANEL_PATH="${PANEL_PATH:-/panel}"
export NODE_ENV="${NODE_ENV:-production}"
export DATABASE_URL="${DATABASE_URL:-sqlite:///app/data/persian-panel.db}"
export SESSION_SECRET="${SESSION_SECRET:-$(openssl rand -hex 32)}"
export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"

# Create data directory if not exists
mkdir -p /app/data /app/logs

# Generate nginx config from template
echo "📝 Generating nginx configuration..."
envsubst '${PORT} ${DOMAIN} ${PANEL_PATH}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

# Test nginx configuration
echo "🔍 Testing nginx configuration..."
nginx -t

# Start nginx in background
echo "🚀 Starting nginx..."
nginx

# Start Node.js application
echo "🚀 Starting Node.js backend on port ${PORT}..."
echo "🌐 Domain: ${DOMAIN}"
echo "📂 Panel path: ${PANEL_PATH}"
echo "🗄️ Database: ${DATABASE_URL}"
echo ""
echo "✅ PERSIAN PANEL is ready!"
echo "🔗 Access panel at: http://${DOMAIN}${PANEL_PATH}"
echo ""

# Run Node.js with auto-restart on file changes (development)
if [ "$NODE_ENV" = "development" ]; then
    exec node --watch server.js
else
    exec node server.js
fi
