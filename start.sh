#!/bin/sh
set -e

echo "🔮 Starting Persian Panel..."

# ساخت پوشه data اگه نبود
mkdir -p /data

# کپی فایل‌های استاتیک اگه نیاز بود
if [ ! -d "/app/public" ]; then
  mkdir -p /app/public
fi

# بررسی NODE_ENV
export NODE_ENV=${NODE_ENV:-production}
export PORT=${PORT:-3000}

echo "📦 Environment: $NODE_ENV"
echo "🌐 Port: $PORT"

# اجرای nginx در پس‌زمینه (اگه وجود داشت)
if command -v nginx >/dev/null 2>&1; then
  echo "🔧 Starting Nginx..."
  nginx -g "daemon off;" &
  NGINX_PID=$!
  echo "✅ Nginx PID: $NGINX_PID"
fi

# اجرای Node.js
echo "🚀 Starting Node.js..."
exec node server.js
