#!/bin/bash
set -e

: "${PORT:=8080}"

mkdir -p /tmp/client_temp /tmp/proxy_temp /tmp/fastcgi_temp /tmp/uwsgi_temp /tmp/scgi_temp

echo "🚀 [persian-panel] starting x-ui (official entrypoint, admin/admin on :2053 by default)..."
/app/DockerEntrypoint.sh &

echo "🚀 [persian-panel] rendering nginx config for PORT=${PORT}..."
envsubst '${PORT}' < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

echo "🚀 [persian-panel] starting nginx on ${PORT}..."
exec nginx -g "daemon off;"
