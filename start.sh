#!/bin/bash
set -e

echo "🇮🇷 Starting PERSIAN PANEL..."

export PORT="${PORT:-2053}"
export NODE_ENV="${NODE_ENV:-production}"

mkdir -p /app/data

echo "🚀 Starting on port ${PORT}..."

exec node server.js
