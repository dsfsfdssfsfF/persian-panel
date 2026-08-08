# ════════════════════════════
# Stage 1: Builder
# ════════════════════════════
FROM node:20-alpine AS builder

WORKDIR /app

COPY package*.json ./

# --only=production رو حذف کن، از --omit=dev استفاده کن
RUN npm ci --omit=dev && \
    npm cache clean --force

# ════════════════════════════
# Stage 2: Runtime
# ════════════════════════════
FROM node:20-alpine

LABEL maintainer="Persian Panel"
LABEL version="2.0.0"

RUN apk add --no-cache \
    nginx \
    supervisor \
    curl \
    tzdata && \
    cp /usr/share/zoneinfo/Asia/Tehran /etc/localtime && \
    echo "Asia/Tehran" > /etc/timezone && \
    rm -rf /var/cache/apk/*

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY . .

RUN mkdir -p /data \
             /var/log/supervisor \
             /var/log/nginx \
             /run/nginx \
             /app/public && \
    chmod +x start.sh

COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

EXPOSE 3000 80

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
