# ════════════════════════════
# Stage 1: Builder
# ════════════════════════════
FROM node:20-alpine AS builder

WORKDIR /app

# فقط package files اول (برای cache)
COPY package*.json ./

RUN npm ci --only=production && \
    npm cache clean --force

# ════════════════════════════
# Stage 2: Runtime
# ════════════════════════════
FROM node:20-alpine

LABEL maintainer="Persian Panel"
LABEL version="1.0.0"

# نصب nginx + supervisord + ابزارها
RUN apk add --no-cache \
    nginx \
    supervisor \
    curl \
    tzdata && \
    cp /usr/share/zoneinfo/Asia/Tehran /etc/localtime && \
    echo "Asia/Tehran" > /etc/timezone && \
    rm -rf /var/cache/apk/*

WORKDIR /app

# کپی node_modules از builder
COPY --from=builder /app/node_modules ./node_modules

# کپی سورس
COPY . .

# ساخت پوشه‌های مورد نیاز
RUN mkdir -p /data \
             /var/log/supervisor \
             /var/log/nginx \
             /run/nginx \
             /app/public && \
    chmod +x start.sh

# کپی کانفیگ‌ها
COPY nginx.conf /etc/nginx/nginx.conf
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# پورت‌ها
EXPOSE 3000 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# اجرا
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
