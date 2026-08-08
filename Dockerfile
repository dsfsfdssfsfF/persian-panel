FROM node:20-alpine

WORKDIR /app

# ابزارهای build برای better-sqlite3
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    gcc \
    curl \
    tzdata && \
    cp /usr/share/zoneinfo/Asia/Tehran /etc/localtime && \
    echo "Asia/Tehran" > /etc/timezone && \
    rm -rf /var/cache/apk/*

# اول package.json کپی کن
COPY package*.json ./

# نصب همه dependencies
RUN npm install && \
    npm cache clean --force

# بقیه فایل‌ها
COPY . .

# پوشه‌های لازم
RUN mkdir -p /data /app/public

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

CMD ["node", "server.js"]
