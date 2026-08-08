FROM node:20-slim

WORKDIR /app

# نصب ابزارها + Xray
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    curl \
    wget \
    unzip \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# دانلود و نصب Xray
RUN wget -q https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip \
    && unzip Xray-linux-64.zip -d /usr/local/bin/xray-core \
    && mv /usr/local/bin/xray-core/xray /usr/local/bin/xray \
    && chmod +x /usr/local/bin/xray \
    && rm -rf Xray-linux-64.zip /usr/local/bin/xray-core

# نصب dependencies
COPY package*.json ./
RUN npm install

COPY . .

# پوشه‌های لازم
RUN mkdir -p /data /app/public /etc/xray /var/log/supervisor

# کپی کانفیگ‌ها
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
