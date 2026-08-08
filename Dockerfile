FROM node:20-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    curl \
    wget \
    unzip \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip \
    && unzip -q Xray-linux-64.zip -d /tmp/xray \
    && mv /tmp/xray/xray /usr/local/bin/xray \
    && chmod +x /usr/local/bin/xray \
    && rm -rf Xray-linux-64.zip /tmp/xray

COPY package*.json ./
RUN npm install && npm cache clean --force

COPY . .

RUN mkdir -p /etc/xray /data /app/public /var/log/supervisor && \
    cp /app/xray-config.json /etc/xray/config.json

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
