FROM node:20-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./

RUN npm install --prefer-offline

COPY . .

RUN mkdir -p /data /app/public

ENV NODE_ENV=production

EXPOSE 3000

CMD ["node", "server.js"]
