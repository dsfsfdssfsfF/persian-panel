FROM node:18-alpine

RUN apk add --no-cache python3 make g++ gcc

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

COPY . .

RUN mkdir -p /app/data

EXPOSE 2053

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:2053/health || exit 1

CMD ["node", "server.js"]
