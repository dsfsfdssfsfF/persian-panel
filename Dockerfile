FROM node:18-alpine

RUN apk add --no-cache python3 make g++ gcc

WORKDIR /app

COPY . .

RUN npm install --production

RUN mkdir -p /data /app/public

EXPOSE 3000

CMD ["node", "server.js"]
