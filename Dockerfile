FROM node:18-alpine

RUN apk add --no-cache python3 make g++ gcc

WORKDIR /app

COPY package*.json ./

RUN npm install --production

COPY . .

RUN mkdir -p /data /app/public

EXPOSE 3000

CMD ["node", "server.js"]
