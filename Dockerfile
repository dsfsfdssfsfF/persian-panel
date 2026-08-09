# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Install build dependencies for better-sqlite3
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package*.json ./

# Install dependencies (بدون npm ci)
RUN npm install --omit=dev && npm cache clean --force

# Copy application files
COPY . .

# Runtime stage
FROM node:18-alpine

# Install nginx and other dependencies
RUN apk add --no-cache \
    nginx \
    gettext \
    tzdata \
    curl \
    bash \
    ca-certificates \
    && rm -rf /var/cache/apk/*

# Set timezone to Tehran
ENV TZ=Asia/Tehran
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Create app directory
WORKDIR /app

# Copy from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./
COPY . .

# Copy nginx config template
COPY nginx.conf.template /etc/nginx/nginx.conf.template

# Create necessary directories
RUN mkdir -p /var/log/nginx /var/lib/nginx /run/nginx /app/data /app/logs \
    && chmod +x /start.sh || true

# Copy start script
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Expose ports
EXPOSE 80 2053

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

# Start application
CMD ["/start.sh"]
