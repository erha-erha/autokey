FROM node:24-bookworm-slim

# Install system dependencies for Chromium & Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    curl \
    gnupg \
    ca-certificates \
    libnss3 \
    libatk-bridge2.0-0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpangocairo-1.0-0 \
    libpango-1.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    fonts-noto-color-emoji \
    fonts-wqy-zenhei \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

# Install Chromium
RUN npx patchright install --with-deps chromium

COPY . .

ENV AUTOKEY_HOST=0.0.0.0
ENV AUTOKEY_PORT=8080
ENV AUTOKEY_DATA_DIR=/app/data

EXPOSE 8080

CMD ["node", "bin/autokey.mjs", "serve"]
