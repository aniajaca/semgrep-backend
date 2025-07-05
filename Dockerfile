FROM node:18-slim

# 1) Python & Semgrep
RUN apt-get update \
 && apt-get install -y python3-venv curl --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

# 2) Force cache‐bust when server.js (or any code) changes
ARG CACHE_BUST=1

# 3) Create venv and install semgrep
RUN python3 -m venv /opt/semgrep-venv \
 && /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep

ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# 4) App setup
WORKDIR /app
COPY package*.json ./
RUN npm ci --production

# 5) Copy source code
COPY . .

# 6) Expose port & run
EXPOSE 3000
CMD ["node", "src/server.js"]
