FROM node:18-slim

# 1) Python & Semgrep
RUN apt-get update \
 && apt-get install -y python3-venv curl --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/semgrep-venv \
 && /opt/semgrep-venv/bin/pip install semgrep

ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# 2) App setup
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .

# 3) Port & entrypoint
EXPOSE 3000
CMD ["node","src/server.js"]
