FROM node:18-slim

RUN apt-get update \
 && apt-get install -y python3-venv curl --no-install-recommends \
 && python3 -m venv /opt/semgrep-venv \
 && /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep \
 && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/semgrep-venv/bin:${PATH}"

WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .

EXPOSE 3000
CMD ["node", "src/server.js"]
