FROM node:18-slim

# Install Python venv & curl
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-venv curl \
 && rm -rf /var/lib/apt/lists/*

# Create venv & install Semgrep
RUN python3 -m venv /opt/semgrep-venv \
 && /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep

# **Put the venv bin on PATH so 'semgrep' is found**
ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# App directory
WORKDIR /app

# Install Node deps
COPY package*.json ./
RUN npm ci --production

# Copy source
COPY . .

# Expose & healthcheck
ENV PORT=3000
EXPOSE ${PORT}
HEALTHCHECK --interval=30s --timeout=5s \
  CMD curl --fail http://localhost:${PORT}/healthz || exit 1

CMD ["node", "src/server.js"]
