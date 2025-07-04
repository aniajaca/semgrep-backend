# Dockerfile
FROM node:18-slim

# 1. Install Python venv and pip
RUN apt-get update && \
    apt-get install -y --no-install-recommends python3-venv python3-pip curl && \
    rm -rf /var/lib/apt/lists/*

# 2. Create & activate a venv, install Semgrep into it
RUN python3 -m venv /opt/semgrep-venv && \
    /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep

# 3. Add venv bin to PATH
ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# 4. Create app directory
WORKDIR /app

# 5. Install Node dependencies
COPY package*.json ./
RUN npm ci --production

# 6. Copy source
COPY . .

# 7. Expose port and healthcheck
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s \
  CMD curl --fail http://localhost:3000/healthz || exit 1

# 8. Launch the service
CMD ["node", "src/server.js"]
