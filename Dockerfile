# Dockerfile
FROM node:18-slim

# 1. Install Python venv support (includes pip) and curl for healthcheck
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3-venv curl \
  && rm -rf /var/lib/apt/lists/*

# 2. Create & activate a venv, install Semgrep into it
RUN python3 -m venv /opt/semgrep-venv \
  && /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep

# 3. Put the venv's bin directory first on the PATH
ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# 4. Set a default PORT env var (can be overridden by Railway/Heroku)
ENV PORT=3000

# 5. Create & switch into the app directory
WORKDIR /app

# 6. Copy and install Node dependencies
COPY package*.json ./
RUN npm ci --production

# 7. Copy the rest of your source
COPY . .

# 8. Expose the port (will match $PORT)
EXPOSE ${PORT}

# 9. Healthcheck against the /healthz endpoint (added below)
HEALTHCHECK --interval=30s --timeout=5s \
  CMD curl --fail http://localhost:${PORT}/healthz || exit 1

# 10. Launch the service
CMD ["node", "src/server.js"]
