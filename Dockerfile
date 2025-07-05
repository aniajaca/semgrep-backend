FROM node:18-slim

# Install Python venv & curl
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-venv curl \
 && rm -rf /var/lib/apt/lists/*

# Create venv & install Semgrep
RUN python3 -m venv /opt/semgrep-venv \
 && /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep

# Add venv to PATH
ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# App directory
WORKDIR /app

# Copy package.json and install deps
COPY package*.json ./
RUN npm ci

# Copy code
COPY . .

# Expose port (Railway will override via $PORT)
EXPOSE 3000

# Launch the server directly
CMD ["node", "src/server.js"]
