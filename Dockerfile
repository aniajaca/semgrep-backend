FROM node:18-slim

# Install system dependencies
RUN apt-get update \
 && apt-get install -y python3-venv curl --no-install-recommends \
 && python3 -m venv /opt/semgrep-venv \
 && /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep \
 && rm -rf /var/lib/apt/lists/*

# Add semgrep to PATH
ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# Create app directory
WORKDIR /app

# Copy package files first (for better Docker layer caching)
COPY package*.json ./

# Install dependencies
RUN npm ci --production

# Copy source code
COPY . .

# Create uploads directory
RUN mkdir -p /tmp/uploads

# Set proper permissions
RUN chown -R node:node /app /tmp/uploads

# Switch to non-root user
USER node

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/healthz || exit 1

# Start the application
CMD ["node", "src/server.js"]