# Use Node.js 18 slim image
FROM node:18-slim

# Install Python and Semgrep (optional - remove if not using Semgrep)
RUN apt-get update && apt-get install -y \
    python3-venv \
    curl \
    --no-install-recommends && \
    python3 -m venv /opt/semgrep-venv && \
    /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package.json (not package-lock.json since you might not have it)
COPY package.json ./

# Install dependencies using npm install instead of npm ci
# npm ci requires package-lock.json, npm install doesn't
RUN npm install --production

# Copy source code
COPY . .

# Expose port (Railway will override this)
EXPOSE 3000

# Set environment variables
ENV NODE_ENV=production
ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# Start the application
CMD ["node", "server.js"]