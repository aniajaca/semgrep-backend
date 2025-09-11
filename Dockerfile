# Use Node.js 18 slim image
FROM node:18-slim

# Install Python and Semgrep (optional - you can remove this since using AST now)
RUN apt-get update && apt-get install -y \
    python3-venv \
    curl \
    --no-install-recommends && \
    python3 -m venv /opt/semgrep-venv && \
    /opt/semgrep-venv/bin/pip install --no-cache-dir semgrep && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy all source code
COPY . .

# Expose port
EXPOSE 3000

# Set environment variables
ENV NODE_ENV=production
ENV PATH="/opt/semgrep-venv/bin:${PATH}"

# CRITICAL FIX: Point to the correct location of server.js
CMD ["node", "src/server.js"]