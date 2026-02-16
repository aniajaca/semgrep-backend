FROM node:18-alpine

# Install Python and pip for Semgrep
RUN apk add --no-cache python3 py3-pip git curl

# Install Semgrep and ensure it's in PATH
RUN pip3 install semgrep --break-system-packages && \
    ln -s /usr/bin/python3 /usr/bin/python || true

# Pre-cache Semgrep rules (do this AFTER installing Semgrep)
RUN mkdir -p /tmp/test && \
    echo 'print("test")' > /tmp/test/test.py && \
    semgrep --config=p/security --metrics=off --json /tmp/test || true && \
    semgrep --config=p/owasp-top-ten --metrics=off --json /tmp/test || true && \
    semgrep --config=p/r2c-security-audit --metrics=off --json /tmp/test || true && \
    semgrep --config=p/javascript --metrics=off --json /tmp/test || true && \
    semgrep --config=p/python --metrics=off --json /tmp/test || true && \
    rm -rf /tmp/test

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install Node dependencies
RUN npm ci --omit=dev

# Copy the rest of the application
COPY . .

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]