FROM node:18-alpine

# Install Python and pip for Semgrep
RUN apk add --no-cache python3 py3-pip git

# Install Semgrep
RUN pip3 install semgrep --break-system-packages

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install Node dependencies
RUN npm install

# Copy the rest of the application
COPY . .

# Expose port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]