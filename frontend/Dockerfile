# Development Dockerfile for Shizuha ID Frontend
FROM node:20-alpine

WORKDIR /app

# Create packages directory (will be volume-mounted in dev)
RUN mkdir -p /packages

# Install dependencies
COPY package*.json ./
COPY vendor/ ./vendor/
RUN npm ci --ignore-scripts --no-audit --no-fund

# Copy source code
COPY . .

# Expose Vite dev server port
EXPOSE 80

# Start development server
CMD ["npm", "run", "dev"]
