# Multi-stage Dockerfile for SBOM Visualizer
# Supports dev, test, and prod environments

# Base stage with common dependencies
FROM python:3.12-slim as base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Development stage
FROM base as dev

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    black \
    flake8 \
    mypy

# Set development environment
ENV ENVIRONMENT=development

# Expose port for development server
EXPOSE 8000

# Default command for development
CMD ["python", "-m", "sbom_visualizer", "--help"]

# Test stage
FROM base as test

# Install test dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    pytest-mock

# Set test environment
ENV ENVIRONMENT=test

# Copy test files
COPY tests/ ./tests/
COPY examples/ ./examples/

# Create test user
RUN useradd --create-home --shell /bin/bash testuser
USER testuser

# Default command for tests
CMD ["python", "-m", "pytest", "tests/", "-v", "--cov=sbom_visualizer", "--cov-report=term-missing"]

# Production stage
FROM base as prod

# Install production dependencies only
RUN pip install --no-cache-dir \
    gunicorn \
    uvicorn

# Set production environment
ENV ENVIRONMENT=production

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Expose port for production server
EXPOSE 8000

# Default command for production
CMD ["python", "-m", "sbom_visualizer", "--help"]
