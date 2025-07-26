#!/bin/bash

# Script to run SBOM Visualizer tests in Docker

set -e

echo "🐳 Building and running SBOM Visualizer tests in Docker..."

# Build the test image
echo "📦 Building test Docker image..."
docker build --target test -t sbom-visualizer:test .

# Run tests
echo "🧪 Running tests..."
docker run --rm \
    -v "$(pwd):/app" \
    -e PYTHONPATH=/app \
    sbom-visualizer:test \
    python -m pytest tests/ -v --cov=sbom_visualizer --cov-report=term-missing

echo "✅ Tests completed!" 