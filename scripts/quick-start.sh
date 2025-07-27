#!/bin/bash

# SBOM Visualizer Quick Start Script
# This script demonstrates the basic usage of the SBOM Visualizer tool using Docker

set -e

echo "🚀 SBOM Visualizer Quick Start (Docker)"
echo "========================================="
echo ""

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH"
    echo "Please install Docker and try again"
    exit 1
fi

# Function to run commands and show output
run_command() {
    echo "Running: $1"
    echo "----------------------------------------"
    eval "$1"
    echo "----------------------------------------"
    echo ""
}

# Function to run commands and save output to file
run_command_save() {
    echo "Running: $1"
    echo "Output saved to: $2"
    echo "----------------------------------------"
    mkdir -p quick-start-output
    eval "$1" > "quick-start-output/$2"
    echo "----------------------------------------"
    echo ""
}

# Build the Docker image
echo "🔨 Building Docker image..."
docker build --target prod -t sbom-visualizer:prod . > /dev/null 2>&1
echo "✅ Docker image built successfully"
echo ""

echo "🔍 Step 1: Basic Analysis"
echo "=========================="
run_command "docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer analyze examples/sample.spdx.json"

echo "🔍 Step 2: Verification"
echo "======================="
run_command "docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer verify examples/sample.spdx.json"

echo "🌳 Step 3: Dependency Tree"
echo "==========================="
run_command "docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer dep examples/sample.spdx.json"

echo "📦 Step 4: Package Information"
echo "=============================="
run_command "docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer check-pkg examples/sample.spdx.json flask"

echo "🔍 Step 5: Comprehensive Scan"
echo "============================="
run_command "docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer scan examples/sample.spdx.json"

echo "📊 Step 6: Different Output Formats"
echo "==================================="

# Generate JSON output
run_command_save "docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer analyze examples/sample.spdx.json --output json" "analysis.json"

# Generate HTML output
run_command_save "docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer analyze examples/sample.spdx.json --output html" "analysis.html"

# Generate Markdown output
run_command_save "docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer analyze examples/sample.spdx.json --output markdown" "analysis.md"

echo "🔍 Step 7: CycloneDX Example"
echo "============================="
run_command "docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer analyze examples/sample.cyclonedx.json"

echo "🔍 Step 8: SPDX with Vulnerabilities"
echo "===================================="
run_command "docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer analyze examples/sample-with-vulnerabilities.spdx.json"

echo "🎉 Quick Start Complete!"
echo "======================="
echo ""
echo "📁 Generated files are in: quick-start-output/"
echo "📖 For more examples, see: examples/"
echo "📚 For detailed usage, see: docs/USAGE.md"
echo ""
echo "💡 Try these commands:"
echo "  make analyze FILE=examples/sample.spdx.json"
echo "  make verify FILE=examples/sample.cyclonedx.json"
echo "  make dep FILE=examples/sample.spdx.json"
echo "  make check-pkg FILE=examples/sample.spdx.json PKG=flask"
echo "  make scan FILE=examples/sample.spdx.json"
echo "" 