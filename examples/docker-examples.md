# Docker Examples for SBOM Visualizer

This document provides specific examples of how to use the SBOM Visualizer with Docker containers.

## Prerequisites

Ensure you have Docker installed and the project built:

```bash
# Build the development image
make build-dev

# Build the test image
make build-test
```

## Basic Usage Examples

### 1. Simple Analysis

```bash
# Analyze an SPDX file
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.spdx.json

# Analyze a CycloneDX file
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.cyclonedx.json
```

### 2. Output to Files

```bash
# Generate HTML report
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.spdx.json --format html --output report.html

# Generate JSON analysis
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.spdx.json --format json --output analysis.json

# Generate Markdown documentation
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.spdx.json --format markdown --output analysis.md
```

### 3. Verification

```bash
# Verify SBOM completeness
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli verify examples/sample.spdx.json

# Check for vulnerabilities
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli verify examples/sample-with-vulnerabilities.spdx.json
```

### 4. Dependency Analysis

```bash
# Generate dependency tree
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli dep examples/sample.spdx.json

# Get package information
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli check-pkg examples/sample.spdx.json requests
```

### 5. Comprehensive Scanning

```bash
# Full analysis with all outputs
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli scan examples/sample.spdx.json

# Scan with specific output format
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli scan examples/sample.spdx.json --format html --output full-report.html
```

## Advanced Docker Examples

### 1. Interactive Development

```bash
# Start an interactive shell
docker run --rm -it -v $(pwd):/app sbom-visualizer:dev bash

# Inside the container, you can run:
# python -m sbom_visualizer.cli analyze examples/sample.spdx.json
# python -m sbom_visualizer.cli verify examples/sample.spdx.json
# exit
```

### 2. Batch Processing

```bash
# Process all example files
for file in examples/*.json; do
    docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli analyze "$file" --output "reports/$(basename "$file" .json).txt"
done

# Generate HTML reports for all files
for file in examples/*.json; do
    docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli analyze "$file" --format html --output "reports/$(basename "$file" .json).html"
done
```

### 3. Custom Volume Mounts

```bash
# Mount a specific directory for input/output
docker run --rm -v /path/to/sbom/files:/input -v /path/to/output:/output sbom-visualizer:dev python -m sbom_visualizer.cli analyze /input/my-sbom.json --output /output/analysis.txt

# Mount current directory with different name
docker run --rm -v $(pwd):/workspace sbom-visualizer:dev python -m sbom_visualizer.cli analyze /workspace/examples/sample.spdx.json
```

### 4. Environment Variables

```bash
# Set environment variables
docker run --rm -v $(pwd):/app -e SBOM_LOG_LEVEL=DEBUG sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.spdx.json

# Multiple environment variables
docker run --rm -v $(pwd):/app \
  -e SBOM_LOG_LEVEL=INFO \
  -e SBOM_OUTPUT_FORMAT=json \
  sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.spdx.json
```

### 5. Network Access (for future features)

```bash
# If the tool needs network access for vulnerability databases
docker run --rm -v $(pwd):/app --network host sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.spdx.json
```

## CI/CD Integration Examples

### GitHub Actions

```yaml
name: SBOM Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build Docker image
        run: make build-dev
      
      - name: Analyze SBOM
        run: |
          docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli analyze sbom.json --format json --output analysis.json
          docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli verify sbom.json --format json --output verification.json
      
      - name: Upload reports
        uses: actions/upload-artifact@v3
        with:
          name: sbom-reports
          path: |
            analysis.json
            verification.json
```

### GitLab CI

```yaml
sbom-analysis:
  image: docker:latest
  services:
    - docker:dind
  before_script:
    - docker build -t sbom-visualizer:dev .
  script:
    - docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli analyze sbom.json --format json --output analysis.json
    - docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli verify sbom.json --format json --output verification.json
  artifacts:
    paths:
      - analysis.json
      - verification.json
```

## Troubleshooting Docker Issues

### 1. Permission Issues

```bash
# If you get permission errors, try:
docker run --rm -v $(pwd):/app --user $(id -u):$(id -g) sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.spdx.json
```

### 2. File Not Found

```bash
# Ensure the file exists in the mounted directory
ls -la examples/sample.spdx.json
docker run --rm -v $(pwd):/app sbom-visualizer:dev ls -la /app/examples/sample.spdx.json
```

### 3. Output Directory Issues

```bash
# Create output directory first
mkdir -p reports
docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.spdx.json --output reports/analysis.txt
```

### 4. Memory Issues

```bash
# Increase memory limit for large files
docker run --rm -v $(pwd):/app --memory=2g sbom-visualizer:dev python -m sbom_visualizer.cli analyze large-sbom.json
```

## Performance Tips

### 1. Use Named Volumes for Repeated Access

```bash
# Create a named volume for better performance
docker volume create sbom-data

# Use the named volume
docker run --rm -v sbom-data:/data sbom-visualizer:dev python -m sbom_visualizer.cli analyze /data/sbom.json
```

### 2. Multi-stage Builds for Production

```bash
# Build production image
make build-prod

# Use production image for analysis
docker run --rm -v $(pwd):/app sbom-visualizer:prod python -m sbom_visualizer.cli analyze examples/sample.spdx.json
```

### 3. Parallel Processing

```bash
# Process multiple files in parallel
parallel docker run --rm -v $(pwd):/app sbom-visualizer:dev python -m sbom_visualizer.cli analyze {} --output reports/{/.}.txt ::: examples/*.json
```

## Security Considerations

### 1. Run as Non-root User

```bash
# Run with specific user
docker run --rm -v $(pwd):/app --user 1000:1000 sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.spdx.json
```

### 2. Read-only Mounts

```bash
# Mount input directory as read-only
docker run --rm -v $(pwd)/examples:/input:ro sbom-visualizer:dev python -m sbom_visualizer.cli analyze /input/sample.spdx.json --output /tmp/analysis.txt
```

### 3. Resource Limits

```bash
# Set resource limits
docker run --rm -v $(pwd):/app \
  --memory=512m \
  --cpus=1.0 \
  sbom-visualizer:dev python -m sbom_visualizer.cli analyze examples/sample.spdx.json
``` 