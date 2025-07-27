# SBOM Visualizer Usage Guide

This guide provides detailed instructions for using the SBOM Visualizer tool to analyze, verify, and visualize Software Bill of Materials files.

## 🚀 Quick Start

### Using Docker (Recommended)

The easiest way to use SBOM Visualizer is with Docker:

```bash
# Build the production image
docker build --target prod -t sbom-visualizer:prod .

# Analyze an SBOM file
docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer analyze examples/sample.spdx.json

# Verify SBOM compliance
docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer verify examples/sample.spdx.json

# Show dependency tree
docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer dep examples/sample.spdx.json
```

### Using Make Commands

For convenience, you can use the provided Make commands:

```bash
# Analyze SBOM file
make analyze FILE=examples/sample.spdx.json

# Verify SBOM file
make verify FILE=examples/sample.cyclonedx.json

# Show dependency tree
make dep FILE=examples/sample.spdx.json

# Check specific package
make check-pkg FILE=examples/sample.spdx.json PKG=flask

# Comprehensive scan
make scan FILE=examples/sample.spdx.json
```

## 📋 Available Commands

### 1. Analyze Command

Analyzes an SBOM file and provides comprehensive insights.

```bash
sbom-analyzer analyze <file_path> [options]
```

**Options:**
- `--output, -o`: Output format (text, json, markdown, html)
- `--output-file, -f`: Save output to file

**Examples:**
```bash
# Basic analysis
sbom-analyzer analyze examples/sample.spdx.json

# JSON output
sbom-analyzer analyze examples/sample.spdx.json --output json

# HTML output saved to file
sbom-analyzer analyze examples/sample.spdx.json --output html --output-file report.html
```

**Output includes:**
- Package count and analysis
- License distribution
- Vulnerability summary
- Dependency depth analysis
- Completeness score
- Recommendations

### 2. Verify Command

Verifies SBOM compliance and completeness.

```bash
sbom-analyzer verify <file_path> [options]
```

**Options:**
- `--output, -o`: Output format (text, json, markdown, html)
- `--output-file, -f`: Save output to file

**Examples:**
```bash
# Basic verification
sbom-analyzer verify examples/sample.spdx.json

# JSON verification report
sbom-analyzer verify examples/sample.spdx.json --output json
```

**Verification checks:**
- Format compliance
- License compliance
- Dependency completeness
- Metadata validation
- Overall quality scoring

### 3. Dependency Tree Command

Shows the dependency tree structure.

```bash
sbom-analyzer dep <file_path> [options]
```

**Options:**
- `--output, -o`: Output format (text, json, markdown, html)
- `--output-file, -f`: Save output to file

**Examples:**
```bash
# Show dependency tree
sbom-analyzer dep examples/sample.spdx.json

# JSON dependency tree
sbom-analyzer dep examples/sample.spdx.json --output json
```

**Tree information includes:**
- Root packages
- Dependency relationships
- Circular dependency detection
- Depth analysis
- Total dependency count

### 4. Package Check Command

Provides detailed information about a specific package.

```bash
sbom-analyzer check-pkg <file_path> <package_name> [options]
```

**Options:**
- `--output, -o`: Output format (text, json, markdown, html)
- `--output-file, -f`: Save output to file

**Examples:**
```bash
# Check specific package
sbom-analyzer check-pkg examples/sample.spdx.json flask

# JSON package info
sbom-analyzer check-pkg examples/sample.spdx.json flask --output json
```

**Package information includes:**
- Version and description
- License information
- Dependencies
- Vulnerabilities
- Metadata

### 5. Scan Command

Performs a comprehensive scan with all analysis types.

```bash
sbom-analyzer scan <file_path> [options]
```

**Options:**
- `--output, -o`: Output format (text, json, markdown, html)
- `--output-file, -f`: Save output to file

**Examples:**
```bash
# Comprehensive scan
sbom-analyzer scan examples/sample.spdx.json

# HTML scan report
sbom-analyzer scan examples/sample.spdx.json --output html --output-file scan-report.html
```

**Scan includes:**
- Analysis report
- Verification results
- Dependency tree
- Package details
- Recommendations

## 📊 Output Formats

All commands support multiple output formats:

### Text Output (Default)
Human-readable text format with emojis and formatting.

### JSON Output
Structured JSON data for programmatic processing.

### HTML Output
Beautiful HTML reports with styling and charts.

### Markdown Output
Markdown format for documentation and reports.

## 📁 Example Files

The project includes several example SBOM files for testing:

### `examples/sample.spdx.json`
Basic SPDX example with 4 packages and dependency relationships:
- flask → requests → urllib3
- sqlalchemy (independent)

### `examples/sample.cyclonedx.json`
CycloneDX format example with components and dependencies.

### `examples/sample-with-vulnerabilities.spdx.json`
SPDX example with older package versions to demonstrate vulnerability detection.

## 🔧 Advanced Usage

### Environment Variables

You can configure the tool using environment variables:

```bash
# Set log level
export SBOM_LOG_LEVEL=DEBUG

# Set default output format
export SBOM_OUTPUT_FORMAT=json

# Set analysis depth
export SBOM_ANALYSIS_DEPTH=5
```

### Docker Volume Mounts

For persistent data and configuration:

```bash
# Mount configuration directory
docker run --rm -v $(pwd):/app -v $(pwd)/config:/app/config sbom-visualizer:prod sbom-analyzer analyze file.json

# Mount output directory
docker run --rm -v $(pwd):/app -v $(pwd)/output:/app/output sbom-visualizer:prod sbom-analyzer analyze file.json --output-file /app/output/report.html
```

### Batch Processing

Process multiple files:

```bash
# Process all JSON files in a directory
for file in *.json; do
    docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer analyze "$file" --output-file "analysis_${file%.json}.html"
done
```

## 🐳 Docker Development

### Development Environment

```bash
# Build development image
make build-dev

# Start development shell
make dev-shell

# Run tests
make test-docker

# Format code
make format-docker

# Lint code
make lint-docker
```

### Production Environment

```bash
# Build production image
make build-prod

# Run production container
make run-prod
```

## 📈 Expected Output Examples

### Analysis Report (Text)
```
📊 SBOM Analysis Report
========================

📦 Package Analysis
• Total Packages: 4
• Unique Licenses: 3 (Apache-2.0, BSD-3-Clause, MIT)
• Completeness Score: 87.5%

📋 License Distribution
• Apache-2.0: 1 package
• BSD-3-Clause: 1 package  
• MIT: 2 packages

🔍 Dependency Analysis
• Root Packages: 2
• Max Depth: 2
• Total Dependencies: 2

⚠️ Vulnerability Summary
• No vulnerabilities found

💡 Recommendations
• All packages have proper license information
• Dependency relationships are well-defined
• SBOM is well-structured and complete
```

### Verification Report
```
✅ SBOM Verification Report
==========================

📊 Overall Score: 87/100

✅ Passed Checks:
• Document metadata is complete
• All packages have license information
• Package versions are specified
• Dependency relationships are defined

⚠️ Warnings:
• Consider adding more package metadata
• Some packages lack PURLs

🔍 Issues Found: 0
```

## 🚨 Troubleshooting

### Common Issues

1. **File not found**
   ```
   Error: File not found: /path/to/file.json
   ```
   Solution: Ensure the file path is correct and the file exists.

2. **Invalid SBOM format**
   ```
   Error: Not a valid SPDX file
   ```
   Solution: Check that the file is a valid SBOM in supported format.

3. **Docker permission issues**
   ```
   Error: permission denied
   ```
   Solution: Ensure Docker has access to the mounted directories.

### Getting Help

- Use `--help` for command options: `sbom-analyzer analyze --help`
- Check the [README](../README.md) for basic usage
- Review [Docker examples](../examples/docker-examples.md) for advanced Docker usage
- Run the quick start script: `./scripts/quick-start.sh`

## 📚 Next Steps

1. **Try the examples**: Run the quick start script to see all features
2. **Analyze your SBOMs**: Use your own SBOM files for analysis
3. **Customize output**: Experiment with different output formats
4. **Integrate**: Use the tool in your CI/CD pipelines
5. **Contribute**: Help improve the tool by contributing code or documentation 