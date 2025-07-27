# SBOM Visualizer

AI-powered SBOM analysis and visualization tool for comprehensive Software Bill of Materials insights.

## 🚀 Quick Start

### Using Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/your-org/sbom-visualizer.git
cd sbom-visualizer

# Run the quick start script
./scripts/quick-start.sh

# Or use individual commands
make analyze FILE=examples/sample.spdx.json
make verify FILE=examples/sample.cyclonedx.json
make dep FILE=examples/sample.spdx.json
make check-pkg FILE=examples/sample.spdx.json PKG=flask
make scan FILE=examples/sample.spdx.json
```

### Direct Docker Commands

```bash
# Build the Docker image
docker build --target prod -t sbom-visualizer:prod .

# Analyze an SBOM file
docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer analyze examples/sample.spdx.json

# Verify SBOM compliance
docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer verify examples/sample.spdx.json

# Show dependency tree
docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer dep examples/sample.spdx.json

# Check specific package
docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer check-pkg examples/sample.spdx.json flask

# Comprehensive scan
docker run --rm -v $(pwd):/app sbom-visualizer:prod sbom-analyzer scan examples/sample.spdx.json
```

## 📋 Available Commands

| Command | Description | Example |
|---------|-------------|---------|
| `analyze` | Analyze SBOM and provide insights | `sbom-analyzer analyze file.json` |
| `verify` | Verify SBOM compliance | `sbom-analyzer verify file.json` |
| `dep` | Show dependency tree | `sbom-analyzer dep file.json` |
| `check-pkg` | Check specific package | `sbom-analyzer check-pkg file.json package-name` |
| `scan` | Comprehensive scan | `sbom-analyzer scan file.json` |

### Output Formats

All commands support multiple output formats:

```bash
# Text output (default)
sbom-analyzer analyze file.json

# JSON output
sbom-analyzer analyze file.json --output json

# HTML output
sbom-analyzer analyze file.json --output html

# Markdown output
sbom-analyzer analyze file.json --output markdown

# Save to file
sbom-analyzer analyze file.json --output-file analysis.html
```

## 📁 Example Files

The project includes several example SBOM files:

- `examples/sample.spdx.json` - Basic SPDX example with dependencies
- `examples/sample.cyclonedx.json` - CycloneDX format example
- `examples/sample-with-vulnerabilities.spdx.json` - SPDX with vulnerability data

## 🛠️ Development

### Prerequisites

- Python 3.9+
- Docker (for containerized development)

### Local Development

```bash
# Install dependencies
make install

# Run tests
make test

# Format code
make format

# Lint code
make lint
```

### Docker Development

```bash
# Run tests in Docker
make test-docker

# Format code in Docker
make format-docker

# Lint code in Docker
make lint-docker

# Development shell
make dev-shell
```

## 📊 Features

### 🔍 Analysis
- Package counting and categorization
- License distribution analysis
- Vulnerability summary by severity
- Dependency depth analysis
- Completeness scoring (0-100%)
- Intelligent recommendations

### ✅ Verification
- Format compliance checking
- License compliance validation
- Dependency completeness verification
- Metadata validation
- Overall quality scoring

### 🌳 Dependency Visualization
- Interactive dependency trees
- Circular dependency detection
- Depth analysis
- Root package identification
- Multiple output formats

### 📦 Package Information
- Detailed package metadata
- Dependency relationships
- License information
- Vulnerability data
- Version constraints

## 🐳 Docker Support

The project includes comprehensive Docker support with multiple stages:

- **Development**: Full development environment with debugging tools
- **Testing**: Optimized for running tests and coverage
- **Production**: Minimal production image with the application

### Docker Commands

```bash
# Build different stages
make build-dev    # Development environment
make build-test   # Testing environment  
make build-prod   # Production environment

# Run containers
make run-dev      # Development server
make run-prod     # Production server

# Development tools
make dev-shell    # Interactive development shell
```

## 📚 Documentation

- [Usage Guide](docs/USAGE.md) - Detailed usage instructions
- [Docker Examples](examples/docker-examples.md) - Docker-specific examples
- [API Documentation](docs/API.md) - API reference (coming soon)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone and setup
git clone https://github.com/your-org/sbom-visualizer.git
cd sbom-visualizer

# Install in development mode
make install

# Run tests
make test-docker

# Start development
make dev-shell
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- SPDX community for the SBOM standard
- CycloneDX for the comprehensive SBOM format
- Open source community for inspiration and tools
