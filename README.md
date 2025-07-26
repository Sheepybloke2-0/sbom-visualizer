# SBOM Visualizer

A comprehensive tool for analyzing and visualizing Software Bill of Materials (SBOMs). The goal is to be an AI-powered SBOM analysis and visualization tool that allows users to easily parse and understand SBOMs. Think of it as the "Notebook LM" version of SBOM analysis.

## 🎯 Features

- **Multi-Format Support**: Automatically detects and parses SPDX 3.0, CycloneDX 1.5, and SWID formats
- **Comprehensive Analysis**: Package counting, license distribution, vulnerability assessment, dependency analysis
- **Multiple Output Formats**: Text (CLI-friendly), JSON, Markdown, and HTML with modern styling
- **AI Integration**: Claude-powered CVE checking, license analysis, and intelligent insights (Stage 4)
- **Web Interface**: Interactive visualization and analysis (Stage 2)

## 🚀 Quick Start

### Using Python (Local Installation)

#### 1. Install Dependencies
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install the package in development mode
pip install -e .
```

#### 2. Basic Usage
```bash
# Analyze an SBOM file
sbom-analyzer analyze examples/sample.spdx.json

# Verify SBOM validity
sbom-analyzer verify examples/sample.spdx.json

# Show dependency tree
sbom-analyzer dep examples/sample.spdx.json

# Get package details
sbom-analyzer check-pkg examples/sample.spdx.json requests
```

#### 3. Advanced Usage
```bash
# Generate HTML report
sbom-analyzer analyze examples/sample.spdx.json -t html -o report.html

# Export JSON analysis
sbom-analyzer analyze examples/sample.spdx.json -t json -o analysis.json

# Generate Markdown documentation
sbom-analyzer dep examples/sample.spdx.json -t markdown -o dependencies.md

# Verbose output for debugging
sbom-analyzer --verbose analyze examples/sample.spdx.json
```

### Using Docker

#### 1. Build and Run
```bash
# Build the development image
make build-dev

# Run analysis in container
docker run --rm -v $(pwd):/app sbom-visualizer:dev sbom-analyzer analyze examples/sample.spdx.json

# Run with interactive shell
docker run --rm -it -v $(pwd):/app sbom-visualizer:dev bash
```

#### 2. Docker Compose (Full Environment)
```bash
# Start development environment with MongoDB
docker-compose --profile dev up --build

# Run tests in container
make test-docker

# Clean up containers
docker-compose down
```

## 📋 CLI Commands

### Basic Commands

```bash
# Analyze SBOM and generate report
sbom-analyzer analyze <file> [options]

# Verify SBOM validity and completeness
sbom-analyzer verify <file>

# Show dependency tree
sbom-analyzer dep <file> [options]

# Get detailed package information
sbom-analyzer check-pkg <file> <package-name>

# Scan for vulnerabilities (Stage 4)
sbom-analyzer scan <file> [options]
```

### Command Options

```bash
# Global options
--verbose          # Increase log level to DEBUG
--quiet           # Decrease log level to WARN
--version         # Show version information

# Output options (for analyze, dep, scan)
-o, --output      # Specify output filename
-t, --type        # Output type: text, json, markdown, html
```

### Output Types

- **text**: Human-readable CLI output with emojis and formatting
- **json**: Structured data for programmatic processing
- **markdown**: Documentation-friendly format
- **html**: Modern, styled output with dark mode support

## 🔧 Development

### Local Development Setup

```bash
# Clone repository
git clone <repository-url>
cd spdx-visualizer

# Install dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
pytest tests/ -v --cov=sbom_visualizer

# Format code
black sbom_visualizer/ tests/

# Lint code
flake8 sbom_visualizer/ tests/
```

### Docker Development

```bash
# Build all images
make build-dev
make build-test
make build-prod

# Run tests
make test-docker

# Development environment
make run-dev

# Production environment
make run-prod

# Clean up
make clean
```

### Testing

```bash
# Run all tests with coverage
make test-docker

# Run specific test file
pytest tests/test_analyzer.py -v

# Run with coverage report
pytest --cov=sbom_visualizer --cov-report=term-missing

# Run tests in Docker
docker run --rm -v $(pwd):/app sbom-visualizer:test
```

## 📊 Example Output

### Text Analysis Report
```
📊 SBOM Analysis Report
==================================================
📦 Total Packages: 3
📋 Unique Licenses: 2
🎯 Completeness Score: 85.5%

📜 License Distribution:
- MIT: 2 packages
- Apache-2.0: 1 package

⚠️ Vulnerability Summary:
- HIGH: 1 vulnerability
- MEDIUM: 0 vulnerabilities
- LOW: 0 vulnerabilities

💡 Recommendations:
1. Add dependency information for packages
2. Consider updating vulnerable packages
```

### HTML Report
Generates modern, styled HTML reports with:
- Responsive design
- Dark mode support
- Interactive elements
- Professional styling

## 🏗️ Architecture

### Technology Stack
- **Backend**: Python 3.12+, FastAPI, GraphQL (Strawberry)
- **CLI**: Click framework
- **Data Validation**: Pydantic models
- **Testing**: pytest with coverage
- **Containerization**: Docker multi-stage builds
- **Database**: MongoDB (Stage 3)

### Project Structure
```
sbom_visualizer/
├── cli.py                 # CLI interface
├── core/                  # Core functionality
│   ├── analyzer.py       # SBOM analysis
│   ├── parser.py         # SBOM parsing
│   ├── verifier.py       # SBOM validation
│   └── parsers/          # Format-specific parsers
├── models/               # Data models
├── utils/                # Utilities
└── tests/                # Test suite
```

## 📈 Development Stages

- **✅ Stage 1**: CLI Tool (COMPLETED)
- **🔄 Stage 2**: Web Interface
- **⏳ Stage 3**: User Management
- **⏳ Stage 4**: AI Integration

## 🔐 Security & Configuration

- **API Keys**: Stored using SOPS, .netrc, and environment variables
- **Secrets Management**: Secure handling of sensitive data
- **Input Validation**: Comprehensive validation of SBOM files
- **Error Handling**: Graceful error management and reporting

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure code coverage remains high
6. Submit a pull request

## 📄 License

[License information to be added]

---

**Current Status**: Stage 1 Complete (65% test coverage)  
**Next Milestone**: Stage 2 - Web Interface Development
