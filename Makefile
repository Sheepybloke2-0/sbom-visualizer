# Makefile for SBOM Visualizer

.PHONY: help build-dev build-test build-prod test test-docker run-dev run-prod clean install lint format

# Default target
help:
	@echo "SBOM Visualizer - Available commands:"
	@echo ""
	@echo "Development:"
	@echo "  make install     - Install dependencies"
	@echo "  make lint        - Run linting checks"
	@echo "  make format      - Format code with black"
	@echo "  make test        - Run tests locally"
	@echo ""
	@echo "Docker:"
	@echo "  make build-dev   - Build development Docker image"
	@echo "  make build-test  - Build test Docker image"
	@echo "  make build-prod  - Build production Docker image"
	@echo "  make test-docker - Run tests in Docker container"
	@echo "  make run-dev     - Run development container"
	@echo "  make run-prod    - Run production container"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean       - Clean up Docker images and containers"

# Local development
install:
	pip install -r requirements.txt
	pip install -e .

lint:
	flake8 sbom_visualizer/ tests/
	mypy sbom_visualizer/

format:
	black sbom_visualizer/ tests/
	isort sbom_visualizer/ tests/

test:
	pytest tests/ -v --cov=sbom_visualizer --cov-report=term-missing

# Docker commands
build-dev:
	docker build --target dev -t sbom-visualizer:dev .

build-test:
	docker build --target test -t sbom-visualizer:test .

build-prod:
	docker build --target prod -t sbom-visualizer:prod .

test-docker:
	docker build --target test -t sbom-visualizer:test .
	docker run --rm -v $(PWD):/app sbom-visualizer:test

run-dev:
	docker-compose --profile dev up --build

run-prod:
	docker-compose --profile prod up --build

# Cleanup
clean:
	docker system prune -f
	docker rmi sbom-visualizer:dev sbom-visualizer:test sbom-visualizer:prod 2>/dev/null || true