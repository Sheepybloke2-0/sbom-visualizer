# Makefile for SBOM Visualizer

.PHONY: help build-dev build-test build-prod test test-docker run-dev run-prod clean install lint format format-docker lint-docker test-docker-cov dev-shell

# Default target
help:
	@echo "SBOM Visualizer - Available commands:"
	@echo ""
	@echo "Development (Local):"
	@echo "  make install     - Install dependencies"
	@echo "  make lint        - Run linting checks"
	@echo "  make format      - Format code with black and isort"
	@echo "  make test        - Run tests locally"
	@echo ""
	@echo "Development (Docker):"
	@echo "  make format-docker - Format code in Docker container"
	@echo "  make lint-docker   - Run linting in Docker container"
	@echo "  make test-docker   - Run tests in Docker container"
	@echo "  make test-docker-cov - Run tests with coverage in Docker"
	@echo "  make dev-shell     - Open development shell in Docker"
	@echo ""
	@echo "Docker Build:"
	@echo "  make build-dev   - Build development Docker image"
	@echo "  make build-test  - Build test Docker image"
	@echo "  make build-prod  - Build production Docker image"
	@echo ""
	@echo "Docker Run:"
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
	flake8 sbom_visualizer/ tests/ --max-line-length=88 --extend-ignore=E203,W503
	mypy sbom_visualizer/ --ignore-missing-imports

format:
	black sbom_visualizer/ tests/ --line-length 88
	isort sbom_visualizer/ tests/ --profile black

test:
	pytest tests/ -v --cov=sbom_visualizer --cov-report=term-missing

# Docker development commands
format-docker:
	docker build --target dev -t sbom-visualizer:dev .
	docker run --rm -v $(PWD):/app sbom-visualizer:dev black sbom_visualizer/ tests/ --line-length 88
	docker run --rm -v $(PWD):/app sbom-visualizer:dev isort sbom_visualizer/ tests/ --profile black

lint-docker:
	docker build --target dev -t sbom-visualizer:dev .
	docker run --rm -v $(PWD):/app sbom-visualizer:dev flake8 sbom_visualizer/ tests/ --max-line-length=88 --extend-ignore=E203,W503
	docker run --rm -v $(PWD):/app sbom-visualizer:dev mypy sbom_visualizer/ --ignore-missing-imports

test-docker:
	docker build --target test -t sbom-visualizer:test .
	docker run --rm -v $(PWD):/app sbom-visualizer:test

test-docker-cov:
	docker build --target test -t sbom-visualizer:test .
	docker run --rm -v $(PWD):/app sbom-visualizer:test pytest tests/ -v --cov=sbom_visualizer --cov-report=term-missing --cov-report=html

dev-shell:
	docker build --target dev -t sbom-visualizer:dev .
	docker run --rm -it -v $(PWD):/app sbom-visualizer:dev /bin/bash

# Docker build commands
build-dev:
	docker build --target dev -t sbom-visualizer:dev .

build-test:
	docker build --target test -t sbom-visualizer:test .

build-prod:
	docker build --target prod -t sbom-visualizer:prod .

# Docker run commands
run-dev:
	docker-compose --profile dev up --build

run-prod:
	docker-compose --profile prod up --build

# Cleanup
clean:
	docker system prune -f
	docker rmi sbom-visualizer:dev sbom-visualizer:test sbom-visualizer:prod 2>/dev/null || true