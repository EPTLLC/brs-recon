# BRS-RECON Production Makefile
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-10-02
# Status: Production

.PHONY: deps lint build docker clean install help

# Default target
help:
	@echo "BRS-RECON Production Build Targets:"
	@echo ""
	@echo "Development:"
	@echo "  deps        - Install production dependencies"
	@echo "  install     - Install package in development mode"
	@echo ""
	@echo "Code Quality:"
	@echo "  format      - Format code with black and isort"
	@echo "  lint        - Run code quality checks (flake8)"
	@echo ""
	@echo "Build & Deploy:"
	@echo "  build       - Build distribution packages"
	@echo "  docker      - Build Docker container"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean       - Clean build artifacts"

# Dependency management
deps:
	pip install -r requirements/requirements.txt -c requirements/constraints.txt

# Package installation
install:
	pip install -e .

# Code formatting
format:
	black brsrecon/ examples/
	isort brsrecon/ examples/

# Code quality checks
lint:
	flake8 brsrecon/
	black --check brsrecon/
	isort --check-only brsrecon/

# Build targets
build:
	python3 -m build
	twine check dist/*

# Docker targets
docker:
	docker build -t brs-recon:latest .

# Cleaning targets
clean:
	rm -rf build/ dist/ *.egg-info/
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name "*.pyo" -delete 2>/dev/null || true
	rm -rf .mypy_cache/

# Development workflow
dev: format lint