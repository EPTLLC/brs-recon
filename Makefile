# BRS-RECON Makefile
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Sun 07 Sep 2025

.PHONY: deps lint test build docker clean help

# Default target
help:
	@echo "BRS-RECON Build Targets:"
	@echo "  deps    - Install Python dependencies"
	@echo "  lint    - Run code quality checks"
	@echo "  test    - Run test suite"
	@echo "  build   - Build distribution packages"
	@echo "  docker  - Build Docker container"
	@echo "  clean   - Clean build artifacts"

# Install dependencies
deps:
	pip3 install -r requirements/requirements.txt

# Code quality checks
lint:
	flake8 brs-recon && black --check brs-recon

# Run tests
test:
	pytest -q tests/

# Build distribution
build:
	python3 -m build

# Build Docker container
docker:
	docker build -t brs-recon .

# Clean build artifacts
clean:
	rm -rf build/ dist/ *.egg-info/
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
