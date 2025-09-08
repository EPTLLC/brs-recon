# BRS-RECON Enhanced Makefile
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Enhanced

.PHONY: deps deps-dev deps-test lint test test-unit test-integration test-all
.PHONY: build docker docker-security format check benchmark
.PHONY: clean clean-all install install-dev pre-commit setup help

# Default target
help:
	@echo "BRS-RECON Enhanced Build Targets:"
	@echo ""
	@echo "Development:"
	@echo "  setup       - Complete development environment setup"
	@echo "  deps        - Install production dependencies"
	@echo "  deps-dev    - Install development dependencies"
	@echo "  deps-test   - Install testing dependencies"
	@echo "  install     - Install package in development mode"
	@echo "  install-dev - Install package with dev dependencies"
	@echo "  pre-commit  - Install pre-commit hooks"
	@echo ""
	@echo "Code Quality:"
	@echo "  format      - Format code with black and isort"
	@echo "  lint        - Run code quality checks (flake8, mypy, bandit)"
	@echo "  check       - Run all quality checks and tests"
	@echo ""
	@echo "Testing:"
	@echo "  test        - Run basic test suite"
	@echo "  test-unit   - Run unit tests only"
	@echo "  test-integration - Run integration tests"
	@echo "  test-all    - Run all tests with coverage"
	@echo ""
	@echo "Performance:"
	@echo "  benchmark   - Run performance benchmarks"
	@echo ""
	@echo "Build & Deploy:"
	@echo "  build       - Build distribution packages"
	@echo "  docker      - Build Docker container"
	@echo "  docker-security - Build Docker with security scanning"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean       - Clean build artifacts"
	@echo "  clean-all   - Deep clean including caches and results"

# Development environment setup
setup: deps-dev install-dev pre-commit

# Dependency management
deps:
	pip install -r requirements/requirements.txt -c requirements/constraints.txt

deps-dev:
	pip install -r requirements/requirements-dev.txt -c requirements/constraints.txt

deps-test:
	pip install -r requirements/requirements-test.txt -c requirements/constraints.txt

# Package installation
install:
	pip install -e .

install-dev:
	pip install -e .[dev,test,docs]

# Pre-commit hooks
pre-commit:
	pre-commit install --install-hooks

# Code formatting
format:
	black brsrecon/ tests/ examples/
	isort brsrecon/ tests/ examples/

# Code quality checks
lint:
	flake8 brsrecon/ tests/
	black --check brsrecon/ tests/
	isort --check-only brsrecon/ tests/
	mypy brsrecon/ || true
	bandit -r brsrecon/ -f json -o bandit-report.json || true

# Comprehensive quality check
check: lint test-unit

# Testing targets
test:
	pytest tests/unit/ -v --tb=short

test-unit:
	pytest tests/unit/ -v --cov=brsrecon --cov-report=term-missing

test-integration:
	pytest tests/integration/ -v -m "not privileged" || true

test-all:
	pytest tests/ -v --cov=brsrecon --cov-report=html --cov-report=xml --cov-fail-under=80

test-parallel:
	pytest tests/ -n 4 --cov=brsrecon

test-coverage:
	pytest --cov=brsrecon --cov-report=html --cov-report=term

test-performance:
	pytest tests/ -k "benchmark or performance" --tb=short

test-security:
	pytest tests/ -k "security or auth or validation" --tb=short

test-check:
	python scripts/run_tests.py check

test-specific:
	@if [ -z "$(TEST)" ]; then echo "Usage: make test-specific TEST=tests/unit/core/test_base.py"; exit 1; fi
	pytest $(TEST) -v

# Performance benchmarking
benchmark:
	mkdir -p results/benchmarks
	python3 -m brsrecon.core.benchmark --output results/benchmarks --report

# Build targets
build:
	python3 -m build
	twine check dist/*

# Docker targets
docker:
	docker build -t brs-recon:latest .

docker-security: docker
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		-v $(pwd):/tmp aquasec/trivy image brs-recon:latest || true

# Validation targets
validate-schemas:
	python3 -c "import json; [json.load(open(f)) for f in ['examples/schemas/scan-result.schema.json', 'examples/schemas/sarif-mapping.json']]"

validate-examples:
	python3 -c "import json; json.load(open('examples/outputs/network-discovery-example.json'))"
	python3 -c "import json; json.load(open('examples/outputs/vulnerability-scan-example.sarif'))"

validate: validate-schemas validate-examples

# Cleaning targets
clean:
	rm -rf build/ dist/ *.egg-info/
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name "*.pyo" -delete 2>/dev/null || true
	find . -name ".coverage" -delete 2>/dev/null || true
	rm -rf .pytest_cache/ htmlcov/ .mypy_cache/

clean-all: clean
	rm -rf results/benchmarks/ results/logs/
	rm -rf .tox/ .coverage.*
	rm -f bandit-report.json safety-report.json
	docker system prune -f 2>/dev/null || true

# CI/CD simulation
ci-local: clean format lint test-all validate build

# Security checks
security:
	safety check --json --output safety-report.json || true
	bandit -r brsrecon/ -f json -o bandit-report.json || true

# Documentation
docs:
	mkdir -p docs/

# Release preparation
release-check: clean lint test-all security validate build

# Development workflow
dev: format lint test
