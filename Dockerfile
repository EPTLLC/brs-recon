# BRS-RECON Multi-Stage Docker Container
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-07
# Status: Modified
# Contact: https://t.me/EasyProTech

# =============================================================================
# Build Stage - Install dependencies and build application
# =============================================================================
FROM ubuntu:22.04 AS builder

# Build-time metadata
LABEL stage="builder"
LABEL description="BRS-RECON build stage"

# Environment variables for build
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    bsdextrautils \
    build-essential \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install build tools
RUN pip install --upgrade pip setuptools wheel

# Copy requirements and install Python dependencies
COPY requirements/requirements.txt /tmp/requirements.txt
COPY requirements/requirements-base.txt /tmp/requirements-base.txt
COPY requirements/constraints.txt /tmp/constraints.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Install testssl.sh with required etc resources (clone repo to ensure path correctness)
ENV TESTSSL_INSTALL_DIR=/usr/local/bin
RUN wget -q --progress=dot:giga https://testssl.sh/testssl.sh -O /usr/local/bin/testssl.sh && \
    chmod +x /usr/local/bin/testssl.sh && \
    mkdir -p /usr/local/bin/etc && \
    apt-get update && apt-get install -y --no-install-recommends git && \
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /tmp/testssl && \
    cp -r /tmp/testssl/etc/* /usr/local/bin/etc/ && \
    rm -rf /var/lib/apt/lists/* /tmp/testssl && \
    /usr/local/bin/testssl.sh --version

# Copy and install application
COPY pyproject.toml setup.cfg /app/
COPY brsrecon/ /app/brsrecon/
COPY cli/ /app/cli/
COPY config/ /app/config/
WORKDIR /app
RUN pip install -e .

# =============================================================================
# Runtime Stage - Minimal production image
# =============================================================================
FROM ubuntu:22.04 AS runtime

# Runtime metadata
LABEL maintainer="brabus <https://t.me/EasyProTech>"
LABEL description="BRS-RECON - Network Reconnaissance Tool"
LABEL version="0.0.1"
LABEL vendor="EasyProTech LLC"
LABEL org.opencontainers.image.title="BRS-RECON"
LABEL org.opencontainers.image.description="Python Network Reconnaissance Toolkit"
LABEL org.opencontainers.image.version="0.0.1"
LABEL org.opencontainers.image.vendor="EasyProTech LLC"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later OR Commercial"
LABEL org.opencontainers.image.source="https://github.com/EPTLLC/brs-recon"
LABEL org.opencontainers.image.documentation="https://github.com/EPTLLC/brs-recon#readme"

# Security and runtime environment
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONIOENCODING=utf-8
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV BRS_RESULTS_DIR=/results
ENV BRS_CONFIG_DIR=/config
ENV PATH="/opt/venv/bin:$PATH"
ENV TESTSSL_INSTALL_DIR=/usr/local/bin

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Python runtime
    python3 \
    python3-distutils \
    bsdextrautils \
    # Network scanning tools
    nmap \
    fping \
    arp-scan \
    masscan \
    # DNS and network utilities  
    dnsutils \
    whois \
    iputils-ping \
    iproute2 \
    net-tools \
    # Web security scanners
    nikto \
    sslscan \
    sqlmap \
    dirb \
    # System utilities
    curl \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && rm -rf /tmp/* /var/tmp/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy testssl.sh from builder
COPY --from=builder /usr/local/bin/testssl.sh /usr/local/bin/testssl.sh
COPY --from=builder /usr/local/bin/etc /usr/local/bin/etc

# Copy application from builder
COPY --from=builder /app /app

# Create non-root user with minimal privileges
RUN groupadd -g 1000 brsuser && \
    useradd -r -u 1000 -g brsuser -s /bin/false -c "BRS-RECON User" brsuser

# Create directories with proper permissions
RUN mkdir -p /results/{html,json,sarif,xml,csv,scans,logs} \
    /config \
    /app/cache \
    && chown -R brsuser:brsuser /results /config /app/cache \
    && chmod 755 /results /config \
    && chmod 750 /app/cache

# Set capabilities for network tools (with error handling)
RUN setcap cap_net_raw+ep /usr/bin/fping 2>/dev/null || echo "Warning: Could not set fping capabilities"
RUN setcap cap_net_admin,cap_net_raw+ep /usr/bin/masscan 2>/dev/null || echo "Warning: Could not set masscan capabilities"  
RUN setcap cap_net_admin,cap_net_raw+ep /usr/bin/nmap 2>/dev/null || echo "Warning: Could not set nmap capabilities"

# Security hardening
RUN chmod u-s /usr/bin/* 2>/dev/null || true && \
    chmod g-s /usr/bin/* 2>/dev/null || true && \
    rm -rf /usr/share/doc/* /usr/share/man/* /usr/share/info/* && \
    find /usr/bin -type f -perm +6000 -exec chmod a-s {} \; 2>/dev/null || true

# Switch to non-root user
USER brsuser:brsuser

# Set working directory
WORKDIR /app

# Health check with timeout and proper error handling
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import sys; sys.path.insert(0, '/app'); from brsrecon import __version__; print(f'BRS-RECON {__version__} healthy')" || exit 1

# Security: Run as read-only filesystem (can be overridden)
# VOLUME ["/results", "/config"]

# Expose no ports by default (tool doesn't run services)
# EXPOSE

# Default entrypoint and command
ENTRYPOINT ["python", "-m", "brsrecon"]
CMD ["--help"]

# =============================================================================
# Usage Examples:
# =============================================================================
# 
# Build:
#   docker build -t brs-recon .
#
# Basic usage:
#   docker run --rm -v $(pwd)/results:/results brs-recon --version
#   docker run --rm -v $(pwd)/results:/results brs-recon --help
#
# Network scanning (requires capabilities):
#   docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     -v $(pwd)/results:/results brs-recon network 192.168.1.0/24
#
# Port scanning:
#   docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     -v $(pwd)/results:/results brs-recon ports target.com --ports top100
#
# Domain reconnaissance:
#   docker run --rm -v $(pwd)/results:/results \
#     brs-recon domain example.com --scan-type comprehensive
#
# With custom configuration:
#   docker run --rm -v $(pwd)/results:/results -v $(pwd)/config:/config \
#     brs-recon network 10.0.0.0/24 --config /config/custom.yaml
#
# Read-only filesystem (enhanced security):
#   docker run --rm --read-only --tmpfs /tmp --tmpfs /app/cache \
#     --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     -v $(pwd)/results:/results brs-recon network 192.168.1.0/24
#
# Rootless with podman:
#   podman run --rm --cap-add=net_raw,net_admin \
#     -v $(pwd)/results:/results localhost/brs-recon network 10.0.0.0/24
