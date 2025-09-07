# BRS-RECON Docker Container
# Project: BRS-RECON (Network Reconnaissance Tool)
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: Sun 07 Sep 2025
# Contact: https://t.me/EasyProTech

FROM ubuntu:22.04

# Metadata
LABEL maintainer="brabus <https://t.me/EasyProTech>"
LABEL description="BRS-RECON - Network Reconnaissance Tool"
LABEL version="0.0.1"
LABEL vendor="EasyProTech LLC"

# Environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV BRS_RESULTS_DIR=/results

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    nmap \
    fping \
    arp-scan \
    masscan \
    dig \
    whois \
    nikto \
    sslscan \
    sqlmap \
    dirb \
    curl \
    wget \
    iputils-ping \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install testssl.sh
RUN wget -q https://testssl.sh/testssl.sh -O /usr/local/bin/testssl.sh && \
    chmod +x /usr/local/bin/testssl.sh

# Set capabilities for network tools
RUN setcap cap_net_raw+ep /usr/bin/fping || true
RUN setcap cap_net_admin,cap_net_raw+ep /usr/bin/masscan || true
RUN setcap cap_net_admin,cap_net_raw+ep /usr/bin/nmap || true

# Create app directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements/requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY brs-recon/ ./brs-recon/
COPY cli/ ./cli/
COPY config/ ./config/

# Create results directory
RUN mkdir -p /results/{html,json,sarif,xml,csv,scans,logs}

# Create non-root user for security
RUN useradd -m -u 1000 brsuser && \
    chown -R brsuser:brsuser /app /results
USER brsuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -m brs-recon --version || exit 1

# Default command
ENTRYPOINT ["python3", "-m", "brs-recon"]
CMD ["--help"]

# Usage examples:
# docker build -t brs-recon .
# docker run --rm -v $(pwd)/results:/results brs-recon network 192.168.1.0/24
# docker run --rm -v $(pwd)/results:/results brs-recon ports google.com --ports top100
# docker run --rm -v $(pwd)/results:/results brs-recon domain example.com --scan-type comprehensive
