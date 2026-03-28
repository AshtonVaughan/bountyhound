FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for mitmproxy, weasyprint, and Playwright
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev libssl-dev gcc \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libcairo2 \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libdrm2 libxcomposite1 \
    libxdamage1 libxrandr2 libgbm1 libasound2 libpangoft2-1.0-0 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN playwright install chromium --with-deps 2>/dev/null || true

COPY . .

# Generate mitmproxy CA cert on first run
RUN python -c "from mitmproxy.certs import CertStore; CertStore.from_store(str(__import__('pathlib').Path.home() / '.mitmproxy'), 'mitmproxy')" 2>/dev/null || true

EXPOSE 8080 8187

ENV PROXY_PORT=8080
ENV API_PORT=8187

CMD ["python", "main.py"]
