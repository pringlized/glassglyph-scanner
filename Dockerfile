FROM python:3.12-slim

WORKDIR /app

# Install build deps first so this layer caches well
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir '.[server]'

# Run as non-root
RUN useradd --system --uid 1000 glassglyph-scanner && chown -R glassglyph-scanner /app
USER glassglyph-scanner

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=2).read()"

CMD ["uvicorn", "glassglyph_scanner.server:app", "--host", "0.0.0.0", "--port", "8080"]
