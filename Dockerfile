# Base image (Python 3.9 + Slim OS)
FROM python:3.9-slim

# ===== SYSTEM DEPENDENCIES (Chromium for Selenium) =====
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# ===== PYTHON ENVIRONMENT =====
WORKDIR /app

# Install Poetry (better than requirements.txt)
RUN pip install poetry

# Copy dependency files first (for caching)
COPY pyproject.toml poetry.lock ./

# Install Python dependencies
RUN poetry config virtualenvs.create false && \
    poetry install --no-dev --no-root

# ===== COPY CODE =====
COPY . .

# ===== RUNTIME CONFIG =====
# Set Chromium paths (critical for Selenium)
ENV CHROME_BIN=/usr/bin/chromium \
    CHROME_DRIVER_PATH=/usr/bin/chromedriver

# Run FastAPI on Render's default port
CMD ["poetry", "run", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "10000"]