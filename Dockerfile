FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV CHROME_BIN=/usr/bin/chromium \
    CHROME_DRIVER_PATH=/usr/bin/chromedriver

# Create and set working directory
WORKDIR /app

# Copy requirements.txt for dependency installation
COPY requirements.txt ./

# Install dependencies using pip
RUN pip install -r requirements.txt

# Copy the rest of the application
COPY . .

# Run the application
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "10000"]
