FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy and install python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and tests
COPY . /app/

# Set Python path
ENV PYTHONPATH=/app
ENV PORT=8000

EXPOSE 8000

# Run tests first, then start Web Dashboard server
CMD ["sh", "-c", "pytest -v && python web/app.py"]
