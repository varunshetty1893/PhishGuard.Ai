FROM python:3.12-slim

# Create a non-root user for security
RUN groupadd --gid 1001 phishguard \
    && useradd --uid 1001 --gid phishguard --shell /bin/bash --create-home phishguard

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements and install as root (needs write access)
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application code and ML artifacts
COPY backend/ /app/

# Create data directory for SQLite volume mount and set ownership
RUN mkdir -p /data && chown -R phishguard:phishguard /app /data

# Switch to non-root user
USER phishguard

# Expose port
EXPOSE 8000

# Run Uvicorn server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
