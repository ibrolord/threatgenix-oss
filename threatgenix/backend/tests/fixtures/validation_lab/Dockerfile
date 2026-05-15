FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

# Deliberately vulnerable for deterministic validation fixtures.
USER root
CMD ["python", "-m", "app.auth"]
