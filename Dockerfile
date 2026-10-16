FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /app
COPY requirements-cloud.txt .
RUN python -m pip install --no-cache-dir -r requirements-cloud.txt
COPY . .
RUN mkdir -p /app/runtime

EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "8", "--timeout", "120", "application:app"]
