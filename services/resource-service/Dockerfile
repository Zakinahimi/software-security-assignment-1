# Build context is the repository root (see docker-compose.yml), for consistency with
# processing-service's Dockerfile, which needs that to reach packages/exportkit.
FROM python:3.12-slim
WORKDIR /app
COPY services/resource-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/resource-service/ .
ENV RESOURCE_DB_PATH=/app/data/resource.db
RUN mkdir -p /app/data
EXPOSE 5002
CMD ["python", "app.py"]
