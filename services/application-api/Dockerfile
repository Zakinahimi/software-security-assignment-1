# Build context is the repository root (see docker-compose.yml), for consistency with
# processing-service's Dockerfile, which needs that to reach packages/exportkit.
FROM python:3.12-slim
WORKDIR /app
COPY services/application-api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/application-api/ .
ENV APPLICATION_API_DB_PATH=/app/data/users.db
RUN mkdir -p /app/data
EXPOSE 5001
CMD ["python", "app.py"]
