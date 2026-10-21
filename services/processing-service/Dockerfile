# Build context must be the repository root (see docker-compose.yml) so this Dockerfile can
# reach packages/exportkit, which is declared and installed as a real dependency rather than
# copied into this service's own source tree.
FROM python:3.12-slim
WORKDIR /app
COPY services/processing-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY packages/exportkit /tmp/exportkit
RUN pip install --no-cache-dir /tmp/exportkit && rm -rf /tmp/exportkit
COPY services/processing-service/ .
EXPOSE 5003
CMD ["python", "app.py"]
