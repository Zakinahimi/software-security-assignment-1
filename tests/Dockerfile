# Build context is the repository root (see docker-compose.yml): this image only needs the
# root-level tests/ package and a couple of lightweight dependencies to exercise the three
# services over the network, so it does NOT reuse any single service's Dockerfile.
FROM python:3.12-slim
WORKDIR /work
COPY requirements-dev.txt .
RUN pip install --no-cache-dir -r requirements-dev.txt pyjwt==2.8.0
COPY tests/ tests/
CMD ["pytest", "-q", "tests/", "--junitxml=/reports/e2e-results.xml"]
