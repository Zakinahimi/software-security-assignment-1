# Build context must be the repository root (see docker-compose.yml) so this Dockerfile can
# reach the approved exportkit wheel, which is declared and installed as a real dependency rather
# than copied into this service's own source tree.
FROM python:3.12-slim
WORKDIR /app
COPY services/processing-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Experiment A (supply-chain integrity gate): the installation phase verifies the wheel against the
# consumer-controlled manifest BEFORE installing it. A wheel whose name/version match but whose
# sha256 differs makes verify_manifest.py exit 1, which fails the image build (fail closed).
COPY manifest/approved_packages.json /build/manifest/approved_packages.json
COPY scripts/verify_manifest.py /build/scripts/verify_manifest.py
COPY packages/exportkit/dist/ /build/wheels/
RUN python /build/scripts/verify_manifest.py /build/wheels/*.whl \
    && pip install --no-cache-dir --no-deps /build/wheels/*.whl \
    && rm -rf /build

COPY services/processing-service/ .
EXPOSE 5003
CMD ["python", "app.py"]
