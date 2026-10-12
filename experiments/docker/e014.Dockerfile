FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/ztai/src

WORKDIR /opt/ztai
COPY pyproject.toml /opt/ztai/pyproject.toml
RUN pip install --no-cache-dir "cryptography>=45,<51"
COPY src /opt/ztai/src
COPY experiments/e014_provider_server.py /opt/ztai/experiments/e014_provider_server.py

ENTRYPOINT ["python", "/opt/ztai/experiments/e014_provider_server.py"]
