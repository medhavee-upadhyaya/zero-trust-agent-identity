FROM python:3.12-slim-bookworm@sha256:392307d22300de8b5986851a12d9176dfc0fc073e65bf6523ebd7dcbeb23564e

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/artifact/src

ARG SOURCE_REVISION=unavailable
ENV ZTAI_SOURCE_REVISION=${SOURCE_REVISION}

WORKDIR /artifact

COPY requirements.lock pyproject.toml ./
RUN python -m pip install --no-cache-dir --requirement requirements.lock

COPY src ./src
COPY tests ./tests
COPY experiments ./experiments

ENTRYPOINT ["python", "experiments/run_offline_suite.py"]
