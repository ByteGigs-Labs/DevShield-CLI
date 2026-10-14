FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY devshield ./devshield
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /wheels

FROM python:3.12-slim
LABEL org.opencontainers.image.title="DevShield" \
      org.opencontainers.image.source="https://github.com/ByteGigs-Labs/DevShield-CLI" \
      org.opencontainers.image.licenses="MIT"
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 devshield
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER devshield
# Mounted projects are owned by another user, which git would otherwise refuse to read.
RUN git config --global --add safe.directory /project
WORKDIR /project
HEALTHCHECK NONE
ENTRYPOINT ["devshield"]
CMD ["scan", "."]
