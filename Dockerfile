FROM python:3.12-slim

# The app itself is pure Python standard library; `conntrack` is only used by
# the optional agent (python -m tfv.agent) to read the kernel's NAT table.
RUN apt-get update \
    && apt-get install -y --no-install-recommends conntrack \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY tfv/ /app/tfv/
COPY tools/ /app/tools/

# commit the image was built from (set by CI), shown in the Status tab
ARG TFV_VERSION=dev
ENV TFV_VERSION=$TFV_VERSION \
    PYTHONUNBUFFERED=1 \
    TFV_DATA_DIR=/data \
    TFV_CONFIG=/data/config.toml

COPY docker-entrypoint.sh /usr/local/bin/
RUN groupadd --gid 1000 tfv \
    && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /data --shell /usr/sbin/nologin tfv \
    && mkdir -p /data && chown tfv:tfv /data
VOLUME ["/data"]

# 2055/udp = flow collector, 8080/tcp = web UI
EXPOSE 2055/udp 8080/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "-m", "tfv"]
