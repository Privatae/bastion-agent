# PII sterilization service (docs/pii-sterilization.md). Runtime is the
# Python stdlib only — no pip install exists in this image on purpose;
# the vault holds the household's most sensitive data and every
# dependency is attack surface.
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

WORKDIR /app
# every runtime module, named: a module missing here is an ImportError at
# boot (recall.py was, once)
COPY __init__.py detect.py llmclient.py pipeline.py recall.py service.py vault.py /app/pii/

# The service runs as its own unprivileged user. The vault and its directory
# are created 0700/0600 (the service sets umask 077), so a volume mounted on
# /data must be writable by uid 10001.
RUN groupadd --system --gid 10001 pii \
    && useradd --system --uid 10001 --gid 10001 --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin pii \
    && install -d -m 0700 -o pii -g pii /data
USER 10001:10001

# The service listens on 127.0.0.1 unless PII_BIND says otherwise, and inside
# a container that is reachable from nothing else. To publish it, choose the
# address and the host side explicitly, for example:
#   docker run -e PII_BIND=0.0.0.0:8091 -p 127.0.0.1:8091:8091 ...
ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "pii.service"]
