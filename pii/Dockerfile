# PII sterilization service (docs/pii-sterilization.md). Runtime is the
# Python stdlib only — no pip install exists in this image on purpose;
# the vault holds the household's most sensitive data and every
# dependency is attack surface.
FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

WORKDIR /app
# every runtime module, named: a module missing here is an ImportError at
# boot (recall.py was, once)
COPY __init__.py detect.py llmclient.py pipeline.py recall.py service.py vault.py /app/pii/

# Root inside the container is deliberate: the vault db and its directory
# are created 0700/0600 (service sets umask 077) on the mounted /data,
# and the single-purpose process is bind-scoped by PII_BIND. Revisit if
# the service ever grows a second concern.
ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "pii.service"]
