FROM python:3.12-slim

WORKDIR /app
# Only third-party dep: PyJWT[crypto] for Keycloak (workloads realm) token validation.
RUN pip install --no-cache-dir "PyJWT[crypto]==2.9.0"

# agents.json (agent cards + grants), lab_ca.crt, and certs/ are DOMAIN files —
# the domain's deploy stage overlays them into the build context (this repo ships none).
COPY gateway.py poller.py langfuse_emit.py agents.json lab_ca.crt /app/
COPY certs/ /app/certs/

ENV STATE_DIR=/data
ENV LAB_CA_FILE=/app/lab_ca.crt
VOLUME ["/data"]
EXPOSE 8095

CMD ["python", "-u", "/app/gateway.py"]
