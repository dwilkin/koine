FROM python:3.12-slim

WORKDIR /app
# Only third-party dep: PyJWT[crypto] for Keycloak (workloads realm) token validation.
RUN pip install --no-cache-dir "PyJWT[crypto]==2.9.0"

# NOTE: `docker compose build` from this repo alone WILL FAIL — the COPY below expects a
# staged build context, not the repo layout. The operator's deploy must stage, next to this
# Dockerfile:
#   gateway.py, poller.py, langfuse_emit.py   (from gateway/ — this dir)
#   crypto.py                                 (from the REPO ROOT)
#   agents.json                               (DOMAIN file: agent cards + grants)
#   koine-peers.json                          (DOMAIN file: multi-peer poller directory;
#                                              stage '{}' if unused)
#   lab_ca.crt                                (DOMAIN file: CA bundle for the OIDC JWKS
#                                              fetch — the name is arbitrary, set by the
#                                              operator's staging + the OIDC_CA_FILE env;
#                                              stage an empty file if OIDC is unused)
#   certs/                                    (DOMAIN dir: pinned peer mailbox certs;
#                                              stage an empty dir if unused)
# Worked example: the wilkin-lab overlay's deploy.sh (its private ops repo) copies the code
# files + crypto.py from this repo and its own agents.json/koine-peers.json/lab_ca.crt/certs/
# into a temp dir, then builds there.
COPY gateway.py poller.py langfuse_emit.py crypto.py agents.json koine-peers.json lab_ca.crt /app/
COPY certs/ /app/certs/

ENV STATE_DIR=/data
ENV LAB_CA_FILE=/app/lab_ca.crt
VOLUME ["/data"]
EXPOSE 8095

CMD ["python", "-u", "/app/gateway.py"]
