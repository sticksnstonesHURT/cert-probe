# Local-only test fixture. Not part of the deployment image set.
# Runs as root only so it can bind :443 (privileged port); the container has
# no host port mapping and shares a private bridge network only with the
# tls-checker service, so this does not widen the app's attack surface.
FROM python:3.12-slim
WORKDIR /app
COPY server.py ./
EXPOSE 443
CMD ["python", "server.py"]
