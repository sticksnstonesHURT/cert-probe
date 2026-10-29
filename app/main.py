"""FastAPI application entry point for the TLS Certificate Checker."""

from fastapi import FastAPI

app = FastAPI(title="TLS Certificate Checker", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness endpoint: the process is up and serving requests."""
    return {"status": "ok"}
