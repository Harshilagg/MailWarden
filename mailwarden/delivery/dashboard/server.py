"""Run the dashboard with uvicorn, loopback only."""

from __future__ import annotations

from fastapi import FastAPI


class UnsafeBind(RuntimeError):
    pass


def _config(app: FastAPI, host: str, port: int):
    if host != "127.0.0.1":
        raise UnsafeBind("the dashboard only listens on 127.0.0.1")
    import uvicorn

    return uvicorn.Config(
        app,
        host=host,
        port=port,
        access_log=False,  # access logs would record one-time login URLs
        server_header=False,
        date_header=False,
        proxy_headers=False,
        log_level="warning",
    )


def serve(app: FastAPI, *, host: str, port: int) -> None:
    import uvicorn

    uvicorn.Server(_config(app, host, port)).run()


def serve_in_background(app: FastAPI, *, host: str, port: int):
    """Start the dashboard in a daemon thread (used by the desktop app when no agent is running)."""
    import threading

    import uvicorn

    server = uvicorn.Server(_config(app, host, port))
    thread = threading.Thread(target=server.run, name="mailwarden-dashboard", daemon=True)
    thread.start()
    return server
