"""Run the dashboard with uvicorn, loopback only."""

from __future__ import annotations

from fastapi import FastAPI


class UnsafeBind(RuntimeError):
    pass


def serve(app: FastAPI, *, host: str, port: int) -> None:
    if host != "127.0.0.1":
        raise UnsafeBind("the dashboard only listens on 127.0.0.1")
    import uvicorn

    uvicorn.run(
        app,
        host=host,
        port=port,
        access_log=False,  # access logs would record one-time login URLs
        server_header=False,
        date_header=False,
        proxy_headers=False,
        log_level="warning",
    )
