"""Structural rules that keep the security model enforceable."""

import ast
from pathlib import Path

PKG = Path(__file__).resolve().parents[1] / "mailwarden"
HTTP_CLIENTS = {"requests", "urllib3", "httpx", "aiohttp", "urllib.request", "http.client", "socket"}
LAYERS = ("mailwarden.providers", "mailwarden.storage", "mailwarden.delivery")


def _imports(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _modules():
    return [p for p in PKG.rglob("*.py")]


def test_only_net_module_imports_http_clients():
    offenders = []
    for path in _modules():
        if path == PKG / "security" / "net.py":
            continue
        bad = {n for n in _imports(path) if n in HTTP_CLIENTS or n.split(".")[0] in {"requests", "urllib3", "httpx", "aiohttp"}}
        if bad:
            offenders.append(f"{path.relative_to(PKG)}: {sorted(bad)}")
    assert not offenders, offenders


def test_core_depends_only_on_interfaces():
    offenders = []
    for path in (PKG / "core").rglob("*.py"):
        for name in _imports(path):
            if name.startswith(LAYERS) and not name.endswith(".base"):
                offenders.append(f"{path.relative_to(PKG)} imports {name}")
    assert not offenders, offenders


def test_no_attachment_or_write_endpoints_referenced():
    text = "\n".join(p.read_text() for p in (PKG / "providers").rglob("*.py"))
    for forbidden in ("attachments", "/send", "/modify", "/trash", "batchDelete", "batchModify", "gmail.modify", "mail.google.com/"):
        assert forbidden not in text, forbidden


def test_llm_backends_are_only_invoked_from_approved_call_sites():
    """`.classify(` on a backend may only appear in the pipeline's guarded path.

    cli.py calls it once for `doctor --llm` with a hard-coded synthetic email.
    """
    allowed = {
        PKG / "core" / "pipeline.py",
        PKG / "core" / "classify" / "base.py",  # retry-once helper
        PKG / "core" / "classify" / "ratelimit.py",  # rate-limit wrapper around a backend
        PKG / "cli.py",
    }
    offenders = []
    for path in _modules():
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "classify":
                if path not in allowed:
                    offenders.append(f"{path.relative_to(PKG)}:{node.lineno}")
    assert not offenders, offenders
