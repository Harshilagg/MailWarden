"""File permission enforcement for config and data files."""

from __future__ import annotations

import os
import stat
from pathlib import Path


class InsecurePermissions(RuntimeError):
    pass


def _posix() -> bool:
    return os.name == "posix"


def check_private(path: Path) -> None:
    """Refuse if ``path`` is readable/writable by group or others, or not ours."""
    if not _posix():
        return  # Windows: ACLs are per-user under %APPDATA% by default.
    st = path.stat()
    wanted = "700" if stat.S_ISDIR(st.st_mode) else "600"
    if st.st_mode & 0o077:
        raise InsecurePermissions(
            f"{path} has mode {oct(st.st_mode & 0o777)}; run: chmod {wanted} '{path}'"
        )
    if st.st_uid != os.getuid():
        raise InsecurePermissions(f"{path} is not owned by the current user")


def ensure_private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if _posix():
        os.chmod(path, 0o700)
    check_private(path)


def write_private(path: Path, data: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        if _posix():
            os.fchmod(fd, 0o600)
        os.write(fd, data.encode("utf-8"))
    finally:
        os.close(fd)
