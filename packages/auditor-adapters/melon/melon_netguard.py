"""Loopback-only socket guard for the MELON episode process.

Every model request from the episode process goes to the local budget guard
(chat) or stays in-process / on loopback Ollama (embeddings). Any attempt to
open a non-loopback connection therefore indicates a bypass (for example an
SDK default base URL or a model download) and is refused here. The guard
process, not this one, talks to DeepSeek.
"""

from __future__ import annotations

import os
import socket

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
BLOCKED: list[str] = []
_installed = False
_orig_connect = socket.socket.connect
_orig_create_connection = socket.create_connection


def _host_of(address: object) -> str:
    if isinstance(address, tuple) and address:
        return str(address[0])
    return str(address)


def _guarded_connect(self: socket.socket, address: object) -> None:
    host = _host_of(address)
    if self.family in (socket.AF_INET, socket.AF_INET6) and host not in ALLOWED_HOSTS:
        BLOCKED.append(host)
        raise ConnectionRefusedError(f"[melon-netguard] blocked non-loopback connection to {host}")
    return _orig_connect(self, address)


def _guarded_create_connection(address: object, *args: object, **kwargs: object) -> socket.socket:
    host = _host_of(address)
    if host not in ALLOWED_HOSTS:
        BLOCKED.append(host)
        raise ConnectionRefusedError(f"[melon-netguard] blocked non-loopback connection to {host}")
    return _orig_create_connection(address, *args, **kwargs)


def install() -> None:
    global _installed
    if _installed:
        return
    socket.socket.connect = _guarded_connect  # type: ignore[method-assign]
    socket.create_connection = _guarded_create_connection  # type: ignore[assignment]
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    _installed = True
