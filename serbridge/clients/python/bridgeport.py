# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Howard M. Harte
"""Open a serial port through serbridge when a bridge is serving it.

``serbridge --listen`` writes the URL of its RFC 2217 server to a file named
for the port it holds. :func:`open_port` looks there first, so a tool keeps
naming the port it always named (``COM20``, ``/dev/ttyUSB0``) and, when a
bridge is running, shares the port through it: the bridge keeps logging
everything the board says, rides out a re-plug, and lets several tools use the
port at once. With no bridge, the port is opened directly, as before.

This file is copied into each repository that uses it; the canonical copy is
``retrosim-transports/serbridge/clients/python/bridgeport.py``.

Differences from opening the port directly, all from pySerial's RFC 2217
client: ``write_timeout`` is not supported, and DTR and RTS are asserted on
open unless ``dtr=False``/``rts=False`` are passed — the same default as a
real port, which on a board whose reset is wired to DTR resets it.
"""

import os
import sys
from pathlib import Path

import serial


def url_file(name: str) -> Path:
    """Where a bridge holding ``name`` writes its URL (serbridge's rule)."""
    base = name.removeprefix("/dev/")
    for c in "/\\:":
        base = base.replace(c, "_")
    if os.name == "nt":
        base = base.replace("?", "_")
        root = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or "."
        return Path(root) / "serbridge" / f"{base.upper()}.url"
    run = os.environ.get("XDG_RUNTIME_DIR")
    if run:
        return Path(run) / "serbridge" / f"{base}.url"
    import tempfile

    user = os.environ.get("USER", "user")
    return Path(tempfile.gettempdir()) / f"serbridge-{user}" / f"{base}.url"


def bridge_url(name: str):
    """The ``rfc2217://`` URL of the bridge holding ``name``, or None."""
    try:
        url = url_file(name).read_text(encoding="utf-8").strip().splitlines()[0]
    except (OSError, IndexError):
        return None
    return url if url.startswith("rfc2217://") else None


def open_port(name: str, baudrate: int = 115200, **kwargs):
    """Open ``name`` through its bridge if one serves it, else directly.

    ``name`` may also be a pySerial URL (``rfc2217://host:port``,
    ``socket://...``), which is opened as given. Keyword arguments are
    pySerial's (``timeout``, ``dtr``, ``rts``, ``do_not_open``...).

    ⚠ ``dtr`` and ``rts`` are applied before the port opens, so a board whose
    reset is on DTR never sees it pulse: pySerial itself opens with both
    asserted and only then applies a later ``port.dtr = False``.
    """
    dtr = kwargs.pop("dtr", None)
    rts = kwargs.pop("rts", None)
    deferred = kwargs.pop("do_not_open", False)

    def make(target, url):
        if url:
            p = serial.serial_for_url(target, baudrate=baudrate, do_not_open=True, **kwargs)
        else:
            p = serial.Serial(None, baudrate=baudrate, **kwargs)
            p.port = target
        if dtr is not None:
            p.dtr = dtr
        if rts is not None:
            p.rts = rts
        if not deferred:
            p.open()
        return p

    if "://" in name:
        return make(name, True)
    url = bridge_url(name)
    if url:
        try:
            return make(url, True)
        except serial.SerialException as e:
            # A file left by a bridge that did not stop cleanly.
            print(f"bridgeport: {url} for {name} did not answer ({e}); "
                  f"opening {name} directly", file=sys.stderr)
    return make(name, False)
