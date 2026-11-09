# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Howard M. Harte
"""Single-use loopback SSH fixture with an ephemeral key and synthetic users."""

import json
from contextlib import suppress
import socket
import sys
import threading

import paramiko


class Server(paramiko.ServerInterface):
    def __init__(self, mode):
        self.mode = mode
        self.attempts = 0
        self.shell_ready = threading.Event()

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.attempts += 1
        if self.mode in ("password", "stall") and password == "synthetic-test-value":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_none(self, username):
        self.attempts += 1
        if self.mode == "none":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.attempts += 1
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.shell_ready.set()
        return True


def echo(transport, server, stop):
    """Bounded polling lets rejected-auth fixtures stop without opening a channel."""
    while not stop.is_set():
        channel = transport.accept(0.1)
        if channel is None:
            continue
        channel.settimeout(0.1)
        while not stop.is_set() and not server.shell_ready.wait(0.1):
            pass
        if server.mode == "stall":
            stop.wait(15)
            return
        while not stop.is_set():
            try:
                data = channel.recv(4096)
                if not data:
                    break
                channel.sendall(data)
            except socket.timeout:
                continue
            except (EOFError, OSError):
                break
        # The Rust drop test deliberately disconnects before the server closes.
        with suppress(EOFError, OSError):
            channel.close()
        return


key = paramiko.RSAKey.generate(2048)
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(15)
    print(json.dumps({"port": listener.getsockname()[1], "key": key.get_base64()}), flush=True)
    conn, _ = listener.accept()
    if len(sys.argv) > 1 and sys.argv[1] == "silent":
        # Accept TCP without sending an SSH banner; the client must time out.
        with conn:
            sys.stdin.readline()
            print(json.dumps({"auth_attempts": 0}), flush=True)
        sys.exit(0)
    with conn, paramiko.Transport(conn) as transport:
        server = Server(sys.argv[1] if len(sys.argv) > 1 else "reject")
        # Use a fixed group; the fixture does not provide a moduli database
        # for group exchange. Keep negotiation deterministic across backends.
        transport.get_security_options().kex = ("diffie-hellman-group14-sha256",)
        transport.add_server_key(key)
        transport.start_server(server=server)
        stop = threading.Event()
        worker = threading.Thread(target=echo, args=(transport, server, stop), daemon=True)
        worker.start()
        # The Rust client signals after its connection attempt has completed.
        sys.stdin.readline()
        stop.set()
        worker.join(timeout=2)
        print(json.dumps({"auth_attempts": server.attempts}), flush=True)
