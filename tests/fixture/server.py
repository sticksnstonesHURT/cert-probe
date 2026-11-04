"""Minimal TLS server for the local test fixture.

Reads:
  FIXTURE_CERT_FILE         combined cert+key PEM (default /certs/valid.pem)
  FIXTURE_HANDSHAKE_DELAY_MS  pre-handshake delay in ms (default 0)

Listens on 0.0.0.0:443. One thread per connection. Does not read HTTP; the
TLS handshake is the entire interaction — matches what app/checker.py exercises.
"""

from __future__ import annotations

import os
import socket
import ssl
import threading
import time

_CERT_FILE = os.environ.get("FIXTURE_CERT_FILE", "/certs/valid.pem")
_DELAY_MS = int(os.environ.get("FIXTURE_HANDSHAKE_DELAY_MS", "0"))
_LISTEN_PORT = 443
_LISTEN_BACKLOG = 256
_HANDSHAKE_SOCK_TIMEOUT = 5.0
_POST_HANDSHAKE_TIMEOUT = 2.0


def _handle(conn: socket.socket, ctx: ssl.SSLContext, delay_s: float) -> None:
    try:
        conn.settimeout(_HANDSHAKE_SOCK_TIMEOUT)
        if delay_s > 0:
            time.sleep(delay_s)
        with ctx.wrap_socket(conn, server_side=True) as tls:
            tls.settimeout(_POST_HANDSHAKE_TIMEOUT)
            try:
                tls.recv(4096)
            except (TimeoutError, ConnectionError, ssl.SSLError):
                pass
    except (ssl.SSLError, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=_CERT_FILE, keyfile=_CERT_FILE)
    delay_s = _DELAY_MS / 1000.0
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", _LISTEN_PORT))
    sock.listen(_LISTEN_BACKLOG)
    print(f"fixture listening on :{_LISTEN_PORT} cert={_CERT_FILE} delay_ms={_DELAY_MS}", flush=True)
    try:
        while True:
            conn, _addr = sock.accept()
            threading.Thread(target=_handle, args=(conn, ctx, delay_s), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
