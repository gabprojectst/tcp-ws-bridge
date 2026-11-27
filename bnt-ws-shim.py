#!/usr/bin/env python3
"""Shim WebSocket untuk miner: TCP lokal <-> WS ke relay. Tanpa dependency.

Pakai:
  python3 bnt-ws-shim.py wss://HOST/bntws/<TOKEN> [--listen 127.0.0.1:3333] [--insecure]

Lalu arahkan miner ke stratum+tcp://127.0.0.1:3333
"""
import base64
import hashlib
import os
import random
import ssl
import time
import socket
import struct
import sys
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# BACKOFF: cegah badai reconnect saat relay sedang sibuk/restart.
_bf_lock = threading.Lock()
_bf_fails = 0
JITTER = float(os.environ.get("BNT_WS_JITTER", "8"))


def parse_url(url):
    assert url.startswith(("ws://", "wss://")), "url harus ws:// atau wss://"
    scheme, rest = url.split("://", 1)
    hostport, _, path = rest.partition("/")
    path = "/" + path
    if ":" in hostport:
        host, port = hostport.split(":")
        port = int(port)
    else:
        host, port = hostport, (443 if scheme == "wss" else 80)
    return scheme, host, port, path


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("eof")
        buf += chunk
    return buf


def frame(payload, opcode=0x2):
    head = bytearray()
    head.append(0x80 | opcode)
    n = len(payload)
    if n < 126:
        head.append(0x80 | n)
    elif n < (1 << 16):
        head.append(0x80 | 126)
        head += struct.pack("!H", n)
    else:
        head.append(0x80 | 127)
        head += struct.pack("!Q", n)
    mask = os.urandom(4)
    head += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return bytes(head) + masked


def read_frame(sock):
    b1, b2 = recv_exact(sock, 2)
    opcode = b1 & 0x0F
    masked = b2 & 0x80
    n = b2 & 0x7F
    if n == 126:
        n = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif n == 127:
        n = struct.unpack("!Q", recv_exact(sock, 8))[0]
    mask = recv_exact(sock, 4) if masked else None
    payload = recv_exact(sock, n) if n else b""
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload


def ws_connect(url, insecure=False):
    scheme, host, port, path = parse_url(url)
    peer = os.environ.get("BNT_WS_PEER", "")
    addr = host
    for pair in peer.split(","):
        k, _, v = pair.partition("=")
        if k.strip() == host and v.strip():
            addr = v.strip()
    sock = socket.create_connection((addr, port), timeout=15)
    if scheme == "wss":
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.settimeout(None)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: bnt-ws-shim/1\r\n\r\n"
    )
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("handshake eof")
        resp += chunk
    head, _, rest = resp.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode(errors="replace")
    if " 101 " not in status:
        raise ConnectionError(f"handshake gagal: {status}")
    expect = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    if expect.lower().encode() not in head.lower():
        raise ConnectionError("Sec-WebSocket-Accept tidak cocok")
    if rest:
        # sisa byte setelah header harus jadi awal stream; taruh di buffer
        return sock, rest
    return sock, b""


def _backoff_wait():
    """Tunda percobaan berikutnya: exponential + jitter, maksimum 60 detik."""
    global _bf_fails
    with _bf_lock:
        n = _bf_fails
        _bf_fails = min(_bf_fails + 1, 6)
    if n == 0:
        delay = random.uniform(0, JITTER)
    else:
        delay = min(60.0, (2 ** n) + random.uniform(0, JITTER))
    return delay


def handle(client, url, insecure=False):
    try:
        delay = _backoff_wait()
        if delay > 0.05:
            time.sleep(delay)
        ws, leftover = ws_connect(url, insecure)
    except (OSError, ConnectionError) as exc:
        print(f"shim: ws gagal ({exc}); jeda sebelum coba lagi", flush=True)
        client.close()
        return
    global _bf_fails
    with _bf_lock:
        _bf_fails = 0

    stop = threading.Event()

    def tcp_to_ws():
        try:
            while not stop.is_set():
                data = client.recv(65536)
                if not data:
                    break
                ws.sendall(frame(data, 0x2))
        except OSError:
            pass
        finally:
            stop.set()
            try:
                ws.sendall(frame(b"", 0x8))
            except OSError:
                pass
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def ws_to_tcp():
        try:
            if leftover:
                client.sendall(leftover)
            while not stop.is_set():
                opcode, payload = read_frame(ws)
                if opcode in (0x1, 0x2, 0x0):
                    if payload:
                        client.sendall(payload)
                elif opcode == 0x9:
                    ws.sendall(frame(payload, 0xA))
                elif opcode == 0x8:
                    break
        except (OSError, ConnectionError):
            pass
        finally:
            stop.set()
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    t = threading.Thread(target=ws_to_tcp, daemon=True)
    t.start()
    tcp_to_ws()
    t.join(timeout=5)
    for s in (ws, client):
        try:
            s.close()
        except OSError:
            pass


def main():
    args = sys.argv[1:]
    url = args[0] if args else os.environ.get("BNT_WS_URL", "")
    listen = os.environ.get("BNT_WS_LISTEN", "127.0.0.1:3333")
    insecure = "--insecure" in args
    if "--listen" in args:
        listen = args[args.index("--listen") + 1]
    if not url:
        print("pakai: bnt-ws-shim.py ws://HOST/bntws/TOKEN [--listen 127.0.0.1:3333]")
        sys.exit(2)
    lh, lp = listen.split(":")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((lh, int(lp)))
    srv.listen(16)
    print(f"shim listening {listen} -> {url}", flush=True)
    while True:
        client, addr = srv.accept()
        threading.Thread(target=handle, args=(client, url, insecure), daemon=True).start()


if __name__ == "__main__":
    main()
