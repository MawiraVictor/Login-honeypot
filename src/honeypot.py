#!/usr/bin/env python3
"""Low-interaction login honeypot (fake Telnet login + fake HTTP admin panel).

It never gives the visitor a shell or executes anything. It only:
  * presents a fake login prompt,
  * records who connected and which credentials they tried,
  * always answers "login failed".

Events are written as JSON Lines so they are easy to analyse later.
Run it only in a VM/container you control, on high ports.
"""
import argparse
import asyncio
import datetime
import json
import re
from functools import partial
from pathlib import Path
from urllib.parse import parse_qs

MAX_FIELD = 128          # max characters stored per captured field
MAX_BODY = 1024          # max HTTP body bytes read
TIMEOUT = 30             # seconds of silence before we drop a client
MAX_ATTEMPTS = 3         # login attempts per Telnet connection
MAX_CONNECTIONS = 100    # concurrent connections allowed
FAIL_DELAY = 1.0         # seconds to wait before "Login incorrect"

LOGIN_PAGE = b"""<!DOCTYPE html>
<html><head><title>Router Admin</title></head>
<body style="font-family:sans-serif;text-align:center;margin-top:80px">
<h2>Router Administration</h2>
<form method="POST" action="/login">
<p><input name="username" placeholder="Username"></p>
<p><input name="password" type="password" placeholder="Password"></p>
<p><button type="submit">Log in</button></p>
</form></body></html>"""

FAILED_PAGE = LOGIN_PAGE.replace(
    b"<h2>Router Administration</h2>",
    b"<h2>Router Administration</h2><p style='color:red'>Invalid credentials</p>",
)


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def clean(text):
    """Strip control characters and cap length so logs stay safe and small."""
    text = re.sub(r"[^\x20-\x7e]", "", text)
    return text[:MAX_FIELD]


class EventLogger:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    async def log(self, **event):
        record = {"timestamp": utc_now(), **event}
        line = json.dumps(record, ensure_ascii=True)
        async with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        print(line, flush=True)


async def read_line(reader):
    data = await asyncio.wait_for(reader.readline(), TIMEOUT)
    if not data:
        raise ConnectionError("client closed connection")
    return clean(data.decode("utf-8", "replace"))


async def handle_telnet(reader, writer, logger, limiter):
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    ip, port = peer[0], peer[1]
    async with limiter:
        await logger.log(service="telnet", event="connect", src_ip=ip, src_port=port)
        try:
            for _ in range(MAX_ATTEMPTS):
                writer.write(b"router login: ")
                await writer.drain()
                username = await read_line(reader)
                writer.write(b"Password: ")
                await writer.drain()
                password = await read_line(reader)
                await logger.log(service="telnet", event="login_attempt",
                                 src_ip=ip, username=username, password=password)
                await asyncio.sleep(FAIL_DELAY)
                writer.write(b"\r\nLogin incorrect\r\n")
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, ValueError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()
            await logger.log(service="telnet", event="disconnect", src_ip=ip)


async def handle_http(reader, writer, logger, limiter):
    peer = writer.get_extra_info("peername") or ("unknown", 0)
    ip, port = peer[0], peer[1]
    async with limiter:
        try:
            raw = await asyncio.wait_for(reader.readline(), TIMEOUT)
            request_line = raw.decode("latin-1").strip()
            if not request_line:
                return
            parts = request_line.split(" ")
            method = clean(parts[0])[:10]
            path = clean(parts[1]) if len(parts) > 1 else "/"

            headers = {}
            for _ in range(50):
                line = await asyncio.wait_for(reader.readline(), TIMEOUT)
                if line in (b"\r\n", b"\n", b""):
                    break
                key, _, value = line.decode("latin-1").partition(":")
                headers[key.strip().lower()] = value.strip()

            await logger.log(service="http", event="http_request", src_ip=ip,
                             method=method, path=path,
                             user_agent=clean(headers.get("user-agent", "")))

            status, page = "200 OK", LOGIN_PAGE
            if method == "POST":
                length = min(int(headers.get("content-length", "0") or 0), MAX_BODY)
                body = await asyncio.wait_for(reader.readexactly(length), TIMEOUT)
                form = parse_qs(body.decode("utf-8", "replace"))
                username = clean(form.get("username", [""])[0])
                password = clean(form.get("password", [""])[0])
                await logger.log(service="http", event="login_attempt", src_ip=ip,
                                 username=username, password=password)
                status, page = "401 Unauthorized", FAILED_PAGE

            header = (f"HTTP/1.1 {status}\r\nServer: Apache/2.4.41 (Ubuntu)\r\n"
                      f"Content-Type: text/html\r\nContent-Length: {len(page)}\r\n"
                      "Connection: close\r\n\r\n")
            writer.write(header.encode() + page)
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, ValueError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()


async def run(args):
    logger = EventLogger(args.log)
    limiter = asyncio.Semaphore(MAX_CONNECTIONS)
    telnet = await asyncio.start_server(
        partial(handle_telnet, logger=logger, limiter=limiter),
        args.host, args.telnet_port, limit=1024)
    http = await asyncio.start_server(
        partial(handle_http, logger=logger, limiter=limiter),
        args.host, args.http_port, limit=1024)
    print(f"Honeypot listening on {args.host}: telnet={args.telnet_port} "
          f"http={args.http_port} -> logging to {args.log}", flush=True)
    async with telnet, http:
        await asyncio.gather(telnet.serve_forever(), http.serve_forever())


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Low-interaction login honeypot")
    p.add_argument("--host", default="127.0.0.1",
                   help="bind address (use 0.0.0.0 only inside a VM/container)")
    p.add_argument("--telnet-port", type=int, default=2323)
    p.add_argument("--http-port", type=int, default=8080)
    p.add_argument("--log", default="logs/events.jsonl")
    return p.parse_args(argv)


if __name__ == "__main__":
    try:
        asyncio.run(run(parse_args()))
    except KeyboardInterrupt:
        print("\nStopped.")
