#!/usr/bin/env python3
import bcrypt
import asyncio
import ssl
import os
import base64
import threading
from urllib.parse import urlsplit
from email.message import Message
from typing import Dict, Optional
from dotenv import load_dotenv

# ==== загрузка .env ====
load_dotenv()

# ==== НАСТРОЙКИ ====
class Settings:
    realm = os.getenv("REALM", "Secure Proxy Server")
    request_timeout = int(os.getenv("REQUEST_TIMEOUT", "30"))
    communication_timeout = int(os.getenv("COMMUNICATION_TIMEOUT", "60"))
    listen_host = os.getenv("LISTEN_HOST", "0.0.0.0")
    listen_port = int(os.getenv("LISTEN_PORT", "8443"))
    pass_file = os.getenv("PASS_FILE", "./pass")

    ssl_certificate_path = os.getenv(
        "SSL_CERT", "/etc/letsencrypt/live/example.com/fullchain.pem"
    )
    ssl_private_key_path = os.getenv(
        "SSL_KEY", "/etc/letsencrypt/live/example.com/privkey.pem"
    )

# ==== КЭШ УЧЁТОК ====
class CredentialsCache:
    _cache: Dict[str, str] = {}
    _mtime: Optional[float] = None
    _lock = threading.Lock()

    @classmethod
    def _load(cls) -> None:
        new_cache: Dict[str, str] = {}
        try:
            with open(Settings.pass_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" not in line:
                        continue
                    user, pwd = line.split(":", 1)
                    if user:
                        new_cache[user.strip()] = pwd.strip()
        except FileNotFoundError:
            new_cache = {}
        cls._cache = new_cache

    @classmethod
    def get(cls) -> Dict[str, str]:
        with cls._lock:
            try:
                mtime = os.path.getmtime(Settings.pass_file)
            except FileNotFoundError:
                mtime = None
            if mtime != cls._mtime:
                cls._load()
                cls._mtime = mtime
            return cls._cache.copy()


# ==== ВСПОМОГАТЕЛЬНОЕ ====
HOP_BY_HOP = {
    "connection", "proxy-connection", "keep-alive", "te",
    "trailer", "transfer-encoding", "upgrade",
    "proxy-authenticate", "proxy-authorization",
}

def strip_hop_by_hop(headers: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in HOP_BY_HOP:
            continue
        out[k] = v
    conn_val = headers.get("Connection")
    if conn_val:
        for token in conn_val.split(","):
            out.pop(token.strip(), None)
    out.pop("Proxy-Authorization", None)
    return out


def parse_headers(raw_lines: list[str]) -> Dict[str, str]:
    headers = {}
    for line in raw_lines:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def authenticate(headers: Dict[str, str]) -> bool:
    auth_header = headers.get("Proxy-Authorization")
    if not auth_header:
        return False
    try:
        auth_type, encoded = auth_header.split(" ", 1)
        if auth_type.lower() != "basic":
            return False
        decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
        if ":" not in decoded:
            return False
        username, password = decoded.split(":", 1)
        creds = CredentialsCache.get()
        stored_hash = creds.get(username)
        if not stored_hash:
            return False
        # проверка bcrypt
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except Exception:
        return False


async def send_auth_required(writer: asyncio.StreamWriter):
    msg = (
        "HTTP/1.1 407 Proxy Authentication Required\r\n"
        f'Proxy-Authenticate: Basic realm="{Settings.realm}"\r\n'
        "Connection: close\r\n\r\n"
    )
    writer.write(msg.encode())
    await writer.drain()
    writer.close()


# ==== ПРОКСИ ====
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        # читаем первую строку (метод path версия)
        request_line = await asyncio.wait_for(reader.readline(), timeout=Settings.request_timeout)
        if not request_line:
            writer.close()
            return
        parts = request_line.decode(errors="ignore").strip().split(" ", 2)
        if len(parts) != 3:
            writer.close()
            return
        method, path, version = parts

        # читаем заголовки
        raw_headers = []
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            raw_headers.append(line.decode(errors="ignore").strip())
        headers = parse_headers(raw_headers)

        # проверка аутентификации
        if not authenticate(headers):
            await send_auth_required(writer)
            return

        if method == "CONNECT":
            if ":" not in path:
                writer.close()
                return
            host, port_str = path.split(":", 1)
            port = int(port_str)
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=Settings.request_timeout
                )
            except Exception as e:
                writer.write(f"HTTP/1.1 502 Bad Gateway: {e}\r\n\r\n".encode())
                await writer.drain()
                writer.close()
                return

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            async def pipe(r, w):
                try:
                    while True:
                        data = await asyncio.wait_for(r.read(65536), timeout=Settings.communication_timeout)
                        if not data:
                            break
                        w.write(data)
                        await w.drain()
                except Exception:
                    pass
                finally:
                    w.close()

            await asyncio.gather(
                pipe(reader, remote_writer),
                pipe(remote_reader, writer)
            )

        else:
            parsed = urlsplit(path)
            if parsed.scheme and parsed.netloc:
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == "https" else 80)
                origin_path = parsed.path or "/"
                if parsed.query:
                    origin_path += "?" + parsed.query
            else:
                host_header = headers.get("Host")
                if not host_header:
                    writer.close()
                    return
                if ":" in host_header:
                    host, port_str = host_header.rsplit(":", 1)
                    port = int(port_str)
                else:
                    host, port = host_header, 80
                origin_path = path or "/"

            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=Settings.request_timeout
                )
            except Exception as e:
                writer.write(f"HTTP/1.1 502 Bad Gateway: {e}\r\n\r\n".encode())
                await writer.drain()
                writer.close()
                return

            fwd_headers = strip_hop_by_hop(headers)
            fwd_headers["Host"] = fwd_headers.get("Host") or host
            fwd_headers["Connection"] = "close"

            header_str = "".join(f"{k}: {v}\r\n" for k, v in fwd_headers.items())
            req = f"{method} {origin_path} HTTP/1.1\r\n{header_str}\r\n"
            remote_writer.write(req.encode())
            await remote_writer.drain()

            async def pipe(r, w):
                try:
                    while True:
                        data = await asyncio.wait_for(r.read(65536), timeout=Settings.communication_timeout)
                        if not data:
                            break
                        w.write(data)
                        await w.drain()
                except Exception:
                    pass
                finally:
                    w.close()

            await asyncio.gather(
                pipe(reader, remote_writer),
                pipe(remote_reader, writer)
            )

    except Exception:
        writer.close()


# ==== ЗАПУСК ====
async def main():
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(Settings.ssl_certificate_path, Settings.ssl_private_key_path)
    server = await asyncio.start_server(handle_client, Settings.listen_host, Settings.listen_port, ssl=ssl_ctx)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
