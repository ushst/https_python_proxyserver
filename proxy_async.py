#!/usr/bin/env python3
import argparse
import asyncio
import base64
import bcrypt
import logging
import os
import ssl
import threading
from typing import Dict, Optional
from urllib.parse import urlsplit

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
    debug = os.getenv("DEBUG", "0").lower() in {"1", "true", "yes", "on"}

    ssl_certificate_path = os.getenv(
        "SSL_CERT", "/etc/letsencrypt/live/example.com/fullchain.pem"
    )
    ssl_private_key_path = os.getenv(
        "SSL_KEY", "/etc/letsencrypt/live/example.com/privkey.pem"
    )


logger = logging.getLogger("https_proxy")

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
        logger.debug("Кэш учётных данных обновлён, записей: %d", len(new_cache))

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
        logger.debug("Нет заголовка Proxy-Authorization")
        return False
    try:
        auth_type, encoded = auth_header.split(" ", 1)
        if auth_type.lower() != "basic":
            logger.debug("Неподдерживаемый тип авторизации: %s", auth_type)
            return False
        decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
        if ":" not in decoded:
            logger.debug(
                "Заголовок авторизации не содержит разделителя username:password"
            )
            return False
        username, password = decoded.split(":", 1)
        creds = CredentialsCache.get()
        stored_hash = creds.get(username)
        if not stored_hash:
            logger.debug("Пользователь %s не найден в кэше", username)
            return False
        # проверка bcrypt
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
    except Exception:
        logger.debug("Ошибка разбора заголовка авторизации", exc_info=True)
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
    peername = writer.get_extra_info("peername")
    logger.debug("Подключился клиент %s", peername)
    try:
        # читаем первую строку (метод path версия)
        request_line = await asyncio.wait_for(
            reader.readline(), timeout=Settings.request_timeout
        )
        if not request_line:
            logger.debug("Клиент %s закрыл соединение до отправки запроса", peername)
            writer.close()
            return
        request_line_str = request_line.decode(errors="ignore").strip()
        logger.debug("Получена стартовая строка запроса: %s", request_line_str)
        parts = request_line_str.split(" ", 2)
        if len(parts) != 3:
            logger.debug("Неверная стартовая строка запроса от %s", peername)
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
            logger.warning("Неуспешная авторизация от %s", peername)
            await send_auth_required(writer)
            return

        if method == "CONNECT":
            if ":" not in path:
                logger.debug("CONNECT без указания порта от %s", peername)
                writer.close()
                return
            host, port_str = path.split(":", 1)
            port = int(port_str)
            logger.debug("Попытка CONNECT к %s:%s от %s", host, port_str, peername)
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=Settings.request_timeout
                )
            except Exception as e:
                logger.warning(
                    "Не удалось установить CONNECT к %s:%s: %s", host, port_str, e
                )
                writer.write(f"HTTP/1.1 502 Bad Gateway: {e}\r\n\r\n".encode())
                await writer.drain()
                writer.close()
                return

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            logger.debug("CONNECT к %s:%s установлен", host, port_str)

            async def pipe(r, w):
                try:
                    while True:
                        data = await asyncio.wait_for(
                            r.read(65536), timeout=Settings.communication_timeout
                        )
                        if not data:
                            break
                        w.write(data)
                        await w.drain()
                except Exception:
                    logger.debug("Соединение разорвано", exc_info=True)
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
                    logger.debug(
                        "Нет заголовка Host для запроса %s от %s", path, peername
                    )
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
                logger.warning(
                    "Не удалось подключиться к %s:%s: %s", host, port, e
                )
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
            logger.debug(
                "Проксируем %s %s:%s%s",
                method,
                host,
                port,
                f" ({origin_path})" if origin_path else "",
            )

            async def pipe(r, w):
                try:
                    while True:
                        data = await asyncio.wait_for(
                            r.read(65536), timeout=Settings.communication_timeout
                        )
                        if not data:
                            break
                        w.write(data)
                        await w.drain()
                except Exception:
                    logger.debug("Соединение разорвано", exc_info=True)
                finally:
                    w.close()

            await asyncio.gather(
                pipe(reader, remote_writer),
                pipe(remote_reader, writer)
            )

    except Exception:
        logger.exception("Ошибка обработки клиента %s", peername)
        writer.close()


# ==== ЗАПУСК ====
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Async HTTPS proxy server")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Включить подробное логирование и отладку asyncio",
    )
    return parser.parse_args()


def setup_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    if not debug:
        logging.getLogger("asyncio").setLevel(logging.WARNING)


async def main():
    loop = asyncio.get_running_loop()
    if Settings.debug:
        loop.set_debug(True)
        logger.debug("Режим asyncio debug включен")
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(Settings.ssl_certificate_path, Settings.ssl_private_key_path)
    server = await asyncio.start_server(
        handle_client, Settings.listen_host, Settings.listen_port, ssl=ssl_ctx
    )
    socknames = ", ".join(
        str(sock.getsockname()) for sock in server.sockets or []
    )
    logger.info("HTTPS-прокси слушает на %s", socknames or "неизвестно")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    args = parse_args()
    if args.debug:
        Settings.debug = True
    setup_logging(Settings.debug)
    logger.debug("Старт сервера в debug=%s", Settings.debug)
    asyncio.run(main())
