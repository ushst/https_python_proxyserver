#!/usr/bin/env python3
import argparse
import asyncio
import base64
import contextlib
import bcrypt
import logging
import os
import ssl
import threading
from typing import Dict, Optional, Tuple
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

    upstream_proxy_url = os.getenv("UPSTREAM_PROXY", "").strip()
    upstream_proxy_scheme: Optional[str] = None
    upstream_proxy_host: Optional[str] = None
    upstream_proxy_port: Optional[int] = None
    upstream_proxy_username: Optional[str] = None
    upstream_proxy_password: Optional[str] = None
    upstream_proxy_authorization: Optional[str] = None
    upstream_proxy_ssl_context: Optional[ssl.SSLContext] = None

    if upstream_proxy_url:
        parsed_upstream = urlsplit(
            upstream_proxy_url
            if "://" in upstream_proxy_url
            else f"http://{upstream_proxy_url}"
        )
        upstream_proxy_scheme = parsed_upstream.scheme or "http"
        upstream_proxy_host = parsed_upstream.hostname
        default_port = 443 if upstream_proxy_scheme == "https" else 8080
        upstream_proxy_port = parsed_upstream.port or default_port
        upstream_proxy_username = parsed_upstream.username
        upstream_proxy_password = parsed_upstream.password
        if upstream_proxy_username is not None:
            credentials = f"{upstream_proxy_username}:{upstream_proxy_password or ''}"
            upstream_proxy_authorization = "Basic " + base64.b64encode(
                credentials.encode("utf-8")
            ).decode("ascii")
        if upstream_proxy_scheme == "https":
            upstream_proxy_ssl_context = ssl.create_default_context()


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


def _is_application_data_after_close(exc: ssl.SSLError) -> bool:
    reason = getattr(exc, "reason", "") or ""
    text = str(exc)
    return "APPLICATION_DATA_AFTER_CLOSE_NOTIFY" in reason or (
        "APPLICATION_DATA_AFTER_CLOSE_NOTIFY" in text
    )


async def close_stream(writer: Optional[asyncio.StreamWriter]) -> None:
    if writer is None:
        return
    if writer.is_closing():
        wait_closed = getattr(writer, "wait_closed", None)
        if callable(wait_closed):
            with contextlib.suppress(Exception):
                await wait_closed()
        return
    writer.close()
    wait_closed = getattr(writer, "wait_closed", None)
    if callable(wait_closed):
        with contextlib.suppress(Exception):
            await wait_closed()


async def safe_drain(writer: asyncio.StreamWriter, description: str) -> bool:
    try:
        await writer.drain()
        return True
    except asyncio.CancelledError:
        raise
    except (ConnectionResetError, BrokenPipeError) as exc:
        logger.debug("%s: соединение закрыто (%s)", description, exc)
    except ssl.SSLError as exc:
        if _is_application_data_after_close(exc):
            logger.debug("%s: SSL-соединение закрыто удалённой стороной", description)
        else:
            logger.debug(
                "%s: SSL-ошибка при ожидании опустошения буфера: %s",
                description,
                exc,
                exc_info=Settings.debug,
            )
    except Exception as exc:
        logger.debug(
            "%s: ошибка при ожидании опустошения буфера: %s",
            description,
            exc,
            exc_info=Settings.debug,
        )
    return False


async def pipe_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    description: str,
) -> None:
    try:
        while True:
            try:
                data = await asyncio.wait_for(
                    reader.read(65536), timeout=Settings.communication_timeout
                )
            except asyncio.TimeoutError:
                logger.debug("%s: превышен таймаут ожидания данных", description)
                break
            if not data:
                break
            writer.write(data)
            if not await safe_drain(writer, f"{description}: отправка данных"):
                break
    except asyncio.CancelledError:
        raise
    except ssl.SSLError as exc:
        if _is_application_data_after_close(exc):
            logger.debug("%s: SSL-соединение закрыто удалённой стороной", description)
        else:
            logger.debug(
                "%s: SSL-ошибка при пересылке данных: %s",
                description,
                exc,
                exc_info=Settings.debug,
            )
    except (ConnectionResetError, BrokenPipeError, OSError) as exc:
        logger.debug("%s: соединение разорвано: %s", description, exc)
    except Exception:
        logger.debug(
            "%s: неожиданная ошибка при пересылке данных", description, exc_info=True
        )
    finally:
        await close_stream(writer)


async def send_auth_required(writer: asyncio.StreamWriter):
    msg = (
        "HTTP/1.1 407 Proxy Authentication Required\r\n"
        f'Proxy-Authenticate: Basic realm="{Settings.realm}"\r\n'
        "Connection: close\r\n\r\n"
    )
    writer.write(msg.encode())
    await safe_drain(writer, "Отправка ответа 407 клиенту")
    await close_stream(writer)


async def open_upstream_connection() -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if not Settings.upstream_proxy_host:
        raise RuntimeError("Апстрим-прокси не настроен")
    connect_kwargs = {}
    if Settings.upstream_proxy_scheme == "https":
        connect_kwargs["ssl"] = Settings.upstream_proxy_ssl_context
        connect_kwargs["server_hostname"] = Settings.upstream_proxy_host
    return await asyncio.wait_for(
        asyncio.open_connection(
            Settings.upstream_proxy_host,
            Settings.upstream_proxy_port,
            **connect_kwargs,
        ),
        timeout=Settings.request_timeout,
    )


# ==== ПРОКСИ ====
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peername = writer.get_extra_info("peername")
    logger.debug("Подключился клиент %s", peername)
    remote_reader: Optional[asyncio.StreamReader] = None
    remote_writer: Optional[asyncio.StreamWriter] = None
    try:
        request_line = await asyncio.wait_for(
            reader.readline(), timeout=Settings.request_timeout
        )
        if not request_line:
            logger.debug("Клиент %s закрыл соединение до отправки запроса", peername)
            await close_stream(writer)
            return

        request_line_str = request_line.decode(errors="ignore").strip()
        logger.debug("Получена стартовая строка запроса: %s", request_line_str)
        parts = request_line_str.split(" ", 2)
        if len(parts) != 3:
            logger.debug("Неверная стартовая строка запроса от %s", peername)
            await close_stream(writer)
            return
        method, path, version = parts

        raw_headers = []
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            raw_headers.append(line.decode(errors="ignore").strip())
        headers = parse_headers(raw_headers)

        if not authenticate(headers):
            logger.warning("Неуспешная авторизация от %s", peername)
            await send_auth_required(writer)
            return

        if method == "CONNECT":
            if ":" not in path:
                logger.debug("CONNECT без указания порта от %s", peername)
                await close_stream(writer)
                return
            host, port_str = path.split(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                logger.debug("CONNECT с некорректным портом %s от %s", port_str, peername)
                await close_stream(writer)
                return

            logger.debug("Попытка CONNECT к %s:%s от %s", host, port_str, peername)
            try:
                if Settings.upstream_proxy_host:
                    logger.debug(
                        "CONNECT %s:%s через апстрим %s:%s",
                        host,
                        port_str,
                        Settings.upstream_proxy_host,
                        Settings.upstream_proxy_port,
                    )
                    remote_reader, remote_writer = await open_upstream_connection()
                    connect_target = f"{host}:{port}"
                    lines = [
                        f"CONNECT {connect_target} HTTP/1.1",
                        f"Host: {connect_target}",
                    ]
                    if Settings.upstream_proxy_authorization:
                        lines.append(
                            f"Proxy-Authorization: {Settings.upstream_proxy_authorization}"
                        )
                    request_data = "\r\n".join(lines) + "\r\n\r\n"
                    remote_writer.write(request_data.encode())
                    if not await safe_drain(
                        remote_writer,
                        f"CONNECT {connect_target}: ожидание подтверждения апстрима",
                    ):
                        await close_stream(remote_writer)
                        remote_writer = None
                        await close_stream(writer)
                        return
                    response_line = await asyncio.wait_for(
                        remote_reader.readline(), timeout=Settings.request_timeout
                    )
                    if not response_line:
                        raise RuntimeError("Пустой ответ апстрим-прокси")
                    response_line_str = response_line.decode(errors="ignore").strip()
                    parts = response_line_str.split(" ", 2)
                    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
                    while True:
                        header_line = await asyncio.wait_for(
                            remote_reader.readline(), timeout=Settings.request_timeout
                        )
                        if header_line in (b"\r\n", b"\n", b""):
                            break
                    if status_code != 200:
                        raise RuntimeError(
                            f"Апстрим-прокси вернул статус {response_line_str}"
                        )
                else:
                    remote_reader, remote_writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=Settings.request_timeout,
                    )
            except Exception as e:
                logger.warning(
                    "Не удалось установить CONNECT к %s:%s: %s", host, port_str, e
                )
                await close_stream(remote_writer)
                remote_writer = None
                writer.write(f"HTTP/1.1 502 Bad Gateway: {e}\r\n\r\n".encode())
                await safe_drain(writer, f"Отправка 502 клиенту {peername}")
                await close_stream(writer)
                return

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if not await safe_drain(
                writer, f"Отправка подтверждения CONNECT клиенту {peername}"
            ):
                await close_stream(remote_writer)
                remote_writer = None
                await close_stream(writer)
                return
            logger.debug("CONNECT к %s:%s установлен", host, port_str)

            await asyncio.gather(
                pipe_stream(reader, remote_writer, f"{peername} -> {host}:{port}"),
                pipe_stream(remote_reader, writer, f"{host}:{port} -> {peername}"),
            )
            remote_writer = None

        else:
            parsed = urlsplit(path)
            if parsed.scheme and parsed.netloc:
                host = parsed.hostname or ""
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
                    await close_stream(writer)
                    return
                if ":" in host_header:
                    host, port_str = host_header.rsplit(":", 1)
                    try:
                        port = int(port_str)
                    except ValueError:
                        logger.debug(
                            "Некорректный порт в Host (%s) от %s", host_header, peername
                        )
                        await close_stream(writer)
                        return
                else:
                    host, port = host_header, 80
                origin_path = path or "/"

            if not host:
                logger.debug("Не удалось определить целевой хост для %s", peername)
                await close_stream(writer)
                return

            try:
                if Settings.upstream_proxy_host:
                    remote_reader, remote_writer = await open_upstream_connection()
                else:
                    remote_reader, remote_writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=Settings.request_timeout,
                    )
            except Exception as e:
                logger.warning(
                    "Не удалось подключиться к %s:%s: %s", host, port, e
                )
                await close_stream(remote_writer)
                remote_writer = None
                writer.write(f"HTTP/1.1 502 Bad Gateway: {e}\r\n\r\n".encode())
                await safe_drain(writer, f"Отправка 502 клиенту {peername}")
                await close_stream(writer)
                return

            fwd_headers = strip_hop_by_hop(headers)
            fwd_headers["Host"] = fwd_headers.get("Host") or host
            fwd_headers["Connection"] = "close"
            if Settings.upstream_proxy_host:
                if Settings.upstream_proxy_authorization:
                    fwd_headers["Proxy-Authorization"] = (
                        Settings.upstream_proxy_authorization
                    )
                fwd_headers.setdefault("Proxy-Connection", "close")

            if Settings.upstream_proxy_host:
                if parsed.scheme and parsed.netloc:
                    request_target = path
                else:
                    scheme = parsed.scheme or "http"
                    if (scheme == "http" and port == 80) or (
                        scheme == "https" and port == 443
                    ):
                        host_port = host
                    else:
                        host_port = f"{host}:{port}"
                    request_target = f"{scheme}://{host_port}{origin_path}"
            else:
                request_target = origin_path

            header_str = "".join(f"{k}: {v}\r\n" for k, v in fwd_headers.items())
            req = f"{method} {request_target} HTTP/1.1\r\n{header_str}\r\n"
            remote_writer.write(req.encode())
            if not await safe_drain(
                remote_writer, f"Отправка {method} запроса на {host}:{port}"
            ):
                await close_stream(remote_writer)
                remote_writer = None
                await close_stream(writer)
                return
            logger.debug(
                "Проксируем %s %s:%s%s",
                method,
                host,
                port,
                f" ({request_target})" if request_target else "",
            )

            await asyncio.gather(
                pipe_stream(reader, remote_writer, f"{peername} -> {host}:{port}"),
                pipe_stream(remote_reader, writer, f"{host}:{port} -> {peername}"),
            )
            remote_writer = None

    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("Ошибка обработки клиента %s", peername)
        await close_stream(writer)
    finally:
        await close_stream(remote_writer)


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
