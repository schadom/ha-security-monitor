"""Stand-in for an integration's API client (only its file path matters)."""

import asyncio
import socket


async def fetch(session, url):
    """HTTP request through aiohttp."""
    async with session.get(url) as resp:
        return await resp.text()


def blocking_connect(host, port):
    """Plain socket, as libraries like requests/urllib3 do in executor threads."""
    with socket.create_connection((host, port), timeout=2):
        pass


async def asyncio_connect(host, port):
    """Raw asyncio stream, as MQTT or websocket libraries do."""
    _reader, writer = await asyncio.open_connection(host, port)
    writer.close()
    await writer.wait_closed()


def lookup(host):
    """DNS lookup through getaddrinfo."""
    try:
        socket.getaddrinfo(host, None)
    except OSError:
        pass
