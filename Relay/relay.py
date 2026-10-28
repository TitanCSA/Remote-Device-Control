"""Bounded ciphertext relay for explicitly paired Remote Device Control clients.

Nginx terminates the outer HTTPS connection. A separate pinned Schannel session
runs end to end inside the two WebSocket channels; this process cannot decrypt it.
No desktop, input, capabilities or client IPs are recorded persistently.
"""
from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
import hashlib
import hmac
import ipaddress
import re
import time

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

READY = b"RDC-READY-1"
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ROLES = frozenset(("host", "viewer"))
CHANNELS = frozenset(("video", "input"))
HEADER_NAMES = frozenset(("x-remote-room", "x-remote-token", "x-remote-role", "x-remote-channel"))


@dataclass(frozen=True)
class Limits:
    rooms: int = 8
    active_rooms: int = 4
    connections_per_ip: int = 8
    attempts_per_minute: int = 20
    tracked_ips: int = 1024
    packet_bytes: int = 65536
    pairing_seconds: float = 20.0
    lifetime_seconds: float = 3600.0
    send_seconds: float = 10.0
    # The video allowance is 6 Mbit/s; input has a reserved 2 Mbit/s allowance.
    # Separate budgets prevent video saturation from delaying key releases.
    video_bytes_per_second: int = 750000
    input_bytes_per_second: int = 250000


class Refused(Exception):
    def __init__(self, code=1008):
        self.code = code


@dataclass(eq=False)
class Peer:
    socket: WebSocket
    ip: str
    role: str
    channel: str
    room: "Room"
    paired: asyncio.Event = field(default_factory=asyncio.Event)
    ready_sent: asyncio.Event = field(default_factory=asyncio.Event)
    closed: asyncio.Event = field(default_factory=asyncio.Event)
    mate: "Peer | None" = None


@dataclass
class Room:
    identifier: str
    token_hash: bytes
    expires: float
    peers: dict[tuple[str, str], Peer] = field(default_factory=dict)
    next_video: float = 0.0
    next_input: float = 0.0
    bandwidth_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    @property
    def active(self):
        return any(role == "viewer" for role, _ in self.peers)


def client_ip(socket: WebSocket) -> str:
    peer = socket.client.host if socket.client else "unknown"
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return "unknown"
    # Nginx must REPLACE X-Forwarded-For, never append untrusted header text.
    if address.is_loopback:
        forwarded = socket.headers.get("x-forwarded-for", "")
        if len(forwarded) <= 45:
            try:
                return str(ipaddress.ip_address(forwarded))
            except ValueError:
                pass
    return str(address)


class Registry:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.rooms: dict[str, Room] = {}
        self.connections: dict[str, int] = {}
        self.attempts: dict[str, deque[float]] = {}
        self.lock = asyncio.Lock()

    def _attempt(self, ip, now):
        for key in tuple(self.attempts):
            bucket = self.attempts[key]
            while bucket and bucket[0] <= now - 60:
                bucket.popleft()
            if not bucket:
                del self.attempts[key]
        if ip not in self.attempts:
            if len(self.attempts) >= self.limits.tracked_ips:
                raise Refused(1013)
            self.attempts[ip] = deque()
        bucket = self.attempts[ip]
        if len(bucket) >= self.limits.attempts_per_minute:
            raise Refused(1013)
        bucket.append(now)

    @staticmethod
    def _parameters(socket):
        if socket.headers.get("origin") is not None or socket.url.query:
            raise Refused()
        if sum(len(key) + len(value) for key, value in socket.scope.get("headers", ())) > 4096:
            raise Refused()
        remote_headers = {key.lower() for key, _ in socket.scope.get("headers", ()) if key.lower().startswith(b"x-remote-")}
        if remote_headers != {name.encode() for name in HEADER_NAMES}:
            raise Refused()
        values = {}
        for name in HEADER_NAMES:
            entries = socket.headers.getlist(name)
            if len(entries) != 1:
                raise Refused()
            values[name] = entries[0]
        room, token, role, channel = (values[name] for name in ("x-remote-room", "x-remote-token", "x-remote-role", "x-remote-channel"))
        if not HEX32.fullmatch(room) or not HEX64.fullmatch(token) or role not in ROLES or channel not in CHANNELS:
            raise Refused()
        return room, hashlib.sha256(token.encode("ascii")).digest(), role, channel

    async def join(self, socket, ip):
        async with self.lock:
            now = time.monotonic()
            self._attempt(ip, now)
            identifier, token_hash, role, channel = self._parameters(socket)
            if self.connections.get(ip, 0) >= self.limits.connections_per_ip:
                raise Refused(1013)
            room = self.rooms.get(identifier)
            if room and room.expires <= now:
                for old in room.peers.values():
                    old.closed.set()
                raise Refused(1013)
            if room is None:
                if role != "host":
                    raise Refused()
                if len(self.rooms) >= self.limits.rooms:
                    raise Refused(1013)
                room = Room(identifier, token_hash, now + self.limits.lifetime_seconds)
                self.rooms[identifier] = room
            elif not hmac.compare_digest(room.token_hash, token_hash):
                raise Refused()
            if (role, channel) in room.peers:
                raise Refused()
            if role == "viewer":
                if ("host", channel) not in room.peers:
                    raise Refused()
                if not room.active and sum(item.active for item in self.rooms.values()) >= self.limits.active_rooms:
                    raise Refused(1013)
            peer = Peer(socket, ip, role, channel, room)
            room.peers[role, channel] = peer
            self.connections[ip] = self.connections.get(ip, 0) + 1
            opposite = room.peers.get(("viewer" if role == "host" else "host", channel))
            if opposite:
                peer.mate = opposite
                opposite.mate = peer
                peer.paired.set()
                opposite.paired.set()
            return peer

    async def leave(self, peer):
        async with self.lock:
            peer.closed.set()
            if peer.mate:
                peer.mate.closed.set()
            room = peer.room
            if room.peers.get((peer.role, peer.channel)) is peer:
                del room.peers[peer.role, peer.channel]
                amount = self.connections.get(peer.ip, 0) - 1
                if amount > 0:
                    self.connections[peer.ip] = amount
                else:
                    self.connections.pop(peer.ip, None)
            if not room.peers and self.rooms.get(room.identifier) is room:
                del self.rooms[room.identifier]

    async def bandwidth(self, peer, count):
        room = peer.room
        rate = self.limits.video_bytes_per_second if peer.channel == "video" else self.limits.input_bytes_per_second
        if rate <= 0:
            raise Refused(1013)
        field_name = "next_video" if peer.channel == "video" else "next_input"
        async with room.bandwidth_lock:
            now = time.monotonic()
            scheduled = max(now, getattr(room, field_name))
            setattr(room, field_name, scheduled + count / rate)
            delay = scheduled - now
        # No accumulation beyond the two bounded in-flight packets per stream.
        if delay > self.limits.send_seconds or scheduled >= room.expires:
            raise Refused(1013)
        if delay:
            await asyncio.sleep(delay)


def create_app(limits=Limits()):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    registry = Registry(limits)
    app.state.registry = registry

    @app.get("/remote-device-control/health")
    async def health():
        return {"status": "ok", "protocol": 1, "ciphertext_only": True, "max_payload_bytes": limits.packet_bytes}

    @app.websocket("/remote-device-control/relay")
    async def relay(socket: WebSocket):
        peer = None
        tasks = []
        close_code = 1000
        try:
            peer = await registry.join(socket, client_ip(socket))
            await socket.accept()
            await asyncio.wait_for(peer.paired.wait(), timeout=limits.pairing_seconds)
            if peer.closed.is_set() or peer.mate is None:
                raise Refused()
            await asyncio.wait_for(socket.send_bytes(READY), timeout=limits.send_seconds)
            peer.ready_sent.set()
            await asyncio.wait_for(peer.mate.ready_sent.wait(), timeout=limits.pairing_seconds)

            async def forward():
                while not peer.closed.is_set():
                    message = await socket.receive()
                    if message["type"] == "websocket.disconnect":
                        return
                    payload = message.get("bytes")
                    if not isinstance(payload, bytes) or not 0 < len(payload) <= limits.packet_bytes:
                        raise Refused(1003 if message.get("text") is not None else 1009)
                    await registry.bandwidth(peer, len(payload))
                    if peer.closed.is_set():
                        return
                    await asyncio.wait_for(peer.mate.socket.send_bytes(payload), timeout=limits.send_seconds)

            tasks = [asyncio.create_task(forward()), asyncio.create_task(peer.closed.wait())]
            done, _pending = await asyncio.wait(tasks, timeout=max(0.0, peer.room.expires-time.monotonic()), return_when=asyncio.FIRST_COMPLETED)
            if not done:
                close_code = 1001
            for task in done:
                task.result()
        except Refused as error:
            close_code = error.code
        except asyncio.TimeoutError:
            close_code = 1001
        except (WebSocketDisconnect, RuntimeError, OSError):
            close_code = 1001
        finally:
            if peer:
                await registry.leave(peer)
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            try:
                await socket.close(code=close_code)
            except (RuntimeError, OSError):
                pass

    return app


app = create_app()
