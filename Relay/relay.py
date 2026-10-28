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
import json
import re
import time

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

READY = b"RDC-READY-1"
HEX32 = re.compile(r"^[0-9a-f]{32}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ROLES = frozenset(("host", "viewer"))
CHANNELS = frozenset(("video", "input"))
HEADER_NAMES = frozenset(("x-remote-room", "x-remote-token", "x-remote-role", "x-remote-channel"))
HOST_KEY = "x-remote-host-key"
RELAY_URL = "wss://licences.configcsa.com/remote-device-control/relay"


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
    host_key_hash: bytes | None = field(default=None, repr=False)

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
        self.public_hosts: dict[str, tuple[dict, float]] = {}
        self.owner_leases: dict[str, tuple[bytes, float]] = {}

    def _prune_public(self, now):
        for identifier, (_, expires) in tuple(self.public_hosts.items()):
            if expires <= now:
                del self.public_hosts[identifier]
        for identifier, (_, expires) in tuple(self.owner_leases.items()):
            if expires <= now and identifier not in self.rooms:
                del self.owner_leases[identifier]

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
        base = {name.encode() for name in HEADER_NAMES}
        if remote_headers not in (base, base | {HOST_KEY.encode()}):
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
        host_keys = socket.headers.getlist(HOST_KEY)
        if host_keys and (len(host_keys) != 1 or role != "host" or not HEX64.fullmatch(host_keys[0])):
            raise Refused()
        host_hash = hashlib.sha256(host_keys[0].encode("ascii")).digest() if host_keys else None
        return room, hashlib.sha256(token.encode("ascii")).digest(), role, channel, host_hash

    async def join(self, socket, ip):
        async with self.lock:
            now = time.monotonic()
            self._prune_public(now)
            self._attempt(ip, now)
            identifier, token_hash, role, channel, host_hash = self._parameters(socket)
            # Public room ownership is self-certifying. Unlike a timed cache,
            # this proof remains valid across disconnections and relay restarts.
            # The public viewer capability cannot mint another host for this ID.
            if host_hash is not None and not hmac.compare_digest(identifier, host_hash.hex()[:32]):
                raise Refused()
            lease = self.owner_leases.get(identifier)
            if role == "host" and lease and (host_hash is None or not hmac.compare_digest(lease[0], host_hash)):
                raise Refused()
            room = self.rooms.get(identifier)
            if role == "host" and host_hash is not None and room and room.host_key_hash is None:
                # A recorded public capability can occupy an unkeyed legacy
                # slot after a restart. Only the cryptographically proven room
                # owner may retire that slot. Never evict a keyed/live owner.
                for old in tuple(room.peers.values()):
                    old.closed.set()
                    amount = self.connections.get(old.ip, 0) - 1
                    if amount > 0:
                        self.connections[old.ip] = amount
                    else:
                        self.connections.pop(old.ip, None)
                room.peers.clear()
                del self.rooms[identifier]
                room = None
            if self.connections.get(ip, 0) >= self.limits.connections_per_ip:
                raise Refused(1013)
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
                if host_hash is not None:
                    if not lease and len(self.owner_leases) >= 64:
                        raise Refused(1013)
                    room.host_key_hash = host_hash
                    self.owner_leases[identifier] = (host_hash, now + 60)
                self.rooms[identifier] = room
            elif not hmac.compare_digest(room.token_hash, token_hash):
                raise Refused()
            if role == "host" and room.host_key_hash != host_hash:
                raise Refused()
            if role == "host" and host_hash is not None:
                self.owner_leases[identifier] = (host_hash, now + 60)
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

    async def list_public(self):
        async with self.lock:
            self._prune_public(time.monotonic())
            result = []
            for identifier, (metadata, _) in self.public_hosts.items():
                room = self.rooms.get(identifier)
                if not room or not any(role == "host" for role, _ in room.peers):
                    continue
                item = dict(metadata)
                item["busy"] = item["busy"] or room.active
                result.append(item)
            return result

    async def publish(self, metadata, owner):
        async with self.lock:
            now = time.monotonic()
            self._prune_public(now)
            identifier = metadata["room"]
            room = self.rooms.get(identifier)
            owner_hash = hashlib.sha256(owner.encode("ascii")).digest()
            if (not hmac.compare_digest(identifier, owner_hash.hex()[:32])
                    or not room or not room.host_key_hash or not hmac.compare_digest(room.host_key_hash, owner_hash)
                    or not hmac.compare_digest(room.token_hash, hashlib.sha256(metadata["relay_token"].encode("ascii")).digest())
                    or not any(role == "host" for role, _ in room.peers)):
                return False
            if identifier not in self.public_hosts and len(self.public_hosts) >= 64:
                return False
            self.owner_leases[identifier] = (owner_hash, now + 60)
            self.public_hosts[identifier] = (dict(metadata), now + 12)
            return True

    async def remove_public(self, identifier, owner):
        async with self.lock:
            self._prune_public(time.monotonic())
            lease = self.owner_leases.get(identifier)
            if not lease or not hmac.compare_digest(lease[0], hashlib.sha256(owner.encode("ascii")).digest()):
                return False
            self.public_hosts.pop(identifier, None)
            return True

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

    @app.api_route("/remote-device-control/hosts", methods=["GET", "POST", "DELETE"])
    async def directory(request: Request):
        def reply(data, status=200):
            return JSONResponse(data, status_code=status, headers={"Cache-Control": "no-store"})
        if request.method == "GET":
            if request.url.query:
                return reply({"error": "invalid_request"}, 400)
            return reply({"hosts": await registry.list_public()})
        owners = request.headers.getlist("x-remote-owner")
        if len(owners) != 1 or not HEX64.fullmatch(owners[0]) or request.headers.get("origin") is not None:
            return reply({"error": "owner_required"}, 403)
        if request.method == "DELETE":
            identifiers = request.query_params.getlist("room")
            if set(request.query_params) != {"room"} or len(identifiers) != 1 or not HEX32.fullmatch(identifiers[0]):
                return reply({"error": "invalid_request"}, 400)
            removed = await registry.remove_public(identifiers[0], owners[0])
            return reply({"ok": True} if removed else {"error": "owner_refused"}, 200 if removed else 403)
        if request.url.query:
            return reply({"error": "invalid_request"}, 400)
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 4096:
                return reply({"error": "request_too_large"}, 413)
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate field")
                result[key] = value
            return result
        try:
            metadata = json.loads(raw, object_pairs_hook=unique)
            if not isinstance(metadata, dict) or set(metadata) != {"name", "room", "pin", "relay_token", "relay", "busy", "available", "require_approval"}:
                raise ValueError("invalid fields")
            if (not isinstance(metadata["name"], str) or not 1 <= len(metadata["name"]) <= 64 or len(metadata["name"].encode("utf-8")) > 128 or not metadata["name"].isprintable()
                    or any(not isinstance(metadata[key], str) or not pattern.fullmatch(metadata[key]) for key, pattern in (("room", HEX32), ("pin", HEX64), ("relay_token", HEX64)))
                    or metadata["relay"] != RELAY_URL or any(type(metadata[key]) is not bool for key in ("busy", "available", "require_approval"))):
                raise ValueError("invalid values")
        except (ValueError, TypeError, UnicodeError):
            return reply({"error": "invalid_request"}, 400)
        accepted = await registry.publish(metadata, owners[0])
        return reply({"ok": True} if accepted else {"error": "owner_refused"}, 200 if accepted else 403)

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
