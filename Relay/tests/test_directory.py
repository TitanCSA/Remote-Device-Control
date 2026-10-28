"""Public opt-in discovery cannot disclose or replace private host ownership."""
import asyncio
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))
from fastapi.testclient import TestClient
from starlette.datastructures import Headers
from relay import Limits, READY, Registry, Refused, create_app

TOKEN, OWNER = "a" * 64, "c" * 64
ROOM = hashlib.sha256(OWNER.encode("ascii")).hexdigest()[:32]
URL, HOSTS = "/remote-device-control/relay", "/remote-device-control/hosts"
def headers(role="host", key=OWNER):
    result = {"x-remote-room": ROOM, "x-remote-token": TOKEN, "x-remote-role": role, "x-remote-channel": "input"}
    if key is not None:
        result["x-remote-host-key"] = key
    return result
def metadata():
    return dict(name="Disposable test PC", room=ROOM, pin="b" * 64, relay_token=TOKEN,
                relay="wss://licences.configcsa.com/remote-device-control/relay", busy=False, available=True, require_approval=True)

class DirectoryHTTPTests(unittest.TestCase):
    def make(self):
        return create_app(replace(Limits(), pairing_seconds=3))
    def test_private_hosts_are_hidden_until_explicit_owner_publication(self):
        with TestClient(self.make()) as client:
            with client.websocket_connect(URL, headers=headers()) as host:
                self.assertEqual(client.get(HOSTS).json(), {"hosts": []})
                self.assertEqual(client.post(HOSTS, json=metadata(), headers={"x-remote-owner": OWNER}).status_code, 200)
                response = client.get(HOSTS)
                self.assertEqual(response.json(), {"hosts": [metadata()]})
                self.assertEqual(response.headers["cache-control"], "no-store")
                self.assertNotIn(OWNER, response.text)
                self.assertNotIn("host_key", response.text)
                self.assertEqual(client.delete(HOSTS + "?room=" + ROOM, headers={"x-remote-owner": OWNER}).status_code, 200)
                self.assertFalse(client.get(HOSTS).json()["hosts"])
    def test_unregistered_or_legacy_private_room_cannot_publish(self):
        with TestClient(self.make()) as client:
            self.assertEqual(client.post(HOSTS, json=metadata(), headers={"x-remote-owner": OWNER}).status_code, 403)
            with client.websocket_connect(URL, headers=headers(key=None)):
                self.assertEqual(client.post(HOSTS, json=metadata(), headers={"x-remote-owner": OWNER}).status_code, 403)
    def test_public_viewer_capability_is_not_an_owner_key(self):
        with TestClient(self.make()) as client:
            with client.websocket_connect(URL, headers=headers()):
                self.assertEqual(client.post(HOSTS, json=metadata(), headers={"x-remote-owner": TOKEN}).status_code, 403)
                self.assertEqual(client.post(HOSTS, json=metadata(), headers={"x-remote-owner": OWNER}).status_code, 200)
                self.assertEqual(client.delete(HOSTS + "?room=" + ROOM, headers={"x-remote-owner": TOKEN}).status_code, 403)
                changed = metadata(); changed["relay_token"] = "f" * 64
                self.assertEqual(client.post(HOSTS, json=changed, headers={"x-remote-owner": OWNER}).status_code, 403)
                self.assertEqual(client.get(HOSTS).json()["hosts"], [metadata()])
    def test_invalid_fields_duplicate_json_and_oversized_body_are_rejected(self):
        with TestClient(self.make()) as client:
            for key, value in (("name", ""), ("name", "bad\nname"), ("name", "x" * 65), ("pin", "invalid"),
                               ("relay", "wss://example.invalid/relay"), ("busy", 1), ("available", None), ("room", "A" * 32)):
                data = metadata(); data[key] = value
                self.assertEqual(client.post(HOSTS, json=data, headers={"x-remote-owner": OWNER}).status_code, 400)
            raw = json.dumps(metadata())[:-1] + ',"busy":true}'
            self.assertEqual(client.post(HOSTS, content=raw, headers={"x-remote-owner": OWNER}).status_code, 400)
            self.assertEqual(client.post(HOSTS, content=b"x" * 4097, headers={"x-remote-owner": OWNER}).status_code, 413)
    def test_origins_and_ambiguous_queries_do_not_modify_hosts(self):
        with TestClient(self.make()) as client:
            self.assertEqual(client.post(HOSTS, json=metadata(), headers={"x-remote-owner": OWNER, "origin": "https://example.invalid"}).status_code, 403)
            self.assertEqual(client.get(HOSTS + "?room=" + ROOM).status_code, 400)
            self.assertEqual(client.delete(HOSTS + "?room=" + ROOM + "&room=" + ROOM, headers={"x-remote-owner": OWNER}).status_code, 400)
    def test_unicode_names_cannot_exceed_native_viewer_byte_limit(self):
        with TestClient(self.make()) as client:
            with client.websocket_connect(URL, headers=headers()):
                item = metadata(); item["name"] = "é" * 64
                self.assertEqual(client.post(HOSTS, json=item, headers={"x-remote-owner": OWNER}).status_code, 200)
                self.assertEqual(len(client.get(HOSTS).json()["hosts"][0]["name"].encode("utf-8")), 128)
                item["name"] = "😀" * 33
                self.assertEqual(client.post(HOSTS, json=item, headers={"x-remote-owner": OWNER}).status_code, 400)
                self.assertEqual(client.get(HOSTS).json()["hosts"][0]["name"], "é" * 64)
    def test_busy_catalog_does_not_evict_first_viewer(self):
        with TestClient(self.make()) as client:
            with client.websocket_connect(URL, headers=headers()) as host:
                self.assertEqual(client.post(HOSTS, json=metadata(), headers={"x-remote-owner": OWNER}).status_code, 200)
                with client.websocket_connect(URL, headers=headers("viewer", None)) as viewer:
                    self.assertEqual(host.receive_bytes(), READY); self.assertEqual(viewer.receive_bytes(), READY)
                    self.assertTrue(client.get(HOSTS).json()["hosts"][0]["busy"])
                    viewer.send_bytes(b"opaque"); self.assertEqual(host.receive_bytes(), b"opaque")

class DirectoryRegistryTests(unittest.IsolatedAsyncioTestCase):
    def socket(self, role="host", key=OWNER):
        values = Headers(headers(role, key))
        return SimpleNamespace(headers=values, url=SimpleNamespace(query=""), scope={"headers": values.raw})
    async def test_public_token_cannot_take_host_role_across_rendezvous_gap(self):
        registry = Registry(Limits())
        host = await registry.join(self.socket(), "192.0.2.1")
        self.assertTrue(await registry.publish(metadata(), OWNER))
        await registry.leave(host)
        self.assertFalse(await registry.list_public())
        with self.assertRaises(Refused):
            await registry.join(self.socket(key=None), "192.0.2.2")
        with self.assertRaises(Refused):
            await registry.join(self.socket(key=TOKEN), "192.0.2.2")
        replacement = await registry.join(self.socket(), "192.0.2.1")
        self.assertTrue(await registry.publish(metadata(), OWNER))
        await registry.leave(replacement)
    async def test_stale_metadata_expires_without_losing_live_owner(self):
        registry = Registry(Limits())
        host = await registry.join(self.socket(), "192.0.2.1")
        self.assertTrue(await registry.publish(metadata(), OWNER))
        registry.public_hosts[ROOM] = (metadata(), time.monotonic() - 1)
        self.assertFalse(await registry.list_public())
        self.assertIn(ROOM, registry.owner_leases)
        self.assertTrue(await registry.publish(metadata(), OWNER))
        await registry.leave(host)
    async def test_owner_memory_is_bounded_and_expired_leases_are_pruned(self):
        registry = Registry(Limits())
        for value in range(64):
            registry.owner_leases[format(value + 16, "032x")] = (hashlib.sha256(b"fixture").digest(), time.monotonic() + 60)
        with self.assertRaises(Refused):
            await registry.join(self.socket(), "192.0.2.1")
        registry.owner_leases = {key: (owner, time.monotonic() - 1) for key, (owner, _) in registry.owner_leases.items()}
        host = await registry.join(self.socket(), "192.0.2.1")
        self.assertEqual(len(registry.owner_leases), 1)
        await registry.leave(host)
    async def test_second_host_channel_needs_private_owner_key(self):
        registry = Registry(Limits())
        await registry.join(self.socket(), "192.0.2.1")
        sock = self.socket(key=TOKEN)
        values = dict(sock.headers); values["x-remote-channel"] = "video"
        sock.headers = Headers(values); sock.scope["headers"] = sock.headers.raw
        with self.assertRaises(Refused):
            await registry.join(sock, "192.0.2.2")

    async def test_public_ownership_survives_expired_lease_and_relay_restart(self):
        registry = Registry(Limits())
        host = await registry.join(self.socket(), "192.0.2.1")
        self.assertTrue(await registry.publish(metadata(), OWNER))
        await registry.leave(host)
        registry.owner_leases[ROOM] = (hashlib.sha256(OWNER.encode("ascii")).digest(), time.monotonic() - 1)
        for current in (registry, Registry(Limits())):
            with self.assertRaises(Refused):
                await current.join(self.socket(key="d" * 64), "192.0.2.2")
            self.assertFalse(await current.publish(metadata(), "d" * 64))
            owner = await current.join(self.socket(), "192.0.2.1")
            self.assertTrue(await current.publish(metadata(), OWNER))
            await current.leave(owner)

    async def test_owner_can_retire_only_unkeyed_legacy_occupant(self):
        registry = Registry(Limits())
        intruder = await registry.join(self.socket(key=None), "192.0.2.2")
        viewer = await registry.join(self.socket("viewer", None), "192.0.2.3")
        with self.assertRaises(Refused):
            await registry.join(self.socket(key="d" * 64), "192.0.2.4")
        self.assertFalse(intruder.closed.is_set())
        self.assertFalse(await registry.publish(metadata(), OWNER))
        owner = await registry.join(self.socket(), "192.0.2.1")
        self.assertTrue(intruder.closed.is_set())
        self.assertTrue(viewer.closed.is_set())
        self.assertIs(registry.rooms[ROOM], owner.room)
        self.assertEqual(registry.connections, {"192.0.2.1": 1})
        # The retired handlers may finish after replacement; their cleanup must
        # neither delete the new room nor decrement the new owner's admission.
        await registry.leave(intruder)
        await registry.leave(viewer)
        self.assertIs(registry.rooms[ROOM], owner.room)
        self.assertEqual(registry.connections, {"192.0.2.1": 1})
        self.assertTrue(await registry.publish(metadata(), OWNER))
        with self.assertRaises(Refused):
            await registry.join(self.socket(), "192.0.2.5")
        self.assertFalse(owner.closed.is_set())
        await registry.leave(owner)

if __name__ == "__main__":
    unittest.main()
