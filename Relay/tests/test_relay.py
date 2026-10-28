"""Disposable room/capability tests; no real host or input ever enters this suite."""
from pathlib import Path
import asyncio
from dataclasses import replace
import json
import sys
import time
import unittest
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).parents[1]))
from fastapi.testclient import TestClient
from httpx import Headers
from starlette.websockets import WebSocketDisconnect
from starlette.datastructures import Headers as StarletteHeaders
from relay import Limits, READY, Registry, Refused, client_ip, create_app

ROOM="1"*32
TOKEN="a"*64
URL="/remote-device-control/relay"

def headers(role="host",channel="video",room=ROOM,token=TOKEN):
    return {"x-remote-room":room,"x-remote-token":token,"x-remote-role":role,"x-remote-channel":channel}


class RelayTests(unittest.TestCase):
    def make(self,**changes):
        return create_app(replace(Limits(),pairing_seconds=.7,send_seconds=.5,**changes))

    def assert_refused(self,client,**options):
        with self.assertRaises(WebSocketDisconnect):
            with client.websocket_connect(URL,headers=options.pop('headers',headers()),**options) as socket:
                socket.receive_bytes()

    def test_health_exposes_no_room_or_client_information(self):
        with TestClient(self.make()) as client:
            response=client.get('/remote-device-control/health')
            self.assertEqual(response.status_code,200)
            self.assertEqual(set(response.json()),{'status','protocol','ciphertext_only','max_payload_bytes'})
            self.assertTrue(response.json()['ciphertext_only'])

    def test_matching_pair_forwards_binary_both_directions(self):
        app=self.make()
        with TestClient(app) as client:
            with client.websocket_connect(URL,headers=headers()) as host:
                with client.websocket_connect(URL,headers=headers('viewer')) as viewer:
                    self.assertEqual(host.receive_bytes(),READY)
                    self.assertEqual(viewer.receive_bytes(),READY)
                    host.send_bytes(b'encrypted video fixture');self.assertEqual(viewer.receive_bytes(),b'encrypted video fixture')
                    viewer.send_bytes(b'encrypted response fixture');self.assertEqual(host.receive_bytes(),b'encrypted response fixture')
                    self.assertNotIn(TOKEN,repr(app.state.registry.rooms))
            self.assertFalse(app.state.registry.rooms)
            self.assertFalse(app.state.registry.connections)

    def test_input_and_video_are_distinct_channels(self):
        with TestClient(self.make()) as client:
            with client.websocket_connect(URL,headers=headers(channel='video')) as video_host:
                with client.websocket_connect(URL,headers=headers(channel='input')) as input_host:
                    with client.websocket_connect(URL,headers=headers('viewer','input')) as input_viewer:
                        self.assertEqual(input_host.receive_bytes(),READY);self.assertEqual(input_viewer.receive_bytes(),READY)
                        input_viewer.send_bytes(b'cipher input');self.assertEqual(input_host.receive_bytes(),b'cipher input')
                        with client.websocket_connect(URL,headers=headers('viewer','video')) as video_viewer:
                            self.assertEqual(video_host.receive_bytes(),READY);self.assertEqual(video_viewer.receive_bytes(),READY)
                            video_host.send_bytes(b'cipher pixels');self.assertEqual(video_viewer.receive_bytes(),b'cipher pixels')

    def test_unknown_room_viewer_wrong_secret_and_duplicate_host_are_refused(self):
        with TestClient(self.make()) as client:
            self.assert_refused(client,headers=headers('viewer'))
            with client.websocket_connect(URL,headers=headers()) as host:
                self.assert_refused(client,headers=headers('viewer',token='b'*64))
                self.assert_refused(client)
                with client.websocket_connect(URL,headers=headers('viewer')) as viewer:
                    self.assertEqual(host.receive_bytes(),READY);self.assertEqual(viewer.receive_bytes(),READY)
                    self.assert_refused(client,headers=headers('viewer'))
                    host.send_bytes(b'original peer retained');self.assertEqual(viewer.receive_bytes(),b'original peer retained')

    def test_browser_origin_queries_extra_fields_and_malformed_capabilities_are_refused(self):
        with TestClient(self.make()) as client:
            for changed in ({'origin':'https://example.invalid'},{'x-remote-token':'x'*64},{'x-remote-room':'A'*32},{'x-remote-role':'server'},
                            {'x-remote-channel':'audio'},{'x-remote-extra':'unexpected'}):
                with self.subTest(changed=tuple(changed)):
                    self.assert_refused(client,headers={**headers(),**changed})
            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect(URL+'?token='+TOKEN,headers=headers()):pass

    def test_missing_and_duplicate_capability_headers_are_refused(self):
        with TestClient(self.make()) as client:
            for name in headers():
                changed=headers();del changed[name];self.assert_refused(client,headers=changed)
            duplicated=Headers(list(headers().items())+[('x-remote-role','viewer')])
            self.assert_refused(client,headers=duplicated)

    def test_text_and_oversized_messages_disconnect_the_pair(self):
        for text in (True,False):
            with self.subTest(text=text),TestClient(self.make(packet_bytes=32)) as client:
                with client.websocket_connect(URL,headers=headers()) as host:
                    with client.websocket_connect(URL,headers=headers('viewer')) as viewer:
                        self.assertEqual(host.receive_bytes(),READY);self.assertEqual(viewer.receive_bytes(),READY)
                        if text:viewer.send_text('plaintext refused')
                        else:viewer.send_bytes(b'x'*33)
                        with self.assertRaises(WebSocketDisconnect):viewer.receive_bytes()
                        with self.assertRaises(WebSocketDisconnect):host.receive_bytes()

    def test_peer_disconnect_closes_counterpart_and_cleans_room(self):
        app=self.make()
        with TestClient(app) as client:
            with client.websocket_connect(URL,headers=headers()) as host:
                with client.websocket_connect(URL,headers=headers('viewer')) as viewer:
                    self.assertEqual(host.receive_bytes(),READY);self.assertEqual(viewer.receive_bytes(),READY)
                with self.assertRaises(WebSocketDisconnect):host.receive_bytes()
            self.assertFalse(app.state.registry.rooms)

    def test_unpaired_registration_times_out_without_leaking_capacity(self):
        app=self.make()
        with TestClient(app) as client:
            start=time.monotonic()
            self.assert_refused(client)
            self.assertLess(time.monotonic()-start,3)
            self.assertFalse(app.state.registry.rooms)
            self.assertFalse(app.state.registry.connections)

    def test_room_and_connection_limits(self):
        with TestClient(self.make(rooms=1)) as client:
            with client.websocket_connect(URL,headers=headers()):
                self.assert_refused(client,headers=headers(room='2'*32))
        with TestClient(self.make(connections_per_ip=1)) as client:
            with client.websocket_connect(URL,headers=headers()):
                self.assert_refused(client,headers=headers(channel='input'))

    def test_active_room_limit_does_not_evict_existing_pair(self):
        with TestClient(self.make(active_rooms=1)) as client:
            with client.websocket_connect(URL,headers=headers()) as host:
                with client.websocket_connect(URL,headers=headers('viewer')) as viewer:
                    host.receive_bytes();viewer.receive_bytes()
                    with client.websocket_connect(URL,headers=headers(room='2'*32)):
                        self.assert_refused(client,headers=headers('viewer',room='2'*32))
                    host.send_bytes(b'still paired');self.assertEqual(viewer.receive_bytes(),b'still paired')

    def test_lifetime_is_bounded_and_capabilities_are_not_logged(self):
        app=self.make(lifetime_seconds=.2)
        with self.assertNoLogs('relay'),TestClient(app) as client:
            with client.websocket_connect(URL,headers=headers()) as host:
                with client.websocket_connect(URL,headers=headers('viewer')) as viewer:
                    host.receive_bytes();viewer.receive_bytes()
                    with self.assertRaises(WebSocketDisconnect):host.receive_bytes()
            self.assertFalse(app.state.registry.rooms)


class RegistryTests(unittest.IsolatedAsyncioTestCase):
    def fake_socket(self,role='host',room=ROOM):
        values=StarletteHeaders(headers(role=role,room=room))
        return SimpleNamespace(headers=values,url=SimpleNamespace(query=''),scope={'headers':values.raw})

    async def test_simultaneous_host_registration_cannot_replace_the_owner(self):
        registry=Registry(Limits())
        results=await asyncio.gather(registry.join(self.fake_socket(),'192.0.2.1'),registry.join(self.fake_socket(),'192.0.2.1'),return_exceptions=True)
        peers=[result for result in results if not isinstance(result,Exception)]
        self.assertEqual(len(peers),1)
        self.assertEqual(sum(isinstance(result,Refused) for result in results),1)
        viewer=await registry.join(self.fake_socket('viewer'),'192.0.2.2')
        self.assertIs(peers[0].mate,viewer)
        await registry.leave(peers[0]);await registry.leave(viewer);await registry.leave(viewer)
        self.assertFalse(registry.rooms);self.assertFalse(registry.connections)

    async def test_repeated_create_remove_cycles_release_every_room_and_connection(self):
        registry=Registry(Limits())
        for iteration in range(120):
            peer=await registry.join(self.fake_socket(room=format(iteration,'032x')),'192.0.2.'+str(iteration%8+1))
            await registry.leave(peer)
            self.assertFalse(registry.rooms);self.assertFalse(registry.connections)
        self.assertLessEqual(len(registry.attempts),8)

    async def test_forwarded_addresses_are_trusted_only_from_loopback(self):
        for peer,forwarded,expected in (('198.51.100.4','192.0.2.9','198.51.100.4'),('127.0.0.1','192.0.2.9','192.0.2.9'),
                                        ('127.0.0.1','192.0.2.9, 198.51.100.4','127.0.0.1'),('::1','2001:db8::1','2001:db8::1')):
            socket=SimpleNamespace(client=SimpleNamespace(host=peer),headers={'x-forwarded-for':forwarded})
            self.assertEqual(client_ip(socket),expected)

    async def test_attempt_buckets_are_bounded(self):
        registry=Registry(replace(Limits(),tracked_ips=2,attempts_per_minute=2))
        registry._attempt('192.0.2.1',100);registry._attempt('192.0.2.1',101)
        with self.assertRaises(Refused):registry._attempt('192.0.2.1',102)
        registry._attempt('192.0.2.2',103)
        with self.assertRaises(Refused):registry._attempt('192.0.2.3',104)
        registry._attempt('192.0.2.3',200)
        self.assertEqual(len(registry.attempts),1)

    async def test_video_budget_does_not_delay_input_budget(self):
        from relay import Peer,Room
        registry=Registry(replace(Limits(),video_bytes_per_second=100,input_bytes_per_second=100000))
        room=Room(ROOM,b'fake',time.monotonic()+60)
        video=Peer(None,'test','host','video',room)
        control=Peer(None,'test','viewer','input',room)
        await registry.bandwidth(video,100)
        start=time.monotonic();await registry.bandwidth(control,10)
        self.assertLess(time.monotonic()-start,.1)
        self.assertGreater(room.next_video-room.next_input,.5)


if __name__=='__main__':unittest.main()
