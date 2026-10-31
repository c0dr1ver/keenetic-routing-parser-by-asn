import socket
import unittest

import asn_routes
from asn_routes import IRRdResponse, NetworkQueryError, ProgressReporter, RISWhoisClient


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeSocket:
    TIMEOUT = object()

    def __init__(self, events, clock=None, timeout_advance=0.1):
        self.events = list(events)
        self.buffer = b""
        self.clock = clock
        self.timeout_advance = timeout_advance

    def recv(self, size):
        if not self.buffer:
            if not self.events:
                return b""
            event = self.events.pop(0)
            if event is self.TIMEOUT:
                if self.clock is not None:
                    self.clock.advance(self.timeout_advance)
                raise socket.timeout()
            self.buffer = event
        result = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return result

    def close(self):
        pass


class IRRdParserTests(unittest.TestCase):
    def client_for(self, events, clock=None):
        progress = ProgressReporter()
        client = RISWhoisClient("example.test", 43, progress=progress, time_func=clock or (lambda: 0.0))
        client.sock = FakeSocket(events, clock)
        return client

    def read_response(self, client):
        return client._read_irrd_response(
            asn=123,
            current=1,
            total=1,
            query_started_at=0.0,
            label="test",
        )

    def test_fragmented_a_response(self):
        client = self.client_for([b"A11\n", b"1.0.", b"0.0/24 ", b"C\n"])
        response = self.read_response(client)
        self.assertEqual(response, IRRdResponse("A", payload=b"1.0.0.0/24 "))

    def test_empty_success_response(self):
        client = self.client_for([b"C\n"])
        self.assertEqual(self.read_response(client).kind, "C")

    def test_absent_response(self):
        client = self.client_for([b"D\n"])
        self.assertEqual(self.read_response(client).kind, "D")

    def test_error_response(self):
        client = self.client_for([b"F bad query\n"])
        response = self.read_response(client)
        self.assertEqual(response.kind, "F")
        self.assertEqual(response.message, "bad query")

    def test_premature_eof(self):
        client = self.client_for([b"A12\n", b"1.0.0"])
        with self.assertRaises(NetworkQueryError):
            self.read_response(client)

    def test_poll_timeout_is_not_final_before_query_timeout(self):
        clock = Clock()
        client = self.client_for([FakeSocket.TIMEOUT, FakeSocket.TIMEOUT, b"C\n"], clock=clock)
        self.assertEqual(self.read_response(client).kind, "C")

    def test_query_timeout_eventually_fails(self):
        old_timeout = asn_routes.QUERY_TIMEOUT
        asn_routes.QUERY_TIMEOUT = 0.25
        try:
            clock = Clock()
            client = self.client_for(
                [FakeSocket.TIMEOUT, FakeSocket.TIMEOUT, FakeSocket.TIMEOUT, FakeSocket.TIMEOUT],
                clock=clock,
            )
            with self.assertRaises(NetworkQueryError):
                self.read_response(client)
        finally:
            asn_routes.QUERY_TIMEOUT = old_timeout


if __name__ == "__main__":
    unittest.main()
