import asyncio
import json
import sys
import tempfile
import unittest
from functools import partial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import honeypot  # noqa: E402


class HoneypotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        honeypot.FAIL_DELAY = 0
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = Path(self.tmp.name) / "events.jsonl"
        self.logger = honeypot.EventLogger(self.log_path)
        limiter = asyncio.Semaphore(10)
        self.telnet = await asyncio.start_server(
            partial(honeypot.handle_telnet, logger=self.logger, limiter=limiter),
            "127.0.0.1", 0, limit=1024)
        self.http = await asyncio.start_server(
            partial(honeypot.handle_http, logger=self.logger, limiter=limiter),
            "127.0.0.1", 0, limit=1024)

    async def asyncTearDown(self):
        self.telnet.close()
        self.http.close()
        await self.telnet.wait_closed()
        await self.http.wait_closed()
        self.tmp.cleanup()

    def events(self):
        return [json.loads(x) for x in self.log_path.read_text().splitlines()]

    async def test_telnet_captures_credentials_and_always_fails(self):
        port = self.telnet.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.readuntil(b"login: ")
        writer.write(b"root\r\n")
        await reader.readuntil(b"Password: ")
        writer.write(b"toor\r\n")
        self.assertIn(b"Login incorrect", await reader.readuntil(b"incorrect\r\n"))
        writer.close()
        attempts = [e for e in self.events() if e["event"] == "login_attempt"]
        self.assertEqual((attempts[0]["username"], attempts[0]["password"]), ("root", "toor"))

    async def test_http_post_captured_and_rejected(self):
        port = self.http.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        body = b"username=admin&password=pass123"
        writer.write(b"POST /login HTTP/1.1\r\nUser-Agent: test\r\n"
                     b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        await writer.drain()
        response = await reader.read()
        writer.close()
        self.assertIn(b"401 Unauthorized", response)
        attempts = [e for e in self.events() if e["event"] == "login_attempt"]
        self.assertEqual(attempts[0]["password"], "pass123")

    def test_clean_strips_control_chars_and_caps_length(self):
        self.assertEqual(honeypot.clean("a\x00b\x1b[31m"), "ab[31m")
        self.assertEqual(len(honeypot.clean("x" * 1000)), honeypot.MAX_FIELD)


if __name__ == "__main__":
    unittest.main()
