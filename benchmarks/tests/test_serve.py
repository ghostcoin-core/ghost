"""The page server sends the headers that make the page cross-origin isolated."""

import functools
import http.server
import sys
import threading
import unittest
import urllib.request
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "web"
sys.path.insert(0, str(WEB))

import serve  # noqa: E402


class ServeHeaders(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class Quiet(serve.IsolatedHandler):
            def log_message(self, *args):
                pass

        handler = functools.partial(Quiet, directory=str(WEB))
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def get(self, path):
        with urllib.request.urlopen(self.base + path) as resp:
            return resp.headers, resp.read()

    def test_page_is_cross_origin_isolated_and_uncached(self):
        headers, body = self.get("/index.html")
        self.assertEqual(headers["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertEqual(headers["Cross-Origin-Embedder-Policy"], "require-corp")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn(b'src="main.js"', body)

    def test_reveal_page_loads_its_own_worker(self):
        _, body = self.get("/reveal.html")
        self.assertIn(b'src="reveal-main.js"', body)
        _, main = self.get("/reveal-main.js")
        self.assertIn(b"./reveal-worker.js", main)
        headers, worker = self.get("/reveal-worker.js")
        self.assertEqual(headers["Content-Type"], "text/javascript")
        self.assertIn(b"reveal-pkg/ghost_reveal_bench.wasm", worker)

    def test_scripts_and_modules_have_the_right_types(self):
        headers, _ = self.get("/worker.js")
        self.assertEqual(headers["Content-Type"], "text/javascript")
        self.assertEqual(serve.IsolatedHandler.extensions_map[".wasm"], "application/wasm")


if __name__ == "__main__":
    unittest.main()
