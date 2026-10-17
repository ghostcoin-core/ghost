#!/usr/bin/env python3
"""Serve the benchmark page cross-origin isolated (standard library only).

Cross-origin isolation (COOP same-origin plus COEP require-corp) is what
gives the page SharedArrayBuffer and so WebAssembly threads. Caching is off
so every session loads the module afresh.

    python3 benchmarks/web/serve.py [--port 8000]

then open http://localhost:8000/ in a fresh browser profile.
"""

import argparse
import functools
import http.server
from pathlib import Path

HERE = Path(__file__).resolve().parent


class IsolatedHandler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript",
        ".mjs": "text/javascript",
        ".wasm": "application/wasm",
        ".json": "application/json",
    }

    def end_headers(self):
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def main():
    ap = argparse.ArgumentParser(description="Serve the benchmark page cross-origin isolated.")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--bind", default="127.0.0.1")
    args = ap.parse_args()
    if not (HERE / "pkg" / "ghost_bench_wasm.js").exists():
        print("note: web/pkg is missing; build it with: benchmarks/run.sh --web")
    handler = functools.partial(IsolatedHandler, directory=str(HERE))
    with http.server.ThreadingHTTPServer((args.bind, args.port), handler) as server:
        print(f"serving {HERE} at http://localhost:{args.port}/ (cross-origin isolated)")
        server.serve_forever()


if __name__ == "__main__":
    main()
