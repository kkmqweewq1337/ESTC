#!/usr/bin/env python3
import http.server
import os
from functools import partial

PORT = int(os.environ.get("MAP_PORT", "8085"))
DIRECTORY = os.environ.get("MAP_OUTPUT_DIR", "/opt/network_map")


class NoCacheHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        super().end_headers()

    def log_message(self, fmt, *args):
        print(f"[{self.log_date_time_string()}] {fmt % args}")


if __name__ == "__main__":
    handler = partial(NoCacheHandler, directory=DIRECTORY)
    with http.server.ThreadingHTTPServer(("", PORT), handler) as httpd:
        print(f" Serving maps on http://0.0.0.0:{PORT}")
        print(f" Directory: {DIRECTORY}")
        print(f" Cache: DISABLED")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n Server stopped")
