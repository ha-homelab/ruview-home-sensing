"""Exercise the actual IDF component downloader without external endpoints."""

import gzip
import importlib.metadata
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from idf_component_tools.errors import FetchingError
from idf_component_tools.sources.web_service import download_file


class DownloadTests(unittest.TestCase):
    def test_component_download_encodings(self):
        payload = b"fixed public component fixture"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                layers = 6 if self.path == "/excess.tar.gz" else 1
                body = payload
                for _ in range(layers):
                    body = gzip.compress(body)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Encoding", ", ".join(["gzip"] * layers))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                base = f"http://127.0.0.1:{server.server_port}"
                result = download_file(f"{base}/ordinary.tar.gz", directory)
                self.assertEqual(Path(result).read_bytes(), payload)
                with self.assertRaisesRegex(
                    FetchingError, "Too many content encodings"
                ):
                    download_file(f"{base}/excess.tar.gz", directory)
                self.assertFalse((Path(directory) / "excess.tar.gz").exists())
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    print(
        json.dumps(
            {
                name: importlib.metadata.version(name)
                for name in ("urllib3", "requests", "idf-component-manager")
            },
            sort_keys=True,
        ),
        flush=True,
    )
    unittest.main()
