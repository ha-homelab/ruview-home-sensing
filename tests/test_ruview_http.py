import gzip
import unittest
import zlib

from ruview_http import decode_http_body


class DecodeHttpBodyTests(unittest.TestCase):
    def test_identity_preserves_exact_bytes_at_limit(self):
        raw = b' {"value": 1}\n\x00'
        for encoding in (None, "", "identity", " IDENTITY "):
            with self.subTest(encoding=encoding):
                self.assertIs(decode_http_body(raw, encoding, len(raw)), raw)
        self.assertEqual(decode_http_body(b"", None, 0), b"")

    def test_wire_size_is_bounded_for_both_encodings(self):
        for raw, encoding in ((b"abc", None), (gzip.compress(b""), "gzip")):
            with self.subTest(encoding=encoding):
                with self.assertRaisesRegex(ValueError, "^document_too_large$"):
                    decode_http_body(raw, encoding, len(raw) - 1)

    def test_gzip_preserves_exact_bytes_and_accepts_empty_member(self):
        raw = b'  {"value": 1, "text": "unchanged"}\n' * 10
        self.assertEqual(decode_http_body(gzip.compress(raw), " GZIP ", 1024), raw)
        self.assertEqual(decode_http_body(gzip.compress(b""), "gzip", 64), b"")

    def test_decoded_size_at_limit_and_one_byte_over(self):
        self.assertEqual(
            decode_http_body(gzip.compress(b"x" * 512), "gzip", 512), b"x" * 512
        )
        with self.assertRaisesRegex(ValueError, "^document_too_large$"):
            decode_http_body(gzip.compress(b"x" * 513), "gzip", 512)

    def test_small_compressed_bomb_is_rejected_at_output_limit(self):
        raw = gzip.compress(b"x" * (1024 * 1024))
        self.assertLess(len(raw), 2048)
        with self.assertRaisesRegex(ValueError, "^document_too_large$"):
            decode_http_body(raw, "gzip", 2048)

    def test_rejects_malformed_truncated_and_non_gzip_data(self):
        member = gzip.compress(b"valid body")
        invalid = [b"", b"not gzip", zlib.compress(b"body")]
        invalid.extend(member[:-removed] for removed in (1, 4, 8, len(member) - 1))
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, "^invalid_gzip_body$"):
                    decode_http_body(raw, "gzip", 1024)

    def test_rejects_wrong_crc_and_size_trailer(self):
        for offset in (-8, -4):
            raw = bytearray(gzip.compress(b"valid body"))
            raw[offset] ^= 1
            with self.subTest(offset=offset):
                with self.assertRaisesRegex(ValueError, "^invalid_gzip_body$"):
                    decode_http_body(bytes(raw), "gzip", 1024)

    def test_rejects_concatenated_members_and_trailing_bytes(self):
        member = gzip.compress(b"body")
        for suffix in (gzip.compress(b"second"), gzip.compress(b""), b"\x00", b"junk"):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(ValueError, "^invalid_gzip_body$"):
                    decode_http_body(member + suffix, "gzip", 1024)

    def test_rejects_unsupported_or_stacked_content_encodings(self):
        for encoding in ("br", "deflate", "gzip, gzip", "identity, gzip", "x-gzip", 1):
            with self.subTest(encoding=encoding):
                with self.assertRaisesRegex(
                    ValueError, "^unsupported_content_encoding$"
                ):
                    decode_http_body(b"data", encoding, 1024)

    def test_rejects_invalid_limits(self):
        for limit in (-1, True, 1.5, None):
            with self.subTest(limit=limit):
                with self.assertRaisesRegex(ValueError, "^invalid_body_limit$"):
                    decode_http_body(b"", None, limit)


if __name__ == "__main__":
    unittest.main()
