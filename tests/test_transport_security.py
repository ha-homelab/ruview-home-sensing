# SPDX-License-Identifier: MIT
"""Synthetic real TLS handshakes and client wiring; no network or live keys."""

import datetime
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.request import HTTPSHandler

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ruview_home_assistant.bridge import Bridge, configure_mqtt
from ruview_home_assistant.config import Config

from scripts.transport_security import client_context


def certificate(name, key, parent, parent_key, *, ca):
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(parent.subject if parent else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                (parent_key or key).public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=not ca,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("synthetic.test")]),
            critical=False,
        )
    return builder.sign(parent_key or key, hashes.SHA256())


def handshake(client, server, *, hostname="synthetic.test"):
    cin, cout, sin, sout = (ssl.MemoryBIO() for _ in range(4))
    peers = [
        client.wrap_bio(cin, cout, server_hostname=hostname),
        server.wrap_bio(sin, sout, server_side=True),
    ]
    done = [False, False]
    for _ in range(100):
        for i, peer in enumerate(peers):
            if not done[i]:
                try:
                    peer.do_handshake()
                    done[i] = True
                except ssl.SSLWantReadError:
                    # MemoryBIO needs peer bytes; the transfer below resumes the handshake.
                    pass
        for source, target in [(cout, sin), (sout, cin)]:
            data = source.read()
            if data:
                target.write(data)
        if all(done):
            return peers[0].version()
    raise AssertionError("TLS handshake did not finish")


class StrictTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.strong = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cls.weak = rsa.generate_private_key(public_exponent=65537, key_size=2047)

    def contexts(self, directory, weak_part, version):
        keys = [
            self.weak if part == weak_part else self.strong
            for part in ("root", "intermediate", "leaf")
        ]
        root = certificate("root", keys[0], None, None, ca=True)
        intermediate = certificate("intermediate", keys[1], root, keys[0], ca=True)
        leaf = certificate("synthetic.test", keys[2], intermediate, keys[1], ca=False)
        rootfile, chainfile, keyfile = [
            Path(directory) / x for x in ("root.pem", "chain.pem", "key.pem")
        ]
        rootfile.write_bytes(root.public_bytes(serialization.Encoding.PEM))
        chainfile.write_bytes(
            leaf.public_bytes(serialization.Encoding.PEM)
            + intermediate.public_bytes(serialization.Encoding.PEM)
        )
        keyfile.touch(mode=0o600)
        keyfile.write_bytes(
            keys[2].private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.set_ciphers("DEFAULT:@SECLEVEL=0")  # Synthetic weak test peer only.
        server.minimum_version = server.maximum_version = version
        server.load_cert_chain(chainfile, keyfile)
        return client_context(strict=True, cafile=rootfile), server

    def test_real_tls_accepts_strong_chain_and_rejects_every_weak_position(self):
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            for weak_part in (None, "root", "intermediate", "leaf"):
                with (
                    self.subTest(version=version, weak_part=weak_part),
                    tempfile.TemporaryDirectory() as d,
                ):
                    client, server = self.contexts(d, weak_part, version)
                    if weak_part:
                        with self.assertRaisesRegex(
                            ssl.SSLCertVerificationError, "key too weak"
                        ):
                            handshake(client, server)
                    else:
                        self.assertEqual(
                            handshake(client, server), version.name.replace("_", ".")
                        )

    def test_verifies_hostname_and_trust(self):
        with tempfile.TemporaryDirectory() as d:
            client, server = self.contexts(d, None, ssl.TLSVersion.TLSv1_3)
            with self.assertRaises(ssl.SSLCertVerificationError):
                handshake(client, server, hostname="wrong.test")
            with self.assertRaises(ssl.SSLCertVerificationError):
                handshake(client_context(strict=True), server)

    def test_stronger_platform_policy_is_preserved(self):
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=4")
        with patch(
            "scripts.transport_security.ssl.create_default_context",
            return_value=context,
        ):
            actual = client_context(strict=True)
        self.assertEqual(actual.security_level, 4)
        self.assertEqual(actual.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(
            [x["name"] for x in actual.get_ciphers() if x["protocol"] != "TLSv1.3"],
            ["ECDHE-RSA-AES256-GCM-SHA384"],
        )

    def test_strict_configuration_rejects_plaintext_and_invalid_values(self):
        good = dict(
            upstream_url="https://synthetic.test", mqtt_tls=True, strict_tls=True
        )
        Config(**good)
        for change in [
            dict(upstream_url="http://synthetic.test"),
            dict(mqtt_tls=False),
            dict(modules_url="http://synthetic.test"),
            dict(websocket_url="ws://synthetic.test"),
            dict(strict_tls="true"),
        ]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                Config(**(good | change))
        configured = Config.from_env(
            {
                "RUVIEW_URL": "https://synthetic.test",
                "MQTT_TLS": "true",
                "RUVIEW_STRICT_TLS": "true",
            }
        )
        self.assertTrue(configured.strict_tls)

    def test_http_wss_and_mqtt_receive_the_strict_context(self):
        config = Config(
            upstream_url="https://synthetic.test",
            modules_url="https://synthetic.test",
            websocket_url="wss://synthetic.test",
            mqtt_tls=True,
            strict_tls=True,
        )
        with patch(
            "ruview_home_assistant.bridge.urllib.request.build_opener"
        ) as opener:
            bridge = Bridge(Mock(), config)
            bridge.stopped.set()
            bridge.listen_modules()
        self.assertEqual(opener.call_count, 2)
        for call in opener.call_args_list:
            context = next(h._context for h in call.args if isinstance(h, HTTPSHandler))
            self.assertGreaterEqual(context.security_level, 3)
            self.assertTrue(context.check_hostname)
        client = Mock()
        configure_mqtt(client, config)
        self.assertGreaterEqual(
            client.tls_set_context.call_args.args[0].security_level, 3
        )
        bridge.stopped.clear()
        captured = {}

        def connect(*args, **kwargs):
            captured.update(kwargs)
            bridge.stopped.set()
            raise ValueError("synthetic stop before any socket")

        with patch("websockets.sync.client.connect", side_effect=connect):
            bridge.listen_falls()
        self.assertGreaterEqual(captured["ssl"].security_level, 3)
        self.assertTrue(captured["ssl"].check_hostname)
