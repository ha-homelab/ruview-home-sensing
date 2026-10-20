"""Verified TLS for public downloads and optional encrypted service endpoints.

The context policy matches the pinned public bridge dependency. It uses only the
standard library so that source fetchers can run before runtime dependencies
are installed. No encryption algorithm or certificate verifier is implemented
here.
"""

import os
import ssl
import urllib.request
from urllib.parse import urlsplit


def enabled(name):
    value = os.environ.get(name, "false").lower()
    if value not in ("true", "false", "1", "0"):
        raise ValueError(f"{name} must be true, false, 1 or 0")
    return value in ("true", "1")


def client_context(*, strict=None, cafile=None):
    """Preserve trust/hostname checks, TLS 1.2 minimum and stronger host policy."""
    if strict is None:
        strict = enabled("RUVIEW_STRICT_TLS")
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = max(context.minimum_version, ssl.TLSVersion.TLSv1_2)
    if strict:
        if ssl.OPENSSL_VERSION_INFO < (3, 0, 0):
            raise RuntimeError("Strict TLS requires OpenSSL 3 or newer")
        if context.security_level < 3:
            suites = ":".join(
                cipher["name"]
                for cipher in context.get_ciphers()
                if cipher["protocol"] != "TLSv1.3"
            )
            context.set_ciphers(f"{suites}:@SECLEVEL=3")
    return context


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_opener(*handlers):
    """Credential-bearing requests never follow redirects or ambient proxies."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=client_context()),
        *(handlers or (NoRedirect(),)),
    )


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        if parsed.scheme != "https" or parsed.username or parsed.password:
            raise ValueError("Source download requires HTTPS without URL credentials")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_source(request, *, timeout):
    """Public source downloads may redirect only to verified HTTPS."""
    url = request.full_url if isinstance(request, urllib.request.Request) else request
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password:
        raise ValueError("Source download requires HTTPS without URL credentials")
    return http_opener(HTTPSRedirect()).open(request, timeout=timeout)


def websocket_options(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("ws", "wss") or parsed.username or parsed.password:
        raise ValueError("Expected WS/WSS without URL credentials")
    if enabled("RUVIEW_STRICT_TLS") and parsed.scheme != "wss":
        raise ValueError("Strict TLS requires a WSS endpoint")
    return {"ssl": client_context()} if parsed.scheme == "wss" else {}


def configure_mqtt_tls(client):
    if enabled("RUVIEW_STRICT_TLS") and not enabled("MQTT_TLS"):
        raise ValueError("Strict TLS requires MQTT_TLS")
    if enabled("MQTT_TLS"):
        context = client_context(cafile=os.environ.get("MQTT_CA_CERTS"))
        certfile = os.environ.get("MQTT_CERTFILE")
        keyfile = os.environ.get("MQTT_KEYFILE")
        if keyfile and not certfile:
            raise ValueError("MQTT client key requires a client certificate")
        if certfile:
            context.load_cert_chain(certfile, keyfile)
        client.tls_set_context(context)
