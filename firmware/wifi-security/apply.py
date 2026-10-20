#!/usr/bin/env python3
"""Apply the cipher policy only to the pinned ESP-IDF 5.4.4 supplicant source."""

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = Path("components/wpa_supplicant/src/rsn_supp/wpa.c")
ENTRY = "int wpa_set_bss(char *macddr, char * bssid, u8 pairwise_cipher, u8 group_cipher, char *passphrase, u8 *ssid, size_t ssid_len)"
PREFIX = ENTRY + "\n{\n    int res = 0;\n    struct wpa_sm *sm = &gWpaSm;\n"
GUARD = """#if !defined(CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY) || !CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY
    /* Before PMK/cache/nonce processing: reject weak pairwise AND group ciphers. */
    if (!home_wifi_security_allowed(sm->proto, pairwise_cipher, group_cipher)) {
        wpa_printf(MSG_ERROR, "RuView requires RSN with AES pairwise and group ciphers");
        return -1;
    }
#endif
"""


def patched_source(raw):
    lock = json.loads((ROOT / "source.json").read_text())
    if hashlib.sha256(raw).hexdigest() != lock["source_sha256"]:
        raise ValueError("Unexpected ESP-IDF WPA source; refusing an unreviewed patch")
    text = raw.decode()
    if text.count(PREFIX) != 1:
        raise ValueError("Unexpected WPA entrypoint")
    policy = (ROOT / "policy.c.inc").read_text()
    policy = (
        '#include "sdkconfig.h"\n#include "esp_wifi_types.h"\n'
        "#if !defined(CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY) || !CONFIG_HOME_WIFI_ALLOW_LEGACY_SECURITY\n"
        + policy
        + "#endif\n\n"
    )
    return text.replace(PREFIX, policy + PREFIX + GUARD).encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("idf", type=Path)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    path = args.idf / SOURCE
    original = path.read_bytes()
    result = patched_source(original)
    path.write_bytes(result)
    receipt = json.loads((ROOT / "source.json").read_text())
    receipt["patched_sha256"] = hashlib.sha256(result).hexdigest()
    receipt["policy_sha256"] = hashlib.sha256(
        (ROOT / "policy.c.inc").read_bytes()
    ).hexdigest()
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n")
    print("Applied pinned ESP-IDF pre-handshake cipher policy")


if __name__ == "__main__":
    main()
