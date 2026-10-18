"""Extract pinned Ubuntu CAD libraries into job scratch without system writes."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import platform
import re
import subprocess
import urllib.request
from pathlib import Path

LOCK = Path(__file__).with_name("native-runtime.lock.json")
ARCHIVE_PREFIX = "https://archive.ubuntu.com/ubuntu/pool/"


def read_lock(path: Path) -> list[dict]:
    document = json.loads(path.read_text())
    if (
        document.get("schema") != "ruview.cad-native-runtime.v1"
        or document.get("platform") != "ubuntu-24.04-amd64"
    ):
        raise ValueError("Unsupported native CAD lock")
    packages = document["packages"]
    if not isinstance(packages, list) or not 1 <= len(packages) <= 20:
        raise ValueError("Expected a bounded native CAD package list")
    seen = set()
    for package in packages:
        name = package["name"]
        url = package["url"]
        if (
            not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name)
            or name in seen
            or package["architecture"] not in {"amd64", "all"}
            or not url.startswith(ARCHIVE_PREFIX)
            or not re.fullmatch(r"[a-zA-Z0-9+._/-]+\.deb", url[len(ARCHIVE_PREFIX) :])
            or "/../" in url
            or not re.fullmatch(r"[a-f0-9]{64}", package["sha256"])
            or type(package["size"]) is not int
            or not 0 < package["size"] <= 10 * 1024 * 1024
        ):
            raise ValueError("Invalid locked native CAD package")
        seen.add(name)
    return packages


def download(package: dict, destination: Path) -> None:
    request = urllib.request.Request(
        package["url"], headers={"User-Agent": "ruview-cad-native-runtime/1"}
    )
    digest = hashlib.sha256()
    count = 0
    with urllib.request.urlopen(request, timeout=60) as response:
        if not response.geturl().startswith(ARCHIVE_PREFIX):
            raise ValueError("Native CAD archive redirected outside Ubuntu archive")
        with destination.open("xb") as output:
            while chunk := response.read(min(65536, package["size"] + 1 - count)):
                count += len(chunk)
                if count > package["size"]:
                    raise ValueError("Native CAD archive exceeds locked size")
                digest.update(chunk)
                output.write(chunk)
    if count != package["size"] or digest.hexdigest() != package["sha256"]:
        raise ValueError("Native CAD archive does not match its lock")


def provision(output: Path, packages: list[dict]) -> dict[str, str]:
    output = output.resolve()
    if any(character in str(output) for character in "\r\n"):
        raise ValueError("Invalid native CAD output path")
    output.mkdir(parents=True, exist_ok=False)
    archives = output / "archives"
    archives.mkdir()
    # Verify every archive before any library is extracted. dpkg-deb --extract
    # does not run package maintainer scripts or update the system package DB.
    for package in packages:
        download(package, archives / f"{package['name']}.deb")
    sysroot = output / "sysroot"
    sysroot.mkdir()
    for package in packages:
        subprocess.run(
            [
                "dpkg-deb",
                "--extract",
                str(archives / f"{package['name']}.deb"),
                str(sysroot),
            ],
            check=True,
        )
    fonts = sysroot / "usr/share/fonts/truetype/dejavu"
    if not (fonts / "DejaVuSans.ttf").is_file():
        raise ValueError("Locked CAD font is missing")
    cache = output / "font-cache"
    cache.mkdir()
    config = output / "fonts.conf"
    config.write_text(
        '<?xml version="1.0"?>\n<fontconfig>\n'
        f"  <dir>{html.escape(str(fonts))}</dir>\n"
        f"  <cachedir>{html.escape(str(cache))}</cachedir>\n"
        "  <alias><family>Arial</family><prefer><family>DejaVu Sans</family>"
        "</prefer></alias>\n</fontconfig>\n"
    )
    libraries = str(sysroot / "usr/lib/x86_64-linux-gnu")
    previous = os.environ.get("LD_LIBRARY_PATH", "")
    if any(character in previous for character in "\r\n"):
        raise ValueError("Invalid existing library path")
    return {
        "LD_LIBRARY_PATH": libraries + (":" + previous if previous else ""),
        "FONTCONFIG_FILE": str(config),
        "FONTCONFIG_PATH": str(output),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        parser.error("The native CAD lock supports only Ubuntu 24.04 AMD64")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        parser.error("The native CAD lock supports only Ubuntu 24.04 AMD64")
    environment = provision(args.output, read_lock(LOCK))
    with args.github_env.open("a") as stream:
        for name, value in environment.items():
            stream.write(f"{name}={value}\n")
    print("Verified and extracted native CAD libraries and DejaVu fonts in job scratch")


if __name__ == "__main__":
    main()
