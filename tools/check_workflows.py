"""Check the public workflow trust boundary without executing workflow contents."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLKIT = "21a366f200f0371a10a6de7ad6ca263af230b842"


def main():
    errors = []
    for path in sorted((ROOT / ".github/workflows").glob("*.yml")):
        text = path.read_text()
        for number, line in enumerate(text.splitlines(), 1):
            value = line.strip()
            if value.startswith("runs-on:") and value.split(":", 1)[1].strip() not in {
                "ubuntu-24.04",
                "ubuntu-24.04-arm",
                "ubuntu-latest",
            }:
                errors.append(
                    f"{path.name}:{number}: runner must be a literal hosted image"
                )
            match = re.search(r"(?:^|\s)uses:\s*(\S+)", line)
            if match and not match[1].startswith("./"):
                if not re.fullmatch(r"[^@]+@[0-9a-f]{40}", match[1]):
                    errors.append(
                        f"{path.name}:{number}: action must use an immutable commit"
                    )
                if "venus-os-ci-toolkit/" in match[1] and not match[1].endswith(
                    "@" + TOOLKIT
                ):
                    errors.append(
                        f"{path.name}:{number}: shared toolkit revisions differ"
                    )
            if "secrets: inherit" in value or "pull_request_target:" in value:
                errors.append(
                    f"{path.name}:{number}: public code validation must not inherit secrets or use privileged PR events"
                )
    if errors:
        raise SystemExit("\n".join(errors))
    print("Public workflow runner, action pin and token boundaries passed.")


if __name__ == "__main__":
    main()
