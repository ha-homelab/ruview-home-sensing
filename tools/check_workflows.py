"""Check the public workflow trust boundary without executing workflow contents."""

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLKIT = "e71559f44e41f39ad0037bf13c7f43bbbb2ec9af"
# Composite actions retain their independently pinned implementation.
TOOLKIT_ACTIONS = "21a366f200f0371a10a6de7ad6ca263af230b842"
# These reviewed callers execute only pinned toolkit metadata logic on hosted
# runners. Any byte change needs independent review and an intentional pin update;
# neither a filename alone nor a privileged event grants an exemption.
METADATA_CALLERS = {
    "auto-approve.yml": "aa151712c0d7beb52f1653de9bfebf0ed1c3d48816aaf062d2184d1fdc9ef393",
    "auto-merge.yml": "4dac083a835091c037ebf6ce526169b67e9d5c1a6f53278462e22e9a3e8facf1",
}


def workflow_errors(name, raw):
    errors = []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return [f"{name}: workflow must be UTF-8"]
    expected = METADATA_CALLERS.get(name)
    reviewed_metadata = (
        expected is not None and hashlib.sha256(raw).hexdigest() == expected
    )
    if expected is not None and not reviewed_metadata:
        errors.append(
            f"{name}: metadata caller differs from independently reviewed bytes"
        )
    for number, line in enumerate(text.splitlines(), 1):
        value = line.strip()
        if value.startswith("runs-on:") and value.split(":", 1)[1].strip() not in {
            "ubuntu-24.04",
            "ubuntu-24.04-arm",
            "ubuntu-latest",
        }:
            errors.append(f"{name}:{number}: runner must be a literal hosted image")
        match = re.search(r"(?:^|\s)uses:\s*(\S+)", line)
        if match and not match[1].startswith("./"):
            if not re.fullmatch(r"[^@]+@[0-9a-f]{40}", match[1]):
                errors.append(f"{name}:{number}: action must use an immutable commit")
            if "venus-os-ci-toolkit/" in match[1]:
                expected_pin = (
                    TOOLKIT_ACTIONS
                    if "/venus-os-ci-toolkit/actions/" in match[1]
                    else TOOLKIT
                )
                if not match[1].endswith("@" + expected_pin):
                    errors.append(f"{name}:{number}: shared toolkit revisions differ")
        if re.search(
            r"(?:^|[\s,{])['\"]?secrets['\"]?\s*:\s*['\"]?inherit['\"]?(?=\s|[,}]|$)",
            value,
        ):
            errors.append(f"{name}:{number}: workflows must not inherit secrets")
        if "pull_request_target" in value.split("#", 1)[0] and not reviewed_metadata:
            errors.append(
                f"{name}:{number}: privileged PR events require an exact reviewed metadata caller"
            )
    return errors


def main():
    directory = ROOT / ".github/workflows"
    paths = sorted((*directory.glob("*.yml"), *directory.glob("*.yaml")))
    errors = [
        error
        for path in paths
        for error in workflow_errors(path.name, path.read_bytes())
    ]
    if errors:
        raise SystemExit("\n".join(errors))
    print("Public workflow runner, action pin and token boundaries passed.")


if __name__ == "__main__":
    main()
