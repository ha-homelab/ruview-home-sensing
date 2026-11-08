"""Check the public workflow trust boundary without executing workflow contents."""

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLKIT = "e71559f44e41f39ad0037bf13c7f43bbbb2ec9af"
MERGE_TOOLKIT = "0047a13b5eb79dfa770e31070a83e9696ddd36d1"
# Composite actions retain their independently pinned implementation.
TOOLKIT_ACTIONS = "21a366f200f0371a10a6de7ad6ca263af230b842"
# These reviewed callers execute only pinned toolkit metadata logic on hosted
# runners. Any byte change needs independent review and an intentional pin update;
# neither a filename alone nor a privileged event grants an exemption.
METADATA_CALLERS = {
    "auto-approve.yml": "dab9f06330ea8cdae34ae96c8b73a51f7088e5c4c32e1a26c8271cd31c0a5a20",
    "auto-merge.yml": "6c8352990277461de22f6d12e454ccdf9ff058c1c5f801f75e0897d6e981dd0b",
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
                if (
                    name == "auto-merge.yml"
                    and reviewed_metadata
                    and match[1].startswith(
                        "victron-venus/venus-os-ci-toolkit/.github/workflows/auto-merge.yml@"
                    )
                ):
                    expected_pin = MERGE_TOOLKIT
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
