#!/usr/bin/env python3
"""Verify checkpoint files for the update-checkpoints skill.

Validates exactly the checkpoint files that are new or modified in the working
tree — i.e. what is about to be committed — under
Sources/ZcashLightClientKit/Resources/checkpoints/<network>. Run it after
fetch_checkpoints.py and before committing.

Per changed file it checks:
  - the filename is <height>.json
  - it parses as JSON and has keys: network, height, hash, time, saplingTree,
    orchardTree (a half-written / error-captured grpcurl output fails here)
  - network matches the directory ("main" for mainnet, "test" for testnet)
  - the height field equals the filename
  - height is a multiple of the network interval (no stray chain-tip file)
  - hash is 64 lowercase hex chars
  - time is a positive integer
  - saplingTree / orchardTree are non-empty, even-length, lowercase hex

Across a network's changed files it also checks:
  - every change is an ADDITION (a modified/deleted committed checkpoint is
    flagged — the grid is supposed to be append-only and the anchor immutable)
  - the new heights are a gap-free arithmetic sequence stepping by the interval
  - the lowest new height is exactly (committed max at HEAD + interval), so the
    grid was extended with no gap

Exit code: 0 = everything verified, 1 = problems found, 2 = setup error.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

NETWORKS = {
    "mainnet": {"interval": 2500, "network_value": "main"},
    "testnet": {"interval": 10000, "network_value": "test"},
}

CHECKPOINTS_REL = "Sources/ZcashLightClientKit/Resources/checkpoints"
HEX_RE = re.compile(r"^[0-9a-f]+$")


def repo_root() -> Path:
    out = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL)
    return Path(out.decode().strip())


def git_status_for(directory: Path):
    """Return list of (status, height, path) for *.json changes under `directory`."""
    out = subprocess.run(
        ["git", "status", "--porcelain", "--", str(directory)],
        capture_output=True,
        text=True,
    ).stdout
    changes = []
    for line in out.splitlines():
        if not line.strip():
            continue
        status = line[:2].strip()
        path_part = line[3:].strip().strip('"')
        if " -> " in path_part:  # rename
            path_part = path_part.split(" -> ")[-1]
        path = Path(path_part)
        if path.suffix == ".json" and path.stem.isdigit():
            changes.append((status, int(path.stem), repo_root() / path))
    return changes


def committed_max(directory: Path):
    """Highest committed checkpoint height at HEAD for `directory`, or None."""
    out = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "HEAD", "--", str(directory)],
        capture_output=True,
        text=True,
    ).stdout
    heights = []
    for line in out.splitlines():
        path = Path(line.strip().strip('"'))
        if path.suffix == ".json" and path.stem.isdigit():
            heights.append(int(path.stem))
    return max(heights) if heights else None


def validate_file(path: Path, height: int, network_value: str, interval: int, errors: list):
    name = path.name
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        errors.append(f"{name}: not valid JSON ({exc})")
        return

    for key in ("network", "height", "hash", "time", "saplingTree", "orchardTree"):
        if key not in data:
            errors.append(f"{name}: missing key '{key}'")

    if data.get("network") != network_value:
        errors.append(f"{name}: network is {data.get('network')!r}, expected {network_value!r}")

    if str(data.get("height")) != str(height):
        errors.append(f"{name}: height field {data.get('height')!r} does not match filename {height}")

    if height % interval != 0:
        errors.append(f"{name}: height {height} is not aligned to interval {interval}")

    h = data.get("hash")
    if not (isinstance(h, str) and len(h) == 64 and HEX_RE.match(h)):
        errors.append(f"{name}: hash is not 64 lowercase hex chars ({h!r})")

    t = data.get("time")
    if not (isinstance(t, int) and t > 0):
        errors.append(f"{name}: time is not a positive integer ({t!r})")

    for key in ("saplingTree", "orchardTree"):
        v = data.get(key)
        if not (isinstance(v, str) and len(v) > 0 and len(v) % 2 == 0 and HEX_RE.match(v)):
            errors.append(f"{name}: {key} is not a non-empty even-length hex string")


def verify_network(root: Path, network: str, errors: list) -> int:
    cfg = NETWORKS[network]
    directory = root / CHECKPOINTS_REL / network
    interval = cfg["interval"]
    changes = git_status_for(directory)

    if not changes:
        print(f"  {network}: no changed checkpoint files (nothing to verify)")
        return 0

    added_heights = []
    for status, height, path in changes:
        # 'A' (staged add) and '??' (untracked) are the expected additive cases.
        if status in ("A", "??", "AM"):
            added_heights.append(height)
            validate_file(path, height, cfg["network_value"], interval, errors)
        elif status in ("M", "MM", "D", "AD", "R"):
            errors.append(
                f"{network}: {path.name} has unexpected git status {status!r} — "
                "checkpoint updates must be additive and must not modify or delete "
                "already-committed checkpoints (the anchor must stay immutable)"
            )
        else:
            errors.append(f"{network}: {path.name} has unexpected git status {status!r}")

    added_heights.sort()
    if not added_heights:
        return len(errors)

    # Contiguity: consecutive multiples of the interval, no gaps.
    for prev, cur in zip(added_heights, added_heights[1:]):
        if cur - prev != interval:
            errors.append(
                f"{network}: gap between added checkpoints {prev} and {cur} "
                f"(expected step {interval})"
            )

    # The first new height must directly follow the committed max.
    cmax = committed_max(directory)
    if cmax is not None and added_heights[0] != cmax + interval:
        errors.append(
            f"{network}: lowest new checkpoint is {added_heights[0]}, but the committed "
            f"max is {cmax}; expected the grid to extend from {cmax + interval} "
            "(gap or unexpected start)"
        )

    status_word = "OK" if not errors else "see errors"
    print(
        f"  {network}: {len(added_heights)} new checkpoint(s) "
        f"{added_heights[0]}..{added_heights[-1]} (interval {interval}) — {status_word}"
    )
    return len(errors)


def main() -> int:
    try:
        root = repo_root()
    except Exception:
        print("ERROR: not inside a git repository", file=sys.stderr)
        return 2

    errors: list = []
    print("Verifying checkpoint changes:")
    for network in sorted(NETWORKS):
        verify_network(root, network, errors)

    print()
    if errors:
        print(f"FAILED — {len(errors)} problem(s):")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("PASS — all changed checkpoints are valid, aligned, and contiguous.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
