#!/usr/bin/env python3
"""Driver for the update-checkpoints skill.

For one Zcash network (mainnet|testnet) this:

  1. Finds the highest <height>.json checkpoint already on disk (the "anchor").
     This is the "last checkpoint currently stored in the SDK", which is exactly
     what checkmate wants as its --start-height.
  2. Runs the bundled checkmate.py from *inside* the network's checkpoints
     directory, so it writes <height>.json files there (checkmate's --to-json
     redirects to the current working directory). checkmate pulls GetTreeState
     for the anchor, then every `interval` blocks up to the chain tip, plus the
     tip itself.
  3. Restores the anchor file. checkmate re-downloads --start-height, but the
     anchor is an already-committed checkpoint and must never change — a
     transient grpcurl hiccup on that one query could otherwise overwrite a good
     file with garbage. Restoring guarantees the run is purely additive.
  4. Deletes the non-interval-aligned chain-tip file checkmate emits. Only
     interval-aligned checkpoints are committed to the SDK (see the git history
     of the checkpoints directory), so the tip (a non-aligned block) is dropped.
  5. Prints a JSON summary of what changed, for the verifier and the CHANGELOG.

The actual download is done by checkmate.py (bundled alongside this file); this
driver only handles anchor resolution, safe placement, and cleanup so the result
matches the repo's established "Checkpoints updated" convention every time.

Usage:
    python3 fetch_checkpoints.py mainnet
    python3 fetch_checkpoints.py testnet
    python3 fetch_checkpoints.py mainnet --checkpoints-dir /path/to/checkpoints
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Per-network constants. Hosts and intervals are fixed by convention; do not
# parameterize them — the whole point of the skill is that these never drift.
NETWORKS = {
    "mainnet": {"host": "zec.rocks:443", "interval": 2500, "network_value": "main"},
    "testnet": {"host": "testnet.zec.rocks:443", "interval": 10000, "network_value": "test"},
}

CHECKPOINTS_REL = "Sources/ZcashLightClientKit/Resources/checkpoints"


def repo_root() -> Path:
    """Repo top level via git, falling back to this script's known location."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], stderr=subprocess.DEVNULL
        )
        return Path(out.decode().strip())
    except Exception:
        # .claude/skills/update-checkpoints/scripts/fetch_checkpoints.py
        #   parents[4] == repo root
        return Path(__file__).resolve().parents[4]


def heights_on_disk(directory: Path):
    """Sorted integer heights of every <digits>.json file in `directory`."""
    heights = []
    for path in directory.glob("*.json"):
        if path.stem.isdigit():
            heights.append(int(path.stem))
    return sorted(heights)


def main() -> int:
    parser = argparse.ArgumentParser(description="Download SDK checkpoints for one network.")
    parser.add_argument("network", choices=sorted(NETWORKS))
    parser.add_argument(
        "--checkpoints-dir",
        help="Override the checkpoints base dir (default: <repo>/%s)" % CHECKPOINTS_REL,
    )
    args = parser.parse_args()

    cfg = NETWORKS[args.network]
    root = repo_root()
    base = Path(args.checkpoints_dir) if args.checkpoints_dir else root / CHECKPOINTS_REL
    target = base / args.network

    if not target.is_dir():
        print(f"ERROR: checkpoints directory not found: {target}", file=sys.stderr)
        return 2

    existing = heights_on_disk(target)
    if not existing:
        print(f"ERROR: no existing checkpoints in {target}; cannot resolve a start height", file=sys.stderr)
        return 2

    anchor = max(existing)
    before = set(existing)
    interval = cfg["interval"]

    if anchor % interval != 0:
        print(
            f"WARNING: anchor {anchor} is not a multiple of interval {interval}; "
            "the checkpoint grid may be misaligned. Proceeding anyway.",
            file=sys.stderr,
        )

    # Back up the anchor so we can guarantee it is never modified (see step 3).
    anchor_path = target / f"{anchor}.json"
    anchor_backup = anchor_path.read_bytes()

    checkmate = Path(__file__).resolve().parent / "checkmate.py"
    cmd = [
        sys.executable,
        str(checkmate),
        cfg["host"],
        "--start-height",
        str(anchor),
        "--interval",
        str(interval),
        "--to-json",
    ]
    print(f"[{args.network}] anchor={anchor} host={cfg['host']} interval={interval}", file=sys.stderr)
    print(f"[{args.network}] running checkmate in {target} ...", file=sys.stderr)
    # checkmate.py exits 0 even when individual grpcurl calls fail; per-file
    # correctness is enforced afterwards by verify_checkpoints.py.
    subprocess.run(cmd, cwd=str(target), check=False)

    # Restore the anchor — it must remain byte-identical to the committed file.
    anchor_path.write_bytes(anchor_backup)

    after = set(heights_on_disk(target))
    new_heights = sorted(after - before)

    # Drop any non-interval-aligned new file (the chain-tip checkmate appends).
    dropped = []
    added = []
    for height in new_heights:
        if height % interval != 0:
            (target / f"{height}.json").unlink()
            dropped.append(height)
        else:
            added.append(height)

    try:
        dir_display = str(target.relative_to(root))
    except ValueError:
        dir_display = str(target)

    summary = {
        "network": args.network,
        "host": cfg["host"],
        "interval": interval,
        "anchor": anchor,
        "added": added,
        "added_count": len(added),
        "first_added": added[0] if added else None,
        "new_max": added[-1] if added else anchor,
        "dropped_tip": dropped,
        "dir": dir_display,
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
