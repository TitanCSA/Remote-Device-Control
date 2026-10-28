#!/usr/bin/env python3
"""Fetch the exact upstream GameStream/crypto source used by this project.

No installer is run. Existing modified trees are refused rather than cleaned.
Requires Python 3.9+ and Git. All builds remain out of the upstream source trees.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

PINS = {
    "MoonlightCommon": {
        "url": "https://github.com/moonlight-stream/moonlight-common-c.git",
        "commit": "5d3c0ecca00c1bb3f587acb8060476edcf8e24aa",
        "submodules": {
            "enet": "aca87840b57f045a1f7f9299e4b1b9b8e2a5e2f1",
            "nanors": "a9b1636f9c98dbfdd0daeaf6982ccd24d1c30f29",
        },
    },
    "MbedTLS": {
        "url": "https://github.com/Mbed-TLS/mbedtls.git",
        "commit": "068ff080b369adfac81509f9b57b2afabaf82dc5",
        "version": "mbedtls-3.6.7",
        "submodules": {"framework": "dde0c4a0e448a0552f18817dcea633bb851fd288"},
    },
}


def git(directory: Path | None, *arguments: str, capture: bool = False) -> str:
    command = ["git", "-c", "protocol.file.allow=never"]
    if directory is not None:
        command += ["-C", str(directory)]
    completed = subprocess.run(
        command + list(arguments), check=True, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )
    return completed.stdout.strip() if capture else ""


def ensure_sources(base: Path) -> None:
    base.mkdir(parents=True, exist_ok=True)
    for name, pin in PINS.items():
        target = base / name
        if target.is_symlink():
            raise RuntimeError(f"Refusing redirected source directory: {target}")
        if target.exists():
            if not (target / ".git").is_dir():
                raise RuntimeError(f"Existing source directory is not a normal Git clone: {target}")
            origin = git(target, "remote", "get-url", "origin", capture=True)
            if origin != pin["url"]:
                raise RuntimeError(f"Unexpected Git origin for {name}; no files changed")
            if git(target, "status", "--porcelain", "--untracked-files=all", capture=True):
                raise RuntimeError(f"Modified/untracked source in {name}; no files were discarded")
        else:
            git(None, "clone", "--no-checkout", "--filter=blob:none", pin["url"], str(target))
        present = git(target, "rev-parse", "HEAD", capture=True)
        if present != pin["commit"]:
            git(target, "fetch", "--depth", "1", "origin", pin["commit"])
        # A fresh --no-checkout clone may already point at this commit while its
        # worktree is still empty. Checkout is required in either case.
        git(target, "checkout", "--detach", pin["commit"])
        git(target, "submodule", "update", "--init", "--recursive")
        if git(target, "rev-parse", "HEAD", capture=True) != pin["commit"]:
            raise RuntimeError(f"Pinned commit verification failed for {name}")
        for relative, expected in pin["submodules"].items():
            if git(target / relative, "rev-parse", "HEAD", capture=True) != expected:
                raise RuntimeError(f"Pinned submodule verification failed: {name}/{relative}")
        if git(target, "status", "--porcelain", "--untracked-files=all", capture=True):
            raise RuntimeError(f"Upstream source is not clean after checkout: {name}")
        print(f"Verified {name}: {pin['commit']}")
    (base / "moonlight-pins.json").write_text(
        json.dumps(PINS, indent=2) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--directory", type=Path,
        default=Path(__file__).resolve().parents[1] / "obj" / "Upstream",
        help="Source cache, matching CMake RDC_UPSTREAM_DIR",
    )
    parser.add_argument("--print-pins", action="store_true", help="Print pins without reading or writing sources")
    args = parser.parse_args()
    if args.print_pins:
        print(json.dumps(PINS, indent=2))
        return 0
    ensure_sources(args.directory.resolve())
    print("Sources ready. No driver, service, firewall or installed application was changed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
