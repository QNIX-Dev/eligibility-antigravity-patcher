#!/usr/bin/env python3
"""Build a standalone agy-manager runtime with PyInstaller.

Install build requirements first:
  python -m pip install -r requirements.txt pyinstaller
"""
from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build the standalone agy-manager runtime")
    parser.add_argument("--clean", action="store_true", help="remove PyInstaller build caches first")
    args = parser.parse_args(argv)
    if args.clean:
        for directory in (ROOT / "build", ROOT / "dist"):
            shutil.rmtree(directory, ignore_errors=True)

    command = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
        "--name", "agy-manager", "--collect-all", "rich", "--collect-all", "questionary",
        str(ROOT / "manager.py"),
    ]
    subprocess.run(command, cwd=ROOT, check=True)
    runtime = ROOT / "dist" / ("agy-manager.exe" if sys.platform == "win32" else "agy-manager")
    print(f"runtime created: {runtime}")


if __name__ == "__main__":
    main()
