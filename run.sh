#!/usr/bin/env bash
# Run netshift without touching the system Python.
#   ./run.sh scan        # bootstraps .venv, then re-executes itself with sudo
#   ./run.sh tui
#   sudo ./run.sh scan   # also fine
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install --quiet --upgrade pip
  .venv/bin/pip install --quiet -e .
fi

if [ "$(id -u)" -ne 0 ]; then
  exec sudo -- "$0" "$@"
fi

exec .venv/bin/python -m netshift "$@"
