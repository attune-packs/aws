#!/usr/bin/env python3
"""Shared stdin/JSON entry point for AWS actions."""

from __future__ import annotations

import json
import os
import sys

_PACK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACK_ROOT not in sys.path:
    sys.path.insert(0, _PACK_ROOT)

from lib.aws_client import AWSPackError, execute_action  # noqa: E402


def main() -> int:
    try:
        raw = sys.stdin.read()
        params = json.loads(raw) if raw.strip() else {}
        if not isinstance(params, dict):
            raise AWSPackError("action parameters must be a JSON object")
        operation = os.environ.get("ATTUNE_ACTION", "").rsplit(".", 1)[-1]
        result = execute_action(operation, params)
        json.dump(
            {"operation": operation, "result": result},
            sys.stdout,
            separators=(",", ":"),
        )
        sys.stdout.write("\n")
        return 0
    except json.JSONDecodeError:
        print("aws action failed: invalid stdin JSON", file=sys.stderr)
    except AWSPackError as exc:
        print(f"aws action failed: {exc}", file=sys.stderr)
    except Exception as exc:  # noqa: BLE001
        # SDK exceptions can contain signed requests or credential values.
        print(f"aws action failed: {type(exc).__name__}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
