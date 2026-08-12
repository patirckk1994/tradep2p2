#!/usr/bin/env python3
"""Analyze q=7933 CLI harness artifacts without re-running any proofs.

Usage:
    python3 scripts/analyze_cli_artifacts.py cli-test-artifacts-nizk2

The report is deliberately forensic rather than pass/fail-only: it records
sizes and SHA-256 hashes, parses JSON where possible, shows receipt presence,
and prints the tail of stderr for any empty or malformed JSON response.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from typing import Any


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stderr_tail(out: pathlib.Path, stem: str, lines: int = 20) -> list[str]:
    path = out / f"{stem}.stderr"
    if not path.exists():
        return []
    text = path.read_text(errors="replace")
    return text.splitlines()[-lines:]


def inspect_json(out: pathlib.Path, path: pathlib.Path) -> dict[str, Any]:
    data = path.read_bytes()
    result: dict[str, Any] = {
        "bytes": len(data),
        "sha256": sha256(data),
        "parse_ok": False,
    }
    text = data.decode("utf-8", errors="replace")
    if not text.strip():
        result["error"] = "empty JSON response"
        result["stderr_tail"] = stderr_tail(out, path.stem)
        return result
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        result["error"] = f"JSON decode failed: {exc}"
        result["preview"] = text[:500]
        result["stderr_tail"] = stderr_tail(out, path.stem)
        return result

    result["parse_ok"] = True
    result["value"] = value
    return result


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} ARTIFACT_DIR", file=sys.stderr)
        return 2

    out = pathlib.Path(sys.argv[1]).resolve()
    if not out.is_dir():
        print(f"not a directory: {out}", file=sys.stderr)
        return 2

    report: dict[str, Any] = {
        "artifact_dir": str(out),
        "files": {},
        "json": {},
    }

    for path in sorted(p for p in out.iterdir() if p.is_file()):
        data = path.read_bytes()
        report["files"][path.name] = {
            "bytes": len(data),
            "sha256": sha256(data),
        }
        if path.suffix == ".json":
            report["json"][path.name] = inspect_json(out, path)

    # Surface the two expensive receipt checkpoints prominently.
    for receipt_name in ("pi1.receipt", "pi2.receipt"):
        entry = report["files"].get(receipt_name)
        if entry:
            report[receipt_name] = {
                "present": True,
                **entry,
            }
        else:
            report[receipt_name] = {"present": False}

    report_path = out / "analysis.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    print(f"Artifact directory: {out}")
    print(f"Analysis written:   {report_path}")
    print()

    for name in sorted(report["json"]):
        info = report["json"][name]
        if info["parse_ok"]:
            value = info["value"]
            summary = []
            if isinstance(value, dict):
                if "ok" in value:
                    summary.append(f"ok={value['ok']}")
                if "verified" in value:
                    summary.append(f"verified={value['verified']}")
                if "elapsed_seconds" in value:
                    summary.append(f"elapsed={value['elapsed_seconds']}s")
            suffix = ("; " + ", ".join(summary)) if summary else ""
            print(f"OK   {name}: {info['bytes']} bytes{suffix}")
        else:
            print(f"FAIL {name}: {info.get('error', 'unknown error')}")
            tail = info.get("stderr_tail") or []
            if tail:
                print("     stderr tail:")
                for line in tail:
                    print(f"       {line}")

    print()
    for receipt_name in ("pi1.receipt", "pi2.receipt"):
        entry = report[receipt_name]
        if entry["present"]:
            print(
                f"RECEIPT {receipt_name}: {entry['bytes']} bytes, "
                f"sha256={entry['sha256']}"
            )

    # Return non-zero only for malformed/empty JSON responses. A clean
    # verified=false response is still valid CLI output and belongs in the
    # report rather than being treated as an analyzer failure.
    malformed = any(not info["parse_ok"] for info in report["json"].values())
    return 1 if malformed else 0


if __name__ == "__main__":
    raise SystemExit(main())
