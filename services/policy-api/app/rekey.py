"""Move stored prompt/response bodies to the active content key (key rotation, ADR 0002 P3).

With the Policy API's DATABASE_URL and content keys (migrations already applied):

    python -m app.rekey [--dry-run] [--batch-size N]

Rotation: put the new key first in CONTENT_ENCRYPTION_KEYS (or the keys file), keep the old ones
after it, restart the Policy API, run this until "remaining" shows only the active id, then remove
the old keys. Prints the result as JSON; the audit.content.rekey OCSF event goes to the audit log.
Exit status: 0 done, 1 failed or rows left that could not be moved, 2 misconfigured. Safe to rerun.
"""
import argparse
import json
import sys


def positive(v):
    n = int(v)
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m app.rekey", description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true", help="count what would be moved, change nothing")
    ap.add_argument("--batch-size", type=positive, help="rows per batch (default CONTENT_REKEY_BATCH_SIZE or 50)")
    args = ap.parse_args(argv)
    from fastapi import HTTPException
    from .main import REKEY_ACTOR, rekey_contents
    try:
        out = rekey_contents(REKEY_ACTOR, trigger="cli", dry_run=args.dry_run, batch_size=args.batch_size)
    except HTTPException as e:  # no or malformed keys
        print(f"error: {e.detail}", file=sys.stderr)
        return 2
    print(json.dumps(out))
    return 1 if out["failed"] or out["missing_keys"] else 0


if __name__ == "__main__":
    sys.exit(main())
