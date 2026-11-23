"""Purge prompt/response content past CONTENT_RETENTION_DAYS, sparing content under legal hold.

For cron or a Kubernetes CronJob, with the Policy API's DATABASE_URL (migrations already applied):

    python -m app.purge [--dry-run] [--batch-size N]

Prints the result as JSON on stdout; the audit.content.purge OCSF event goes to the audit log.
Exit status: 0 done, 1 failed (an audit.content.purge event with success=false is still written
when the database is reachable), 2 misconfigured (nothing is touched). Safe to run concurrently.
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
    ap = argparse.ArgumentParser(prog="python -m app.purge", description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true", help="count what would be purged, delete nothing")
    ap.add_argument("--batch-size", type=positive, help="rows per batch (default CONTENT_PURGE_BATCH_SIZE or 500)")
    args = ap.parse_args(argv)
    from .main import RETENTION_ACTOR, content_retention_days, int_env, purge_contents
    try:
        content_retention_days()
        if args.batch_size is None:
            int_env("CONTENT_PURGE_BATCH_SIZE", "500", 1)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(purge_contents(RETENTION_ACTOR, trigger="cli", dry_run=args.dry_run, batch_size=args.batch_size)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
