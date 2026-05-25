# Ad-hoc IP reputation lookup against a bundled mock feed.
# Use this only for spot checks — `evaluate_location_anomaly` already pulls
# reputation for every IoC IP in its output.
#
# Usage:
#   python scripts/ip_reputation_lookup.py --ip 198.51.100.7
#
# Output (stdout, JSON):
#   {"IP": "198.51.100.7", "Reputation": "Malicious", "IsProxy": false, "IsVPN": false}

import argparse
import json
from pathlib import Path

# Minimal bundled feed — extend as needed. In production, replace with a call
# to Defender TI / VirusTotal / your enterprise reputation provider.
DEFAULT_FEED: dict[str, dict] = {
    "198.51.100.7":  {"Reputation": "Malicious",  "IsProxy": False, "IsVPN": False,
                      "Country": "NG", "ASN": "AS-EXAMPLE"},
    "203.0.113.42":  {"Reputation": "Clean",      "IsProxy": False, "IsVPN": False,
                      "Country": "US", "ASN": "AS-EXAMPLE"},
    "192.0.2.10":    {"Reputation": "Suspicious", "IsProxy": True,  "IsVPN": True,
                      "Country": "DE", "ASN": "AS-VPN"},
}


def lookup(ip: str, feed_path: Path | None = None) -> dict:
    if feed_path and feed_path.is_file():
        with feed_path.open(encoding="utf-8") as f:
            feed = json.load(f)
    else:
        feed = DEFAULT_FEED
    entry = feed.get(ip, {"Reputation": "Unknown"})
    return {"IP": ip, **entry}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Spot-check IP reputation against a bundled mock feed.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python scripts/ip_reputation_lookup.py --ip 198.51.100.7",
    )
    parser.add_argument("--ip", required=True, help="IP address to look up.")
    parser.add_argument("--feed", default=None,
                        help="Optional path to a JSON feed file overriding the default mock.")
    args = parser.parse_args()
    feed_path = Path(args.feed) if args.feed else None
    print(json.dumps(lookup(args.ip, feed_path)))


if __name__ == "__main__":
    main()
