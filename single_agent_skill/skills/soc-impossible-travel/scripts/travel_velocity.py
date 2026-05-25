# Travel-velocity check: is moving --km in --seconds physically possible?
#
# Threshold: 900 km/h (typical commercial jet cruise ceiling).
#
# Usage:
#   python scripts/travel_velocity.py --km 12300 --seconds 1020
#
# Output (stdout, JSON):
#   {"km": 12300, "seconds": 1020, "km_per_hour": 43411.76, "impossible": true,
#    "threshold_kmh": 900}

import argparse
import json


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check if a distance/time pair exceeds the commercial-flight ceiling.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python scripts/travel_velocity.py --km 12300 --seconds 1020",
    )
    parser.add_argument("--km", type=float, required=True, help="Great-circle distance (km).")
    parser.add_argument("--seconds", type=float, required=True, help="Elapsed seconds between sign-ins.")
    parser.add_argument("--threshold-kmh", type=float, default=900.0,
                        help="Velocity above which travel is flagged 'impossible' (default 900).")
    args = parser.parse_args()
    if args.seconds <= 0:
        print(json.dumps({
            "km": args.km, "seconds": args.seconds,
            "km_per_hour": float("inf"), "impossible": True,
            "threshold_kmh": args.threshold_kmh,
            "note": "Non-positive elapsed time — treated as impossible.",
        }))
        return
    kmh = args.km / (args.seconds / 3600.0)
    print(json.dumps({
        "km": args.km,
        "seconds": args.seconds,
        "km_per_hour": round(kmh, 2),
        "impossible": kmh > args.threshold_kmh,
        "threshold_kmh": args.threshold_kmh,
    }))


if __name__ == "__main__":
    main()
