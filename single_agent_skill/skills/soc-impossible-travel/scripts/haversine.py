# Haversine great-circle distance between two lat/lon points.
#
# Usage:
#   python scripts/haversine.py --lat1 47.61 --lon1 -122.33 --lat2 6.52 --lon2 3.38
#
# Output (stdout, JSON):
#   {"km": 12345.6, "miles": 7670.1}

import argparse
import json
import math


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0  # Earth radius in km
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return r * c


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Great-circle distance between two lat/lon points.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python scripts/haversine.py --lat1 47.61 --lon1 -122.33 --lat2 6.52 --lon2 3.38",
    )
    parser.add_argument("--lat1", type=float, required=True)
    parser.add_argument("--lon1", type=float, required=True)
    parser.add_argument("--lat2", type=float, required=True)
    parser.add_argument("--lon2", type=float, required=True)
    args = parser.parse_args()
    km = haversine_km(args.lat1, args.lon1, args.lat2, args.lon2)
    print(json.dumps({"km": round(km, 2), "miles": round(km * 0.621371, 2)}))


if __name__ == "__main__":
    main()
