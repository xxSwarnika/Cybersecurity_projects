#!/usr/bin/env python3
"""
IP Info Finder: look up information about an IP address or domain name.

Usage:
    python ip_info.py                  # your own public IP
    python ip_info.py 8.8.8.8          # an IP address
    python ip_info.py github.com       # a domain name
    python ip_info.py 192.168.1.1      # private IPs are analysed offline only
    python ip_info.py 1.1.1.1 --json   # machine-readable output
    python ip_info.py 1.1.1.1 --offline

Uses only the Python standard library. Location data comes from the free
ipwho.is API (no key needed).
"""

import argparse
import ipaddress
import json
import socket
import sys
import urllib.error
import urllib.request

API_URL = "https://ipwho.is/"
TIMEOUT_SECONDS = 8
USER_AGENT = "ip-info-finder/1.0"

# Example ranges from RFC 5737 (IPv4) and RFC 3849 (IPv6).
DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network(net)
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]


# ---------------------------------------------------------------------------
# Offline analysis: works without internet
# ---------------------------------------------------------------------------

def resolve(target):
    """Turn a domain name into a list of IP addresses. An IP is returned as is."""
    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        pass  # not an IP, so treat it as a domain name

    try:
        results = socket.getaddrinfo(target, None)
    except socket.gaierror:
        raise ValueError(f"'{target}' is not a valid IP address, and the domain could not be found.")

    addresses = []
    for family, _, _, _, sockaddr in results:
        if family in (socket.AF_INET, socket.AF_INET6) and sockaddr[0] not in addresses:
            addresses.append(sockaddr[0])
    return addresses


def classify(ip):
    """Describe what kind of address this is, using the ipaddress module."""
    address = ipaddress.ip_address(ip)

    # Order matters: the most specific category wins.
    if address.is_unspecified:
        kind, note = "Unspecified", "Means 'no address' or 'all addresses'."
    elif address.is_loopback:
        kind, note = "Loopback", "This computer itself (localhost)."
    elif address.is_link_local:
        kind, note = "Link-local", "Only valid on the local network segment, often self-assigned."
    elif address.is_multicast:
        kind, note = "Multicast", "Sends to a group of devices, not one host."
    elif any(address in net for net in DOCUMENTATION_NETWORKS if net.version == address.version):
        kind, note = "Documentation", "Reserved for examples in books and manuals. Never used on the real internet."
    elif address.version == 4 and address in ipaddress.ip_network("100.64.0.0/10"):
        kind, note = "Shared (CGNAT)", "Used by internet providers that put many customers behind one public IP."
    elif address.is_private:
        kind, note = "Private", "Used inside home and company networks. Not reachable from the internet."
    elif address.is_reserved:
        kind, note = "Reserved", "Set aside by the IETF and not used on the internet."
    elif address.is_global:
        kind, note = "Public", "Reachable on the internet."
    else:
        kind, note = "Special-purpose", "Reserved for documentation, testing or other special use."

    return {
        "ip": str(address),
        "version": f"IPv{address.version}",
        "type": kind,
        "note": note,
        "is_public": address.is_global,
        "reverse_pointer": address.reverse_pointer,
    }


def reverse_dns(ip):
    """Find the hostname registered for an IP (PTR record), if any."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


# ---------------------------------------------------------------------------
# Online lookup
# ---------------------------------------------------------------------------

def lookup(ip=None):
    """
    Ask ipwho.is about an IP. With no IP, the API answers with your own public IP.
    Returns the parsed JSON. Raises RuntimeError with a readable message on failure.
    """
    url = API_URL + (ip or "")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 429:
            raise RuntimeError("Too many lookups. Wait a minute and try again.")
        raise RuntimeError(f"The lookup service answered with HTTP {error.code}.")
    except urllib.error.URLError as error:
        raise RuntimeError(f"Could not reach the lookup service ({error.reason}).")
    except (TimeoutError, socket.timeout):
        raise RuntimeError("The lookup service took too long to answer.")
    except json.JSONDecodeError:
        raise RuntimeError("The lookup service sent an unreadable answer.")

    if not data.get("success", False):
        raise RuntimeError(data.get("message") or "The lookup service could not find this IP.")
    return data


def summarise(data):
    """Pick the useful fields from the API answer."""
    connection = data.get("connection") or {}
    timezone = data.get("timezone") or {}
    lat, lon = data.get("latitude"), data.get("longitude")

    place = ", ".join(part for part in (data.get("city"), data.get("region"), data.get("country")) if part)
    asn = connection.get("asn")

    return {
        "location": place or None,
        "country_code": data.get("country_code"),
        "coordinates": f"{lat}, {lon}" if lat is not None and lon is not None else None,
        "map": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=10/{lat}/{lon}" if lat is not None and lon is not None else None,
        "isp": connection.get("isp"),
        "organisation": connection.get("org"),
        "asn": f"AS{asn}" if asn else None,
        "domain": connection.get("domain"),
        "timezone": timezone.get("id"),
        "utc_offset": timezone.get("utc"),
    }


# ---------------------------------------------------------------------------
# Putting it together
# ---------------------------------------------------------------------------

def get_ip_info(target=None, online=True):
    """
    Collect everything about one target (IP, domain, or None for your own IP).
    Returns a dict. Online errors are reported in 'lookup_error' instead of raised,
    so the offline information is always shown.
    """
    if target is None:
        if not online:
            raise ValueError("Finding your own public IP needs the internet. Remove --offline or give an IP.")
        data = lookup()
        info = classify(data["ip"])
        info["query"] = "your public IP"
        info["all_addresses"] = [data["ip"]]
        info["hostname"] = reverse_dns(data["ip"])
        info["details"] = summarise(data)
        info["lookup_error"] = None
        return info

    addresses = resolve(target)
    if not addresses:
        raise ValueError(f"'{target}' has no IP addresses.")

    # Prefer IPv4 for the detailed lookup; it has better location data.
    main_ip = next((a for a in addresses if ":" not in a), addresses[0])

    info = classify(main_ip)
    info["query"] = target
    info["all_addresses"] = addresses
    info["hostname"] = reverse_dns(main_ip)
    info["details"] = None
    info["lookup_error"] = None

    if not online:
        info["lookup_error"] = "Skipped (offline mode)."
    elif not info["is_public"]:
        info["lookup_error"] = "Skipped: non-public addresses have no location or provider on the internet."
    else:
        try:
            info["details"] = summarise(lookup(main_ip))
        except RuntimeError as error:
            info["lookup_error"] = str(error)

    return info


def format_report(info):
    """Turn the info dict into readable text."""
    rows = [
        ("Query", info["query"]),
        ("IP address", info["ip"]),
        ("Version", info["version"]),
        ("Type", f"{info['type']}: {info['note']}"),
        ("Hostname", info["hostname"] or "none found"),
    ]
    if len(info["all_addresses"]) > 1:
        rows.append(("All addresses", ", ".join(info["all_addresses"])))

    details = info["details"]
    if details:
        rows += [
            ("Location", details["location"]),
            ("Coordinates", details["coordinates"]),
            ("Map", details["map"]),
            ("ISP", details["isp"]),
            ("Organisation", details["organisation"]),
            ("ASN", details["asn"]),
            ("Timezone", f"{details['timezone']} (UTC{details['utc_offset']})" if details["timezone"] else None),
        ]
    else:
        rows.append(("Online lookup", info["lookup_error"]))

    width = max(len(label) for label, _ in rows)
    lines = [f"{label.ljust(width)}  {value}" for label, value in rows if value]
    rule = "-" * max(len(line) for line in lines)
    note = "\nLocation is approximate: usually the provider's city, not a street address." if details else ""
    return "\n".join([rule, *lines, rule]) + note


def main(argv=None):
    parser = argparse.ArgumentParser(description="Find information about an IP address or domain name.")
    parser.add_argument("target", nargs="?", help="IP address or domain. Leave out to check your own public IP.")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    parser.add_argument("--offline", action="store_true", help="skip the online lookup")
    args = parser.parse_args(argv)

    try:
        info = get_ip_info(args.target, online=not args.offline)
    except (ValueError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(json.dumps(info, indent=2, ensure_ascii=False) if args.json else format_report(info))
    return 0


if __name__ == "__main__":
    sys.exit(main())
