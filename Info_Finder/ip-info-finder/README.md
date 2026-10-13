# IP Info Finder

A small command-line tool in Python that looks up information about an IP address or domain name: what kind of address it is, who owns it, roughly where it is, and its hostname.

Uses only the Python standard library. No installation, no API key.

## Example

```
$ python ip_info.py 8.8.8.8
-----------------------------------------------------------------
Query         8.8.8.8
IP address    8.8.8.8
Version       IPv4
Type          Public: Reachable on the internet.
Hostname      dns.google
Location      Mountain View, California, United States
Coordinates   37.386, -122.0838
Map           https://www.openstreetmap.org/?mlat=37.386&mlon=-122.0838#map=10/37.386/-122.0838
ISP           Google LLC
Organisation  Google LLC
ASN           AS15169
Timezone      America/Los_Angeles (UTC-07:00)
-----------------------------------------------------------------
Location is approximate: usually the provider's city, not a street address.
```

## Usage

Requires Python 3.8 or newer.

```bash
python ip_info.py                  # your own public IP
python ip_info.py 8.8.8.8          # an IPv4 address
python ip_info.py 2606:4700:4700::1111   # an IPv6 address
python ip_info.py github.com       # a domain name
python ip_info.py 192.168.1.1      # a private address (offline analysis only)
python ip_info.py 1.1.1.1 --json   # JSON output, for use in other scripts
python ip_info.py 1.1.1.1 --offline   # skip the online lookup
```

On Windows, use `py` instead of `python` if needed.

## What it finds

| Information                     | Where it comes from                               | Needs internet |
| ------------------------------- | ------------------------------------------------- | -------------- |
| IP version and address type     | Python's `ipaddress` module                       | No             |
| IP addresses of a domain        | DNS lookup (`socket.getaddrinfo`)                 | Yes (DNS)      |
| Hostname                        | Reverse DNS / PTR record (`socket.gethostbyaddr`) | Yes (DNS)      |
| Location, coordinates, timezone | [ipwho.is](https://ipwho.is) API                  | Yes            |
| ISP, organisation, ASN          | ipwho.is API                                      | Yes            |

### Address types

| Type           | Example                    | Meaning                                                |
| -------------- | -------------------------- | ------------------------------------------------------ |
| Public         | `8.8.8.8`                  | Reachable on the internet                              |
| Private        | `192.168.1.10`, `10.0.0.1` | Inside home or company networks (RFC 1918)             |
| Shared (CGNAT) | `100.70.1.1`               | Providers sharing one public IP between many customers |
| Loopback       | `127.0.0.1`, `::1`         | This computer itself                                   |
| Link-local     | `169.254.10.1`             | Self-assigned, local network only                      |
| Multicast      | `224.0.0.1`                | Sent to a group of devices                             |
| Documentation  | `192.0.2.5`                | Reserved for examples in manuals                       |
| Unspecified    | `0.0.0.0`                  | "No address" or "all addresses"                        |

## Design decisions

- **Private addresses are never sent online.** They have no public owner or location, and sending them to a third party would leak details about your network.
- **Offline information always shows.** If the API is down, rate-limited or there is no internet, you still get the address type and version, plus a clear message about what failed.
- **HTTPS only**, with an 8-second timeout.
- **IPv4 is preferred** when a domain has both IPv4 and IPv6 addresses, because location data for IPv4 is usually better. All addresses are still listed.

## Running the tests

```bash
python -m unittest discover tests
```

The 16 tests replace the internet and DNS with fakes, so they run offline and give the same result every time. They cover every address type, domain resolution, API errors, rate limiting, missing internet and both output formats.

## Project structure

```
ip-info-finder/
├── ip_info.py            The tool
└── tests/
    └── test_ip_info.py   Unit tests (unittest)
```

## Limitations

- IP geolocation is approximate. It usually points to the internet provider's location, not the device. VPNs, proxies and mobile networks make it less accurate.
- The free ipwho.is service has usage limits and its terms can change. For heavy use, a paid provider or a local database (such as MaxMind GeoLite2) is better.
- Use it responsibly. Looking up public information about an IP is legal, but don't use it to track or harass people.

## Possible improvements

- WHOIS lookup for the network owner and abuse contact
- Check the IP against blocklists (for example AbuseIPDB) to spot known malicious addresses
- Look up several IPs from a file, such as a server log
- Offline geolocation with a downloaded GeoLite2 database

## Author

Swarnika Sellathurai, Bachelor's in Informatics (Cybersecurity), University of Bergen

## License

MIT. See [LICENSE](LICENSE).
