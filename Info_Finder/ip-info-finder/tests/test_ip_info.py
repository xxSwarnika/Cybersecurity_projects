"""
Tests for ip_info.py. Run from the project folder with:

    python -m unittest discover tests

The internet and DNS are replaced with fakes, so the tests run offline.
"""

import io
import json
import os
import socket
import sys
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import ip_info  # noqa: E402

# Shaped like a real ipwho.is answer (trimmed).
FAKE_ANSWER = {
    "ip": "8.8.8.8",
    "success": True,
    "type": "IPv4",
    "country": "United States",
    "country_code": "US",
    "region": "California",
    "city": "Mountain View",
    "latitude": 37.386,
    "longitude": -122.0838,
    "connection": {"asn": 15169, "org": "Google LLC", "isp": "Google LLC", "domain": "google.com"},
    "timezone": {"id": "America/Los_Angeles", "utc": "-07:00"},
}


def fake_response(payload):
    """Something that behaves like the object urlopen returns."""
    response = mock.MagicMock()
    response.read.return_value = json.dumps(payload).encode("utf-8")
    response.__enter__.return_value = response
    return response


class ClassifyTests(unittest.TestCase):
    def test_types(self):
        cases = {
            "8.8.8.8": "Public",
            "192.168.1.10": "Private",
            "10.0.0.1": "Private",
            "127.0.0.1": "Loopback",
            "169.254.10.1": "Link-local",
            "224.0.0.1": "Multicast",
            "100.70.1.1": "Shared (CGNAT)",
            "192.0.2.5": "Documentation",
            "0.0.0.0": "Unspecified",
            "::1": "Loopback",
            "fe80::1": "Link-local",
            "fd00::1": "Private",
            "2001:db8::1": "Documentation",
            "2606:4700:4700::1111": "Public",
        }
        for ip, expected in cases.items():
            with self.subTest(ip=ip):
                self.assertEqual(ip_info.classify(ip)["type"], expected)

    def test_version_and_reverse_pointer(self):
        info = ip_info.classify("1.2.3.4")
        self.assertEqual(info["version"], "IPv4")
        self.assertEqual(info["reverse_pointer"], "4.3.2.1.in-addr.arpa")
        self.assertEqual(ip_info.classify("::1")["version"], "IPv6")


class ResolveTests(unittest.TestCase):
    def test_ip_is_returned_unchanged(self):
        self.assertEqual(ip_info.resolve("8.8.8.8"), ["8.8.8.8"])

    def test_ipv6_is_normalised(self):
        self.assertEqual(ip_info.resolve("2001:0db8:0000::0001"), ["2001:db8::1"])

    @mock.patch("socket.getaddrinfo")
    def test_domain_is_resolved_without_duplicates(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, 1, 6, "", ("93.184.215.14", 0)),
            (socket.AF_INET, 2, 17, "", ("93.184.215.14", 0)),
            (socket.AF_INET6, 1, 6, "", ("2606:2800:21f:cb07:6820:80da:af6b:8b2c", 0, 0, 0)),
        ]
        self.assertEqual(ip_info.resolve("example.com"),
                         ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"])

    @mock.patch("socket.getaddrinfo", side_effect=socket.gaierror)
    def test_unknown_domain(self, _):
        with self.assertRaises(ValueError):
            ip_info.resolve("no-such-domain.invalid")


class LookupTests(unittest.TestCase):
    @mock.patch("urllib.request.urlopen")
    def test_summary_fields(self, urlopen):
        urlopen.return_value = fake_response(FAKE_ANSWER)
        details = ip_info.summarise(ip_info.lookup("8.8.8.8"))
        self.assertEqual(details["location"], "Mountain View, California, United States")
        self.assertEqual(details["asn"], "AS15169")
        self.assertEqual(details["isp"], "Google LLC")
        self.assertIn("openstreetmap.org", details["map"])
        self.assertTrue(urlopen.call_args[0][0].full_url.endswith("/8.8.8.8"))

    @mock.patch("urllib.request.urlopen")
    def test_api_failure_message(self, urlopen):
        urlopen.return_value = fake_response({"success": False, "message": "Invalid IP address"})
        with self.assertRaisesRegex(RuntimeError, "Invalid IP address"):
            ip_info.lookup("8.8.8.8")

    @mock.patch("urllib.request.urlopen")
    def test_rate_limit(self, urlopen):
        urlopen.side_effect = urllib.error.HTTPError("url", 429, "Too Many Requests", {}, None)
        with self.assertRaisesRegex(RuntimeError, "Too many lookups"):
            ip_info.lookup("8.8.8.8")

    @mock.patch("urllib.request.urlopen", side_effect=urllib.error.URLError("no network"))
    def test_no_network_still_gives_offline_info(self, _):
        with mock.patch("ip_info.reverse_dns", return_value=None):
            info = ip_info.get_ip_info("8.8.8.8")
        self.assertEqual(info["type"], "Public")
        self.assertIsNone(info["details"])
        self.assertIn("Could not reach", info["lookup_error"])


class GetIpInfoTests(unittest.TestCase):
    @mock.patch("urllib.request.urlopen")
    def test_private_ip_is_never_sent_online(self, urlopen):
        with mock.patch("ip_info.reverse_dns", return_value=None):
            info = ip_info.get_ip_info("192.168.1.1")
        urlopen.assert_not_called()
        self.assertIn("non-public", info["lookup_error"])

    @mock.patch("urllib.request.urlopen")
    def test_own_ip(self, urlopen):
        urlopen.return_value = fake_response(FAKE_ANSWER)
        with mock.patch("ip_info.reverse_dns", return_value="dns.google"):
            info = ip_info.get_ip_info(None)
        self.assertEqual(info["ip"], "8.8.8.8")
        self.assertEqual(info["query"], "your public IP")
        self.assertTrue(urlopen.call_args[0][0].full_url.endswith("ipwho.is/"))

    def test_own_ip_offline_is_an_error(self):
        with self.assertRaises(ValueError):
            ip_info.get_ip_info(None, online=False)

    @mock.patch("socket.getaddrinfo")
    def test_domain_prefers_ipv4(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET6, 1, 6, "", ("2606:4700::6810:84e5", 0, 0, 0)),
            (socket.AF_INET, 1, 6, "", ("104.16.132.229", 0)),
        ]
        with mock.patch("ip_info.reverse_dns", return_value=None):
            info = ip_info.get_ip_info("example.org", online=False)
        self.assertEqual(info["ip"], "104.16.132.229")
        self.assertEqual(len(info["all_addresses"]), 2)


class CommandLineTests(unittest.TestCase):
    @mock.patch("urllib.request.urlopen")
    def test_report_and_json_output(self, urlopen):
        urlopen.return_value = fake_response(FAKE_ANSWER)
        with mock.patch("ip_info.reverse_dns", return_value="dns.google"):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(ip_info.main(["8.8.8.8"]), 0)
            self.assertIn("Mountain View", out.getvalue())
            self.assertIn("dns.google", out.getvalue())

            out = io.StringIO()
            with redirect_stdout(out):
                ip_info.main(["8.8.8.8", "--json"])
            self.assertEqual(json.loads(out.getvalue())["details"]["asn"], "AS15169")

    def test_invalid_input_exits_with_error(self):
        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror), \
                redirect_stdout(io.StringIO()), mock.patch("sys.stderr", new=io.StringIO()) as err:
            self.assertEqual(ip_info.main(["not an ip"]), 1)
        self.assertIn("not a valid IP", err.getvalue())


if __name__ == "__main__":
    unittest.main()
