"""Тесты dns-check: DNS-запрос, DoH-проба, разбор resolvectl, утечки ПК, stamp.

dns-check tests: DNS query, DoH probe, resolvectl parsing, PC leaks, stamp.
"""

import base64
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules import dns_check  # noqa: E402

STATUS = """Global
         Protocols: -LLMNR -mDNS +DNSOverTLS DNSSEC=yes/unsupported
  resolv.conf mode: stub
Current DNS Server: 1.1.1.1
       DNS Servers: 1.1.1.1 9.9.9.9

Link 3 (wlp1s0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS +DNSOverTLS DNSSEC=yes/supported
Current DNS Server: 192.168.15.1
       DNS Servers: 192.168.15.1
     Default Route: yes

Link 4 (tailscale0)
    Current Scopes: none
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
     Default Route: yes

Link 5 (docker0)
         Protocols: -DefaultRoute -LLMNR -mDNS +DNSOverTLS DNSSEC=yes/supported
       DNS Servers: 172.17.0.1
"""
DOT = """Global: yes
Link 3 (wlp1s0): yes
Link 4 (tailscale0): no
Link 5 (docker0): opportunistic
"""


class TestQuery(unittest.TestCase):
    def test_wire_format(self):
        q = dns_check.build_query("example.com", qid=0x1234)
        self.assertEqual(q[:2], b"\x12\x34")
        self.assertIn(b"\x07example\x03com\x00", q)
        self.assertEqual(q[-4:], b"\x00\x01\x00\x01")


class TestProbe(unittest.TestCase):
    def _run(self, stdout, rc=0, stderr=b""):
        proc = mock.Mock(returncode=rc, stdout=stdout, stderr=stderr)
        with mock.patch.object(dns_check.shutil, "which", return_value="/usr/bin/curl"), \
             mock.patch.object(dns_check.subprocess, "run", return_value=proc) as run, \
             mock.patch.object(dns_check, "build_query", return_value=b"\xab\xcd" + b"\x00" * 15):
            res = dns_check.probe("https://dns.example/dns-query", "192.0.2.1")
        return res, run.call_args.args[0]

    def test_ok_pins_address(self):
        (ok, detail, _), cmd = self._run(b"\xab\xcd" + b"\x81\x80" + b"\x00" * 20 + b"\n200")
        self.assertTrue(ok, detail)
        self.assertIn("dns.example:443:192.0.2.1", cmd)

    def test_blocked(self):
        (ok, detail, _), _ = self._run(b"\n000", rc=7, stderr=b"curl: (7) Failed to connect to x port 443 after 3 ms: Could not connect")
        self.assertFalse(ok)
        self.assertIn("нет соединения", detail)
        self.assertNotIn("(7)", detail)

    def test_bad_certificate(self):
        (ok, detail, _), _ = self._run(b"\n000", rc=60, stderr=b"curl: (60) SSL certificate problem")
        self.assertFalse(ok)
        self.assertIn("сертификат", detail)

    def test_wrong_answer_id(self):
        (ok, detail, _), _ = self._run(b"\x00\x00" + b"\x00" * 20 + b"\n200")
        self.assertFalse(ok)


class TestPcDns(unittest.TestCase):
    def setUp(self):
        self.links = dns_check.parse_resolvectl(STATUS)
        self.modes = dns_check.parse_dot_modes(DOT)

    def test_parse(self):
        names = [l.name for l in self.links]
        self.assertEqual(names, ["Global", "wlp1s0", "tailscale0", "docker0"])
        self.assertEqual(self.links[1].servers, ["192.168.15.1"])
        self.assertEqual(self.modes["docker0"], "opportunistic")

    def test_strict_dot_unreachable_is_broken(self):
        issues = dns_check.pc_dns_issues(self.links, self.modes, reachable=lambda s: False)
        self.assertEqual([(i.link, i.kind) for i in issues], [("Global", "broken"), ("wlp1s0", "broken")])

    def test_strict_dot_reachable_is_fine(self):
        self.assertEqual(dns_check.pc_dns_issues(self.links, self.modes, reachable=lambda s: True), [])

    def test_opportunistic_is_leak(self):
        modes = dict(self.modes, wlp1s0="opportunistic")
        issues = dns_check.pc_dns_issues(self.links, modes, reachable=lambda s: True)
        self.assertEqual([(i.link, i.kind) for i in issues], [("wlp1s0", "leak")])


class TestStamp(unittest.TestCase):
    def test_doh_stamp_layout(self):
        stamp = dns_check.doh_stamp("https://base.dns.mullvad.net/dns-query", "194.242.2.4")
        raw = base64.urlsafe_b64decode(stamp[7:] + "=" * (-len(stamp[7:]) % 4))
        self.assertEqual(raw[0], 0x02)
        self.assertEqual(int.from_bytes(raw[1:9], "little"), 2)  # без логов / no logs
        self.assertIn(b"\x0b194.242.2.4\x00\x14base.dns.mullvad.net\x0a/dns-query", raw)

    def test_snippet(self):
        snip = dns_check.dnscrypt_snippet("mullvad")
        self.assertIn("sdns://", snip)
        self.assertIn("127.0.2.1:53", snip)


if __name__ == "__main__":
    unittest.main()
