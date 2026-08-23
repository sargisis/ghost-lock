"""Тесты фишинг-щита: извлечение URL, эвристики, краевые случаи."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ghost_lock.modules.phishing_guard import (  # noqa: E402
    _host_of,
    blocklist_for_profile,
    extract_urls,
    heuristic_url_findings,
)

IOCS = {
    "phishing_heuristics": {
        "brand_keywords": ["apple", "icloud", "appleid", "sberbank"],
        "tld_watchlist": [".top", ".xyz", ".click", ".icu"],
        "patterns": [
            {"pattern": "xn--", "desc": "punycode-домен"},
            {"pattern": "(apple|icloud|appleid)[^.]{0,20}(-|\\.)?(support|id|verify|secure|login)", "desc": "имитация домена Apple ID"},
            {"pattern": "(verify|secure|confirm|unlock|suspend)[-_.]", "desc": "фишинговая лексика в поддомене"},
            {"pattern": "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}", "desc": "сырой IP вместо домена"},
        ],
    }
}


class TestExtractUrls(unittest.TestCase):
    def test_single_url(self):
        self.assertEqual(extract_urls("see https://example.com/x?a=1 now"), {"https://example.com/x?a=1"})

    def test_www_prefix(self):
        self.assertEqual(extract_urls("go www.example.com"), {"www.example.com"})

    def test_multiple_urls(self):
        urls = extract_urls("a http://one.io b https://two.org/path c")
        self.assertEqual(len(urls), 2)

    def test_trailing_punctuation_stripped(self):
        urls = extract_urls("visit https://ok.site/page.")
        self.assertEqual(list(urls)[0], "https://ok.site/page")

    def test_no_urls(self):
        self.assertEqual(extract_urls("plain text without links"), set())

    def test_url_inside_json_log_line(self):
        line = '{"req":"GET","url":"https://cdn.apple.com/mzstore/1"}'
        self.assertEqual(extract_urls(line), {"https://cdn.apple.com/mzstore/1"})


class TestHostOf(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(_host_of("https://Example.com/p"), "example.com")

    def test_with_port(self):
        self.assertEqual(_host_of("http://evil.host:8080/login"), "evil.host")

    def test_www_prefix(self):
        self.assertEqual(_host_of("www.ok.ru"), "www.ok.ru")

    def test_subdomains_kept(self):
        self.assertEqual(_host_of("https://a.b.example.co.uk/"), "a.b.example.co.uk")


class TestHeuristics(unittest.TestCase):
    def find(self, url):
        return heuristic_url_findings(IOCS, f"req {url}", "t.log")

    # — то, что ДОЛЖНО ловиться —
    def test_brand_plus_bad_tld(self):
        f = self.find("https://apple-id-verify.top/login")
        self.assertTrue(f)
        self.assertIn("TLD", f[0].source)

    def test_brand_with_fishy_lexeme(self):
        f = self.find("https://icloud-secure-login.com/auth")
        self.assertTrue(f, "должен поймать icloud-secure-login")

    def test_punycode(self):
        f = self.find("https://xn--80ak6aa92e.com/")
        self.assertTrue(any("punycode" in x.source for x in f))

    def test_raw_ip(self):
        f = self.find("https://192.168.44.12/pay")
        self.assertTrue(any("IP" in x.source for x in f))

    def test_generic_verify_lexeme_any_host(self):
        f = self.find("https://verify-account.random-site.xyz/start")
        self.assertTrue(f)

    def test_weight_is_three(self):
        for url in ("https://apple-id.top/", "https://xn--aa.com"):
            self.assertTrue(all(x.weight == 3 for x in self.find(url)))

    # — то, что НЕ должно ловиться (ложные срабатывания) —
    def test_legit_apple_clean(self):
        self.assertFalse(self.find("https://www.apple.com/iphone/"))

    def test_apple_cdn_clean(self):
        self.assertFalse(self.find("https://cdn.apple.com/mzstore/config"))

    def test_icloud_main_clean(self):
        self.assertFalse(self.find("https://www.icloud.com/mail/"))

    def test_bank_domain_without_brand_overlap_clean(self):
        self.assertFalse(self.find("https://online.sberbank.ru/"))

    def test_normal_site_clean(self):
        self.assertFalse(self.find("https://ru.wikipedia.org/wiki/iOS"))

    def test_no_false_positive_from_empty_host(self):
        self.assertFalse(heuristic_url_findings(IOCS, "https:///path", "t.log"))


class TestBlocklistRender(unittest.TestCase):
    def test_sorted_unique_lowercase(self):
        out = blocklist_for_profile(["B.com", "a.com", "b.com"])
        self.assertEqual(out, "- a.com\n- b.com")

    def test_empty(self):
        self.assertEqual(blocklist_for_profile([]), "(пусто)")


if __name__ == "__main__":
    unittest.main()
