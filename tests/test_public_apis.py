"""Public OSINT API body parsers -- no network."""

from __future__ import annotations

import unittest

from pipeline.public_apis import hosts_from_api_body


class TestPublicApiParsers(unittest.TestCase):
    def test_hackertarget_csv(self):
        body = "www.example.com,93.184.216.34\napi.example.com,1.2.3.4\nerror checking host\n"
        hosts = hosts_from_api_body("hackertarget", body, "example.com")
        self.assertEqual(hosts, ["www.example.com", "api.example.com"])

    def test_anubis_json_list(self):
        hosts = hosts_from_api_body("anubis", '["mail.example.com","dev.example.com"]', "example.com")
        self.assertEqual(hosts, ["mail.example.com", "dev.example.com"])

    def test_otx_passive_dns(self):
        body = '{"passive_dns":[{"hostname":"cdn.example.com"},{"hostname_unhashed":"img.example.com"}]}'
        hosts = hosts_from_api_body("otx", body, "example.com")
        self.assertEqual(hosts, ["cdn.example.com", "img.example.com"])

    def test_urlscan_page_domain(self):
        body = '{"results":[{"page":{"domain":"shop.example.com"},"task":{"domain":"example.com"}}]}'
        hosts = hosts_from_api_body("urlscan", body, "example.com")
        self.assertIn("shop.example.com", hosts)
        self.assertIn("example.com", hosts)

    def test_securitytrails_labels(self):
        body = '{"subdomains":["www","staging"]}'
        hosts = hosts_from_api_body("securitytrails", body, "example.com")
        self.assertEqual(hosts, ["www.example.com", "staging.example.com"])

    def test_virustotal_v3_ids(self):
        body = '{"data":[{"id":"vpn.example.com"}]}'
        hosts = hosts_from_api_body("virustotal", body, "example.com")
        self.assertEqual(hosts, ["vpn.example.com"])


if __name__ == "__main__":
    unittest.main()
