
import unittest
from unittest.mock import patch, MagicMock
import tkinter as tk
import socket
import whois
import requests

# Correctly import your application class from your file.
from web_enum_tool import WebEnumerationTool

class TestWebEnumerationTool(unittest.TestCase):
    def setUp(self):
        # Create a Tkinter root window and hide it
        self.root = tk.Tk()
        self.root.withdraw()
        # Initialize the Web Enumeration Tool
        self.app = WebEnumerationTool(self.root)

    def tearDown(self):
        # Destroy the Tkinter root window after each test
        self.root.destroy()

    @patch('socket.gethostbyname')
    def test_dns_lookup_success(self, mock_gethostbyname):
        domain = "example.com"
        fake_ip = "93.184.216.34"
        mock_gethostbyname.return_value = fake_ip

        self.app.domain_entry.delete(0, tk.END)
        self.app.domain_entry.insert(0, domain)
        self.app.dns_lookup()

        output = self.app.output_text.get("1.0", tk.END)
        self.assertIn(fake_ip, output)

    @patch('socket.gethostbyname')
    def test_dns_lookup_failure(self, mock_gethostbyname):
        domain = "invalid_domain"
        mock_gethostbyname.side_effect = socket.gaierror

        self.app.domain_entry.delete(0, tk.END)
        self.app.domain_entry.insert(0, domain)
        self.app.dns_lookup()

        output = self.app.output_text.get("1.0", tk.END)
        self.assertIn("DNS Lookup failed", output)

    @patch('whois.whois')
    def test_whois_lookup_success(self, mock_whois):
        domain = "example.com"
        fake_whois_info = {"domain_name": "example.com", "registrar": "Example Registrar"}
        mock_whois.return_value = fake_whois_info

        self.app.domain_entry.delete(0, tk.END)
        self.app.domain_entry.insert(0, domain)
        self.app.whois_lookup()

        output = self.app.output_text.get("1.0", tk.END)
        self.assertIn("example.com", output)
        self.assertIn("Example Registrar", output)

    @patch('whois.whois')
    def test_whois_lookup_failure(self, mock_whois):
        domain = "example.com"
        mock_whois.side_effect = Exception("error")

        self.app.domain_entry.delete(0, tk.END)
        self.app.domain_entry.insert(0, domain)
        self.app.whois_lookup()

        output = self.app.output_text.get("1.0", tk.END)
        self.assertIn("WHOIS Lookup failed", output)

    @patch('requests.head')
    def test_http_headers_success(self, mock_requests_head):
        domain = "example.com"
        fake_headers = {"Content-Type": "text/html"}
        fake_response = MagicMock()
        fake_response.headers = fake_headers
        mock_requests_head.return_value = fake_response

        self.app.domain_entry.delete(0, tk.END)
        self.app.domain_entry.insert(0, domain)
        self.app.http_headers()

        output = self.app.output_text.get("1.0", tk.END)
        self.assertIn("Content-Type", output)

    @patch('requests.head')
    def test_http_headers_failure(self, mock_requests_head):
        domain = "example.com"
        mock_requests_head.side_effect = requests.exceptions.RequestException("error")

        self.app.domain_entry.delete(0, tk.END)
        self.app.domain_entry.insert(0, domain)
        self.app.http_headers()

        output = self.app.output_text.get("1.0", tk.END)
        self.assertIn("HTTP Headers lookup failed", output)

if __name__ == "__main__":
    unittest.main()
