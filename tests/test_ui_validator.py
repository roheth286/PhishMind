"""
Unit tests for lightweight frontend URL input validation.
"""

import pytest
from src.ui_validator import validate_url_format


def test_empty_and_whitespace_input():
    assert validate_url_format("")[0] is False
    assert validate_url_format("   ")[0] is False
    assert validate_url_format("https://example .com")[0] is False
    assert validate_url_format("http://example.com/test path")[0] is False


def test_valid_domain_urls():
    assert validate_url_format("https://example.com")[0] is True
    assert validate_url_format("http://sub.domain.co.uk/path/file.html?q=1#top")[0] is True
    assert validate_url_format("example.org")[0] is True
    assert validate_url_format("my-site.company.io/login")[0] is True


def test_valid_ip_urls():
    assert validate_url_format("http://192.168.1.1/admin")[0] is True
    assert validate_url_format("10.0.0.1")[0] is True
    assert validate_url_format("http://8.8.8.8:8080/test")[0] is True
    assert validate_url_format("http://[2001:db8::1]/path")[0] is True


def test_invalid_urls():
    # Single label without dot
    assert validate_url_format("localhost")[0] is False
    assert validate_url_format("https://com")[0] is False
    # Final label less than 2 chars
    assert validate_url_format("example.c")[0] is False
    assert validate_url_format("https://example.")[0] is False
    assert validate_url_format(".example.com")[0] is False
    assert validate_url_format("http://invalid_ip: 999.999.999.999")[0] is False
