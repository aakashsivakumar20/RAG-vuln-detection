import ipaddress
import socket
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"images.example.com", "cdn.example.com"}


def fetch_preview(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read(4096)


def fetch_preview_safe(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    address = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    if address.is_private or address.is_loopback:
        raise ValueError("private address blocked")
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read(4096)


def build_cache_key(url):
    return urllib.parse.quote(url, safe="")
