import re
import tldextract
from urllib.parse import urlparse

URL_REGEX = re.compile(
    r'^(https?://)?'             # http:// or https:// (optional)
    r'([A-Za-z0-9.-]+)'          # domain
    r'(\.[A-Za-z]{2,})'          # TLD (.com, .in, .org)
    r'(:\d+)?'                   # optional port
    r'(\/.*)?$'                  # optional path
)

def normalize_url(url: str) -> str:
    url = url.strip()

    # Auto add scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url

def is_valid_url(url: str) -> bool:
    if not URL_REGEX.match(url):
        return False
    return True


def extract_domain(url: str) -> str:
    parsed = tldextract.extract(url)
    return f"{parsed.domain}.{parsed.suffix}"


def validate_and_normalize(url: str):
    """
    Returns:
        (True, clean_url)  → URL is valid
        (False, reason)    → URL invalid
    """

    url = normalize_url(url)

    if not is_valid_url(url):
        return False, "Invalid URL format"

    parsed = urlparse(url)

    # Block dangerous schemes
    if parsed.scheme not in ("http", "https"):
        return False, "URL uses unsafe scheme"

    # Extract domain
    domain = extract_domain(url)
    if not domain:
        return False, "Could not extract domain"

    return True, url
