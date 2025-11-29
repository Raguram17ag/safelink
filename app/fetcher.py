# app/fetcher.py
import time
from typing import Optional, Dict, Any
from urllib.parse import urlparse

import httpx

# Config
FETCH_TIMEOUT = 10               # seconds
MAX_CONTENT_BYTES = 1_000_000    # 1 MB
USER_AGENT = "CliqLinkScanner/1.0 (+your-email@example.com)"


async def head_request(url: str, timeout: int = FETCH_TIMEOUT) -> Dict[str, Any]:
    """
    Perform a safe HEAD request that follows redirects.
    Returns dict with: status_code, final_url, redirects (list), headers, error(optional)
    """
    result = {"status_code": None, "final_url": url, "redirects": [], "headers": {}, "error": None}
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
            resp = await client.head(url, follow_redirects=True)
            result["status_code"] = resp.status_code
            # httpx Response.history is a list of Response objects for redirects
            result["redirects"] = [str(r.url) for r in getattr(resp, "history", [])]
            result["final_url"] = str(resp.url)
            result["headers"] = dict(resp.headers)
    except httpx.RequestError as e:
        result["error"] = f"head_request_error: {repr(e)}"
    except Exception as e:
        result["error"] = f"head_request_unexpected: {repr(e)}"
    return result


async def get_request(url: str, timeout: int = FETCH_TIMEOUT, max_bytes: int = MAX_CONTENT_BYTES) -> Dict[str, Any]:
    """
    Perform a safe GET request that follows redirects and truncates content if too large.
    Returns dict with: status_code, final_url, redirects, headers, content (str, truncated), filesize, error(optional)
    """
    result = {
        "status_code": None,
        "final_url": url,
        "redirects": [],
        "headers": {},
        "content": None,
        "filesize": 0,
        "error": None,
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, headers={"User-Agent": USER_AGENT}) as client:
            resp = await client.get(url, follow_redirects=True)
            result["status_code"] = resp.status_code
            result["redirects"] = [str(r.url) for r in getattr(resp, "history", [])]
            result["final_url"] = str(resp.url)
            result["headers"] = dict(resp.headers)
            # filesize
            content_bytes = resp.content or b""
            result["filesize"] = len(content_bytes)
            if result["filesize"] > max_bytes:
                # truncate to max_bytes and decode best-effort
                result["content"] = content_bytes[:max_bytes].decode(errors="ignore")
            else:
                # full body
                result["content"] = resp.text
    except httpx.RequestError as e:
        result["error"] = f"get_request_error: {repr(e)}"
    except Exception as e:
        result["error"] = f"get_request_unexpected: {repr(e)}"
    return result


async def fetch_url_data(url: str, do_head: bool = True) -> Dict[str, Any]:
    """
    High-level fetcher used by the pipeline.
    Returns a combined dict:
      {
        "url": original,
        "normalized_url": final,
        "head": {...} or None,
        "get": {...} or None,
        "duration": seconds,
      }
    """
    start = time.time()
    # Quick scheme guard
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https", ""):
        return {"url": url, "normalized_url": url, "error": "unsupported-scheme", "duration": time.time() - start}

    # If scheme missing, httpx will accept "https://..." — leave normalization to validator before calling
    head_result = None
    get_result = None

    if do_head:
        head_result = await head_request(url)

    # Always attempt GET so we can extract content (unless head error says unreachable)
    get_result = await get_request(url)

    duration = time.time() - start
    return {
        "url": url,
        "normalized_url": get_result.get("final_url") or (head_result and head_result.get("final_url")) or url,
        "head": head_result,
        "get": get_result,
        "duration": duration,
    }
