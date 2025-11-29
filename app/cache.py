# simple file-based cache: cache/scans.json
import json, os, time, hashlib

CACHE_FILE = "cache/scans.json"
TTL = 60*60*12  # 12 hours

def _load():
    if not os.path.exists(CACHE_FILE):
        return {}
    return json.load(open(CACHE_FILE, "r"))

def _save(d):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    json.dump(d, open(CACHE_FILE, "w"))

def cache_get(url):
    d = _load()
    key = hashlib.sha256(url.encode()).hexdigest()
    item = d.get(key)
    if not item: return None
    if time.time() - item["ts"] > TTL:
        d.pop(key, None); _save(d); return None
    return item["result"]

def cache_set(url, result):
    d = _load()
    key = hashlib.sha256(url.encode()).hexdigest()
    d[key] = {"ts": time.time(), "result": result}
    _save(d)
