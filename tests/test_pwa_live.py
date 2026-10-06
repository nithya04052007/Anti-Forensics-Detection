"""
Live HTTP tests for PWA installability — covers all 3 bug fixes.
Run while Flask is running on port 5000.
"""
import urllib.request
import sys

base = "http://127.0.0.1:5000"
results = []


def check(label, url, expected_status=200, expected_content=None,
          expected_header=None, expected_header_value=None):
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as r:
            status = r.status
            body = r.read().decode("utf-8", errors="replace")
            headers = dict(r.headers)
    except urllib.error.HTTPError as e:
        status = e.code
        body = ""
        headers = {}
    except Exception as ex:
        results.append((label, "ERROR", str(ex)))
        print("  ERROR  {}: {}".format(label, ex))
        return

    ok = (status == expected_status)
    if expected_content:
        ok = ok and (expected_content in body)
    if expected_header:
        hval = headers.get(expected_header, "")
        if expected_header_value:
            ok = ok and (expected_header_value.lower() in hval.lower())
        else:
            ok = ok and bool(hval)
    tag = "PASS" if ok else "FAIL"
    results.append((label, tag, "status={}".format(status)))
    print("  {}  {}: status={}".format(tag, label, status))


# ─── FIX 1: /manifest.json must return application/manifest+json ─────────────
print("\n[FIX 1] Manifest MIME type")
check("/manifest.json serves", "{}/manifest.json".format(base), 200, '"name"')
check("/manifest.json Content-Type", "{}/manifest.json".format(base), 200,
      None, "Content-Type", "application/manifest+json")
check("/manifest.json has correct display", "{}/manifest.json".format(base), 200, '"standalone"')
check("/manifest.json has correct start_url", "{}/manifest.json".format(base), 200, '"/"')

# ─── FIX 2+3: SW must be accessible and correct ──────────────────────────────
print("\n[FIX 2+3] Service Worker")
check("sw.js serves from root /sw.js", "{}/sw.js".format(base), 200, "CACHE_NAME")
check("sw.js Content-Type is JS", "{}/sw.js".format(base), 200, None, "Content-Type", "javascript")
check("sw.js has no-cache", "{}/sw.js".format(base), 200, None, "Cache-Control", "no-cache")
check("sw.js has Service-Worker-Allowed header", "{}/sw.js".format(base), 200,
      None, "Service-Worker-Allowed", "/")

# ─── Icons ───────────────────────────────────────────────────────────────────
print("\n[Icons]")
check("icon-192.png serves", "{}/static/icons/icon-192.png".format(base), 200)
check("icon-512.png serves", "{}/static/icons/icon-512.png".format(base), 200)
check("icon-192.png Content-Type is PNG", "{}/static/icons/icon-192.png".format(base), 200,
      None, "Content-Type", "image/png")

# ─── Auth pages have manifest + SW registration ──────────────────────────────
print("\n[Auth pages have SW registration]")
check("login.html has manifest.json link", "{}/login".format(base), 200, 'href="/manifest.json"')
check("login.html has SW registration", "{}/login".format(base), 200, "serviceWorker")
check("login.html has sw.js register", "{}/login".format(base), 200, "sw.js")

# ─── Auth redirect ────────────────────────────────────────────────────────────
print("\n[Auth Redirect]")
try:
    req = urllib.request.Request("{}/".format(base))
    with urllib.request.urlopen(req, timeout=5) as r:
        final_url = r.url
        body = r.read().decode("utf-8", errors="replace")
    tag = "PASS" if ("/login" in final_url or "manifest.json" in body) else "FAIL"
    results.append(("/ redirects to login", tag, "final={}".format(final_url)))
    print("  {}  / redirects to login: final={}".format(tag, final_url))
except urllib.error.HTTPError as e:
    tag = "PASS" if e.code in (301, 302) else "FAIL"
    results.append(("/ redirects unauth", tag, "status={}".format(e.code)))
    print("  {}  / redirects unauth: status={}".format(tag, e.code))

# ─── Security: API must NOT be cached ────────────────────────────────────────
print("\n[Security: API not cached]")
# API is 401 for unauthenticated, but headers should still have no-store
try:
    req = urllib.request.Request("{}/api/history".format(base))
    urllib.request.urlopen(req, timeout=5)
    results.append(("/api returns 401 unauth", "FAIL", "should 401"))
    print("  FAIL  /api/history should require auth")
except urllib.error.HTTPError as e:
    has_no_store = "no-store" in e.headers.get("Cache-Control", "").lower()
    tag = "PASS" if e.code == 401 else "FAIL"
    results.append(("/api/history requires auth (401)", tag, "status={}".format(e.code)))
    print("  {}  /api/history requires auth: status={}".format(tag, e.code))
    tag2 = "PASS" if has_no_store else "FAIL"
    results.append(("/api Cache-Control no-store", tag2, e.headers.get("Cache-Control", "none")))
    print("  {}  /api Cache-Control: {}".format(tag2, e.headers.get("Cache-Control", "none")))

# ─── Summary ─────────────────────────────────────────────────────────────────
passed = sum(1 for _, r, _ in results if r == "PASS")
failed = sum(1 for _, r, _ in results if r != "PASS")
print("\n" + "=" * 55)
print("Live HTTP: {} passed, {} failed".format(passed, failed))
if failed:
    for label, tag, detail in results:
        if tag != "PASS":
            print("  FAIL: {} ({})".format(label, detail))
    sys.exit(1)
else:
    print("ALL LIVE PWA INSTALLABILITY CHECKS PASSED")
