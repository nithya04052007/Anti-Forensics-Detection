"""Live HTTP tests for PWA endpoints — run while Flask server is running on port 5000."""
import urllib.request
import sys

base = "http://127.0.0.1:5000"
results = []


def check(label, url, expected_status=200, expected_content=None, expected_header=None, expected_header_value=None):
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


# --- PWA Assets ---
print("\n[PWA Assets]")
check("manifest.json serves", "{}/static/manifest.json".format(base), 200, '"name"')
check("sw.js serves from /sw.js", "{}/sw.js".format(base), 200, "CACHE_NAME")
check("icon-192.png serves", "{}/static/icons/icon-192.png".format(base), 200)
check("icon-512.png serves", "{}/static/icons/icon-512.png".format(base), 200)
check("sw.js Content-Type is JS", "{}/sw.js".format(base), 200, None, "Content-Type", "javascript")
check("sw.js has no-cache", "{}/sw.js".format(base), 200, None, "Cache-Control", "no-cache")
check("login page has manifest link", "{}/login".format(base), 200, "manifest.json")

# --- Auth redirect (urllib follows redirects, so check final URL is /login) ---
print("\n[Auth Redirect]")
try:
    req = urllib.request.Request("{}/".format(base))
    with urllib.request.urlopen(req, timeout=5) as r:
        final_url = r.url
        body = r.read().decode("utf-8", errors="replace")
    # urllib followed the redirect — check it landed on login page
    tag = "PASS" if ("/login" in final_url or "Investigator Login" in body or "manifest.json" in body) else "FAIL"
    results.append(("dashboard redirects to login", tag, "final_url={}".format(final_url)))
    print("  {}  dashboard redirects to login: final_url={}".format(tag, final_url))
except urllib.error.HTTPError as e:
    tag = "PASS" if e.code in (301, 302) else "FAIL"
    results.append(("dashboard redirects unauth", tag, "status={}".format(e.code)))
    print("  {}  dashboard redirects unauth: status={}".format(tag, e.code))

# --- Summary ---
passed = sum(1 for _, r, _ in results if r == "PASS")
failed = sum(1 for _, r, _ in results if r != "PASS")
print("\n" + "=" * 50)
print("Live HTTP: {} passed, {} failed".format(passed, failed))
if failed:
    for label, tag, detail in results:
        if tag != "PASS":
            print("  FAIL: {} ({})".format(label, detail))
    sys.exit(1)
else:
    print("ALL LIVE HTTP CHECKS PASSED")
