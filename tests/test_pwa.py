"""
PWA installability validation — updated for all 3 bug fixes:
  1. Manifest served via /manifest.json with Content-Type: application/manifest+json
  2. SW registration on login.html (critical — first page users see)
  3. SW registration on register.html
"""
import json
import os
import sys

errors = []
passes = []


def ok(msg):
    passes.append(msg)
    print("  PASS: {}".format(msg))


def fail(msg):
    errors.append(msg)
    print("  FAIL: {}".format(msg))


# --- 1. Validate manifest.json ---
print("\n[1] Checking static/manifest.json...")
manifest_path = "static/manifest.json"
if not os.path.isfile(manifest_path):
    fail("manifest.json not found")
else:
    with open(manifest_path) as f:
        m = json.load(f)
    required = ["name", "short_name", "start_url", "scope", "display", "icons", "theme_color", "background_color"]
    missing = [k for k in required if k not in m]
    if missing:
        fail("manifest missing fields: {}".format(missing))
    else:
        ok("All required manifest fields present")
    ok("name='{}' short_name='{}'".format(m.get("name"), m.get("short_name")))
    ok("start_url='{}' scope='{}' display='{}'".format(m.get("start_url"), m.get("scope"), m.get("display")))
    for icon in m.get("icons", []):
        ok("Icon declared: {} | {} | purpose={}".format(icon["sizes"], icon["type"], icon["purpose"]))

# --- 2. Check icon files ---
print("\n[2] Checking icon files...")
for fname in ["static/icons/icon-192.png", "static/icons/icon-512.png"]:
    if os.path.isfile(fname) and os.path.getsize(fname) > 1000:
        ok("{} exists ({} bytes)".format(fname, os.path.getsize(fname)))
    else:
        fail("{} MISSING or too small".format(fname))

# --- 3. Check service worker ---
print("\n[3] Checking static/sw.js...")
sw_path = "static/sw.js"
if not os.path.isfile(sw_path):
    fail("static/sw.js not found")
else:
    ok("static/sw.js exists")
    with open(sw_path) as f:
        sw = f.read()
    for name, result in {
        "CACHE_NAME defined": "CACHE_NAME" in sw,
        "install handler": "install" in sw,
        "activate handler": "activate" in sw,
        "fetch handler": "fetch" in sw,
        "API network-only rule": "/api/" in sw,
        "auth routes network-only": "/login" in sw,
        "network-only policy": "network-only" in sw,
        "skipWaiting": "skipWaiting" in sw,
        "clients.claim": "clients.claim" in sw,
    }.items():
        ok(name) if result else fail(name)

# --- 4. Check HTML templates ---
print("\n[4] Checking HTML templates...")
templates = [
    ("templates/index.html", True),
    ("templates/login.html", True),    # FIX: login MUST register SW
    ("templates/register.html", True), # FIX: register MUST register SW
]
for path, check_sw in templates:
    with open(path, encoding="utf-8") as f:
        c = f.read()
    for name, result in {
        "manifest link to /manifest.json": 'href="/manifest.json"' in c,
        "NOT /static/manifest.json": '/static/manifest.json' not in c,
        "theme-color meta": "theme-color" in c,
        "apple-mobile-web-app-capable": "apple-mobile-web-app-capable" in c,
        "apple-touch-icon": "apple-touch-icon" in c,
        "viewport-fit=cover": "viewport-fit=cover" in c,
        "serviceWorker registration": "serviceWorker" in c,
        "sw.js register call": "sw.js" in c,
    }.items():
        ok("{}: {}".format(os.path.basename(path), name)) if result else fail("{}: {}".format(os.path.basename(path), name))

# --- 5. Check Flask app.py ---
print("\n[5] Checking app.py...")
with open("app.py", encoding="utf-8") as f:
    app_src = f.read()
for name, result in {
    "/manifest.json route": '@app.route("/manifest.json")' in app_src,
    "pwa_manifest function": "def pwa_manifest" in app_src,
    "application/manifest+json MIME": "application/manifest+json" in app_src,
    "/sw.js route": '@app.route("/sw.js")' in app_src,
    "service_worker function": "def service_worker" in app_src,
    "Service-Worker-Allowed header": "Service-Worker-Allowed" in app_src,
    "send_static_file sw.js": 'send_static_file("sw.js")' in app_src,
}.items():
    ok("app.py: {}".format(name)) if result else fail("app.py: {}".format(name))

# --- Summary ---
print("\n" + "=" * 55)
print("RESULT: {} passed, {} failed".format(len(passes), len(errors)))
if errors:
    print("FAILURES:")
    for e in errors:
        print("  - {}".format(e))
    sys.exit(1)
else:
    print("ALL PWA INSTALLABILITY CHECKS PASSED")
