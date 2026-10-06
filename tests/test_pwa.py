"""PWA validation script — verifies all PWA assets and configuration are correct."""
import json, os, sys

errors = []
passes = []

def ok(msg): passes.append(msg); print(f"  PASS: {msg}")
def fail(msg): errors.append(msg); print(f"  FAIL: {msg}")

# --- 1. Validate manifest.json ---
print("\n[1] Checking manifest.json...")
manifest_path = "static/manifest.json"
if not os.path.isfile(manifest_path):
    fail("manifest.json not found")
else:
    with open(manifest_path) as f:
        m = json.load(f)
    required = ["name", "short_name", "start_url", "scope", "display", "icons", "theme_color", "background_color"]
    missing = [k for k in required if k not in m]
    if missing:
        fail(f"manifest missing fields: {missing}")
    else:
        ok("All required manifest fields present")
    ok(f"name='{m.get('name')}' short_name='{m.get('short_name')}'")
    ok(f"start_url='{m.get('start_url')}' scope='{m.get('scope')}' display='{m.get('display')}'")
    ok(f"theme_color='{m.get('theme_color')}' background_color='{m.get('background_color')}'")
    for icon in m.get("icons", []):
        ok(f"Icon declared: {icon['sizes']} | {icon['type']} | purpose={icon['purpose']}")

# --- 2. Check icon files ---
print("\n[2] Checking icon files...")
for fname, expected_min in [("static/icons/icon-192.png", 1000), ("static/icons/icon-512.png", 1000)]:
    if os.path.isfile(fname):
        size = os.path.getsize(fname)
        if size >= expected_min:
            ok(f"{fname} exists ({size} bytes)")
        else:
            fail(f"{fname} exists but suspiciously small ({size} bytes)")
    else:
        fail(f"{fname} MISSING")

# --- 3. Check service worker ---
print("\n[3] Checking service worker (static/sw.js)...")
sw_path = "static/sw.js"
if not os.path.isfile(sw_path):
    fail("static/sw.js not found")
else:
    ok("static/sw.js exists")
    with open(sw_path) as f:
        sw = f.read()
    checks = {
        "CACHE_NAME defined": "CACHE_NAME" in sw,
        "install handler": "install" in sw,
        "activate handler": "activate" in sw,
        "fetch handler": "fetch" in sw,
        "API network-only rule": "/api/" in sw,
        "auth routes network-only": "/login" in sw,
        "network-only comment": "network-only" in sw or "Never cache" in sw,
        "skipWaiting": "skipWaiting" in sw,
        "clients.claim": "clients.claim" in sw,
    }
    for name, result in checks.items():
        ok(name) if result else fail(name)

# --- 4. Check HTML templates ---
print("\n[4] Checking HTML templates...")
templates = [
    ("templates/index.html", True),
    ("templates/login.html", False),
    ("templates/register.html", False),
]
for path, check_sw in templates:
    with open(path, encoding="utf-8") as f:
        c = f.read()
    checks = {
        "manifest.json link": "manifest.json" in c,
        "theme-color meta": "theme-color" in c,
        "apple-mobile-web-app-capable": "apple-mobile-web-app-capable" in c,
        "apple-touch-icon": "apple-touch-icon" in c,
        "viewport-fit=cover": "viewport-fit=cover" in c,
    }
    if check_sw:
        checks["serviceWorker registration"] = "serviceWorker" in c
        checks["sw.js register call"] = "sw.js" in c
    for name, result in checks.items():
        label = f"{os.path.basename(path)}: {name}"
        ok(label) if result else fail(label)

# --- 5. Check Flask app ---
print("\n[5] Checking app.py...")
with open("app.py") as f:
    app_src = f.read()
app_checks = {
    "/sw.js route": "@app.route(\"/sw.js\")" in app_src,
    "service_worker function": "def service_worker" in app_src,
    "Service-Worker-Allowed header": "Service-Worker-Allowed" in app_src,
    "send_static_file sw.js": "send_static_file(\"sw.js\")" in app_src,
}
for name, result in app_checks.items():
    ok(f"app.py: {name}") if result else fail(f"app.py: {name}")

# --- Summary ---
print(f"\n{'='*50}")
print(f"RESULT: {len(passes)} passed, {len(errors)} failed")
if errors:
    print("FAILURES:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
else:
    print("ALL PWA CHECKS PASSED")
