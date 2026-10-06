"""
PWA installability and standalone interaction validation:
  1. Manifest served via /manifest.json with Content-Type: application/manifest+json
  2. SW registration on all entry points (index, login, register)
  3. Service Worker versioning & network-first shell strategy (afd-static-shell-v2)
  4. Accessible file inputs in DOM layout tree (no display:none)
  5. Native label associations for Chromium standalone PWA system dialog triggers
  6. Drag & drop support in app.js
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
        "CACHE_NAME bumped to v2": "afd-static-shell-v2" in sw,
        "install handler": "install" in sw,
        "activate handler": "activate" in sw,
        "fetch handler": "fetch" in sw,
        "API network-only rule": "/api/" in sw,
        "auth routes network-only": "/login" in sw,
        "evidence vault network-only": "/evidence_vault" in sw,
        "network-only policy": "network-only" in sw,
        "skipWaiting": "skipWaiting" in sw,
        "clients.claim": "clients.claim" in sw,
    }.items():
        ok(name) if result else fail(name)

# --- 4. Check HTML templates & PWA File Input Accessibility ---
print("\n[4] Checking HTML templates & PWA File Input Accessibility...")
templates = [
    ("templates/index.html", True),
    ("templates/login.html", True),
    ("templates/register.html", True),
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

with open("templates/index.html", encoding="utf-8") as f:
    idx_content = f.read()

for name, result in {
    "file input NOT display:none": 'id="evidence-file-input" style="display: none;"' not in idx_content,
    "file input uses accessible class": 'class="accessible-file-input"' in idx_content,
    "label for file input in banner": '<label for="evidence-file-input"' in idx_content,
    "label for file input in modal": 'label for="evidence-file-input" class="scan-option-card"' in idx_content,
    "label for folder input in modal": 'label for="evidence-folder-input" class="scan-option-card"' in idx_content,
}.items():
    ok("index.html: {}".format(name)) if result else fail("index.html: {}".format(name))

# --- 5. Check CSS & JS for standalone PWA support ---
print("\n[5] Checking CSS & JS for standalone PWA support...")
with open("static/css/style.css", encoding="utf-8") as f:
    css_content = f.read()
for name, result in {
    "accessible-file-input CSS exists": ".accessible-file-input" in css_content,
    "drag-over banner styling": ".file-selection-banner.drag-over" in css_content,
}.items():
    ok("style.css: {}".format(name)) if result else fail("style.css: {}".format(name))

with open("static/js/app.js", encoding="utf-8") as f:
    js_content = f.read()
for name, result in {
    "stageChosenFile function": "function stageChosenFile" in js_content,
    "initDragAndDrop function": "function initDragAndDrop" in js_content,
    "showOpenFilePicker check": "showOpenFilePicker" in js_content,
    "handleSelectFileClick handler": "handleSelectFileClick" in js_content,
    "handleModalFileSelect handler": "handleModalFileSelect" in js_content,
}.items():
    ok("app.js: {}".format(name)) if result else fail("app.js: {}".format(name))

# --- 6. Check Flask app.py ---
print("\n[6] Checking app.py...")
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
    print("ALL PWA INSTALLABILITY & STANDALONE CHECKS PASSED")
