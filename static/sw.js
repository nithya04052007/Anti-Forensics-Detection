/**
 * Anti-Forensics Detection System — Secure Service Worker
 *
 * SECURITY POLICY:
 * This application handles sensitive forensic evidence and private user data.
 * Therefore this service worker intentionally does NOT cache:
 *   - Any /api/* responses (scan results, history, reports, stats, ML data)
 *   - Any evidence files or vault contents
 *   - Any user-specific or session-specific data
 *   - Any PDF reports
 *   - Authentication/login state
 *
 * ONLY the following non-sensitive static shell assets are cached:
 *   - CSS stylesheet
 *   - Frontend JavaScript
 *   - PWA icons
 *   - Web manifest
 *
 * All authenticated API requests go NETWORK-ONLY (never cached, never stored).
 */

const CACHE_NAME = 'afd-static-shell-v2';

// Static shell assets that are safe to cache (non-sensitive, non-user-specific)
const STATIC_SHELL = [
  '/static/css/style.css',
  '/static/js/app.js',
  '/manifest.json',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

// ─── Install: pre-cache only the static shell ───────────────────────────────
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_SHELL);
    }).then(() => {
      // Activate immediately without waiting for existing tabs to close
      return self.skipWaiting();
    })
  );
});

// ─── Activate: remove stale caches from previous versions ───────────────────
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    }).then(() => self.clients.claim())
  );
});

// ─── Fetch: strict security-first routing ───────────────────────────────────
self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // RULE 1 — API calls: ALWAYS network-only. Never cache user data.
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(event.request));
    return;
  }

  // RULE 2 — Auth routes: ALWAYS network-only.
  if (
    url.pathname === '/login' ||
    url.pathname === '/logout' ||
    url.pathname === '/register'
  ) {
    event.respondWith(fetch(event.request));
    return;
  }

  // RULE 3 — Evidence vault / reports: ALWAYS network-only.
  if (
    url.pathname.startsWith('/evidence_vault') ||
    url.pathname.startsWith('/reports') ||
    url.pathname.startsWith('/data/')
  ) {
    event.respondWith(fetch(event.request));
    return;
  }

  // RULE 4 — Non-GET requests (POST/DELETE etc.): ALWAYS network-only.
  if (event.request.method !== 'GET') {
    event.respondWith(fetch(event.request));
    return;
  }

  // RULE 5 — Static shell assets: Network-first with cache fallback.
  // Fetches fresh CSS/JS when online so standalone PWA updates immediately,
  // falling back to cache if offline. Sensitive API/auth data is NEVER handled here.
  if (STATIC_SHELL.includes(url.pathname)) {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (
            response &&
            response.status === 200 &&
            response.type === 'basic'
          ) {
            const toCache = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, toCache));
          }
          return response;
        })
        .catch(() => {
          return caches.match(event.request);
        })
    );
    return;
  }

  // RULE 6 — Everything else (HTML pages, unknown routes): network-only.
  // This includes the main dashboard (/) which requires authentication.
  event.respondWith(fetch(event.request));
});
