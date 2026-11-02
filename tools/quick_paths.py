#!/usr/bin/env python3
"""Quick path enumeration for an authorized own-site check (HEAD/GET, low rate)."""
import concurrent.futures as cf
import sys
import urllib.request
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://haydarkadioglu.com"
PATHS = """
admin admin/ adminpanel admin-panel admin_panel administrator adminarea admin-area
yonetim yönetim yonetim/ panel panel/ kontrol kontrol-paneli kontrolpaneli
dashboard dash panel-admin manage management manager cms cp control
giris giriş login signin sign-in auth account accounts user users profile
app apps portal console backoffice back-office office staff
hq ops system settings config configs setup install
api/api api/v1 api/admin api/auth api/login api/users
firebase __/firebase __/firebase/init.json __/firebase/init.js
.firebaserc firebase.json serviceAccountKey.json service-account.json
admin.php admin.html admin/index.html panel.php login.php dashboard.php
private secret internal intern dev staging test beta new old backup
uploads files static assets/media media documents data db database
sitemap.xml sitemap_index.xml robots.txt security.txt .well-known/security.txt
netlify .netlify/functions .netlify/identity _headers _redirects
""".split()

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; authorized-selfcheck/1.0)"}


def probe(path: str) -> tuple[str, int, int]:
    url = f"{BASE.rstrip('/')}/{path.lstrip('/')}"
    req = urllib.request.Request(url, headers=HEADERS, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = r.read(512)
            return path, r.status, len(body)
    except urllib.error.HTTPError as e:
        return path, e.code, 0
    except Exception:
        return path, 0, 0


hits = []
with cf.ThreadPoolExecutor(max_workers=8) as ex:
    for path, code, size in ex.map(probe, PATHS):
        if code and code not in (404, 410):
            hits.append((code, path, size))

for code, path, size in sorted(hits, key=lambda x: (x[0], x[1])):
    print(f"{code}  /{path}  ({size}B)")
print(f"\ntoplam {len(PATHS)} yol, {len(hits)} ilginç yanıt")
