import urllib.request, re, gzip

req = urllib.request.Request(
    "https://cdn.grok.com/_next/static/chunks/972ad090d236fa31.js",
    headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip"}
)
with urllib.request.urlopen(req, timeout=30) as resp:
    raw = resp.read()
    if resp.headers.get("Content-Encoding", "") == "gzip":
        js = gzip.decompress(raw).decode("utf-8", errors="replace")
    else:
        js = raw.decode("utf-8", errors="replace")

print(f"Bundle len: {len(js)}")

paths = set()
i = 0
while True:
    p = js.find("/rest/", i)
    if p == -1:
        break
    if p > 0 and js[p-1] in '"\'`':
        e = p + 6
        while e < len(js) and js[e] not in '"\'`\\ \t\n;,(){}><':
            e += 1
        path = js[p:e]
        if 7 < len(path) < 100:
            paths.add(path)
    i = p + 1

print("=== /rest/ paths ===")
for path in sorted(paths):
    print(f"  {path}")

# Also search for sandbox_environment
for term in ["sandbox_environment", "sandbox_env", "environments", "share_link", "highlights", "voice_share", "livekit/token"]:
    idx = js.find(term)
    if idx >= 0:
        print(f"\n{term}: ...{js[max(0,idx-50):idx+200]}...")
