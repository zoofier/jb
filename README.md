# zoof13r // PS4 13.52 Payload Host

GitHub Pages hosted exploit launcher — same pattern as raw13g.

## Deploy to GitHub Pages

```bash
# 1. create a new repo on GitHub (e.g. zoofier/ps4-jb)
git init
git add .
git commit -m "zoof13r 13.52 payload host"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

Then: **GitHub repo → Settings → Pages → Source: main / root → Save**

Your PS4 points to:
```
https://YOUR_USERNAME.github.io/YOUR_REPO/jb.html
```

Log view:
```
https://YOUR_USERNAME.github.io/YOUR_REPO/jb.html?log=1
```

## Pages

| Page | Purpose |
|------|---------|
| `index.html` | Landing / link hub |
| `jb.html` | Exploit loader — send PS4 here |
| `jb.html?log=1` | Same + live step log |
| `jb.html?verbose=1&log=1` | Full verbose output |

## Local fallback (optional)

```bash
python server.py
# → http://YOUR_LAN_IP:8080/jb.html
```
Includes `/t` telemetry endpoint so exploit logs stream to your terminal.
