# webkit-host

> Local LAN payload server for PS4 WebKit browser testing. Serves static files from `./public/` over HTTP on your local network.

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/zoofier/webkit-host.git
cd webkit-host

# 2. Run (Python 3 — no dependencies needed)
python server.py

# 3. Point your PS4 browser at the printed LAN URL
#    e.g. http://192.168.1.x:8080/index.html
```

---

## Structure

```
webkit-host/
├── server.py          ← local HTTP server (zero deps)
├── public/
│   └── index.html     ← landing page — drop your scripts here
└── README.md
```

---

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `8080` | Port to listen on |
| `--host` | `0.0.0.0` | Interface to bind |

```bash
python server.py --port 9090
```

---

## Adding Payloads

Drop any `.js` or `.html` files into `./public/` and link them from `index.html`. The server logs every request with timestamp and client IP.

---

*zoofier / webkit-host*
