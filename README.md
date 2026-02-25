<div align="center">

# 🛡️ Sentinel

**A beautiful, local network security monitoring dashboard**

![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776ab?style=flat-square&logo=python&logoColor=white)
![License MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Local Only](https://img.shields.io/badge/Network-Local%20Only-blue?style=flat-square)
![Read Only](https://img.shields.io/badge/Access-Read%20Only-purple?style=flat-square)

*Real-time visibility into connections, ports, firewall, and threats—all in one dark-themed interface.*

[Features](#-features) • [Installation](#-installation) • [Screenshots](#-screenshots) • [Security](#-security-model) • [Contributing](#-contributing)

</div>

---

## 📸 Screenshots

<div align="center">

![Sentinel Dashboard](screenshots/dashboard.png)

*Clean, dark interface with real-time threat detection*

</div>

---

## ✨ Features

### 🔌 Real-Time Monitoring
- 📡 **Active Connections** — All network connections with process details and country flags
- 🚪 **Listening Ports** — Open ports with owning processes
- 🔥 **Firewall Status** — UFW status and active rules
- 🌐 **Network Interfaces** — Traffic stats with sparkline graphs
- 📈 **Connection History** — Visual trend line over time

### 💻 System Health
- ⚡ **CPU Usage** — Real-time percentage with visual bar
- 🧠 **Memory Usage** — Current utilization display
- ⏱️ **System Uptime** — Time since boot
- 🖥️ **Host Info** — OS, architecture, hostname

### 🚨 Threat Detection
- 🔴 **Unusual Ports** — Flags high/ephemeral listening ports
- 👻 **Unknown Processes** — Identifies suspicious processes
- 🌍 **Foreign IPs** — Geolocation-based flagging
- 🔄 **Excessive Connections** — Rate limiting alerts
- 📋 **Threat Log** — Session-based security event log
- 🎯 **Top Talkers** — Most active network processes

### 🗺️ GeoIP Intelligence
- 📦 **Offline Mode** — MaxMind GeoLite2 database support
- ☁️ **Online Fallback** — ip-api.com with 1-hour cache
- 🔒 **Privacy First** — Private IPs never leave your machine

### 🎨 UI Polish
- 🎬 **Boot Sequence** — Terminal-style initialization animation
- ⌨️ **Typewriter Title** — SENTINEL types out on load
- 📺 **CRT Effect** — Subtle scan line overlay
- ✨ **Smooth Animations** — Staggered card entrances
- 💫 **Threat Flash** — High threats flash to alert you

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      API LAYER                              │
│   Flask routes serving JSON endpoints and HTML template     │
├─────────────────────────────────────────────────────────────┤
│                   PROCESSING LAYER                          │
│   Data normalization, threat detection, formatting          │
├─────────────────────────────────────────────────────────────┤
│                 DATA COLLECTION LAYER                       │
│   psutil, subprocess, socket - raw system data gathering    │
└─────────────────────────────────────────────────────────────┘
```

Single-file design: everything in `app.py` for simplicity and portability.

---

## 🔒 Security Model

> **Beautiful. Focused. Local. Read-only. One purpose. Do it well.**

| Principle | Implementation |
|-----------|----------------|
| 📖 **Read-Only** | No system modifications, process control, or file writes |
| 🏠 **Local-Only** | Binds to `127.0.0.1`; startup warns if changed |
| 🔐 **No Dynamic Shell** | All subprocess commands hardcoded |
| 🚫 **No Auth Required** | Local-only = no credentials to steal |
| ♻️ **No Persistence** | State resets on restart (by design) |
| 🧭 **Path Privacy** | Executable paths truncated to binary name before API responses |
| 📦 **Minimal Dependencies** | Flask + psutil only |

### Privacy

- Sentinel makes one outbound **HTTPS** request per unique external IP to ip-api.com for geolocation.
- All other data is collected locally. To disable geo lookups entirely, set the `SENTINEL_GEO_LOOKUP=false` environment variable or edit `app.py`.

See [SECURITY.md](SECURITY.md) for full security documentation.

---

## 📋 Requirements

- **Python** 3.10 or higher
- **Linux** (Ubuntu/Debian tested)
- **UFW** (optional, for firewall monitoring)

### Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| Flask | 3.0.0 | Web framework |
| Werkzeug | 3.0.1 | WSGI utilities |
| psutil | 5.9.7 | System monitoring |

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sentinel.git
cd sentinel

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run Sentinel
python app.py
```

Open [http://localhost:5000](http://localhost:5000) — dashboard auto-refreshes every 5 seconds.

### Optional: UFW Status Access

```bash
sudo visudo
# Add at bottom:
yourusername ALL=(ALL) NOPASSWD: /usr/sbin/ufw status verbose
```

### Optional: Offline GeoIP

1. Download [MaxMind GeoLite2-Country.mmdb](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
2. Place in sentinel directory
3. `pip install geoip2`

---

## 🛡️ Security Audit

- Latest audit: 2026-02-25 — Bandit, pip-audit, hardcoded secrets, Flask debug, and host binding checks **all passed**.
- Recommended maintenance: run `pip-audit -r requirements.txt` after dependency changes and before releases.

---

## 🔧 Configuration

Edit constants in `app.py` or set environment variables:

```python
HOME_COUNTRY = os.environ.get("SENTINEL_HOME_COUNTRY", "US") # Your country code
CONNECTION_RATE_THRESHOLD = 10   # Connections before flagging
GEOIP_CACHE_TTL = 3600          # Cache duration (seconds)
GEO_LOOKUP_ENABLED = os.environ.get("SENTINEL_GEO_LOOKUP", "true").lower() == "true" # Set False to disable outbound geo lookups
HOST = "127.0.0.1"              # Bind address (warns if changed)
```

---

## 🔗 API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard (HTML) |
| `GET /api/dashboard` | All data (JSON) |
| `GET /api/connections` | Active connections |
| `GET /api/ports` | Listening ports |
| `GET /api/interfaces` | Network interfaces |
| `GET /api/firewall` | UFW status |
| `GET /api/system` | System info |
| `GET /api/health` | Health check |

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Run security audit (`pip-audit -r requirements.txt`)
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing`)
6. Open a Pull Request

See [SECURITY.md](SECURITY.md) for security checklist.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Made with 🛡️ for network security enthusiasts**

</div>
