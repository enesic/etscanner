# e'tscanner 🔍

> Asynchronous TCP/UDP Port Scanner, Service Analyzer & Security Fingerprinter — built with pure Python asyncio. No Nmap. No external dependencies.

---

## What is it?

**e'tscanner** is a fast, concurrent, and extensible network security scanner written in Python. It goes beyond simple port discovery — it fingerprints services, inspects SSL/TLS certificates, detects web technologies, matches known CVEs, and supports full subnet scanning with host discovery.

Built for pentesters, bug bounty hunters, and security engineers who want a clean, scriptable, dependency-free alternative.

---

## Features

| Category | Feature |
|---|---|
| ⚡ **Scanning** | Async TCP & UDP scanning with `asyncio` |
| 🎯 **Targeting** | Single IP, CIDR (`/24`), dash range (`10.0.0.1-50`), hostname, comma list |
| 🔍 **Host Discovery** | Ping sweep before subnet scan — only scan live hosts |
| 🏷️ **Banner Grabbing** | Read initial server responses to identify services |
| 🖥️ **OS Fingerprinting** | TTL + TCP window size analysis to guess the OS |
| 🔒 **SSL/TLS Inspector** | Cert expiry, issuer, SAN discovery, weak cipher/protocol detection |
| 🌐 **HTTP Fingerprinter** | Page title, Server header, tech stack detection, security header audit |
| 🛡️ **CVE Matching** | Match service banners against a built-in vulnerability database |
| 🌍 **Subdomain Discovery** | DNS-based enumeration using a built-in wordlist |
| ⏱️ **Timing Profiles** | 5 presets from `paranoid` (stealth) to `insane` (max speed) |
| 🎛️ **Port Profiles** | 11 presets: `web`, `db`, `mail`, `smb`, `k8s`, `docker`, and more |
| 💾 **Export** | Save results as JSON, CSV, or TXT |
| 🔁 **Retry / Delay** | Configurable retries and inter-probe delay |
| 🎨 **Colored Output** | Clean ANSI-colored terminal UI with live progress bar |
| 🐍 **Pure Python** | Zero external dependencies — stdlib only |

---

## Project Structure

```
etscanner/
├── core/
│   ├── __init__.py
│   ├── scanner.py          # AsyncPortScanner       — concurrent TCP scanning
│   ├── udp_scanner.py      # AsyncUDPScanner        — UDP port scanning
│   ├── analyzer.py         # ServiceAnalyzer        — banner grabbing
│   ├── fingerprint.py      # OSFingerprinter        — TTL/window OS detection
│   ├── ssl_inspector.py    # SSLInspector           — TLS cert & cipher analysis
│   ├── http_fingerprint.py # HTTPFingerprinter      — web tech & header audit
│   ├── cve_matcher.py      # CVEMatcher             — built-in CVE database
│   ├── host_discovery.py   # HostDiscoverer         — ping sweep / live host detection
│   └── discovery.py        # SubdomainDiscoverer    — DNS subdomain enumeration
├── utils/
│   ├── __init__.py
│   ├── display.py          # Colors, banner, print helpers
│   ├── progress.py         # Terminal progress bar
│   ├── exporter.py         # JSON / CSV / TXT export
│   └── target_parser.py    # CIDR, range, hostname resolution
├── main.py                 # CLI entrypoint
└── .gitignore
```

---

## Requirements

- Python **3.10+**
- No external packages — uses Python stdlib only

---

## Installation

### 🐧 Linux / Kali / Parrot (Önerilen)

```bash
# 1. Repoyu klonla
git clone https://github.com/enesic/etscanner.git
cd etscanner

# 2. Python sürümünü kontrol et (3.10+ gerekli)
python3 --version

# 3. Çalıştır
python3 main.py --help
```

### 🔄 Güncelleme (En Son Sürüme Geç)

Eğer repoyu daha önce klonladıysan, yeni özellikleri almak için:

```bash
cd etscanner
git pull origin master
```

> VMware'deki sanal makinende çalıştırıyorsan bu komutu VM terminalinde çalıştırman yeterli.

### 🪟 Windows

```powershell
# Repoyu klonla
git clone https://github.com/enesic/etscanner.git
cd etscanner

# Çalıştır
python main.py --help
```

> **Windows Notu:** UDP tarama için yönetici (Administrator) olarak çalıştırman gerekebilir.

---

## Usage

```bash
# Linux/Kali
python3 main.py -t <hedef> [seçenekler]

# Windows
python main.py -t <hedef> [seçenekler]
```

### Tüm Argümanlar

| Flag | Açıklama | Varsayılan |
|------|----------|-----------|
| `-t` | Hedef: IP, CIDR, aralık, hostname | *(zorunlu)* |
| `-p` | Taranacak portlar (`80,443,1-1024`) | `1-1024` |
| `--profile` | Port profili adı | — |
| `--top N` | En yaygın N portu tara | — |
| `--udp` | UDP tarama modu | TCP |
| `--timing` | Timing profili | `normal` |
| `-c` | Eşzamanlı bağlantı sayısını geçersiz kıl | profil varsayılanı |
| `-T` | Timeout süresini geçersiz kıl (saniye) | profil varsayılanı |
| `--retry` | Başarısız bağlantılar için yeniden deneme | `0` |
| `--skip-discovery` | Çoklu hedefte host discovery'yi atla | kapalı |
| `-o` | Çıktı dosyası (`.json`, `.csv`, `.txt`) | — |
| `-d` | Domain için subdomain discovery | — |

---

## Timing Profiles

Control scan speed vs. stealth with `--timing`:

| Profile | Concurrent | Timeout | Delay | Use Case |
|---------|-----------|---------|-------|----------|
| `paranoid` | 10 | 5.0s | 1.0s | Evade IDS/IPS |
| `sneaky` | 50 | 3.0s | 0.2s | Low-noise recon |
| `normal` | 500 | 1.5s | 0s | Default |
| `aggressive` | 1000 | 0.8s | 0s | Fast internal scan |
| `insane` | 5000 | 0.3s | 0s | Maximum speed |

---

## Port Profiles

Use `--profile <name>` instead of specifying ports manually:

| Profile | Ports |
|---------|-------|
| `web` | 80, 443, 8080, 8443, 8000, 8888, 3000, 3001, 4000, 5000, 9090 |
| `db` | 3306, 5432, 1433, 1521, 27017, 6379, 9200, 5984, 7474, 8086 |
| `mail` | 25, 110, 143, 465, 587, 993, 995 |
| `ssh` | 22, 2222, 22222 |
| `ftp` | 20, 21, 2121 |
| `smb` | 135, 137, 138, 139, 445 |
| `dns` | 53, 5353 |
| `rdp` | 3389, 3388 |
| `vnc` | 5900–5903 |
| `docker` | 2375, 2376, 4243 |
| `k8s` | 6443, 8080, 10250, 10255, 2379, 2380 |

---

## Target Formats

```bash
# Single IP
python main.py -t 192.168.1.1

# CIDR subnet (auto host discovery)
python main.py -t 192.168.1.0/24

# Dash range
python main.py -t 10.0.0.1-50

# Hostname
python main.py -t scanme.nmap.org

# Comma-separated list
python main.py -t 192.168.1.1,10.0.0.1,172.16.0.5
```

---

## Examples

```bash
# Full subnet web scan with aggressive timing
python main.py -t 192.168.1.0/24 --profile web --timing aggressive

# Stealthy top-100 scan with output
python main.py -t 10.0.0.1 --top 100 --timing sneaky -o report.json

# Full SMB analysis
python main.py -t 192.168.1.1 --profile smb

# Kubernetes port check
python main.py -t 10.0.0.1 --profile k8s --timing aggressive

# UDP scan with retry
python main.py -t 192.168.1.1 -p 53,161,500 --udp --retry 2

# Web fingerprinting with SSL inspection
python main.py -t scanme.nmap.org -p 80,443 --timing normal

# Subdomain enumeration
python main.py -d example.com

# Export results to CSV
python main.py -t 192.168.1.1 --top 1000 -o results.csv
```

---

## Example Output

```
       ' _
      / / |_
  ___/ /| __|___  ___ __ _ _ __  _ __   ___ _ __
 / _ \/ | |_/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
|  __/  | |_\__ \ (_| (_| | | | | | | |  __/ |
 \___|   \__|___/\___\__,_|_| |_|_| |_|\___|_|

  e'tscanner - Asynchronous TCP Port Scanner

[*] Targets    : 1 host(s)
[*] Ports      : 1024
[*] Mode       : TCP  |  Timing: normal  (concurrent=500, timeout=1.5s, delay=0.0s)

────────────────────────────────────────────────────
[*] Scanning: 192.168.1.1
────────────────────────────────────────────────────

  Scanning: [████████████████████████████████████████] 100.0% (1024/1024) | 9.4s elapsed

[+] Found 3 open port(s) in 9.42s
[*] Grabbing banners...
[*] Running OS fingerprinting...
[+] OS Guess: Linux 3.x-6.x  (Confidence: Medium, TTL=64, Window=14600)
[*] Inspecting SSL/TLS...
[*] Fingerprinting HTTP services...

[+] Scan Report — 192.168.1.1
    → Port 22 is open  (SSH-2.0-OpenSSH_8.9p1 Ubuntu)
    → Port 80 is open  (Unknown Service)
      [HTTP] Port 80 — HTTP 200
             Title   : Apache2 Ubuntu Default Page
             Server  : Apache/2.4.52 (Ubuntu)
             Tech    : Apache
             SecHdrs : 1/6 present
             ⚠ Missing security headers: HSTS, CSP, X-Frame-Options, ...
    → Port 443 is open (Unknown Service)
      [SSL] Port 443 — TLS 1.3
             CN      : example.com
             Issuer  : Let's Encrypt
             Expires : 2025-06-14  (87d remaining)
             SANs    : example.com, www.example.com

[*] Total scan time: 14.31 seconds.
```

---

## How It Works

1. **Target Resolution** — Parses IP, CIDR, range, or hostname into a list of targets.
2. **Host Discovery** — On multi-host targets, performs a TCP ping sweep to find live hosts first.
3. **Port Scanning** — `AsyncPortScanner` runs concurrent TCP connections gated by a semaphore with configurable timing.
4. **Banner Grabbing** — `ServiceAnalyzer` reads the initial server response to identify services.
5. **OS Fingerprinting** — Analyses TTL and TCP window size to estimate the target OS.
6. **SSL Inspection** — Performs a TLS handshake and extracts certificate metadata and cipher info.
7. **HTTP Fingerprinting** — Sends HEAD/GET requests to detect web technologies and audit security headers.
8. **CVE Matching** — Matches banners against a built-in vulnerability database.
9. **Export** — Writes structured results to JSON, CSV, or TXT.

---

## Disclaimer

> ⚠️ This tool is intended for **educational purposes** and **authorized security assessments only**.
> Scanning systems without explicit permission is **illegal and unethical**.
> Always ensure you have proper authorization before scanning any host.

---

## License

MIT License — free to use, modify, and distribute.
