# e'tscanner 🔍

> Asynchronous TCP Port Scanner & Service Analyzer — built with pure Python asyncio. No Nmap. No RustScan. No external dependencies.

---

## What is it?

**e'tscanner** is a lightweight, fast, and concurrent TCP port scanner written in Python. It discovers open ports on a target host and performs **banner grabbing** to identify running services — all without relying on external tools.

It uses Python's built-in `asyncio` library with a **semaphore-controlled concurrency** model, making it efficient even when scanning thousands of ports simultaneously.

---

## Features

- ⚡ **Async-powered** — scans hundreds of ports concurrently using `asyncio`
- 🔒 **Semaphore limiting** — avoids overwhelming the target or exhausting local resources
- 🏷️ **Banner grabbing** — reads the initial server response to identify services
- 🧩 **HTTP probing** — falls back to an HTTP HEAD request if the server doesn't speak first
- 🎨 **Colored terminal output** — clean, readable results with ANSI color formatting
- 🛠️ **Pure Python** — zero external dependencies

---

## Project Structure

```
etscanner/
├── core/
│   ├── __init__.py
│   ├── scanner.py       # AsyncPortScanner — concurrent TCP port scanning
│   └── analyzer.py      # ServiceAnalyzer  — banner grabbing & service detection
├── utils/
│   ├── __init__.py
│   └── display.py       # Terminal formatting, colors, and ASCII banner
├── main.py              # CLI entrypoint (argparse integration)
└── .gitignore
```

---

## Requirements

- Python **3.10+** (uses built-in `asyncio` only)
- No external packages required

---

## Usage

```bash
python main.py -t <target> -p <ports>
```

### Arguments

| Flag | Long form | Description | Default |
|------|-----------|-------------|---------|
| `-t` | `--target` | Target IP address or hostname | *(required)* |
| `-p` | `--ports` | Ports to scan (see formats below) | `1-1024` |
| `-c` | `--concurrent` | Max concurrent connections | `500` |

### Port Format Examples

```bash
# Scan a single port
python main.py -t 192.168.1.1 -p 80

# Scan multiple specific ports
python main.py -t 192.168.1.1 -p 80,443,8080

# Scan a range of ports
python main.py -t 192.168.1.1 -p 1-1024

# Mix of specific ports and ranges
python main.py -t 192.168.1.1 -p 22,80,443,8000-9000

# Scan all ports with higher concurrency
python main.py -t 192.168.1.1 -p 1-65535 -c 1000
```

### Example Output

```
       ' _                                     
      / / |_                                   
  ___/ /| __|___  ___ __ _ _ __  _ __   ___ _ __ 
 / _ \/ | |_/ __|/ __/ _` | '_ \| '_ \ / _ \ '__|
|  __/  | |_\__ \ (_| (_| | | | | | | |  __/ |   
 \___|   \__|___/\___\__,_|_| |_|_| |_|\___|_|   

  e'tscanner - Asynchronous TCP Port Scanner

[*] Target: 192.168.1.1
[*] Ports to scan: 1024
[*] Starting port scan...

[+] Found 3 open ports. Grabbing banners...

[+] Scan Report for 192.168.1.1:
    → Port 22 is open  (SSH-2.0-OpenSSH_8.9p1)
    → Port 80 is open  (HTTP/1.1 200 OK)
    → Port 443 is open (Unknown Service)

[*] Total scan time: 4.31 seconds.
```

---

## How It Works

1. **Port Scanning** — `AsyncPortScanner` creates async TCP connection tasks for all target ports and runs them concurrently, gated by a `asyncio.Semaphore` to cap simultaneous connections.

2. **Service Analysis** — `ServiceAnalyzer` connects to each open port and attempts to read an initial banner. If the server stays silent, it sends a generic HTTP HEAD probe to elicit a response.

3. **Display** — Results are printed to the terminal with color-coded output for quick readability.

---

## Disclaimer

> ⚠️ This tool is intended for **educational purposes** and **authorized security assessments only**.  
> Scanning systems without explicit permission is **illegal and unethical**.  
> Always ensure you have proper authorization before scanning any host.

---

## License

MIT License — feel free to use, modify, and distribute.
