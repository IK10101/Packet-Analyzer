# Deep Packet Inspection Engine

A C++17 DPI engine that parses real PCAP network captures, classifies traffic across 18+ application types, performs regex-based payload pattern matching, and exports structured JSON reports.

> Built by [Ishit Kumar](https://github.com/IK10101)

---

## Features

- **TLS SNI Extraction** — Identifies apps (YouTube, Discord, TikTok, Zoom etc.) from encrypted HTTPS traffic
- **HTTP Host Parsing** — Classifies plain HTTP traffic by domain
- **Regex Payload Pattern Matching** — Scans HTTP payloads for sensitive keywords (passwords, tokens, secrets) — similar to Snort/Suricata IDS rules
- **Structured JSON Reports** — Exports per-flow metadata (5-tuple, SNI, app type, block status, matched patterns)
- **Flow-Based Blocking** — Block by IP, application type, or domain substring
- **Multi-threaded Pipeline** — 4-stage architecture (Reader → Load Balancer → Fast Path → Output Writer)

---

## What is DPI?

**Deep Packet Inspection** examines the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at IP headers, DPI looks *inside* the packet payload.

Even though HTTPS is encrypted, the destination domain name is visible in plaintext in the TLS Client Hello handshake — this is called **SNI (Server Name Indication)**. Our engine extracts this to identify applications without breaking encryption.

```
TLS Client Hello:
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← extracted here
```

---

## Project Structure

```
Packet-Analyzer/
├── include/
│   ├── pcap_reader.h          # PCAP file reading
│   ├── packet_parser.h        # Protocol parsing (Ethernet/IP/TCP/UDP)
│   ├── sni_extractor.h        # TLS SNI + HTTP Host extraction
│   ├── types.h                # FiveTuple, AppType, flow structures
│   ├── json_reporter.h        # JSON report generation  ← Added
│   ├── pattern_matcher.h      # Regex payload scanner   ← Added
│   ├── thread_safe_queue.h    # Thread-safe queue
│   └── dpi_engine.h           # Multi-threaded orchestrator
│
├── src/
│   ├── main_working.cpp       # ★ Simple version (start here)
│   ├── dpi_mt.cpp             # ★ Multi-threaded version
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   └── types.cpp
│
├── generate_test_pcap.py      # Generates test PCAP with 18 app types
├── test_dpi.pcap              # Sample capture
└── output.pcap.report.json    # Sample JSON report output
```

---

## Building (Windows — MSYS2 UCRT64)

Install MSYS2 from https://www.msys2.org, then open the MSYS2 UCRT64 terminal:

```bash
pacman -S mingw-w64-ucrt-x86_64-gcc git
git clone https://github.com/IK10101/Packet-Analyzer.git
cd Packet-Analyzer
```

**Build:**
```bash
g++ -std=c++17 -O2 -I include -o dpi_simple.exe src/main_working.cpp src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

## Building (Linux / macOS)

```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

---

## Running

**Generate test data:**
```bash
python3 generate_test_pcap.py
```

**Basic run:**
```bash
./dpi_simple.exe test_dpi.pcap output.pcap
```

**With blocking rules:**
```bash
./dpi_simple.exe test_dpi.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain tiktok
```

**With pattern matching:**
```bash
./dpi_simple.exe test_dpi.pcap output.pcap --pattern "password" --pattern "token" --pattern "secret"
```

**Check JSON report:**
```bash
cat output.pcap.report.json
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║                    DPI ENGINE v1.0                           ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Added pattern: password
[Rules] Added pattern: token
[DPI] Processing packets...

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:              77                               ║
║ Forwarded:                  77                               ║
║ Dropped:                     0                               ║
║ Active Flows:               43                               ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION BREAKDOWN                     ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                    ║
║ Unknown              16  20.8% ####                          ║
║ DNS                   4   5.2% #                             ║
║ YouTube               1   1.3%                               ║
║ Discord               1   1.3%                               ║
║ TikTok                1   1.3%                               ║
║ ...                                                          ║
╚══════════════════════════════════════════════════════════════╝
[JSON] Report saved to: output.pcap.report.json
```

**Sample JSON report:**
```json
{
  "timestamp": "2026-06-27T09:01:17",
  "summary": {
    "total_packets": 77,
    "forwarded": 77,
    "dropped": 0,
    "active_flows": 43
  },
  "app_breakdown": {
    "HTTPS": 39,
    "YouTube": 1,
    "Discord": 1
  },
  "flows": [
    {
      "src_ip": "192.168.1.100",
      "dst_ip": "142.250.185.110",
      "src_port": 58867,
      "dst_port": 443,
      "app": "YouTube",
      "sni": "www.youtube.com",
      "packets": 3,
      "blocked": false,
      "matched_patterns": []
    }
  ]
}
```

---

## How It Works

### Packet Pipeline

```
PCAP File
    │
    ▼
PcapReader ──► PacketParser ──► SNI/HTTP Extractor
                                        │
                                        ▼
                              Flow Table (5-tuple hash)
                                        │
                              ┌─────────┴──────────┐
                              │                    │
                        Pattern Matcher      Blocking Rules
                              │                    │
                              └─────────┬──────────┘
                                        │
                                        ▼
                              Forward / Drop + JSON Report
```

### Supported Applications

YouTube, Google, Facebook, Instagram, Twitter/X, TikTok, Discord, Telegram, Zoom, Spotify, Amazon, GitHub, Cloudflare, Apple, Netflix, HTTP, HTTPS, DNS

---

## Blocking Rules

| Flag | Example | Effect |
|------|---------|--------|
| `--block-ip` | `--block-ip 192.168.1.50` | Drops all traffic from this IP |
| `--block-app` | `--block-app YouTube` | Drops all YouTube flows |
| `--block-domain` | `--block-domain tiktok` | Drops any SNI containing "tiktok" |
| `--pattern` | `--pattern "password"` | Flags HTTP payloads matching regex |

---

## What I Added (vs Original)

| Feature | File | Description |
|---------|------|-------------|
| JSON Reporter | `include/json_reporter.h` | Exports full flow metadata as structured JSON |
| Pattern Matcher | `include/pattern_matcher.h` | Regex-based HTTP payload inspection engine |
| Integrated reporting | `src/main_working.cpp` | Wired both features into the main pipeline |

---

## Resume Highlights

- Parses raw Ethernet/IP/TCP/UDP headers from binary PCAP data in C++17
- Extracts TLS SNI from raw byte offsets in Client Hello handshakes
- Implements regex payload scanning similar to Snort/Suricata IDS rule matching
- Exports structured JSON with per-flow 5-tuple, application, and pattern match metadata
- Tracks 43 concurrent flows across 18 application types from a single capture

---

## License

MIT