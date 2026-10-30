# Deep Packet Inspection Engine
 
A C++17 DPI engine that parses real PCAP network captures, classifies traffic across 18+ application types, performs regex-based payload pattern matching, and exports structured JSON reports.
 
> Built by [Ishit Kumar](https://github.com/IK10101)


 ## Demo
[▶ Watch Demo](https://www.youtube.com/watch?v=tbHb-MGs1nA)

---
 
## Features
 
- **TLS SNI Extraction** — Identifies apps (YouTube, Discord, TikTok, Zoom etc.) from encrypted HTTPS traffic by reading raw Client Hello byte offsets
- **HTTP Host Parsing** — Classifies plain HTTP traffic by domain
- **Regex Payload Pattern Matching** — Scans HTTP payloads for sensitive keywords (passwords, tokens, secrets) — similar to Snort/Suricata IDS rules
- **Structured JSON Reports** — Exports per-flow metadata (5-tuple, SNI, app type, block status, matched patterns)
- **Flow-Based Blocking** — Block by IP, application type, or domain substring
- **Multi-threaded Pipeline** — 4-stage architecture (Reader → Load Balancer → Fast Path → Output Writer) with consistent Five-Tuple hashing for zero data races
---
 
## Real-World Validation
 
Tested on real Wireshark sample captures — not just synthetic data:
 
| Capture | Packets | Flows | Result |
|---|---|---|---|
| `dns.pcap` | 7 | 7 | 100% classified as DNS ✅ |
| `http_google.pcapng` | 12 | 2 | Correctly identified `www.google.com` ✅ |
| `http_dvwa_clearlogin.pcapng` | 54 | 4 | Detected `password`, `username`, `login` fields in HTTP payload ✅ |
 
### DVWA Credential Detection (most significant result)
 
Running the engine on a real DVWA (Damn Vulnerable Web Application) login capture with pattern matching:
 
```bash
./dpi_simple.exe dvwa_fixed.pcap dvwa_output.pcap --pattern "password" --pattern "username" --pattern "login"
```
 
Output:
```
[Rules] Added pattern: password
[Rules] Added pattern: username
[Rules] Added pattern: login
[DPI] Processing packets...
[PATTERN MATCH] 10.2.2.101 -> 10.2.2.104 matched: "login"
[PATTERN MATCH] 10.2.2.101 -> 10.2.2.104 matched: "login"
[PATTERN MATCH] 10.2.2.101 -> 10.2.2.104 matched: "password" "username" "login"
[PATTERN MATCH] 10.2.2.101 -> 10.2.2.104 matched: "login"
```
 
The engine successfully detected HTTP login credentials being transmitted in plaintext — exactly what an IDS like Snort does in production.
 
---
 
## What is DPI?
 
**Deep Packet Inspection** examines the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at IP headers, DPI looks *inside* the packet payload.
 
Even though HTTPS is encrypted, the destination domain name is visible in plaintext in the TLS Client Hello handshake — this is called **SNI (Server Name Indication)**. Our engine extracts this to identify applications without breaking encryption.
 
```
TLS Client Hello:
└── Extensions:
    └── SNI Extension (type 0x0000):
        └── Server Name: "www.youtube.com"  ← extracted here
```
 
---
 
## Project Structure
 
```
Packet-Analyzer/
├── include/
│   ├── pcap_reader.h          # PCAP binary file reading
│   ├── packet_parser.h        # Protocol parsing (Ethernet/IP/TCP/UDP)
│   ├── sni_extractor.h        # TLS SNI + HTTP Host extraction
│   ├── types.h                # FiveTuple, AppType, flow structures
│   ├── json_reporter.h        # JSON report generation       ← Added
│   ├── pattern_matcher.h      # Regex payload scanner        ← Added
│   ├── thread_safe_queue.h    # Thread-safe producer-consumer queue
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
├── generate_test_pcap.py      # Generates synthetic test PCAP with 18 app types
├── test_dpi.pcap              # Synthetic sample capture
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
 
**Generate synthetic test data:**
```bash
python3 generate_test_pcap.py
./dpi_simple.exe test_dpi.pcap output.pcap
```
 
**Run on real PCAP (convert pcapng first if needed):**
```bash
editcap -F pcap input.pcapng input_fixed.pcap
./dpi_simple.exe input_fixed.pcap output.pcap
```
 
**With blocking rules:**
```bash
./dpi_simple.exe capture.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain tiktok
```
 
**With pattern matching (IDS-style):**
```bash
./dpi_simple.exe capture.pcap output.pcap --pattern "password" --pattern "token" --pattern "secret"
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
                              Flow Table (Five-Tuple hash map)
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
 
### SNI Extraction — Byte Level
 
```
TLS Client Hello payload:
Byte 0:    0x16  → Handshake record
Byte 5:    0x01  → Client Hello
Byte 11:   32 bytes random (skip)
Then:      Session ID length + data (skip)
Then:      Cipher Suites length + data (skip)
Then:      Compression Methods (skip)
Then:      Extensions → scan for type 0x0000 → SNI hostname
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
 
## Functionalities
 
| Feature | File | Description |
|---------|------|-------------|
| JSON Reporter | `include/json_reporter.h` | Exports full flow metadata as structured JSON |
| Pattern Matcher | `include/pattern_matcher.h` | Regex-based HTTP payload inspection engine |
| Real-world testing | — | Validated on Wireshark DNS, HTTP, and DVWA security captures |
| Integrated reporting | `src/main_working.cpp` | Wired both features into the main pipeline |
 
---
 
## License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)   
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.   


