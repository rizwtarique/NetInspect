# NetInspect — Deep Packet Inspection Engine

A C++17 network traffic analyzer that inspects, classifies, and filters packets from PCAP capture files. It identifies applications (YouTube, Netflix, TikTok, and more) even inside encrypted HTTPS traffic by extracting the **SNI** field from TLS handshakes, and can block traffic in real time based on rules you define.

Available in two versions: a single-threaded build for learning the internals, and a multi-threaded build for processing large captures fast.

---

## What It Does

- Reads `.pcap` files (from Wireshark or tcpdump)
- Parses Ethernet → IP → TCP/UDP headers layer by layer
- Extracts **SNI** (Server Name Indication) from TLS Client Hello packets
- Classifies traffic into 20+ applications (Google, Facebook, YouTube, Netflix, Discord, Zoom, etc.)
- Tracks **flows** using the 5-tuple (source IP, destination IP, source port, destination port, protocol)
- Blocks traffic by IP address, app name, or domain keyword
- Writes filtered packets to an output PCAP file
- Prints a full traffic report with a per-app breakdown

---

## Tech Stack

| Category | Technology |
|---|---|
| **Language** | C++17 |
| **Concurrency** | `std::thread`, `std::mutex`, `std::atomic`, `std::condition_variable` |
| **Data Structures** | `std::unordered_map`, `std::queue`, `std::optional`, `std::vector` |
| **Networking** | Raw PCAP binary parsing (no `libpcap` dependency) |
| **Protocol Support** | Ethernet, IPv4, TCP, UDP, TLS 1.2/1.3, HTTP, DNS |
| **Build System** | CMake 3.16+ / manual `g++` |
| **Test Data** | Python 3 (`generate_test_pcap.py`) |
| **Platform** | Linux / macOS |

---

## Why SNI Works on HTTPS

HTTPS encrypts the content of a connection, but the domain name is still sent in plaintext during the TLS handshake, inside the Client Hello message. This is called **Server Name Indication (SNI)**, and it's how the server knows which certificate to present. NetInspect reads this field before any encryption kicks in.

```
TLS Client Hello (plaintext):
└── Extensions:
    └── SNI Extension (type 0x0000):
        └── Server Name: "www.youtube.com"  ← extracted here
```

---

## Project Structure

```
NetInspect/
├── include/
│   ├── types.h               # FiveTuple, AppType, Connection structs
│   ├── pcap_reader.h         # PCAP file I/O
│   ├── packet_parser.h       # Ethernet/IP/TCP/UDP parsing
│   ├── sni_extractor.h       # TLS inspection, SNI extraction
│   ├── rule_manager.h        # Blocking rules (IP, app, domain)
│   ├── connection_tracker.h  # Flow/connection state tracking
│   ├── load_balancer.h       # LB thread (multi-threaded version)
│   ├── fast_path.h           # FP thread (multi-threaded version)
│   ├── thread_safe_queue.h   # Thread-safe queue with backpressure
│   └── dpi_engine.h          # Main orchestrator
│
├── src/
│   ├── main_working.cpp      # Single-threaded version (start here)
│   ├── dpi_mt.cpp            # Multi-threaded version
│   ├── packet_parser.cpp
│   ├── sni_extractor.cpp
│   ├── pcap_reader.cpp
│   ├── connection_tracker.cpp
│   ├── rule_manager.cpp
│   ├── types.cpp
│   └── fast_path.cpp / load_balancer.cpp
│
├── generate_test_pcap.py     # Generates a sample PCAP for testing
├── test_dpi.pcap             # Sample capture included
├── CMakeLists.txt
└── README.md
```

---

## Building

No external libraries needed — just a C++17 compiler.

**Single-threaded version:**

```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

**Multi-threaded version:**

```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

**Or using CMake:**

```bash
mkdir build && cd build
cmake ..
make
```

---

## Running

**Basic usage:**

```bash
./dpi_engine test_dpi.pcap output.pcap
```

**With blocking rules:**

```bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

**Configure thread count (multi-threaded only):**

```bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
# 4 Load Balancer threads × 4 Fast Path threads = 16 processing threads
```

**Generate test data:**

```bash
python3 generate_test_pcap.py
```

---

## Multi-threaded Architecture

The multi-threaded version uses a **Reader → Load Balancer → Fast Path** pipeline:

```
┌────────────┐     ┌──────────────────────────────────┐     ┌────────────┐
│   Reader   │────►│  LB Thread 0  ──►  FP Thread 0   │────►│   Output   │
│  (1 thread)│     │               ──►  FP Thread 1   │     │   Writer   │
│            │     ├──────────────────────────────────┤     └────────────┘
│            │────►│  LB Thread 1  ──►  FP Thread 2   │
│            │     │               ──►  FP Thread 3   │
└────────────┘     └──────────────────────────────────┘
```

- **Reader** reads packets from the PCAP file and dispatches them to LB queues
- **Load Balancers** hash the 5-tuple and route packets to the correct FP thread (same flow always lands on the same FP thread)
- **Fast Path threads** perform the actual DPI work: SNI extraction, rule checking, forward/drop decision
- All inter-thread communication uses a **thread-safe queue with backpressure** (`TSQueue`)

Flow consistency matters here — packets from the same TCP connection must always be routed to the same FP thread, otherwise connection state tracking breaks.

---

## Supported Applications

Detected via SNI domain matching:

| App | App | App | App |
|---|---|---|---|
| YouTube | Netflix | Spotify | Zoom |
| Facebook | Instagram | WhatsApp | Discord |
| Google | Microsoft | Apple | GitHub |
| Twitter/X | TikTok | Telegram | Amazon |
| Cloudflare | QUIC/HTTP3 | DNS | Generic HTTPS |

---

## Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                             ║
║ TCP Packets:                  73    UDP Packets:   4         ║
║ Forwarded:                    69    Dropped:       8         ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                      ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS          39   50.6%  ##########                        ║
║ Unknown        16   20.8%  ####                              ║
║ YouTube         4    5.2%  # (BLOCKED)                       ║
║ DNS             4    5.2%  #                                 ║
║ Facebook        3    3.9%                                    ║
╚══════════════════════════════════════════════════════════════╝

[Detected SNIs]
  www.youtube.com    → YouTube (BLOCKED)
  www.facebook.com   → Facebook
  www.google.com     → Google
  github.com         → GitHub
```

---

## How Blocking Works

Blocking is done at the **flow level**, not per-packet:

```
Packet 1 (SYN)          → no SNI yet → FORWARD
Packet 2 (SYN-ACK)      → no SNI yet → FORWARD
Packet 3 (Client Hello) → SNI: www.youtube.com → BLOCKED
Packet 4, 5, 6, ...     → flow is marked BLOCKED → DROP all
```

Once a flow is blocked, every subsequent packet matching that 5-tuple is dropped, and the connection eventually times out on the client side.

Blocking priority:

1. Source IP in blocklist → DROP
2. App type in blocklist → DROP
3. SNI contains blocked domain keyword → DROP
4. Otherwise → FORWARD

---

## Concepts Used

- **PCAP format** — binary capture file format: 24-byte global header + per-packet headers
- **5-tuple flow tracking** — `unordered_map<FiveTuple, Connection>` with a custom hash
- **TLS SNI parsing** — manual byte-level parsing of the TLS Client Hello record
- **Producer-Consumer pattern** — thread-safe queues between Reader, LB, and FP threads
- **Atomic stats** — `std::atomic<uint64_t>` for lock-free per-thread statistics
- **C++17 features** — `std::optional`, structured bindings, `std::variant`

---

## Requirements

- Linux or macOS
- `g++` or `clang++` with C++17 support
- Python 3 (only for generating test data)
- No external libraries

---

## Possible Improvements

- Add QUIC/HTTP3 support (SNI in UDP port 443 Initial packets)
- Bandwidth throttling instead of hard drops
- Load rules from a config file
- Live stats dashboard using a background thread
- Extend app signatures (Twitch, Reddit, LinkedIn, etc.)
- Export report as JSON or CSV

---

## License

No license specified yet — consider adding one (MIT is a common choice for projects like this) if you plan to share or accept contributions.
