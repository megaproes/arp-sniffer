# arp-sniffer

Minimal ARP sniffer written in C for Linux using raw `AF_PACKET` sockets.  
Focus: small codebase, simple build.

Prints ARP requests/replies from a given interface.

---

## Features

- Captures ARP frames (EtherType `0x0806`) via `AF_PACKET`.
- Parses request/reply and prints human-readable lines.
- Optional promiscuous mode so you see broadcasts and replies on the LAN.
- Parser covered by unit tests (cmocka).

---

## Requirements

- Linux
- `gcc` / `make` (or just `gcc`)
- Root privileges or `CAP_NET_RAW` (for raw sockets)  
  Example: `sudo setcap cap_net_raw=eip ./arp-sniffer`
- (Tests) `cmocka` development package

---

## Build

No CMake yet. Straight gcc:

```
sudo gcc -Wall -O2 -Iinclude -o arp-sniffer \
  src/main.c src/sniffer.c src/parser.c src/utils.c
```

(For tests):

```gcc -Iinclude -o test_parser tests/test_parser.c src/parser.c -lcmocka ./test_parser```

## Run
```sudo ./arp-sniffer <iface>```

e.g. 

```sudo ./arp-sniffer enp1s0```

Sample output:
```
ARP request: Who has 192.168.0.1? Tell 192.168.0.100 (src 02:2a:99:fa:2d:af)
ARP reply: 192.168.0.1 is at 58:47:ad:82:12:62
```

## Roadmap / TODO
* **GARP detection**
  * Request where `SPA == TPA` and destination MAC is broadcast.
  * Reply/announcement where `SPA == TPA` and `THA` is broadcast or zeroed.
* **Structured output**
  * Add indexed/structured records (CSV/JSON) instead of only free-form lines.
* **CLI**
  * `-i <iface>`, `-p/--no-promisc`, `-c <count>`, `-o json|text`, `--stats`.
* **Stats & detection**
  * Track `(IP => MAC)` mappings and flag duplicates (spoof suspicion).
  * Rate counters per IP/MAC; top talkers.
  
* **Filtering**
  * Optional BPF/cls filter to drop non-ARP early or select specific IP.
* **Tests**
  * More parser cases: replies, truncation, wrong EtherType, invalid header fields.
* **Portability**
  * Currently Linux-only; add Windows later on.

