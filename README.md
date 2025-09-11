# arp-sniffer

Minimal ARP sniffer written in C for Linux using raw `AF_PACKET` sockets.
Prints ARP requests/replies from a given interface.

---

## Features

* Captures ARP frames (EtherType `0x0806`) via `AF_PACKET`.
* Parses requests/replies and prints in Wireshark-like style.
* Optional promiscuous mode to see broadcasts and replies.

---

## Requirements

* Linux
* `gcc` / `make`
* Root privileges or `CAP_NET_RAW` (for raw sockets)
  Example:
  `sudo setcap cap_net_raw=eip ./arp-sniffer`
* (For tests) `cmocka`

---

## Build

```bash
# build app only (default)
make

# build tests (requires cmocka)
make test

# clean
make clean
```

Manual:

```bash
gcc -Wall -O2 -Iinclude -o arp-sniffer \
  src/main.c src/sniffer.c src/parser.c src/utils.c
```

Tests:

```bash
gcc -Iinclude -o test_parser tests/test_parser.c src/parser.c -lcmocka
./test_parser
```

---

## Run

```bash
sudo ./arp-sniffer <iface>
```

Example:

```bash
sudo ./arp-sniffer enp1s0
```

Sample output:

```
ARP request: Who has 192.168.0.1? Tell 192.168.0.100 (src 02:2a:99:fa:2d:af)
ARP reply: 192.168.0.1 is at 58:47:ad:82:12:62
```

---

## TODO

- [x] GARP detection
      - Request where `SPA == TPA` and dest MAC is broadcast
- [x] **Structured output**: CSV/JSON as option 
- [x] *CLI options**: `-i <iface>`, `-p/--no-promisc`, `-c <count>`, `-o json|text`
- [ ] **Stats & detection**: Track `(IP => MAC)` mappings, detect duplicates, add counters.
- [ ] **Filtering**: optional BPF/cls filter for selective capture.
- [ ] **Tests**: more parser cases (replies, truncation, wrong EtherType, invalid fields).
- [ ] **Portability**: currently Linux-only; add Windows later.
- [ ] Add optional **tcpdump**-style 'who-has'/'is-at' output


## License

MIT — see [`LICENSE`](./LICENSE).
