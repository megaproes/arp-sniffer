# arp-sniffer

Minimal ARP sniffer for Linux built on raw `AF_PACKET` sockets.
Parses ARP requests/replies and prints them in **text**, **CSV**, or **JSON**.
Supports auto-picking a sane default interface and optional promiscuous mode.

---

## Quick start

```bash
make                      # build
sudo ./arp-sniffer \
  [-i IFACE] [-n COUNT] \
  [-f text|csv|json] [-P|--no-promisc]
# use -h/--help for details
```

> Requires Linux and a C toolchain. Run as root or grant the binary `CAP_NET_RAW`:
>
> ```sudo setcap cap_net_raw=eip ./arp-sniffer```

---

## TODO

* [x] GARP detection
  \- Request where `SPA == TPA` and dest MAC is broadcast
* [x] **Structured output**: CSV/JSON as option
* [x] *CLI options*\*: `-i <iface>`, `-p/--no-promisc`, `-c <count>`, `-o json|text`
* [ ] **Stats & detection**: Track `(IP => MAC)` mappings, detect duplicates, add counters.
* [ ] **Filtering**: optional BPF/cls filter for selective capture.
* [ ] **Tests**: more parser cases (replies, truncation, wrong EtherType, invalid fields).
* [ ] **Portability**: currently Linux-only; add Windows later.
* [ ] Add optional **tcpdump**-style 'who-has'/'is-at' output

---

## License

MIT — see [`LICENSE`](./LICENSE).
