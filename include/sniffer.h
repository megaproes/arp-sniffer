#ifndef SNIFFER_H
#define SNIFFER_H
int start_sniffer(const char *ifname, int promiscuous, int count); // count<0 => infinite
#endif
