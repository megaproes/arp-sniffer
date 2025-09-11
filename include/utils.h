#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "sniffer.h"
#include "parser.h"

void mac_to_str(const uint8_t mac[6], char out[18]);
void ip_to_str(uint32_t be_ip, char out[INET_ADDRSTRLEN]);
void print_arp(const struct arp_info *info,
			const char *smac, const char *tmac,
			const char *sip, const char *tip,
			const char *format);

// choose default iface: first UP/RUNNING, non-loopback with IPv4
// returns 0 on success and writes name to out; -1 on failure
int pick_default_iface(char out[], int out_len);
#endif
