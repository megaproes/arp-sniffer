// include/parser.h
#ifndef PARSER_H
#define PARSER_H

#include <stdint.h>
#include <stddef.h>

// Info we want to extract from an ARP packet
struct arp_info {
    uint16_t operation;      // 1=request, 2=reply
    uint8_t sender_mac[6];
    uint8_t target_mac[6];
    uint32_t sender_ip;      // stored in NBO
    uint32_t target_ip;      // stored in NBO
};

// Parse ARP packet into arp_info struct
// Returns 0 on success, -1 on failure
int parse_arp(const uint8_t *packet, size_t len, struct arp_info *out);

#endif
