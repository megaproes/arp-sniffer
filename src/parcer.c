#include "parser.h"
#include <string.h>

#define ETH_HDR_LEN 14
#define ARP_LEN     28

int parse_arp(const uint8_t *packet, size_t len, struct arp_info *out) {
    if (!packet || !out) return -1;
    if (len < ETH_HDR_LEN + ARP_LEN) return -1;

    // Ethernet header
    const uint8_t *eth = packet;
    uint16_t ethertype = ((uint16_t)eth[12] << 8) | eth[13];
    if (ethertype != 0x0806) return -1; // not ARP

    // ARP header (starts after 14 bytes)
    const uint8_t *arp = packet + ETH_HDR_LEN;

    uint16_t htype = ((uint16_t)arp[0] << 8) | arp[1];
    uint16_t ptype = ((uint16_t)arp[2] << 8) | arp[3];
    uint8_t  hlen  = arp[4];
    uint8_t  plen  = arp[5];	

    if (htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4) return -1;

    memcpy(&out->operation, arp + 6, 2);

    // sha(6), spa(4), tha(6), tpa(4)
    memcpy(out->sender_mac, arp + 8, 6);
    memcpy(&out->sender_ip,  arp + 14, 4);
    memcpy(out->target_mac, arp + 18, 6);
    memcpy(&out->target_ip,  arp + 24, 4);

    return 0; 
}
