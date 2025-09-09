#define _GNU_SOURCE
#include "sniffer.h"
#include "parser.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>



int start_sniffer(const char *ifname, int promiscuous, int count) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) { perror("socket"); return -1; }

    if (bind_to_iface(fd, ifname, promiscuous) < 0) {
        close(fd);
        return -1;
    }

    uint8_t buf[2048];
    while (count != 0) {
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, NULL, NULL);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            break;
        }

        struct arp_info info;
        if (parse_arp(buf, (size_t)n, &info) == 0) {
            char smac[18], tmac[18], sip[INET_ADDRSTRLEN], tip[INET_ADDRSTRLEN];
            mac_to_str(info.sender_mac, smac);
            mac_to_str(info.target_mac, tmac);
            ip_to_str(info.sender_ip, sip);
            ip_to_str(info.target_ip, tip);

            switch (ntohs(info.operation)) {
                case 1: // request
                    printf("ARP request: Who has %s? Tell %s (src %s)\n", tip, sip, smac);
                    break;
                case 2: // reply
                    printf("ARP reply: %s is at %s\n", sip, smac);
                    break;
                default:
                    printf("ARP op %u: %s -> %s\n", (unsigned)ntohs(info.operation), sip, tip);
            }
            fflush(stdout);
            if (count > 0) --count;
        }
        // TODO: handle non-ARP or malformed frames
    }

    close(fd);
    return 0;
}
