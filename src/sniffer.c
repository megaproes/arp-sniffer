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
#include <stdbool.h>
static int bind_to_iface(int fd, const char *ifname, int promisc) {
    unsigned ifindex = if_nametoindex(ifname);
    if (ifindex == 0) { perror("if_nametoindex"); return -1; }

    if (promisc) {
        struct packet_mreq mreq = {0};
        mreq.mr_ifindex = ifindex;
        mreq.mr_type    = PACKET_MR_PROMISC;
        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            perror("setsockopt(PROMISC)");
            return -1;
        }
    }

    struct sockaddr_ll sll = {0};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);   // capture all; filter ARP in parser
    sll.sll_ifindex  = (int)ifindex;

    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        return -1;
    }
    return 0;
}

int start_sniffer(const char *ifname, int promiscuous, int count)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0)
    {
        perror("socket");
        return -1;
    }

    if (bind_to_iface(fd, ifname, promiscuous) < 0)
    {
        close(fd);
        return -1;
    }

    uint8_t buf[2048];
    while (count != 0)
    {
        struct sockaddr_ll from;
        socklen_t fromlen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);

        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            perror("recvfrom");
            break;
        }

        struct arp_info info;
        if (parse_arp(buf, (size_t)n, &info) == 0)
        {
            char smac[18], tmac[18], sip[INET_ADDRSTRLEN], tip[INET_ADDRSTRLEN];
            mac_to_str(info.sender_mac, smac);
            mac_to_str(info.target_mac, tmac);
            ip_to_str(info.sender_ip, sip);
            ip_to_str(info.target_ip, tip);

            _Bool is_garp = (info.sender_ip == info.target_ip);


            switch (info.operation)
            {
            case 1: // request
                printf("%sARP request: Who has %s? Tell %s (src %s)\n",
                       is_garp ? "[GARP] " : "", tip, sip, smac);
                break;
            case 2: // reply
                printf("%sARP reply: %s is at %s\n",
                       is_garp ? "[GARP] " : "", sip, smac);
                break;
            default:
                printf("ARP op %u: %s -> %s\n",
                       (unsigned)ntohs(info.operation), sip, tip);
            }
            fflush(stdout);
            if (count > 0)
                --count;
        }
        // TODO: handle non-ARP or malformed frames
    }

    close(fd);
    return 0;
}
