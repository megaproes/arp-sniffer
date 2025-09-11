#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "parser.h"
#include "utils.h"


#include <ifaddrs.h>
#include <net/if.h>
#include <sys/types.h>

void mac_to_str(const uint8_t mac[6], char out[18]) {
    // aa:bb:cc:dd:ee:ff + NUL
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void ip_to_str(uint32_t be_ip, char out[INET_ADDRSTRLEN]) {
    inet_ntop(AF_INET, &be_ip, out, INET_ADDRSTRLEN);
}
void print_arp(const struct arp_info *info,
                      const char *smac, const char *tmac,
                      const char *sip, const char *tip,
                      const char *format) {
    int garp = (info->sender_ip == info->target_ip);

    if (info->operation == 1) {            // request
        if (strcmp(format, "csv") == 0) {
            printf("request,%s,%s,%s,%s,%d\n", smac, sip, tmac, tip, garp);
        } else if (strcmp(format, "json") == 0) {
            printf("{\"type\":\"request\",\"smac\":\"%s\",\"sip\":\"%s\","
                   "\"tmac\":\"%s\",\"tip\":\"%s\",\"garp\":%s}\n",
                   smac, sip, tmac, tip, garp ? "true":"false");
        } else {
            printf("%sARP request: Who has %s? Tell %s (src %s)\n",
                   garp ? "[GARP] " : "", tip, sip, smac);
        }
    } else if (info->operation == 2) {     // reply
        if (strcmp(format, "csv") == 0) {
            printf("reply,%s,%s,%s,%s,%d\n", smac, sip, tmac, tip, garp);
        } else if (strcmp(format, "json") == 0) {
            printf("{\"type\":\"reply\",\"smac\":\"%s\",\"sip\":\"%s\","
                   "\"tmac\":\"%s\",\"tip\":\"%s\",\"garp\":%s}\n",
                   smac, sip, tmac, tip, garp ? "true":"false");
        } else {
            printf("%sARP reply: %s is at %s\n",
                   garp ? "[GARP] " : "", sip, smac);
        }
    }
    fflush(stdout);
}

int pick_default_iface(char out[], int out_len) {
    struct ifaddrs *ifa_list = NULL;
    if (getifaddrs(&ifa_list) != 0) return -1;

    int rc = -1;
    for (struct ifaddrs *ifa = ifa_list; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;           // need IPv4
        unsigned flags = ifa->ifa_flags;
        if (!(flags & IFF_UP) || !(flags & IFF_RUNNING)) continue;    // must be up
        if (flags & IFF_LOOPBACK) continue;                           // skip lo
        // looks good
        snprintf(out, out_len, "%s", ifa->ifa_name);
        rc = 0;
        break;
    }
    freeifaddrs(ifa_list);
    return rc;
}
