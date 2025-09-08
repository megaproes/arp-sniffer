#include "utils.h"
#include <stdio.h>

void mac_to_str(const uint8_t mac[6], char out[18]) {
    // aa:bb:cc:dd:ee:ff + NUL
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void ip_to_str(uint32_t be_ip, char out[INET_ADDRSTRLEN]) {
    inet_ntop(AF_INET, &be_ip, out, INET_ADDRSTRLEN);
}
