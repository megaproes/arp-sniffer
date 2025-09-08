#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void mac_to_str(const uint8_t mac[6], char out[18]);
void ip_to_str(uint32_t be_ip, char out[INET_ADDRSTRLEN]);

#endif
