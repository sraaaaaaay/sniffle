/**
 * @file capture.h
 * @author saul
 * @brief packet capture header
 *
 */

#ifndef CAPTURE_H
#define CAPTURE_H

#include "common.h"

typedef struct eth_header eth_header;
typedef struct ip_header ip_header;
void print_mac_address(const u_char* mac);
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);



#endif