/**
 * @file capture.h
 * @author your name (you@domain.com)
 * @brief 
 * @version 0.1
 * @date 2025-03-29
 * 
 * @copyright Copyright (c) 2025
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