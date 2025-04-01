/**
 * @file capture.h
 * @author saul
 * @brief packet capture header
 *
 */

#ifndef CAPTURE_H
#define CAPTURE_H

#include "common.h"

/**
* @brief Ethernet header
*
*/
typedef struct {
    u_char destination_mac[NUM_MAC_BYTES];
    u_char source_mac[NUM_MAC_BYTES];
    u_short eth_type;
} eth_header;

 /**
 * @brief IPv4 header. need to use inet_ntop() for string repr of address.
 *
 */
typedef struct ip_header {
    uint8_t v_ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t crc;
    struct in_addr source_addr;
    struct in_addr destination_addr;
} ip_header;


/**
 * @brief Ethernet header. Check eth_type against one of: (ETHERTYPE_IPV4, ETHERTYPE_ARP, ETHERTYPE_IPV6)
 *
 */
typedef struct {
    uint8_t source_port;
    uint8_t destination_port;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
} tcp_header;

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);

#endif
