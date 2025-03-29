/**
 * @file capture.c
 * @author saul
 * @brief Packet capture implementation
 * @version 0.1
 * @date 2025-03-29
 * 
 * @copyright Copyright (c) 2025
 * 
 */
#include "common.h"
#include "capture.h"

struct eth_header {
    u_char destination_mac[NUM_MAC_BYTES];
    u_char source_mac[NUM_MAC_BYTES];
    u_short eth_type;
};

struct ip_header {
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
};

void print_mac_address(const u_char* mac) {
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3],
    mac[4], mac[5]);
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    printf("Packet captured at: %s", ctime((const time_t*)&pkthdr->ts.tv_sec));
    printf("Packet length: %d\n", pkthdr->len);
    printf("----------------------------\n");

    struct eth_header* eth = (struct eth_header*)packet;
    printf("\n-- Ethernet Header --\n");
    printf("   Source MAC: ");
    print_mac_address(eth->source_mac);
    printf("\n");

    printf("   Destination MAC: ");
    print_mac_address(eth->destination_mac);
    printf("\n");

    // TODO:
    // Get EtherType and convert from network to host byte order
    // Process IP packets
    // Get IP header (located right after the Ethernet header)
    // Convert IP addresses to string representation
    // Print IP header information
    // Process based on IP protocol
}