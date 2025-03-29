/**
 * @file capture.c
 * @author saul
 * @brief Packet capture implementation
 *
 */
#include "capture.h"


struct eth_header {
    /**
     * @brief Ethernet header. Check eth_type against one of: (ETHERTYPE_IPV4, ETHERTYPE_ARP, ETHERTYPE_IPV6)
     *
     */
    u_char destination_mac[NUM_MAC_BYTES];
    u_char source_mac[NUM_MAC_BYTES];
    u_short eth_type;
};


struct ip_header {
    /**
     * @brief IPv4 header. need to use inet_ntop() for string repr of address.
     *
     */
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

struct tcp_header {
    uint8_t source_port;
    uint8_t destination_port;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint8_t offset_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

void print_mac_address(const char* party, const u_char* mac) {
    printf("%s MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", party, mac[0], mac[1],
    mac[2], mac[3], mac[4], mac[5]);
}

void print_ip_address(const char* party, const char* ip_address) {
    printf("%s IP: %s\n", party, ip_address);
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    /**
     * @brief Packet handler for npcap. Header-by-header parsing & printout of
     * network packet.
     * Ethernet | IP | Transport (tcp, udp) | payload
     *
     */

    /* General packet info */
    printf("Packet captured at: %s", ctime((const time_t*)&pkthdr->ts.tv_sec));
    printf("Packet length: %d\n", pkthdr->len);
    printf("----------------------------\n");
    /* Packet is too small for ethernet header*/
    if (pkthdr->len < sizeof(struct eth_header)) {
        return;
    }

    /* Ethernet info */
    struct eth_header* eth = (struct eth_header*)packet;
    uint16_t ethertype     = ntohs(eth->eth_type);
    printf("\n-- Ethernet Header --\n");
    print_mac_address("Source", eth->source_mac);
    print_mac_address("Destination", eth->destination_mac);
    printf("Ethertype: 0x%04x\n", ethertype);

    /* Ipv4 info */
    if (ethertype == ETHERTYPE_IPV4) {
        struct ip_header* ip_header =
        (struct ip_header*)(packet + sizeof(struct eth_header));
        printf("\n-- IPv4 Header --\n");
        char src_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->source_addr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->source_addr), src_ip, INET_ADDRSTRLEN);
        print_ip_address("Source", src_ip);
        print_ip_address("Source", dest_ip);

        /* Transport info */
        if (ip_header->protocol == PROTO_TCP) {
            struct tcp_header* tcp_header = (struct tcp_header*)(packet +
            sizeof(struct eth_header) + ((ip_header->v_ihl & 4) * 4));
            printf("\n-- TCP Header --\n");
            printf("Source port: %d", tcp_header->source_port);
        }
    }


    // TODO:
    //
    //  [X] Get EtherType & convert from network to host byte order
    //  [X] Get IP header
    //  [X] Convert IP addresses to string
    //  [X] Print IP header information
    //  [ ] Identify source of build failure - ws2tcpip/inet_top() include issues

    // Process based on IP protocol (TCP/UDP/ICMP):
    //  [ ] Display info
    //
}