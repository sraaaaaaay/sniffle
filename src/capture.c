/**
 * @file capture.c
 * @author saul
 * @brief Packet capture implementation
 *
 */
#include "capture.h"
#include "ui.h"

/**
 * @brief Packet handler for npcap. Does header-by-header parsing of the
 * packets Ethernet | IP | Transport (tcp, udp) | payload
 *
 */
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    ui_context* ctx = (ui_context*)user_data;
    update_ui_stats(ctx);
    char packet_info[512];
    int len = 0;

    /* General packet info */
    len += sprintf(packet_info + len, "\nPacket captured at: %s",
    ctime((const time_t*)&pkthdr->ts.tv_sec));
    len += sprintf(packet_info + len, "Packet length: %d\n", pkthdr->len);
    len += sprintf(packet_info + len, "-----------------------------\n");

    /* Packet is too small for ethernet header*/
    if (pkthdr->len < sizeof(eth_header)) {
        return;
    }

    /* Ethernet info */
    ctx->num_eth++;
    eth_header* eth    = (eth_header*)packet;
    uint16_t ethertype = ntohs(eth->eth_type);
    len += sprintf(packet_info + len, "\n-- Ethernet Header --\n");
    const u_char* src_mac  = eth->source_mac;
    const u_char* dest_mac = eth->destination_mac;

    len += sprintf(packet_info + len, "%s MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", "Source",
    src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

    len += sprintf(packet_info + len, "%s MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", "Destination",
    dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);

    len += sprintf(packet_info + len, "Ethertype: 0x%04x\n", ethertype);

    /* Ipv4 info */
    if (ethertype == ETHERTYPE_IPV4) {
        ctx->num_eth--;
        ctx->num_ip++;
        ip_header* ip_hdr = (ip_header*)(packet + sizeof(eth_header));
        len += sprintf(packet_info + len, "\n-- IPv4 Header --\n");

        char src_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];
        strcpy(src_ip, inet_ntoa(ip_hdr->source_addr));
        strcpy(dest_ip, inet_ntoa(ip_hdr->destination_addr));
        len += sprintf(packet_info + len, "Source IP: %s\n", src_ip);
        len += sprintf(packet_info + len, "Destination IP: %s", dest_ip);

        /* Transport info */
        if (ip_hdr->protocol == PROTO_TCP) {
            ctx->num_ip--;
            ctx->num_tcp++;
            tcp_header* tcp_hdr =
            (tcp_header*)(packet + sizeof(eth_header) + ((ip_hdr->v_ihl & 4) * 4));
            len += sprintf(packet_info + len, "\n TCP Header --\n");
            len += sprintf(packet_info + len, "Source port: %d\n", tcp_hdr->source_port);
            len += sprintf(packet_info + len, "Destination port: %d\n", tcp_hdr->destination_port);
            fprintf(ctx->output_file, "\n-- TCP Header --\n");
            fprintf(ctx->output_file, "Source port: %d\n", tcp_hdr->source_port);
            fprintf(ctx->output_file, "Destination port: %d\n", tcp_hdr->destination_port);
        }
        /* Print out the final string */
        fprintf(ctx->output_file, packet_info);
    }

    // TODO:
    // [X] command line parsing for file output
    // [X] file output
    // [X] text GUI progress bar etc
    // [X] code neatening / string-building
    //
    // [ ] Identify source of build failure - ws2tcpip/inet_top() include issues

    // Process based on IP protocol (TCP/UDP/ICMP):
    //  [X] Display info
    //
}
