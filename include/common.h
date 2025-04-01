/**
 * @file capture.h
 * @author saul
 * @brief common header
 *
 */

#ifndef COMMON_H
#define COMMON_H

/* Needed for windows */
#ifdef _WIN32
#define _WIN32_WINNT 0x0600

#include <winsock2.h>
#include <ws2tcpip.h>


#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

/* standard stuff */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


/* libpcap */
#include <pcap.h>

/* "Magic numbers" */
#define NUM_MAC_BYTES 6
#define MAX_PACKET_SIZE 65535
#define DEFAULT_SNAPLEN BUFSIZ
#define DEFAULT_TIMEOUT 1000

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV6 0x86DD

#endif
