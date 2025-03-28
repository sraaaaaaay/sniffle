#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    printf("Packet captured at: %s", ctime((const time_t*)&pkthdr->ts.tv_sec));
    printf("Packet length: %d\n", pkthdr->len);
    printf("----------------------------\n");
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    pcap_if_t *alldevs, *device;
    int status;
    int count           = 0;
    int selected_device = 1;

    // Find network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // List available devices
    printf("Available devices:\n");
    for (device = alldevs; device != NULL; device = device->next) {
        printf("%d. %s", ++count, device->name);
        if (device->description) {
            printf(" (%s)\n", device->description);
        } else {
            printf(" (No description available)\n");
        }
    }
    if (count == 0) {
        printf("No interfaces found (install Npcap?)\n");
        return 1;
    }

    /* Get choice of interface */
    if (count > 1) {
        printf("Enter the interface number (1-%d): ", count);
        scanf("%d", &selected_device);
        if (selected_device < 1 || selected_device > count) {
            printf("Picked an invalid interface. Using default.\n");
            selected_device = 1;
        }
    }

    device = alldevs;
    for (int i = 1; i < selected_device; ++i) {
        device = device->next;
    }


    handle = pcap_create(device->name, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    pcap_set_snaplen(handle, BUFSIZ);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 1000);
    pcap_set_buffer_size(handle, 1024 * 1024);

    status = pcap_activate(handle);
    if (status != 0) {
        fprintf(stderr, "Pcap activate failed: %s\n", pcap_statustostr(status));
        if (status == PCAP_ERROR)
            fprintf(stderr, "Pcap error: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return (2);
    }

    printf("Listening on %s...\n", device->name);
    printf("Press Ctrl+C to stop.\n");

    pcap_freealldevs(alldevs);

    pcap_loop(handle, 10, packet_handler, NULL);
    pcap_close(handle);
    return 0;
}