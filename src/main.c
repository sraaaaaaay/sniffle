/**
 * @file main.c
 * @author saul
 * @brief program entry
 *
 */

#include "capture.h"
#include "ui.h"
#include <stddef.h>

int main(int argc, char* argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    pcap_if_t* alldevs;
    pcap_if_t* device;
    int status;
    int count           = 0;
    int selected_device = 1;
    ui_context ctx      = { 0 };
    ctx.output_file     = stdout;

    // Determine output file
    for (int i = 1; i < argc - 1; ++i) {
        if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {
                const char* filename = argv[i + 1];
                size_t filename_len  = strlen(filename);

                if (filename_len > 4 && strcmp(filename + (filename_len - 4), ".txt") == 0) {
                    ctx.output_file = fopen(filename, "w");
                }
            }
            if (ctx.output_file == NULL) {
                ctx.output_file = stdout;
            }
            break;
        }
    }

    // Find network interfaces
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // List available devices
    printf("Available devices:\n");
    for (device = alldevs; device != NULL; device = device->next) {
        if (device->description) {
            printf("%d. %s\n", ++count, device->description);
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
        printf("Enter the interface number (1-%d)\n> ", count);
        scanf("%d", &selected_device);
        if (selected_device < 1 || selected_device > count) {
            printf("Picked an invalid interface: %d. Using default.\n", selected_device);
            selected_device = 1;
        }
    }

    device = alldevs;
    for (int i = 1; i < selected_device; ++i) {
        device = device->next;
    }


    /* Set up the network interface handle */
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

    /* Activate handle */
    status = pcap_activate(handle);
    if (status != 0) {
        fprintf(stderr, "Pcap activate failed: %s\n", pcap_statustostr(status));
        if (status == PCAP_ERROR) {
            fprintf(stderr, "Pcap error: %s\n", pcap_geterr(handle));
        }
        pcap_close(handle);
        return (2);
    }

    /* Get packet count from user */
    printf("How many packets do you want to read?\n> ");
    uint32_t packets_to_count;
    int result = scanf("%d", &packets_to_count);
    if (result == EOF) {
        packets_to_count = 25;
    }
    if (result == 0) {
        while (fgetc(stdin) != '\n')
            ;
    }

    /* Add to UI context */
    ctx.max_packets = packets_to_count;

    /* Initialize + start ui */
    init_ui(&ctx);
    start_ui(&ctx);
    toggle_cursor(FALSE);

    printf("Listening on %s...\n", device->description);
    printf("Press Ctrl+C to stop.\n");
    pcap_freealldevs(alldevs);
    pcap_loop(handle, packets_to_count, packet_handler, (u_char*)&ctx);

    /* Cleanup */
    ctx.listen_complete = 1;
    Sleep(200);

    /* Close UI + network device handle when done */
    stop_ui();
    pcap_close(handle);
    toggle_cursor(TRUE);
    return 0;
}
