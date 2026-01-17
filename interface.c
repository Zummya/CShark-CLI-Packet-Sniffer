/*
 * C-Shark: Interface Discovery Module
 * Handles network interface enumeration and selection
 * 
 * ############## LLM Generated Code Begins ##############
 */

#define _GNU_SOURCE  // For strdup
#include "cshark.h"

void display_interfaces(void) {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;
    
    printf("[C-Shark] Searching for available interfaces... ");
    fflush(stdout);
    
    // Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }
    
    printf("Found!\n\n");
    
    // Display devices
    for (device = alldevs; device != NULL; device = device->next) {
        count++;
        printf("  %d. %s", count, device->name);
        
        if (device->description) {
            printf(" (%s)", device->description);
        }
        printf("\n");
    }
    
    pcap_freealldevs(alldevs);
}

char* select_interface(void) {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    char input[10];
    int choice;
    int count = 0;
    char *selected = NULL;
    
    display_interfaces();
    
    printf("\nSelect an interface to sniff: ");
    
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return NULL;
    }
    
    choice = atoi(input);
    
    if (choice <= 0) {
        fprintf(stderr, "Invalid choice\n");
        return NULL;
    }
    
    // Find all devices again
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return NULL;
    }
    
    // Get the chosen device
    for (device = alldevs; device != NULL; device = device->next) {
        count++;
        if (count == choice) {
            selected = strdup(device->name);
            break;
        }
    }
    
    pcap_freealldevs(alldevs);
    
    if (selected == NULL) {
        fprintf(stderr, "Invalid device number\n");
    }
    
    return selected;
}
/* ############## LLM Generated Code Ends ################ */
