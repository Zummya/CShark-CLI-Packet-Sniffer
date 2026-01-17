/*
 * C-Shark: Filter Module
 * Handles protocol filtering for selective packet capture
 * 
 * ############## LLM Generated Code Begins ##############
 */

#include "cshark.h"

char* select_filter(void) {
    static char filter_str[256];
    char input[10];
    int choice;
    
    printf("\n");
    printf("[C-Shark] Select a filter:\n");
    printf("\n");
    printf("  1. HTTP (port 80)\n");
    printf("  2. HTTPS (port 443)\n");
    printf("  3. DNS (port 53)\n");
    printf("  4. ARP\n");
    printf("  5. TCP\n");
    printf("  6. UDP\n");
    printf("  0. Cancel\n");
    printf("\n");
    printf("Enter your choice (0-6): ");
    
    if (fgets(input, sizeof(input), stdin) == NULL) {
        return NULL;
    }
    
    choice = atoi(input);
    
    switch (choice) {
        case 1:
            strcpy(filter_str, "tcp and port 80");
            break;
        case 2:
            strcpy(filter_str, "tcp and port 443");
            break;
        case 3:
            strcpy(filter_str, "udp and port 53");
            break;
        case 4:
            strcpy(filter_str, "arp");
            break;
        case 5:
            strcpy(filter_str, "tcp");
            break;
        case 6:
            strcpy(filter_str, "udp");
            break;
        case 0:
            printf("[C-Shark] Filter cancelled\n");
            return NULL;
        default:
            printf("[C-Shark] Invalid filter choice\n");
            return NULL;
    }
    
    return filter_str;
}

/* ############## LLM Generated Code Ends ################ */
