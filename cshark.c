/*
 * C-Shark: Terminal Packet Sniffer
 * Main Program File
 * 
 * Current: Phase 1 - Interface Discovery & Basic Capture
 * 
 * ############## LLM Generated Code Begins ##############
 */

#include "cshark.h"
// Global variables
volatile sig_atomic_t stop_capture = 0;
pcap_t *global_handle = NULL;

void print_banner(void) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║     [C-Shark] The Command-Line Packet Predator     ║\n");
    printf("╚════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void print_menu(const char *interface) {
    printf("\n");
    printf("[C-Shark] Interface '%s' selected. What's next?\n", interface);
    printf("\n");
    printf("  1. Start Sniffing (All Packets)\n");
    printf("  2. Start Sniffing (With Filters)\n");
    printf("  3. Inspect Last Session\n");
    printf("  4. Exit C-Shark\n");
    printf("\n");
    printf("Enter your choice (1 or 4): ");
}

int main(void) {
    char *selected_device = NULL;
    int choice;
    char input[10];
    
    print_banner();
    
    // Phase 1: Device discovery
    selected_device = select_interface();
    if (selected_device == NULL) {
        fprintf(stderr, "Error: No interface selected\n");
        return 1;
    }
    
    // Setup signal handlers
    setup_signal_handlers();
    
    // Main menu loop
    while (1) {
        print_menu(selected_device);
        
        if (fgets(input, sizeof(input), stdin) == NULL) {
            // Ctrl+D pressed (EOF)
            printf("\n[C-Shark] Exiting cleanly...\n");
            free(selected_device);
            exit(0);
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        
        choice = atoi(input);
        
        switch (choice) {
            case 1:
                printf("\n[C-Shark] Starting capture on '%s'...\n", selected_device);
                printf("[C-Shark] Press Ctrl+C to stop capture\n\n");
                stop_capture = 0;
                start_capture(selected_device, NULL);
                break;
                
            // Enable Phase 3: Filtering functionality
            case 2:
                char *filter_string = select_filter(); // This function is in filter.c
                
                if (filter_string != NULL) {
                    printf("\n[C-Shark] Starting capture on '%s' with filter: '%s'\n", selected_device, filter_string);
                    printf("[C-Shark] Press Ctrl+C to stop capture\n\n");
                    stop_capture = 0;
                    start_capture(selected_device, filter_string);
                } else {
                    // User selected "Cancel" from the filter menu
                    printf("\n");
                }
                break;
                
            // Enable Phase 5: Session inspection in the main menu
            case 3:
                inspect_last_session();
                break;
                
            case 4:
                printf("\n[C-Shark] Thanks for using C-Shark! Stay sharp! 🦈\n\n");
                free(selected_device);
                return 0;
                
            default:
                printf("\n[C-Shark] Invalid choice. Please enter 1-4.\n");
        }
    }
    
    // Cleanup
    free(selected_device);
    
    return 0;
}

/* ############## LLM Generated Code Ends ################ */
