/*
 * C-Shark: Terminal Packet Sniffer
 * Main Header File
 * Build incrementally: Phase 1 -> Phase 2 -> Phase 3 -> Phase 4 -> Phase 5
 */

#ifndef CSHARK_H
#define CSHARK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

// For strdup
#define _GNU_SOURCE

// Define BSD types if not already defined
#ifndef u_char
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
#endif

#include <pcap.h>

// Snapshot length for packet capture (max bytes per packet)
#define SNAP_LEN 65535

// Global variables
extern volatile sig_atomic_t stop_capture;
extern pcap_t *global_handle;

// Function prototypes

// Interface management (Phase 1)
void display_interfaces(void);
char* select_interface(void);

// Packet capture (Phase 1)
void start_capture(const char *device, const char *filter);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// Utility functions (Phase 1)
void print_hex_dump_16(const u_char *data);

// Signal handlers (Phase 1)
void handle_sigint(int sig);
void setup_signal_handlers(void);

// Protocol utilities
const char* protocol_name(int proto);
const char* port_name(int port);

// Layer parsing functions
void print_l4_info(const u_char *packet, int ethertype, int ip_proto, int ip_hdr_len, int pkt_len);
void print_l7_info(const u_char *packet, int ethertype, int ip_proto, int ip_hdr_len, int l4_hdr_len, int pkt_len);

// Session management
void store_packet(const struct pcap_pkthdr *header, const unsigned char *packet);
void free_previous_session(void);
void inspect_last_session(void);

// Filtering
int apply_filters(const struct pcap_pkthdr *header, const unsigned char *packet, const char *filter);
char* select_filter(void);
#endif // CSHARK_H
