#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>
#include <errno.h>
#include "cshark.h"

// Utility: Print protocol name from number
const char* protocol_name(int proto) {
    switch (proto) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ICMP: return "ICMP";
        default: return "Unknown";
    }
}

// Utility: Print port name from number
const char* port_name(int port) {
    switch (port) {
        case 80: return "HTTP";
        case 443: return "HTTPS";
        case 53: return "DNS";
        default: return "";
    }
}

// Layer 4: TCP/UDP dissection for output
void print_l4_info(const u_char *packet, int ethertype, int ip_proto, int ip_hdr_len, int pkt_len) {
    if (ethertype == ETHERTYPE_IP) {
        if (ip_proto == IPPROTO_TCP && pkt_len >= 14 + ip_hdr_len + 20) {
            struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_hdr_len);
            int sport = ntohs(tcp->source);
            int dport = ntohs(tcp->dest);
            const char *sport_name = port_name(sport);
            const char *dport_name = port_name(dport);
            printf("L4 (TCP): Src Port: %d", sport);
            if (strlen(sport_name) > 0) printf(" (%s)", sport_name);
            printf(" | Dst Port: %d", dport);
            if (strlen(dport_name) > 0) printf(" (%s)", dport_name);
            printf(" | Seq: %u | Ack: %u | Flags: [",
                ntohl(tcp->seq), ntohl(tcp->ack_seq));
            int flag_count = 0;
            if (tcp->syn) { if (flag_count++) printf(","); printf("SYN"); }
            if (tcp->ack) { if (flag_count++) printf(","); printf("ACK"); }
            if (tcp->psh) { if (flag_count++) printf(","); printf("PSH"); }
            if (tcp->fin) { if (flag_count++) printf(","); printf("FIN"); }
            if (tcp->rst) { if (flag_count++) printf(","); printf("RST"); }
            if (tcp->urg) { if (flag_count++) printf(","); printf("URG"); }
            printf("] | Window: %u | Checksum: 0x%04X | Header Length: %d bytes\n",
                ntohs(tcp->window), ntohs(tcp->check), tcp->doff * 4);
        } else if (ip_proto == IPPROTO_UDP && pkt_len >= 14 + ip_hdr_len + 8) {
            struct udphdr *udp = (struct udphdr *)(packet + 14 + ip_hdr_len);
            int sport = ntohs(udp->source);
            int dport = ntohs(udp->dest);
            const char *sport_name = port_name(sport);
            const char *dport_name = port_name(dport);
            printf("L4 (UDP): Src Port: %d", sport);
            if (strlen(sport_name) > 0) printf(" (%s)", sport_name);
            printf(" | Dst Port: %d", dport);
            if (strlen(dport_name) > 0) printf(" (%s)", dport_name);
            printf(" | Length: %d | Checksum: 0x%04X\n",
                ntohs(udp->len), ntohs(udp->check));
        }
    }
}

// Layer 7: Application protocol and payload
void print_l7_info(const u_char *packet, int ethertype, int ip_proto, int ip_hdr_len, int l4_hdr_len, int pkt_len) {
    int payload_offset = 14 + ip_hdr_len + l4_hdr_len;
    int payload_len = pkt_len - payload_offset;
    if (payload_len <= 0) return;
    int sport = 0, dport = 0;
    if (ethertype == ETHERTYPE_IP) {
        if (ip_proto == IPPROTO_TCP && pkt_len >= payload_offset) {
            struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + ip_hdr_len);
            sport = ntohs(tcp->source);
            dport = ntohs(tcp->dest);
        } else if (ip_proto == IPPROTO_UDP && pkt_len >= payload_offset) {
            struct udphdr *udp = (struct udphdr *)(packet + 14 + ip_hdr_len);
            sport = ntohs(udp->source);
            dport = ntohs(udp->dest);
        }
    }
    const char *app = "Unknown";
    if (sport == 80 || dport == 80) app = "HTTP";
    else if (sport == 443 || dport == 443) app = "HTTPS";
    else if (sport == 53 || dport == 53) app = "DNS";
    printf("L7 (Payload): Identified as %s on port %d/%d - %d bytes\n", app, sport, dport, payload_len);
    printf("Data (first %d bytes):\n", payload_len < 64 ? payload_len : 64);
    for (int i = 0; i < payload_len && i < 64; i += 16) {
        // Print hex values
        for (int j = 0; j < 16 && (i + j) < payload_len && (i + j) < 64; j++) {
            printf("%02X ", packet[payload_offset + i + j]);
        }
        // Pad with spaces if needed
        for (int j = (payload_len - i < 16 ? payload_len - i : 16); j < 16; j++) {
            printf("   ");
        }
        printf(" ");
        // Print ASCII representation
        for (int j = 0; j < 16 && (i + j) < payload_len && (i + j) < 64; j++) {
            unsigned char c = packet[payload_offset + i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        printf("\n");
    }
}
/*
 * C-Shark: Packet Capture Module
 * Current: Phase 1 - Basic capture with first 16 bytes hex dump
 * 
 * ############## LLM Generated Code Begins ##############
 */

#define _DEFAULT_SOURCE  // Ensure legacy definitions like struct ip and struct ether_arp are exposed
#define _BSD_SOURCE  // Additional macro for legacy definitions
#define __FAVOR_BSD  // BSD-style struct field names as mentioned by TA

#include "cshark.h"
#include "custom_ether_arp.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define MAX_PACKETS 10000

// Structure to store packet/session info
typedef struct {
    int id;
    struct timeval timestamp;
    int length;
    unsigned char *packet_data;
} stored_packet_t;

// Session storage
static stored_packet_t packets[MAX_PACKETS];
static int packet_count = 0;
static int session_number = 1;

static int packet_id = 0;

void handle_sigint(int sig) {
    (void)sig; // Unused parameter
    printf("\n\n[C-Shark] Stopping capture...\n");
    stop_capture = 1;
    if (global_handle != NULL) {
        pcap_breakloop(global_handle);
    }
}

void handle_sigquit(int sig) {
    (void)sig; // Unused parameter
    printf("\n\n[C-Shark] Exiting application...\n");
    stop_capture = 1;
    if (global_handle != NULL) {
        pcap_breakloop(global_handle);
    }
    exit(0);
}

void setup_signal_handlers(void) {
    signal(SIGINT, handle_sigint);
    signal(SIGQUIT, handle_sigquit);
    // Note: Ctrl+D (EOF) is handled in main loop via fgets() return value
}

void print_hex_dump_16(const u_char *data) {
    printf("First 16 bytes: ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", data[i]);
        if (i == 7) printf(" "); // Space in middle for readability
    }
    printf("\n");
}

// Expand apply_filters to support protocol-based filtering
#include <netinet/tcp.h> // For TCP header
#include <netinet/udp.h> // For UDP header
#include <netinet/ip_icmp.h> // For ICMP header

// Expand apply_filters to support source/destination IP and port filtering
#include <arpa/inet.h> // For inet_ntoa

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // const char *filter = (const char *)args; // User-defined filter

    // if (!apply_filters(header, packet, filter)) {
    //     return; // Skip packet if it doesn't match the filter
    // }

    (void)args; // Unused parameter
    
    if (stop_capture) {
        return;
    }
    
    packet_id++;
    
    // Phase 1: Basic packet info and first 16 bytes
    printf("-----------------------------------------\n");
    printf("Packet #%d | Timestamp: %ld.%06ld | Length: %d bytes\n",
           packet_id,
           header->ts.tv_sec,
           header->ts.tv_usec,
           header->len);
    
    // Show first 16 bytes as required in Phase 1
    if (header->len >= 16) {
        print_hex_dump_16(packet);
    } else {
        printf("Packet too short (< 16 bytes)\n");
    }
    
    // Phase 2: Decode Ethernet header
    struct ether_header *eth_hdr = (struct ether_header *)packet;

    // Extract and display Ethernet header details
    printf("L2 (Ethernet): Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X | Src MAC: %02X:%02X:%02X:%02X:%02X:%02X | ",
           eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2],
           eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5],
           eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2],
           eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);

    // Determine EtherType
    uint16_t ethertype = ntohs(eth_hdr->ether_type);
    switch (ethertype) {
        case ETHERTYPE_IP:
            printf("EtherType: IPv4 (0x0800)\n");
            break;
        case ETHERTYPE_IPV6:
            printf("EtherType: IPv6 (0x86DD)\n");
            break;
        case ETHERTYPE_ARP:
            printf("EtherType: ARP (0x0806)\n");
            break;
        default:
            printf("EtherType: Unknown (0x%04X)\n", ethertype);
            break;
    }

    // Phase 2: Decode Layer 3 (Network)
    if (ethertype == ETHERTYPE_IP) {
     struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
     int ip_hdr_len = ip_hdr->ihl * 4;
     struct in_addr src_addr, dst_addr;
     src_addr.s_addr = ip_hdr->saddr;
     dst_addr.s_addr = ip_hdr->daddr;
     printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%d) | TTL: %d\n",
         inet_ntoa(src_addr),
         inet_ntoa(dst_addr),
         protocol_name(ip_hdr->protocol),
         ip_hdr->protocol,
         ip_hdr->ttl);
     printf("ID: 0x%04X | Total Length: %d | Header Length: %d bytes\n",
         ntohs(ip_hdr->id), ntohs(ip_hdr->tot_len), ip_hdr_len);
     // Flags
     int flags = ntohs(ip_hdr->frag_off) >> 13;
     printf("Flags: ");
     if (flags & 0x2) printf("DF ");
     if (flags & 0x1) printf("MF ");
     printf("| Fragment Offset: %d\n", ntohs(ip_hdr->frag_off) & 0x1FFF);
     // Layer 4
     print_l4_info(packet, ethertype, ip_hdr->protocol, ip_hdr_len, header->len);
    } else if (ethertype == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst_ip, INET6_ADDRSTRLEN);
        printf("L3 (IPv6): Src IP: %s | Dst IP: %s | Next Header: %s (%d) | Hop Limit: %d\n",
               src_ip, dst_ip, protocol_name(ip6_hdr->ip6_nxt), ip6_hdr->ip6_nxt, ip6_hdr->ip6_hlim);
        printf("Traffic Class: %d | Flow Label: 0x%05X | Payload Length: %d\n",
               ((ntohl(ip6_hdr->ip6_flow) >> 20) & 0xFF),
               ntohl(ip6_hdr->ip6_flow) & 0xFFFFF,
               ntohs(ip6_hdr->ip6_plen));
        // Layer 4 (TCP/UDP)
        print_l4_info(packet, ethertype, ip6_hdr->ip6_nxt, 40, header->len);
    } else if (ethertype == ETHERTYPE_ARP) {
        struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));
        printf("L3 (ARP): Operation: %s (%d) | Sender IP: %s | Target IP: %s\n",
               ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REQUEST ? "Request" : "Reply",
               ntohs(arp_hdr->ea_hdr.ar_op),
               inet_ntoa(*(struct in_addr *)&arp_hdr->arp_spa),
               inet_ntoa(*(struct in_addr *)&arp_hdr->arp_tpa));
        printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X | Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               arp_hdr->arp_sha[0], arp_hdr->arp_sha[1], arp_hdr->arp_sha[2], arp_hdr->arp_sha[3], arp_hdr->arp_sha[4], arp_hdr->arp_sha[5],
               arp_hdr->arp_tha[0], arp_hdr->arp_tha[1], arp_hdr->arp_tha[2], arp_hdr->arp_tha[3], arp_hdr->arp_tha[4], arp_hdr->arp_tha[5]);
        printf("HW Type: %d | Proto Type: 0x%04X | HW Len: %d | Proto Len: %d\n",
               ntohs(arp_hdr->ea_hdr.ar_hrd), ntohs(arp_hdr->ea_hdr.ar_pro), arp_hdr->ea_hdr.ar_hln, arp_hdr->ea_hdr.ar_pln);
    }


    // Layer 7 output for TCP/UDP
    if (ethertype == ETHERTYPE_IP) {
        struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
        int ip_hdr_len = ip_hdr->ihl * 4;
        if (ip_hdr->protocol == IPPROTO_TCP && header->len >= 14 + ip_hdr_len + 20) {
            print_l7_info(packet, ethertype, ip_hdr->protocol, ip_hdr_len, 20, header->len);
        } else if (ip_hdr->protocol == IPPROTO_UDP && header->len >= 14 + ip_hdr_len + 8) {
            print_l7_info(packet, ethertype, ip_hdr->protocol, ip_hdr_len, 8, header->len);
        }
    } else if (ethertype == ETHERTYPE_IPV6) {
        // For IPv6, TCP/UDP header is always after 40 bytes
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        if (ip6_hdr->ip6_nxt == IPPROTO_TCP && header->len >= 14 + 40 + 20) {
            print_l7_info(packet, ethertype, ip6_hdr->ip6_nxt, 40, 20, header->len);
        } else if (ip6_hdr->ip6_nxt == IPPROTO_UDP && header->len >= 14 + 40 + 8) {
            print_l7_info(packet, ethertype, ip6_hdr->ip6_nxt, 40, 8, header->len);
        }
    }

    printf("\n");
    fflush(stdout);

    store_packet(header, packet); // Store packet in session
}

// Store each captured packet in session storage
void store_packet(const struct pcap_pkthdr *header, const unsigned char *packet) {
    if (packet_count >= MAX_PACKETS) return;
    packets[packet_count].id = packet_count + 1;
    packets[packet_count].timestamp = header->ts;
    packets[packet_count].length = header->len;
    packets[packet_count].packet_data = malloc(header->len);
    if (packets[packet_count].packet_data)
        memcpy(packets[packet_count].packet_data, packet, header->len);
    packet_count++;
}

void start_capture(const char *device, const char *filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp; // 
    free_previous_session(); // Free previous session data before new capture
    packet_id = 0;
    
    // Open device for sniffing
    handle = pcap_open_live(device, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
        return;
    }
    // ==========================================================
    // === NEW KERNEL-LEVEL FILTER (BPF) LOGIC ==================
    // ==========================================================

    // Only compile and apply a filter if one was provided
    if (filter != NULL && strlen(filter) > 0) {

        // 1. Compile the filter string into a BPF program
        if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "[C-Shark] Error: Could not parse filter '%s': %s\n", 
                    filter, pcap_geterr(handle));
            pcap_close(handle);
            return;
        }

        // 2. Apply the compiled filter to the pcap session
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "[C-Shark] Error: Could not install filter: %s\n", 
                    pcap_geterr(handle));
            pcap_close(handle);
            pcap_freecode(&fp); // Free the compiled program
            return;
        }

        // 3. Free the compiled program, it's now in the kernel
        pcap_freecode(&fp);
    }
    // ==========================================================
    
    global_handle = handle;
    
    printf("[C-Shark] Starting packet capture...\n");
    printf("[C-Shark] Press Ctrl+C to stop capture, Ctrl+D to exit program\n\n");
    fflush(stdout);
    
    // Set pcap to non-blocking mode
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "Error setting non-blocking mode: %s\n", errbuf);
        pcap_close(handle);
        return;
    }
    
    // Get file descriptor for pcap handle
    int pcap_fd = pcap_get_selectable_fd(handle);
    if (pcap_fd == -1) {
        fprintf(stderr, "Error: pcap_get_selectable_fd failed\n");
        pcap_close(handle);
        return;
    }
    
    // Main capture loop with input monitoring
    fd_set read_fds;
    struct timeval timeout;
    
    while (!stop_capture) {
        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds);  // Monitor stdin for Ctrl+D
        FD_SET(pcap_fd, &read_fds);       // Monitor pcap for packets
        
        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;  // 100ms timeout
        
        int select_result = select(FD_SETSIZE, &read_fds, NULL, NULL, &timeout);
        
        if (select_result == -1) {
            if (errno != EINTR) {  // Ignore signal interrupts
                perror("select");
                break;
            }
            continue;
        }
        
        // Check for input on stdin (Ctrl+D will cause EOF)
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            char buffer[1];
            int bytes_read = read(STDIN_FILENO, buffer, 1);
            if (bytes_read == 0) {
                // EOF detected (Ctrl+D)
                printf("\n[C-Shark] Ctrl+D detected. Exiting program...\n");
                pcap_close(handle);
                global_handle = NULL;
                exit(0);
            }
            // For other input, just consume and ignore
        }
        
        // Check for packets
        if (FD_ISSET(pcap_fd, &read_fds) || select_result == 0) {
            // Process available packets (non-blocking)
            int result = pcap_dispatch(handle, -1, packet_handler, NULL);
            if (result == -1) {
                fprintf(stderr, "Error in pcap_dispatch: %s\n", pcap_geterr(handle));
                break;
            }
        }
    }
    
    // Cleanup
    pcap_close(handle);
    global_handle = NULL;
    
    printf("\n[C-Shark] Capture stopped. Captured %d packets.\n", packet_id);
}

// Add session storage functionality
void save_session(const char *filename, const struct pcap_pkthdr *header, const unsigned char *packet) {
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    fprintf(file, "Packet | Timestamp: %ld.%ld | Length: %d bytes\n",
            header->ts.tv_sec, header->ts.tv_usec, header->len);
    fprintf(file, "First 16 bytes: ");
    for (int i = 0; i < 16 && i < header->len; i++) {
        fprintf(file, "%02x ", packet[i]);
    }
    fprintf(file, "\n\n");

    fclose(file);
}

// Add session inspection functionality
#include <stdio.h>

void inspect_session(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), file) != NULL) {
        printf("%s", line);
    }

    fclose(file);
}

// Free previous session data
void free_previous_session() {
    for (int i = 0; i < packet_count; i++) {
        free(packets[i].packet_data);
    }
    packet_count = 0;
    session_number++;
}

// Function prototypes for helpers
void store_packet(const struct pcap_pkthdr *header, const unsigned char *packet);
void free_previous_session();
void print_session_summary(void);
void print_full_hex_dump(const u_char *data, int length);
void inspect_single_packet(int packet_id);
void inspect_last_session(void);

// Utility: Print session summary for inspection
void print_session_summary(void) {
    if (packet_count == 0) {
        printf("\n[C-Shark] No packets captured in the last session. Run a sniffing session first!\n");
        return;
    }
    printf("\nSession #%d - Total packets: %d\n\n", session_number, packet_count);
    for (int i = 0; i < packet_count; i++) {
        char time_str[64];
        struct tm *tm_info = localtime(&packets[i].timestamp.tv_sec);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
        printf("  [%4d] Time: %s.%06ld | Length: %5d bytes\n",
               packets[i].id, time_str, packets[i].timestamp.tv_usec, packets[i].length);
        // Brief L3/L4 info
        if (packets[i].length >= 14) {
            struct ether_header *eth = (struct ether_header *)packets[i].packet_data;
            uint16_t ethertype = ntohs(eth->ether_type);
            if (ethertype == ETHERTYPE_IP && packets[i].length >= 14 + 20) {
             struct iphdr *ip_hdr = (struct iphdr *)(packets[i].packet_data + 14);
             struct in_addr src_addr, dst_addr;
             src_addr.s_addr = ip_hdr->saddr;
             dst_addr.s_addr = ip_hdr->daddr;
             printf("         L3: %s -> %s | Proto: %s\n",
                 inet_ntoa(src_addr), inet_ntoa(dst_addr), protocol_name(ip_hdr->protocol));
            } else if (ethertype == ETHERTYPE_ARP) {
                printf("         L3: ARP\n");
            } else if (ethertype == ETHERTYPE_IPV6) {
                printf("         L3: IPv6\n");
            } else {
                printf("         L3: Unknown\n");
            }
        }
        if (i < packet_count - 1) printf("\n");
    }
    printf("\n");
}

// Utility: Print full hex dump for inspection
void print_full_hex_dump(const u_char *data, int length) {
    printf("\n=== Full Packet Hex Dump ===\n");
    for (int i = 0; i < length; i++) {
        if (i % 16 == 0) {
            if (i != 0) {
                printf("  ");
                for (int j = i - 16; j < i; j++) {
                    unsigned char c = data[j];
                    printf("%c", (c >= 32 && c <= 126) ? c : '.');
                }
            }
            printf("\n%04X: ", i);
        }
        printf("%02X ", data[i]);
    }
    int remaining = length % 16;
    if (remaining != 0) {
        for (int i = 0; i < (16 - remaining); i++) printf("   ");
        printf("  ");
        for (int i = length - remaining; i < length; i++) {
            unsigned char c = data[i];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
    } else {
        printf("  ");
        for (int i = length - 16; i < length; i++) {
            unsigned char c = data[i];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
    }
    printf("\n\n");
}

// Inspect a single packet in detail
void inspect_single_packet(int packet_id) {
    int index = packet_id - 1;
    if (index < 0 || index >= packet_count) {
        printf("\n[C-Shark] Invalid packet ID. Valid range: 1-%d\n", packet_count);
        return;
    }
    stored_packet_t *pkt = &packets[index];
    char time_str[64];
    struct tm *tm_info = localtime(&pkt->timestamp.tv_sec);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("\nPacket ID: %d\nTimestamp: %s.%06ld\nLength: %d bytes\n\n",
           pkt->id, time_str, pkt->timestamp.tv_usec, pkt->length);
    print_full_hex_dump(pkt->packet_data, pkt->length);
    // Layer-by-layer analysis
    struct ether_header *eth_hdr = (struct ether_header *)pkt->packet_data;
    uint16_t ethertype = ntohs(eth_hdr->ether_type);
    printf("L2 (Ethernet): Dst MAC: %02X:%02X:%02X:%02X:%02X:%02X | Src MAC: %02X:%02X:%02X:%02X:%02X:%02X | ",
           eth_hdr->ether_dhost[0], eth_hdr->ether_dhost[1], eth_hdr->ether_dhost[2], eth_hdr->ether_dhost[3], eth_hdr->ether_dhost[4], eth_hdr->ether_dhost[5],
           eth_hdr->ether_shost[0], eth_hdr->ether_shost[1], eth_hdr->ether_shost[2], eth_hdr->ether_shost[3], eth_hdr->ether_shost[4], eth_hdr->ether_shost[5]);
    switch (ethertype) {
        case ETHERTYPE_IP:
            printf("EtherType: IPv4 (0x0800)\n");
            break;
        case ETHERTYPE_IPV6:
            printf("EtherType: IPv6 (0x86DD)\n");
            break;
        case ETHERTYPE_ARP:
            printf("EtherType: ARP (0x0806)\n");
            break;
        default:
            printf("EtherType: Unknown (0x%04X)\n", ethertype);
            break;
    }
    // Layer 3/4/7
    if (ethertype == ETHERTYPE_IP && pkt->length >= 14 + 20) {
        struct iphdr *ip_hdr = (struct iphdr *)(pkt->packet_data + 14);
        int ip_hdr_len = ip_hdr->ihl * 4;
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = ip_hdr->saddr;
        dst_addr.s_addr = ip_hdr->daddr;
        printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%d) | TTL: %d\n",
               inet_ntoa(src_addr),
               inet_ntoa(dst_addr),
               protocol_name(ip_hdr->protocol),
               ip_hdr->protocol,
               ip_hdr->ttl);
        printf("ID: 0x%04X | Total Length: %d | Header Length: %d bytes\n",
               ntohs(ip_hdr->id), ntohs(ip_hdr->tot_len), ip_hdr_len);
        int flags = ntohs(ip_hdr->frag_off) >> 13;
        printf("Flags: ");
        if (flags & 0x2) printf("DF ");
        if (flags & 0x1) printf("MF ");
        printf("| Fragment Offset: %d\n", ntohs(ip_hdr->frag_off) & 0x1FFF);
        print_l4_info(pkt->packet_data, ethertype, ip_hdr->protocol, ip_hdr_len, pkt->length);
        if (ip_hdr->protocol == IPPROTO_TCP && pkt->length >= 14 + ip_hdr_len + 20) {
            print_l7_info(pkt->packet_data, ethertype, ip_hdr->protocol, ip_hdr_len, 20, pkt->length);
        } else if (ip_hdr->protocol == IPPROTO_UDP && pkt->length >= 14 + ip_hdr_len + 8) {
            print_l7_info(pkt->packet_data, ethertype, ip_hdr->protocol, ip_hdr_len, 8, pkt->length);
        }
    } else if (ethertype == ETHERTYPE_IPV6 && pkt->length >= 14 + 40) {
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(pkt->packet_data + 14);
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst_ip, INET6_ADDRSTRLEN);
        printf("L3 (IPv6): Src IP: %s | Dst IP: %s | Next Header: %s (%d) | Hop Limit: %d\n",
               src_ip, dst_ip, protocol_name(ip6_hdr->ip6_nxt), ip6_hdr->ip6_nxt, ip6_hdr->ip6_hlim);
        printf("Traffic Class: %d | Flow Label: 0x%05X | Payload Length: %d\n",
               ((ntohl(ip6_hdr->ip6_flow) >> 20) & 0xFF), ntohl(ip6_hdr->ip6_flow) & 0xFFFFF, ntohs(ip6_hdr->ip6_plen));
        print_l4_info(pkt->packet_data, ethertype, ip6_hdr->ip6_nxt, 40, pkt->length);
        if (ip6_hdr->ip6_nxt == IPPROTO_TCP && pkt->length >= 14 + 40 + 20) {
            print_l7_info(pkt->packet_data, ethertype, ip6_hdr->ip6_nxt, 40, 20, pkt->length);
        } else if (ip6_hdr->ip6_nxt == IPPROTO_UDP && pkt->length >= 14 + 40 + 8) {
            print_l7_info(pkt->packet_data, ethertype, ip6_hdr->ip6_nxt, 40, 8, pkt->length);
        }
    } else if (ethertype == ETHERTYPE_ARP && pkt->length >= 14 + sizeof(struct ether_arp)) {
        struct ether_arp *arp_hdr = (struct ether_arp *)(pkt->packet_data + 14);
        printf("L3 (ARP): Operation: %s (%d) | Sender IP: %s | Target IP: %s\n",
               ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REQUEST ? "Request" : "Reply", ntohs(arp_hdr->ea_hdr.ar_op),
               inet_ntoa(*(struct in_addr *)&arp_hdr->arp_spa), inet_ntoa(*(struct in_addr *)&arp_hdr->arp_tpa));
        printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X | Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               arp_hdr->arp_sha[0], arp_hdr->arp_sha[1], arp_hdr->arp_sha[2], arp_hdr->arp_sha[3], arp_hdr->arp_sha[4], arp_hdr->arp_sha[5],
               arp_hdr->arp_tha[0], arp_hdr->arp_tha[1], arp_hdr->arp_tha[2], arp_hdr->arp_tha[3], arp_hdr->arp_tha[4], arp_hdr->arp_tha[5]);
        printf("HW Type: %d | Proto Type: 0x%04X | HW Len: %d | Proto Len: %d\n",
               ntohs(arp_hdr->ea_hdr.ar_hrd), ntohs(arp_hdr->ea_hdr.ar_pro), arp_hdr->ea_hdr.ar_hln, arp_hdr->ea_hdr.ar_pln);
    }
    printf("\n");
}

// Inspect last session: list summary and allow packet selection
void inspect_last_session(void) {
    print_session_summary();
    if (packet_count == 0) return;
    printf("Enter packet ID to inspect (or 0 to return): ");
    char input[10];
    if (fgets(input, sizeof(input), stdin) == NULL) return;
    int choice = atoi(input);
    if (choice == 0) return;
    inspect_single_packet(choice);
    while (1) {
        printf("\nEnter another packet ID to inspect (or 0 to return): ");
        if (fgets(input, sizeof(input), stdin) == NULL) return;
        choice = atoi(input);
        if (choice == 0) break;
        inspect_single_packet(choice);
    }
}

/* ############## LLM Generated Code Ends ################ */
