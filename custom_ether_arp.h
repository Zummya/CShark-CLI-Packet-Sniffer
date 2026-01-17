// Custom definition of struct ether_arp
#ifndef CUSTOM_ETHER_ARP_H
#define CUSTOM_ETHER_ARP_H

#include <net/if_arp.h> // Include arphdr structure

struct ether_arp {
    struct arphdr ea_hdr; // Use the existing arphdr structure
    unsigned char arp_sha[6]; // Sender hardware address
    unsigned char arp_spa[4]; // Sender protocol address
    unsigned char arp_tha[6]; // Target hardware address
    unsigned char arp_tpa[4]; // Target protocol address
};

#endif // CUSTOM_ETHER_ARP_H