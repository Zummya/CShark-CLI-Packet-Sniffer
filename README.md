# C-Shark: Command-Line Packet Sniffer 🦈

A terminal-based network packet sniffer built in C using libpcap, featuring layer-by-layer packet dissection from Ethernet (Layer 2) to Application (Layer 7).

## Overview

C-Shark is a comprehensive packet sniffing tool that allows you to:
- Discover and select network interfaces
- Capture live network traffic in real-time
- Apply protocol filters (HTTP, HTTPS, DNS, ARP, TCP, UDP)
- Parse packets layer-by-layer (Ethernet, IP/IPv6/ARP, TCP/UDP, Application)
- Store captured packets for later inspection
- Perform detailed forensic analysis on individual packets

## Features

### Phase 1: Interface Discovery & Basic Capture
- Automatic detection of all network interfaces
- Interactive interface selection
- Live packet capture with ID, timestamp, and length
- Graceful handling of Ctrl+C (stops capture) and Ctrl+D (exits program)

### Phase 2: Layer-by-Layer Dissection
- **Layer 2 (Ethernet)**: MAC addresses, EtherType identification
- **Layer 3 (Network)**:
  - IPv4: Source/Dest IP, Protocol, TTL, Flags, Header details
  - IPv6: Source/Dest IPv6, Next Header, Hop Limit, Flow Label
  - ARP: Operation type, Sender/Target MAC and IP addresses
- **Layer 4 (Transport)**:
  - TCP: Ports, Sequence/Ack numbers, Flags (SYN, ACK, etc.), Window size
  - UDP: Ports, Length, Checksum
- **Layer 7 (Application)**: Protocol identification, Hex dump of payload (first 64 bytes)

### Phase 3: Protocol Filtering
Support for filtering by:
- HTTP (port 80)
- HTTPS (port 443)
- DNS (port 53)
- ARP
- TCP
- UDP

### Phase 4: Session Storage
- Stores up to 10,000 packets per session
- Automatic memory management (clears previous session on new capture)
- Prevents memory leaks with proper cleanup

### Phase 5: Forensic Analysis
- List all captured packets with summary
- Select individual packets for detailed inspection
- Complete hex dump of entire packet frame
- Layer-by-layer breakdown with raw hex values and human-readable interpretations

## Requirements

### System Requirements
- Linux operating system (tested on Ubuntu/Debian)
- Root/sudo privileges (required for packet capture)
- GCC compiler
- libpcap development library

### Installing Dependencies

```bash
# On Ubuntu/Debian
sudo apt-get update
sudo apt-get install libpcap-dev gcc make

# Or use the Makefile
make install-deps
```

## Building

```bash
make
```

This will compile all source files and create the `cshark` executable.

## Usage

### Running C-Shark

```bash
sudo ./cshark
```

**Note:** Root privileges (sudo) are required for packet capture.

### Basic Workflow

1. **Select Interface**: Choose from the list of available network interfaces
2. **Main Menu**: Choose one of four options:
   - Start Sniffing (All Packets)
   - Start Sniffing (With Filters)
   - Inspect Last Session
   - Exit

3. **Capture Packets**: Watch live packets scroll by with detailed layer information
4. **Stop Capture**: Press Ctrl+C to stop and return to menu
5. **Inspect**: View detailed analysis of captured packets

## Project Structure

```
B/
├── cshark.c          # Main program and menu logic
├── cshark.h          # Header file with structures and prototypes
├── interface.c       # Interface discovery and selection
├── capture.c         # Packet capture and live display
├── parser.c          # Layer-by-layer packet parsing
├── filter.c          # Protocol filtering
├── storage.c         # Session storage and memory management
├── inspection.c      # Detailed packet inspection
├── Makefile          # Build system
├── README.md         # This file
├── CHANGELOG.md      # Development history
└── VIVA_GUIDE.md     # Study guide for viva/evaluation
```

## Testing

Test on loopback interface for predictable results:

```bash
# Terminal 1: Run C-Shark on loopback
sudo ./cshark
# Select 'lo' interface

# Terminal 2: Generate traffic
ping 127.0.0.1
curl http://localhost
```

## Key Features Implemented

✅ **Phase 1**: Interface discovery and basic capture  
✅ **Phase 2**: Full layer-by-layer parsing (L2-L7)  
✅ **Phase 3**: Protocol filtering (HTTP, HTTPS, DNS, ARP, TCP, UDP)  
✅ **Phase 4**: Session storage with memory management  
✅ **Phase 5**: Detailed forensic inspection  

## Memory Management

C-Shark carefully manages memory with proper allocation and cleanup to prevent leaks.

## Known Limitations

- Maximum 10,000 packets per session (configurable)
- No persistent storage between runs
- Cannot decrypt encrypted traffic

---

**Built for LAZY Corp's C-Shark Division 🦈**