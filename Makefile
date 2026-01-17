# C-Shark Packet Sniffer Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lpcap
TARGET = cshark

# Source files - Phase 1 only (add more as we progress)
SRCS = cshark.c interface.c capture.c
# SRCS += parser.c      # Uncomment for Phase 2
SRCS += filter.c      # Uncomment for Phase 3  
# SRCS += storage.c     # Uncomment for Phase 4
# SRCS += inspection.c  # Uncomment for Phase 5
OBJS = $(SRCS:.c=.o)
HEADERS = cshark.h

# Default target
all: $(TARGET)

# Link object files to create executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@echo ""
	@echo "==================================================="
	@echo "  C-Shark compiled successfully!"
	@echo "  Run with: sudo ./$(TARGET)"
	@echo "==================================================="
	@echo ""

# Compile source files to object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Cleaned build artifacts"

# Install dependencies (Debian/Ubuntu)
install-deps:
	@echo "Installing libpcap development library..."
	sudo apt-get update
	sudo apt-get install -y libpcap-dev
	@echo "Dependencies installed!"

# Help target
help:
	@echo "C-Shark Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build the C-Shark executable (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  install-deps - Install required dependencies (libpcap-dev)"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make              # Build the project"
	@echo "  sudo ./cshark     # Run the packet sniffer"
	@echo ""

.PHONY: all clean install-deps help
