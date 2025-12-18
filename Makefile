# ESC1-unPAC BOF Makefile for Linux (Kali)
# Cross-compile BOF using mingw-w64

CC_x64 = x86_64-w64-mingw32-gcc
CFLAGS = -c -Os -fno-stack-protector -fno-asynchronous-unwind-tables
CFLAGS += -masm=intel -fno-ident -Wno-pointer-arith
INCLUDES = -I include -I include/beacon

SRC_DIR = src/adcs
BOF_NAME = ESC1-unPAC.x64.o

# Output directories
HAVOC_DIR = havoc/bofs
CS_DIR = cobaltstrike/bofs

.PHONY: all clean help

all: $(HAVOC_DIR)/$(BOF_NAME) $(CS_DIR)/$(BOF_NAME)
	@echo ""
	@echo "=========================================="
	@echo " ESC1-unPAC BOF compiled successfully!"
	@echo "=========================================="
	@echo ""
	@echo "Havoc:        $(HAVOC_DIR)/$(BOF_NAME)"
	@echo "Cobalt Strike: $(CS_DIR)/$(BOF_NAME)"
	@echo ""

$(HAVOC_DIR)/$(BOF_NAME): $(SRC_DIR)/esc1-unpac.c
	@mkdir -p $(HAVOC_DIR)
	@echo "[*] Compiling for Havoc..."
	$(CC_x64) $(CFLAGS) $(INCLUDES) -DBOF -o $@ $(SRC_DIR)/esc1-unpac.c

$(CS_DIR)/$(BOF_NAME): $(SRC_DIR)/esc1-unpac.c
	@mkdir -p $(CS_DIR)
	@echo "[*] Compiling for Cobalt Strike..."
	$(CC_x64) $(CFLAGS) $(INCLUDES) -DBOF -o $@ $(SRC_DIR)/esc1-unpac.c

help:
	@echo "ESC1-unPAC BOF Makefile"
	@echo "======================="
	@echo ""
	@echo "Targets:"
	@echo "  make all    - Build BOF for Havoc and Cobalt Strike"
	@echo "  make clean  - Remove compiled BOFs"
	@echo ""
	@echo "Requirements:"
	@echo "  sudo apt install mingw-w64"
	@echo ""

clean:
	@echo "[*] Cleaning BOF directories..."
	rm -f $(HAVOC_DIR)/*.o
	rm -f $(CS_DIR)/*.o
	@echo "[+] Clean complete"
