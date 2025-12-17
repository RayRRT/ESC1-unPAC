# ESC1-unPAC BOF Makefile for Linux (Kali)
# Cross-compile BOF using mingw-w64

CC_x64 = x86_64-w64-mingw32-gcc
CFLAGS = -c -Os -fno-stack-protector -ffunction-sections -fno-asynchronous-unwind-tables
CFLAGS += -masm=intel -fno-ident -Wno-pointer-arith
INCLUDES = -I include -I include/beacon

BOF_DIR = havoc/bofs
SRC_DIR = src/adcs

# Output
BOF = $(BOF_DIR)/ESC1-unPAC.x64.o

.PHONY: all clean help

all: $(BOF)
	@echo ""
	@echo "=========================================="
	@echo " ESC1-unPAC BOF compiled successfully!"
	@echo "=========================================="
	@echo ""
	@ls -la $(BOF)
	@echo ""

help:
	@echo "ESC1-unPAC BOF Makefile"
	@echo "======================="
	@echo ""
	@echo "Targets:"
	@echo "  make all    - Build ESC1-unPAC BOF"
	@echo "  make clean  - Remove compiled BOF"
	@echo ""
	@echo "Requirements:"
	@echo "  sudo apt install mingw-w64"
	@echo ""

$(BOF): $(SRC_DIR)/esc1-unpac.c
	@mkdir -p $(BOF_DIR)
	@echo "[*] Compiling ESC1-unPAC BOF (ESC1 + PKINIT + UnPAC)..."
	$(CC_x64) $(CFLAGS) $(INCLUDES) -DBOF -o $@ $(SRC_DIR)/esc1-unpac.c

clean:
	@echo "[*] Cleaning BOF directory..."
	rm -f $(BOF_DIR)/*.o
	@echo "[+] Clean complete"

# Install to Havoc (adjust path as needed)
HAVOC_SCRIPTS = /opt/Havoc/data/extensions

install: all
	@echo "[*] Installing to Havoc..."
	@mkdir -p $(HAVOC_SCRIPTS)/ESC1-unPAC/bofs
	cp -r havoc/bofs/*.o $(HAVOC_SCRIPTS)/ESC1-unPAC/bofs/
	cp havoc/esc1-unpac.py $(HAVOC_SCRIPTS)/ESC1-unPAC/
	@echo "[+] Installed to $(HAVOC_SCRIPTS)/ESC1-unPAC/"
	@echo ""
	@echo "In Havoc: Scripts -> Load Script -> $(HAVOC_SCRIPTS)/ESC1-unPAC/esc1-unpac.py"
