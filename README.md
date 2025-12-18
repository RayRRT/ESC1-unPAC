# ESC1-unPAC BOF

Request a certificate with arbitrary SAN (and SID to bypass [KB5014754](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16) AKA Strong Mapping), authenticate via PKINIT, and extract the NT hash

---

## Demo

#Havoc:

https://github.com/user-attachments/assets/806cfbed-2d64-4256-bc2b-0f93bc6c8e08

#CS:

https://github.com/user-attachments/assets/6827e260-b73e-4a49-98ba-df225cf95ac1



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

## Build

```bash
git clone https://github.com/RayRRT/ESC1-unPAC.git && cd ESC1-unPAC && chmod +x build.sh && ./build.sh
```

## Usage

### Havoc
1. Scripts → Load Script → `havoc/esc1-unpac.py`

### Cobalt Strike
1. Script Manager → Load → `cobaltstrike/esc1-unpac.cna`

### Command
```
esc1-unpac <CA> <Template> <UPN> [KDC]
```

### Example
```
esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template administrator@evilcorp.net
```

## Output

- PFX certificate (base64, password: `SpicyAD123`)
- TGT in kirbi format (Rubeus compatible)
- NT Hash

## References

- [Certified Pre-Owned - SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [KB5014754 - Strong Certificate Mapping](https://support.microsoft.com/en-us/topic/kb5014754)


---

## ⚠️ Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.

---

