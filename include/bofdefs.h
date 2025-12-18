/*
 * BOF Definitions and Dynamic Function Resolution
 * SpicyAD-BOF - Active Directory Pentesting Toolkit
 */

#ifndef _BOFDEFS_H_
#define _BOFDEFS_H_

#include <windows.h>
#include <winldap.h>
#include <winber.h>
#include <dsgetdc.h>
#include <lm.h>
#include <ntsecapi.h>

#include "beacon.h"

/* Dynamic Function Resolution Macros for BOF */
#ifdef BOF

/* Kernel32 */
#define KERNEL32$GetLastError               ((DWORD(WINAPI*)(VOID))DynamicResolve(HASH_KERNEL32, HASH_GetLastError))
#define KERNEL32$LocalAlloc                 ((HLOCAL(WINAPI*)(UINT, SIZE_T))DynamicResolve(HASH_KERNEL32, HASH_LocalAlloc))
#define KERNEL32$LocalFree                  ((HLOCAL(WINAPI*)(HLOCAL))DynamicResolve(HASH_KERNEL32, HASH_LocalFree))
#define KERNEL32$VirtualAlloc               ((LPVOID(WINAPI*)(LPVOID, SIZE_T, DWORD, DWORD))DynamicResolve(HASH_KERNEL32, HASH_VirtualAlloc))
#define KERNEL32$VirtualFree                ((BOOL(WINAPI*)(LPVOID, SIZE_T, DWORD))DynamicResolve(HASH_KERNEL32, HASH_VirtualFree))
#define KERNEL32$CloseHandle                ((BOOL(WINAPI*)(HANDLE))DynamicResolve(HASH_KERNEL32, HASH_CloseHandle))
#define KERNEL32$GetComputerNameExW         ((BOOL(WINAPI*)(COMPUTER_NAME_FORMAT, LPWSTR, LPDWORD))DynamicResolve(HASH_KERNEL32, HASH_GetComputerNameExW))
#define KERNEL32$MultiByteToWideChar        ((int(WINAPI*)(UINT, DWORD, LPCCH, int, LPWSTR, int))DynamicResolve(HASH_KERNEL32, HASH_MultiByteToWideChar))
#define KERNEL32$WideCharToMultiByte        ((int(WINAPI*)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL))DynamicResolve(HASH_KERNEL32, HASH_WideCharToMultiByte))

/* WLDAP32 - LDAP Functions */
/* MinGW already declares these in winldap.h, so only declare for MSVC */
#ifndef __MINGW32__
DECLSPEC_IMPORT LDAP* LDAPAPI ldap_initW(PWSTR, ULONG);
DECLSPEC_IMPORT LDAP* LDAPAPI ldap_sslinitW(PWSTR, ULONG, int);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_set_optionW(LDAP*, int, const void*);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_simple_bind_sW(LDAP*, PWSTR, PWSTR);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_search_ext_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, PLDAPControlW*, PLDAPControlW*, struct l_timeval*, ULONG, LDAPMessage**);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI ldap_first_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT LDAPMessage* LDAPAPI ldap_next_entry(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT PWSTR LDAPAPI ldap_get_dnW(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT VOID LDAPAPI ldap_memfreeW(PWSTR);
DECLSPEC_IMPORT PWSTR LDAPAPI ldap_first_attributeW(LDAP*, LDAPMessage*, BerElement**);
DECLSPEC_IMPORT PWSTR LDAPAPI ldap_next_attributeW(LDAP*, LDAPMessage*, BerElement*);
DECLSPEC_IMPORT PWSTR* LDAPAPI ldap_get_valuesW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT struct berval** LDAPAPI ldap_get_values_lenW(LDAP*, LDAPMessage*, PWSTR);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_count_valuesW(PWSTR*);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_count_values_len(struct berval**);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_value_freeW(PWSTR*);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_value_free_len(struct berval**);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_msgfree(LDAPMessage*);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_unbind(LDAP*);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_unbind_s(LDAP*);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_modify_sW(LDAP*, PWSTR, LDAPModW*[]);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_add_sW(LDAP*, PWSTR, LDAPModW*[]);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_delete_sW(LDAP*, PWSTR);
DECLSPEC_IMPORT ULONG LDAPAPI ldap_count_entries(LDAP*, LDAPMessage*);
DECLSPEC_IMPORT ULONG LDAPAPI LdapGetLastError(VOID);
DECLSPEC_IMPORT PWSTR LDAPAPI ldap_err2stringW(ULONG);
#endif

/* Netapi32 */
#ifndef __MINGW32__
DECLSPEC_IMPORT DWORD WINAPI DsGetDcNameW(LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, PDOMAIN_CONTROLLER_INFOW*);
DECLSPEC_IMPORT DWORD WINAPI NetApiBufferFree(LPVOID);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NetUserAdd(LPCWSTR, DWORD, LPBYTE, LPDWORD);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NetUserDel(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NetGroupAddUser(LPCWSTR, LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT NET_API_STATUS WINAPI NetUserSetInfo(LPCWSTR, LPCWSTR, DWORD, LPBYTE, LPDWORD);
#endif

/* Secur32 - Security/Kerberos Functions */
#ifndef __MINGW32__
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY AcquireCredentialsHandleW(LPWSTR, LPWSTR, ULONG, PVOID, PVOID, SEC_GET_KEY_FN, PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY InitializeSecurityContextW(PCredHandle, PCtxtHandle, LPWSTR, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY FreeCredentialsHandle(PCredHandle);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY DeleteSecurityContext(PCtxtHandle);
DECLSPEC_IMPORT SECURITY_STATUS SEC_ENTRY FreeContextBuffer(PVOID);
#endif

/* Advapi32 */
#ifndef __MINGW32__
DECLSPEC_IMPORT BOOL WINAPI OpenProcessToken(HANDLE, DWORD, PHANDLE);
DECLSPEC_IMPORT BOOL WINAPI GetTokenInformation(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
DECLSPEC_IMPORT BOOL WINAPI LookupAccountSidW(LPCWSTR, PSID, LPWSTR, LPDWORD, LPWSTR, LPDWORD, PSID_NAME_USE);
DECLSPEC_IMPORT BOOL WINAPI ConvertSidToStringSidW(PSID, LPWSTR*);
DECLSPEC_IMPORT BOOL WINAPI ConvertStringSidToSidW(LPCWSTR, PSID*);
#endif

/* MSVCRT */
DECLSPEC_IMPORT void* __cdecl malloc(size_t);
DECLSPEC_IMPORT void __cdecl free(void*);
DECLSPEC_IMPORT void* __cdecl memset(void*, int, size_t);
DECLSPEC_IMPORT void* __cdecl memcpy(void*, const void*, size_t);
DECLSPEC_IMPORT int __cdecl memcmp(const void*, const void*, size_t);
DECLSPEC_IMPORT size_t __cdecl strlen(const char*);
DECLSPEC_IMPORT size_t __cdecl wcslen(const wchar_t*);
DECLSPEC_IMPORT int __cdecl strcmp(const char*, const char*);
DECLSPEC_IMPORT int __cdecl wcscmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT int __cdecl _wcsicmp(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl wcscpy(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT wchar_t* __cdecl wcscat(wchar_t*, const wchar_t*);
DECLSPEC_IMPORT char* __cdecl strcpy(char*, const char*);
DECLSPEC_IMPORT char* __cdecl strcat(char*, const char*);
DECLSPEC_IMPORT int __cdecl sprintf(char*, const char*, ...);
DECLSPEC_IMPORT int __cdecl swprintf(wchar_t*, const wchar_t*, ...);
DECLSPEC_IMPORT wchar_t* __cdecl wcsstr(const wchar_t*, const wchar_t*);
DECLSPEC_IMPORT char* __cdecl strstr(const char*, const char*);

/* Simplified Macros for common functions */
#define MSVCRT$malloc   malloc
#define MSVCRT$free     free
#define MSVCRT$memset   memset
#define MSVCRT$memcpy   memcpy
#define MSVCRT$memcmp   memcmp
#define MSVCRT$strlen   strlen
#define MSVCRT$wcslen   wcslen
#define MSVCRT$strcmp   strcmp
#define MSVCRT$wcscmp   wcscmp
#define MSVCRT$_wcsicmp _wcsicmp
#define MSVCRT$wcscpy   wcscpy
#define MSVCRT$wcscat   wcscat
#define MSVCRT$strcpy   strcpy
#define MSVCRT$strcat   strcat
#define MSVCRT$sprintf  sprintf
#define MSVCRT$swprintf swprintf
#define MSVCRT$wcsstr   wcsstr
#define MSVCRT$strstr   strstr

/* LDAP Macros */
#define WLDAP32$ldap_initW              ldap_initW
#define WLDAP32$ldap_sslinitW           ldap_sslinitW
#define WLDAP32$ldap_set_optionW        ldap_set_optionW
#define WLDAP32$ldap_bind_sW            ldap_bind_sW
#define WLDAP32$ldap_simple_bind_sW     ldap_simple_bind_sW
#define WLDAP32$ldap_search_sW          ldap_search_sW
#define WLDAP32$ldap_search_ext_sW      ldap_search_ext_sW
#define WLDAP32$ldap_first_entry        ldap_first_entry
#define WLDAP32$ldap_next_entry         ldap_next_entry
#define WLDAP32$ldap_get_dnW            ldap_get_dnW
#define WLDAP32$ldap_memfreeW           ldap_memfreeW
#define WLDAP32$ldap_first_attributeW   ldap_first_attributeW
#define WLDAP32$ldap_next_attributeW    ldap_next_attributeW
#define WLDAP32$ldap_get_valuesW        ldap_get_valuesW
#define WLDAP32$ldap_get_values_lenW    ldap_get_values_lenW
#define WLDAP32$ldap_count_valuesW      ldap_count_valuesW
#define WLDAP32$ldap_count_values_len   ldap_count_values_len
#define WLDAP32$ldap_value_freeW        ldap_value_freeW
#define WLDAP32$ldap_value_free_len     ldap_value_free_len
#define WLDAP32$ldap_msgfree            ldap_msgfree
#define WLDAP32$ldap_unbind             ldap_unbind
#define WLDAP32$ldap_unbind_s           ldap_unbind_s
#define WLDAP32$ldap_modify_sW          ldap_modify_sW
#define WLDAP32$ldap_add_sW             ldap_add_sW
#define WLDAP32$ldap_delete_sW          ldap_delete_sW
#define WLDAP32$ldap_count_entries      ldap_count_entries
#define WLDAP32$LdapGetLastError        LdapGetLastError
#define WLDAP32$ldap_err2stringW        ldap_err2stringW

/* NetAPI Macros */
#define NETAPI32$DsGetDcNameW       DsGetDcNameW
#define NETAPI32$NetApiBufferFree   NetApiBufferFree
#define NETAPI32$NetUserAdd         NetUserAdd
#define NETAPI32$NetUserDel         NetUserDel
#define NETAPI32$NetGroupAddUser    NetGroupAddUser
#define NETAPI32$NetUserSetInfo     NetUserSetInfo

/* Secur32 Macros */
#define SECUR32$AcquireCredentialsHandleW   AcquireCredentialsHandleW
#define SECUR32$InitializeSecurityContextW  InitializeSecurityContextW
#define SECUR32$FreeCredentialsHandle       FreeCredentialsHandle
#define SECUR32$DeleteSecurityContext       DeleteSecurityContext
#define SECUR32$FreeContextBuffer           FreeContextBuffer

/* Advapi32 Macros */
#define ADVAPI32$OpenProcessToken       OpenProcessToken
#define ADVAPI32$GetTokenInformation    GetTokenInformation
#define ADVAPI32$LookupAccountSidW      LookupAccountSidW
#define ADVAPI32$ConvertSidToStringSidW ConvertSidToStringSidW
#define ADVAPI32$ConvertStringSidToSidW ConvertStringSidToSidW

#else /* Non-BOF compilation */

#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "advapi32.lib")

#define MSVCRT$malloc   malloc
#define MSVCRT$free     free
#define MSVCRT$memset   memset
#define MSVCRT$memcpy   memcpy
#define MSVCRT$memcmp   memcmp
#define MSVCRT$strlen   strlen
#define MSVCRT$wcslen   wcslen
#define MSVCRT$strcmp   strcmp
#define MSVCRT$wcscmp   wcscmp
#define MSVCRT$_wcsicmp _wcsicmp
#define MSVCRT$wcscpy   wcscpy
#define MSVCRT$wcscat   wcscat
#define MSVCRT$strcpy   strcpy
#define MSVCRT$strcat   strcat
#define MSVCRT$sprintf  sprintf
#define MSVCRT$swprintf swprintf
#define MSVCRT$wcsstr   wcsstr
#define MSVCRT$strstr   strstr

#define WLDAP32$ldap_initW              ldap_initW
#define WLDAP32$ldap_sslinitW           ldap_sslinitW
#define WLDAP32$ldap_set_optionW        ldap_set_optionW
#define WLDAP32$ldap_bind_sW            ldap_bind_sW
#define WLDAP32$ldap_simple_bind_sW     ldap_simple_bind_sW
#define WLDAP32$ldap_search_sW          ldap_search_sW
#define WLDAP32$ldap_search_ext_sW      ldap_search_ext_sW
#define WLDAP32$ldap_first_entry        ldap_first_entry
#define WLDAP32$ldap_next_entry         ldap_next_entry
#define WLDAP32$ldap_get_dnW            ldap_get_dnW
#define WLDAP32$ldap_memfreeW           ldap_memfreeW
#define WLDAP32$ldap_first_attributeW   ldap_first_attributeW
#define WLDAP32$ldap_next_attributeW    ldap_next_attributeW
#define WLDAP32$ldap_get_valuesW        ldap_get_valuesW
#define WLDAP32$ldap_get_values_lenW    ldap_get_values_lenW
#define WLDAP32$ldap_count_valuesW      ldap_count_valuesW
#define WLDAP32$ldap_count_values_len   ldap_count_values_len
#define WLDAP32$ldap_value_freeW        ldap_value_freeW
#define WLDAP32$ldap_value_free_len     ldap_value_free_len
#define WLDAP32$ldap_msgfree            ldap_msgfree
#define WLDAP32$ldap_unbind             ldap_unbind
#define WLDAP32$ldap_unbind_s           ldap_unbind_s
#define WLDAP32$ldap_modify_sW          ldap_modify_sW
#define WLDAP32$ldap_add_sW             ldap_add_sW
#define WLDAP32$ldap_delete_sW          ldap_delete_sW
#define WLDAP32$ldap_count_entries      ldap_count_entries
#define WLDAP32$LdapGetLastError        LdapGetLastError
#define WLDAP32$ldap_err2stringW        ldap_err2stringW

#define NETAPI32$DsGetDcNameW       DsGetDcNameW
#define NETAPI32$NetApiBufferFree   NetApiBufferFree
#define NETAPI32$NetUserAdd         NetUserAdd
#define NETAPI32$NetUserDel         NetUserDel
#define NETAPI32$NetGroupAddUser    NetGroupAddUser
#define NETAPI32$NetUserSetInfo     NetUserSetInfo

#define SECUR32$AcquireCredentialsHandleW   AcquireCredentialsHandleW
#define SECUR32$InitializeSecurityContextW  InitializeSecurityContextW
#define SECUR32$FreeCredentialsHandle       FreeCredentialsHandle
#define SECUR32$DeleteSecurityContext       DeleteSecurityContext
#define SECUR32$FreeContextBuffer           FreeContextBuffer

#define ADVAPI32$OpenProcessToken       OpenProcessToken
#define ADVAPI32$GetTokenInformation    GetTokenInformation
#define ADVAPI32$LookupAccountSidW      LookupAccountSidW
#define ADVAPI32$ConvertSidToStringSidW ConvertSidToStringSidW
#define ADVAPI32$ConvertStringSidToSidW ConvertStringSidToSidW

#endif /* BOF */

/* User Account Control Flags */
#define UAC_SCRIPT                          0x00000001
#define UAC_ACCOUNTDISABLE                  0x00000002
#define UAC_HOMEDIR_REQUIRED                0x00000008
#define UAC_LOCKOUT                         0x00000010
#define UAC_PASSWD_NOTREQD                  0x00000020
#define UAC_PASSWD_CANT_CHANGE              0x00000040
#define UAC_ENCRYPTED_TEXT_PWD_ALLOWED      0x00000080
#define UAC_TEMP_DUPLICATE_ACCOUNT          0x00000100
#define UAC_NORMAL_ACCOUNT                  0x00000200
#define UAC_INTERDOMAIN_TRUST_ACCOUNT       0x00000800
#define UAC_WORKSTATION_TRUST_ACCOUNT       0x00001000
#define UAC_SERVER_TRUST_ACCOUNT            0x00002000
#define UAC_DONT_EXPIRE_PASSWORD            0x00010000
#define UAC_MNS_LOGON_ACCOUNT               0x00020000
#define UAC_SMARTCARD_REQUIRED              0x00040000
#define UAC_TRUSTED_FOR_DELEGATION          0x00080000
#define UAC_NOT_DELEGATED                   0x00100000
#define UAC_USE_DES_KEY_ONLY                0x00200000
#define UAC_DONT_REQ_PREAUTH                0x00400000
#define UAC_PASSWORD_EXPIRED                0x00800000
#define UAC_TRUSTED_TO_AUTH_FOR_DELEGATION  0x01000000
#define UAC_PARTIAL_SECRETS_ACCOUNT         0x04000000

/* Helper Macros */
#define SAFE_FREE(p) if(p) { MSVCRT$free(p); p = NULL; }

#endif /* _BOFDEFS_H_ */
