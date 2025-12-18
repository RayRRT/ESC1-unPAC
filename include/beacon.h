/*
 * BOF Beacon API Header
 * Compatible with Havoc C2 and Cobalt Strike
 */

#ifndef _BEACON_H_
#define _BEACON_H_

#include <windows.h>

/* Beacon Output Types */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

/* Beacon Data Parser */
typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

/* Beacon Format */
typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} formatp;

/* Beacon API Functions - Provided by Havoc */
DECLSPEC_IMPORT void    BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap* parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap* parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap* parser);
DECLSPEC_IMPORT char*   BeaconDataExtract(datap* parser, int* size);

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp* format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp* format);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp* format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp* format, char* text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp* format, char* fmt, ...);
DECLSPEC_IMPORT char*   BeaconFormatToString(formatp* format, int* size);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp* format, int value);

DECLSPEC_IMPORT void    BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT void    BeaconOutput(int type, char* data, int len);

DECLSPEC_IMPORT BOOL    BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void    BeaconRevertToken(void);
DECLSPEC_IMPORT BOOL    BeaconIsAdmin(void);

DECLSPEC_IMPORT void    BeaconGetSpawnTo(BOOL x86, char* buffer, int length);
DECLSPEC_IMPORT void    BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int payload_len, int payload_offset, char* arg, int arg_len);
DECLSPEC_IMPORT void    BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int payload_len, int payload_offset, char* arg, int arg_len);
DECLSPEC_IMPORT void    BeaconCleanupProcess(PROCESS_INFORMATION* pInfo);

DECLSPEC_IMPORT BOOL    toWideChar(char* src, wchar_t* dst, int max);

#endif /* _BEACON_H_ */
