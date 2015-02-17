/*
Copyright (c) 2014-2015, Jon Erickson
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors and should not be interpreted as representing official policies,
either expressed or implied, of the FreeBSD Project.

*/

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>
#include <Wincrypt.h>
#include "sdb.h"
#include "udis86.h"


BOOL resolveSdbFunctions();
extern SdbOpenDatabase SdbOpenDatabasePtr;
extern SdbCloseDatabase SdbCloseDatabasePtr;
extern SdbGetFileAttributes SdbGetFileAttributesPtr;
extern SdbTagToString SdbTagToStringPtr;
extern SdbGetFirstChild SdbGetFirstChildPtr;
extern SdbFreeFileAttributes SdbFreeFileAttributesPtr;
extern SdbGetTagFromTagID SdbGetTagFromTagIDPtr;
extern SdbGetNextChild SdbGetNextChildPtr;
extern SdbGetStringTagPtr SdbGetStringTagPtrPtr;
extern SdbReadBinaryTag SdbReadBinaryTagPtr;
extern SdbIsStandardDatabase SdbIsStandardDatabasePtr;
extern SdbReadDWORDTag SdbReadDWORDTagPtr;
extern SdbReadWORDTag SdbReadWORDTagPtr;
extern SdbGetBinaryTagData SdbGetBinaryTagDataPtr;
extern SdbGetTagDataSize SdbGetTagDataSizePtr;
extern SdbCreateDatabase SdbCreateDatabasePtr;
extern SdbGetShowDebugInfoOption SdbGetShowDebugInfoOptionPtr;
extern SdbWriteNULLTag SdbWriteNULLTagPtr;
extern SdbWriteDWORDTag SdbWriteDWORDTagPtr;
extern SdbCloseDatabaseWrite SdbCloseDatabaseWritePtr;
extern SdbBeginWriteListTag SdbBeginWriteListTagPtr;
extern SdbEndWriteListTag SdbEndWriteListTagPtr;
extern SdbWriteStringTag SdbWriteStringTagPtr;
extern SdbWriteBinaryTag SdbWriteBinaryTagPtr;
extern SdbReadQWORDTag SdbReadQWORDTagPtr;
extern SdbFindFirstTag SdbFindFirstTagPtr;
extern SdbFindNextTag SdbFindNextTagPtr;
extern SdbRegisterDatabaseEx SdbRegisterDatabaseExPtr;
extern SdbInitDatabase SdbInitDatabasePtr;
extern SdbGetMatchingExe SdbGetMatchingExePtr;
extern SdbGetMatchingExe SdbGetMatchingExePtr;
extern SdbDeclareIndex SdbDeclareIndexPtr;
extern SdbStartIndexing SdbStartIndexingPtr;
extern SdbStopIndexing SdbStopIndexingPtr;
extern SdbCommitIndexes SdbCommitIndexesPtr;

enum commands {
	INVAILID_COMMAND,
	PRINT_TREE,
	PRINT_LEAK,
	PROCESS_PATCH,
	PROCESS_CHECKSUM,
	PRINT_DLLS,
	CREATE_DATABASE,
	MATCH_EXE,
	REGISTER_DATABASE,
	CREATE_DATABASE_FROMFILE,
} cmd;

enum configDataState {
	INIT,
	APPLICATION,
	DATABASE,
	PATCH,
	COMPLETE,
} myState;

typedef struct _PATCHENTRY
{
	PPATCHBITS pb;
	DWORD size;
	struct _PATCHENTRY* next;
} PATCHENTRY, *PPATCHENTRY;

typedef struct _PATCH_DATA
{
	char* moduleName;
	DWORD checksum;
	DWORD count;
	DWORD totalSizeOfPatchEntries;
	TAGID patch_tagID;
	PPATCHENTRY patchentry;
	struct _PATCH_DATA* next;
} PATCH_DATA, *PPATCH_DATA;

typedef struct _APP_DATA
{
	char* appName;
	DWORD count;
	PPATCH_DATA patches;
} APP_DATA, *PAPP_DATA;

static wchar_t* filename = NULL;
static wchar_t* appname = NULL;
static char* dbname = NULL;
static LPOLESTR configFilename = NULL;
static wchar_t* searchexe;
static DWORD g_checksum = -1;
static DWORD g_patchid = -1;
static BOOL createIDC = FALSE;
static enum commands foo = INVAILID_COMMAND;
static TAGID currentEXEtag = TAGID_NULL;
static LPTSTR currentDLLname = NULL;
static BOOL is32Bit = TRUE;

__declspec(noreturn) void fatalError(char* format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	exit(-1);
}

void initUdis(ud_t *udis)
{
	ud_init(udis);
	if (is32Bit)
		ud_set_mode(udis, 32);
	else
		ud_set_mode(udis, 64);
	ud_set_syntax(udis, UD_SYN_INTEL);
}

void safeCoCreateGuid(LPGUID guid)
{
	if (CoCreateGuid(guid) != S_OK)
		fatalError("CoCreateGuid failed");
}

void usage()
{
	fprintf(stderr, "sdb-explorer\n");
	fprintf(stderr, "Copyright (C) 2015 Jon Erickson\n\n");

	fprintf(stderr, "Print full sdb tree\n");
	fprintf(stderr, "\tsdb-explorer.exe -t filename.sdb\n\n");
	fprintf(stderr, "Print patch details\n");
	fprintf(stderr, "\tsdb-explorer.exe [-i] -p filename.sdb (patch | patchid | patchref | patchbin)\n");
	fprintf(stderr, "\t\t-i - create IDAPython Script (optional)\n\n");
	fprintf(stderr, "Print patch details for checksum\n");
	fprintf(stderr, "\tsdb-explorer.exe [-i] -s filename.sdb\n\n");
	fprintf(stderr, "Create file containing the leaked memory\n");
	fprintf(stderr, "\tsdb-explorer.exe -l filename.sdb\n\n");
	fprintf(stderr, "Print Match Entries\n");
	fprintf(stderr, "\tsdb-explorer.exe -d filename.sdb\n\n");
	fprintf(stderr, "Create Patch From file\n");
	fprintf(stderr, "\tsdb-explorer.exe -C config.dat [-o filename.sdb]\n\n");
	fprintf(stderr, "Register sdb file\n");
	fprintf(stderr, "\tsdb-explorer.exe -r filename.sdb [-a application.exe]\n\n");
	fprintf(stderr, "Display usage\n");
	fprintf(stderr, "\tsdb-explorer.exe -h\n\n");
	
	exit(0);
}

void matchEXE()
{
	HSDB mdb;
	SDBQUERYRESULT result;
	mdb = SdbInitDatabasePtr(HID_DATABASE_FULLPATH | HID_DOS_PATHS, filename);
	if (!mdb)
	{
		fprintf(stderr, "failed to init database\n");
		return;
	}

	if (!SdbGetMatchingExePtr(mdb, searchexe, (LPCTSTR)L"explorer.exe", NULL, 0, &result))
	{
		fprintf(stderr, "Failed to find match\n");
		return;
	}
	printf("Found it\n");
}

DWORD createPatchOperation(PPATCHBITS out, DWORD opcode, LPBYTE buf, DWORD size, LPCTSTR moduleName, DWORD rva)
{
	PATCHBITS pb;
	size_t len;
	size_t ret = sizeof(PATCHBITS) + size;
	if (out == NULL)
	{
		if (opcode == 0)
		{
			// 00000000 00000000
			return 8;
		}
		// return size required
		return ret;
	}

	// end of patch operations
	if (opcode == 0)
	{
		memset(out, 0, 8);
		return 8;
	}

	len = wcslen(moduleName);
	if (len > (MAX_MODULE- 1))
		return -1;

	// callers job to ensure out has enough space to hold the patch data
	memset(&pb, 0, sizeof(PATCHBITS));
	pb.opcode = opcode;
	memcpy(&pb.moduleName, moduleName, len*sizeof(wchar_t));
	pb.patternSize = size;
	pb.actionSize = sizeof(PATCHBITS) + size;
	pb.rva = rva;
	pb.unknown = 0;

	// copy to outbuffer
	memcpy(out, &pb, sizeof(PATCHBITS));
	memcpy(((LPBYTE)out)+sizeof(PATCHBITS), buf, size);

	return ret;
}

LPBYTE getPatch(LPBYTE _sp, DWORD _sp_len, LPBYTE _rp, DWORD _rp_len, LPCTSTR moduleName, DWORD rva, DWORD* out)
{
	DWORD sSize, rSize;
	DWORD total;
	LPBYTE buf;

	sSize = createPatchOperation(NULL, PATCH_MATCH, _sp, _sp_len, moduleName, rva);
	rSize = createPatchOperation(NULL, PATCH_REPLACE, _rp, _rp_len, moduleName, rva);

	total = sSize + rSize + 8;
	buf = (LPBYTE)malloc(total);
	if (!buf) fatalError("Failed to allocate memory");
	memset(buf, 0, total);

	createPatchOperation((PPATCHBITS)buf, PATCH_MATCH, _sp, _sp_len, moduleName, rva);
	createPatchOperation((PPATCHBITS)&buf[sSize], PATCH_REPLACE, _rp, _rp_len, moduleName, rva);
	*out = total;
	return buf;
}

PAPP_DATA newApplication(char* appName)
{
	PAPP_DATA appData = (PAPP_DATA)malloc(sizeof(APP_DATA));
	if (!appData) fatalError("Failed to allocate memory");

	appData->appName = appName;
	appData->count = 0;
	appData->patches = NULL;

	return appData;
}

PPATCH_DATA newPatch(PAPP_DATA appData, char* moduleName, DWORD checksum)
{
	PPATCH_DATA patch_data = (PPATCH_DATA)malloc(sizeof(PATCH_DATA));
	if (!patch_data) fatalError("Failed to allocate memory");

	patch_data->moduleName = moduleName;
	patch_data->count = 0;
	patch_data->checksum = checksum;
	patch_data->patchentry = NULL;
	patch_data->patch_tagID = TAGID_NULL;
	patch_data->totalSizeOfPatchEntries = 0;

	// insert patch to beginning of patch list
	patch_data->next = appData->patches;
	appData->count += 1;
	appData->patches = patch_data;

	return patch_data;
}

void printMyPatchInfo(PAPP_DATA appData)
{
	PPATCH_DATA tmp;
	PPATCHENTRY tmppe;
	DWORD i,j, k;

	printf("%s\n", appData->appName);

	tmp = appData->patches;

	for (i = 0; i < appData->count; i++)
	{
		printf("\tAPP: %s CHECKSUM: %08x Total Patch Size: %d\n", tmp->moduleName, tmp->checksum, tmp->totalSizeOfPatchEntries);

		tmppe = tmp->patchentry;
		for (j = 0; j < tmp->count; j++)
		{
			wprintf(L"\t\tMOD: %s OPCODE: %d SIZE: %d RVA: %08x\n", tmppe->pb->moduleName, tmppe->pb->opcode, tmppe->pb->patternSize, tmppe->pb->rva);
			printf("\t\t\t");
			for (k = 0; k < tmppe->pb->patternSize; k++)
			{
				printf("%02x ", tmppe->pb->pattern[k]);
				if ((k+1) % 16 == 0) printf("\n\t\t\t");	
			}
			printf("\n");
			tmppe = tmppe->next;
		}
		tmp = tmp->next;
	}
}

PPATCHENTRY newMatchReplacePatchEntry(PPATCH_DATA patch_data, LPCTSTR moduleName, DWORD rva, PBYTE matchPattern, DWORD mpSize, PBYTE replacePattern, DWORD rpSize)
{
	DWORD size;
	PPATCHBITS pb;

	// do replace pattern
	PPATCHENTRY pe = (PPATCHENTRY)malloc(sizeof(PATCHENTRY));
	if (!pe) fatalError("Failed to allocate memory");

	size = createPatchOperation(NULL, PATCH_REPLACE, replacePattern, rpSize, moduleName, rva);
	pb = (PPATCHBITS)malloc(size);
	if (!pb) fatalError("Failed to allocate memory");

	// create replace entry first, so that the match will come first after the insert
	createPatchOperation(pb, PATCH_REPLACE, replacePattern, rpSize, moduleName, rva);
	pe->size = size;
	pe->pb = pb;

	// insert
	pe->next = patch_data->patchentry;
	patch_data->patchentry = pe;
	patch_data->totalSizeOfPatchEntries += size;

	// do match pattern
	pe = (PPATCHENTRY)malloc(sizeof(PATCHENTRY));
	if (!pe) fatalError("Failed to allocate memory");

	size = createPatchOperation(NULL, PATCH_MATCH, matchPattern, mpSize, moduleName, rva);
	pb = (PPATCHBITS)malloc(size);
	if (!pb) fatalError("Failed to allocate memory");

	// create replace entry first, so that the match will come first after the insert
	createPatchOperation(pb, PATCH_MATCH, matchPattern, mpSize, moduleName, rva);
	pe->size = size;
	pe->pb = pb;

	// insert match at beginning
	pe->next = patch_data->patchentry;
	patch_data->patchentry = pe;
	patch_data->totalSizeOfPatchEntries += size;

	// increase by two
	patch_data->count += 2;
	return pe;
}

PPATCHENTRY newReplacePatchEntry(PPATCH_DATA patch_data, LPCTSTR moduleName, DWORD rva, PBYTE replacePattern, DWORD rpSize)
{
	DWORD size;
	PPATCHBITS pb;

	// do replace pattern
	PPATCHENTRY pe = (PPATCHENTRY)malloc(sizeof(PATCHENTRY));
	if (!pe) fatalError("Failed to allocate memory");

	size = createPatchOperation(NULL, PATCH_REPLACE, replacePattern, rpSize, moduleName, rva);
	pb = (PPATCHBITS)malloc(size);
	if (!pb) fatalError("Failed to allocate memory");

	// create replace entry first, so that the match will come first after the insert
	createPatchOperation(pb, PATCH_REPLACE, replacePattern, rpSize, moduleName, rva);
	pe->size = size;
	pe->pb = pb;

	// insert
	pe->next = patch_data->patchentry;
	patch_data->patchentry = pe;

	// increase by two
	patch_data->count += 1;
	patch_data->totalSizeOfPatchEntries += size;

	return pe;
}

void getAttr(LPCTSTR filename)
{
	PATTRINFO ppAttrInfo = NULL;
	DWORD attrCount = 0;
	DWORD i;
	if (!SdbGetFileAttributesPtr(filename, &ppAttrInfo, &attrCount))
	{
		fprintf(stderr, "Failed to get attributes\n");
		exit(-1);
	}

	for (i = 0; i < attrCount; i++)
	{
		if ((ppAttrInfo[i].dwFlags & ATTRIBUTE_AVAILABLE) == ATTRIBUTE_AVAILABLE)
		{
			LPCTSTR tmp = SdbTagToStringPtr(ppAttrInfo[i].tAttrID);
			wprintf(L"TAG %x - %s: ", ppAttrInfo[i].tAttrID, tmp);
			if ((ppAttrInfo[i].tAttrID & TAG_TYPE_DWORD) == TAG_TYPE_DWORD)
			{
				wprintf(L"%d (0x%x)\n", ppAttrInfo[i].dwAttr, ppAttrInfo[i].dwAttr);
			} 
			else if ((ppAttrInfo[i].tAttrID & TAG_TYPE_STRINGREF) == TAG_TYPE_STRINGREF)
			{
				wprintf(L"%s\n", ppAttrInfo[i].lpAttr);
			} 
			else if ((ppAttrInfo[i].tAttrID & TAG_TYPE_QWORD) == TAG_TYPE_QWORD)
			{
				wprintf(L"%lld (0x%llx)\n", ppAttrInfo[i].ullAttr, ppAttrInfo[i].ullAttr);
			}
		}
	}
	SdbFreeFileAttributesPtr(ppAttrInfo);

}

void findPatchForChecksum(PDB db, TAGID tid, DWORD checksum, TAGID* found)
{
	TAG tmpTag = 0;
	DWORD dwD = 0;
	TAGID newtid = TAGID_NULL;
	LPCTSTR tmp;
	DWORD i = 0;

	if (*found != TAGID_NULL) return;

	newtid = SdbGetFirstChildPtr(db, tid);
	while (newtid != TAGID_NULL)
	{
		tmpTag = SdbGetTagFromTagIDPtr(db, newtid);
		tmp = SdbTagToStringPtr(tmpTag);

		// process tag types
		switch (tmpTag)
		{
		case TAG_EXE:
			currentEXEtag = newtid;
			break;
		case TAG_NAME:
			currentDLLname = SdbGetStringTagPtrPtr(db, newtid);
			break;
		case TAG_PE_CHECKSUM:
			dwD = SdbReadDWORDTagPtr(db, newtid, -1);
			if (dwD == checksum)
			{
				wprintf(L"Found checksum, EXE id = %x\n", currentEXEtag);
				*found = currentEXEtag;
			}
			break;

		default:
			break;
		}
		// recursive
		if ((tmpTag & TAG_TYPE_LIST) == TAG_TYPE_LIST)
		{
			findPatchForChecksum(db, newtid, checksum, found);
		}

		// get next tag
		newtid = SdbGetNextChildPtr(db, tid, newtid);
	}
}

void printDlls(PDB db, TAGID tid)
{
	TAG tmpTag = 0;
	DWORD dwD = 0;
	TAGID newtid = TAGID_NULL;
	LPCTSTR tmp;
	ULONGLONG quadword = 0;
	DWORD i = 0;

	newtid = SdbGetFirstChildPtr(db, tid);
	while (newtid != TAGID_NULL)
	{
		tmpTag = SdbGetTagFromTagIDPtr(db, newtid);
		tmp = SdbTagToStringPtr(tmpTag);

		// process tag types
		switch (tmpTag)
		{
		case TAG_EXE:
			currentEXEtag = newtid;
			break;
		case TAG_NAME:
			currentDLLname = SdbGetStringTagPtrPtr(db, newtid);
			break;
		case TAG_BIN_FILE_VERSION:
			quadword = SdbReadQWORDTagPtr(db, newtid, -1);
			break;
		case TAG_PE_CHECKSUM:
			dwD = SdbReadDWORDTagPtr(db, newtid, -1);
			printf("%S (", currentDLLname);

			wprintf(L"%d.", ((short*)&quadword)[3]);
			wprintf(L"%d.", ((short*)&quadword)[2]);
			wprintf(L"%d.", ((short*)&quadword)[1]);
			wprintf(L"%d", ((short*)&quadword)[0]);
			wprintf(L") Checksum = (0x%x)", dwD);
			//wprintf(L"%s ", currentDLLname);
			printf("\n");
			break;

		default:
			break;
		}
		// recursive
		if ((tmpTag & TAG_TYPE_LIST) == TAG_TYPE_LIST)
		{
			printDlls(db, newtid);
		}

		// get next tag
		newtid = SdbGetNextChildPtr(db, tid, newtid);
	}
}

void printLeaked(PDB db, TAGID tid, HANDLE leakF)
{
	TAG tmpTag = 0;
	DWORD dwD = 0;
	TAGID newtid = TAGID_NULL;
	DWORD i = 0;
	DWORD len;
	DWORD flag;
	size_t slen;
	size_t patternLen;
	BOOL isMore = TRUE;
	DWORD count = 0;
	DWORD myCount = 0;
	unsigned char* foo;
	unsigned char* leak;

	if (leakF == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Bad file handle passed to print leaked function\n");
		return;
	}

	newtid = SdbGetFirstChildPtr(db, tid);
	while (newtid != TAGID_NULL)
	{
		tmpTag = SdbGetTagFromTagIDPtr(db, newtid);

		// process tag types
		switch (tmpTag)
		{

		case TAG_PATCH_BITS:
			dwD = SdbGetTagDataSizePtr(db, newtid);
			foo = (unsigned char*)SdbGetBinaryTagDataPtr(db, newtid);
			// for each part of the patch
			while (isMore)
			{
				// check for invalid opcode
				flag = *(DWORD*)&foo[0];
				if (flag != 0x2 && flag !=0x4) break;

				len = *(DWORD*)&foo[4];
				patternLen = *(DWORD*)&foo[8];
				printf("Len: %d\n", len);
				slen = wcslen((const wchar_t*)&foo[0x14]);
				leak = foo + 0x14 +(slen*(sizeof(wchar_t)))+sizeof(wchar_t);
				myCount = len-patternLen-(slen*sizeof(wchar_t)+sizeof(wchar_t))-0x14;
				printf("offset: %x - leakLen: %x\n", 0x14+(slen*sizeof(wchar_t)+sizeof(wchar_t)), myCount);
				wprintf(L"\n");
				WriteFile(leakF, (LPVOID)leak, myCount, &count, NULL);
				if (myCount != count)
				{
					fprintf(stderr, "Error writting to leak file\n");
				}
				foo += len;
			}
			/*
			Sample Patch Data

			04 00 00 00 5b 00 00 00 07 00 00 00 ea 58 24 00
			fb 9d 0a 6d 6d 00 73 00 68 00 74 00 6d 00 6c 00
			2e 00 64 00 6c 00 6c 00 00 00 

			// LEAK
			0c 00 50 fc 0c 00
			90 fc 0c 00 e1 26 0c 6d 79 72 15 f7 fe ff ff ff
			fb 9d 0a 6d 5c fc 0c 00 46 27 09 6d 40 fc 49 00
			66 4f 0d 6d 
			// END LEAK
			90 90 90 90 90 8b ff 

			02 00 00 00 5b
			00 00 00 07 00 00 00 ea 58 24 00 00 00 1d 00 6d
			00 73 00 68 00 74 00 6d 00 6c 00 2e 00 64 00 6c
			00 6c 00 00 
			// LEAK
			00 d5 01 fe ff ff ff c3 3c c1 77 ee
			3c c1 77 60 00 00 00 68 00 00 00 82 87 1d 00 80
			87 1d 00 ff ff ff ff 60 00 00 00 46 e0 c0 77 
			// END LEAK
			e9 ac d7 2f 00 eb f9 

			04 00 00 00 58 00 00 00 04 00
			00 00 9b 30 54 00 fb 9d 0a 6d 6d 00 73 00 68 00
			74 00 6d 00 6c 00 2e 00 64 00 6c 00 6c 00 00 

			// LEAK
			00
			0c 00 50 fc 0c 00 90 fc 0c 00 e1 26 0c 6d 79 72
			15 f7 fe ff ff ff fb 9d 0a 6d 5c fc 0c 00 46 27
			09 6d 40 fc 49 00 
			// END LEAK
			66 4f 0d 6d 

			00 00 00 00 

			02 00 00 00 84 00 00 00 30 00 00 00 9b 30 54 00 00 00
			1d 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 2e 00
			64 00 6c 00 6c 00 00 

			// LEAK
			00 d5 01 fe ff ff ff c3 3c
			c1 77 ee 3c c1 77 60 00 00 00 68 00 00 00 82 87
			1d 00 80 87 1d 00 ff ff ff ff 60 00 00 00 46 e0
			c0 77 55 89 e5 8b 45 08 ff 40 04 ff 75 1c ff 75
			18 ff 75 14 ff 75 10 ff 75 0c ff 75 08 e8 36 28
			d0 ff 50 ff 75 08 e8 a7 0d d0 ff 58 89 ec 5d c2
			18 00 00 00 00 00 00 00 00 00 */
			break;
		}
		// recursive
		if ((tmpTag & TAG_TYPE_LIST) == TAG_TYPE_LIST)
		{
			printLeaked(db, newtid, leakF);
		}
		// get next tag
		newtid = SdbGetNextChildPtr(db, tid, newtid);
	}
}


void printTree(PDB db, TAGID tid, DWORD level)
{
	TAG tmpTag = 0;
	DWORD dwD = 0;
	TAGID newtid = TAGID_NULL;
	LPOLESTR str;
	LPCTSTR tmp;
	DWORD i = 0;
	GUID guid;
	ULONGLONG quadword;
	unsigned char* foo;

	newtid = SdbGetFirstChildPtr(db, tid);
	while (newtid != TAGID_NULL)
	{
		tmpTag = SdbGetTagFromTagIDPtr(db, newtid);
		tmp = SdbTagToStringPtr(tmpTag);

		// indent levels
		for (i = 0; i < level; i++)
		{
			wprintf(L"\t");
		}
		wprintf(L"%x TAG %x - %s", newtid, tmpTag, tmp);

		// process tag types
		switch (tmpTag)
		{
		case TAG_DATABASE_ID:
			if (SdbReadBinaryTagPtr(db, newtid, (PBYTE)&guid, sizeof(guid)))
			{
				if (StringFromCLSID((REFCLSID)&guid, &str) == S_OK)
				{
					wprintf(L": %s", str);
					if (SdbIsStandardDatabasePtr(guid))
					{
						wprintf(L" STANDARD");
					}
					else
					{
						wprintf(L" NON-STANDARD");
					}
					CoTaskMemFree(str);
				}
			}
			break;
		case TAG_APP_ID:
		case TAG_FIX_ID:
		case TAG_EXE_ID:
			if (SdbReadBinaryTagPtr(db, newtid, (PBYTE)&guid, sizeof(guid)))
			{
				if (StringFromCLSID((REFCLSID)&guid, &str) == S_OK)
				{
					wprintf(L": %s", str);
					CoTaskMemFree(str);
				}
			}
			break;

		case TAG_PATCH_BITS:
			dwD = SdbGetTagDataSizePtr(db, newtid);
			foo = (unsigned char*)SdbGetBinaryTagDataPtr(db, newtid);
			wprintf(L"\n");
			break;
		case TAG_INDEX_BITS:
			dwD = SdbGetTagDataSizePtr(db, newtid);
			foo = (unsigned char*)SdbGetBinaryTagDataPtr(db, newtid);
			wprintf(L"\n");

			for (i = 0; i < dwD; i++)
			{
				wprintf(L"%02x ", foo[i]);
				if (((i + 1) % 16) == 0)
				{
					wprintf(L"\n");
				}
			}
			//exit(-1);

			break;

			// dwords
		case TAG_PATCH_TAGID:
		case TAG_SHIM_TAGID:
		case TAG_PE_CHECKSUM:
		case TAG_CHECKSUM:
		case TAG_DATA_DWORD:
		case TAG_OS_PLATFORM:
		case TAG_DESCRIPTION_RC_ID:
		case TAG_INDEX_FLAGS:
			dwD = SdbReadDWORDTagPtr(db, newtid, -1);
			wprintf(L": %d (0x%x)", dwD, dwD);
			break;

			// words
		case TAG_INDEX_KEY:
		case TAG_INDEX_TAG:
			dwD = SdbReadWORDTagPtr(db, newtid, -1);
			wprintf(L": %d (0x%x)", dwD, dwD);
			break;

			// strings
		case TAG_APP_NAME:
		case TAG_COMPILER_VERSION:
		case TAG_VENDOR:
		case TAG_COMPANY_NAME:
		case TAG_NAME:
		case TAG_PRODUCT_NAME:
		case TAG_PRODUCT_VERSION:
		case TAG_STRINGTABLE_ITEM:
		case TAG_MODULE:
		case TAG_FILE_DESCRIPTION:
		case TAG_COMMAND_LINE:
		case TAG_DLLFILE:
		case TAG_FLAGS:
			wprintf(L": %ws", SdbGetStringTagPtrPtr(db, newtid));
			break;

			// quad word
		case TAG_UPTO_BIN_PRODUCT_VERSION:
		case TAG_UPTO_BIN_FILE_VERSION:
		case TAG_BIN_FILE_VERSION:
			quadword = SdbReadQWORDTagPtr(db, newtid, -1);
			wprintf(L": %d.", ((short*)&quadword)[3]);
			wprintf(L"%d.", ((short*)&quadword)[2]);
			wprintf(L"%d.", ((short*)&quadword)[1]);
			wprintf(L"%d", ((short*)&quadword)[0]);
			break;

		default:
			break;
		}

		wprintf(L"\n");

		// recursive
		if ((tmpTag & TAG_TYPE_LIST) == TAG_TYPE_LIST)
		{
			printTree(db, newtid, level + 1);
		}

		// get next tag
		newtid = SdbGetNextChildPtr(db, tid, newtid);
	}
}

void registerDatabase()
{
	PDB db = NULL;
	LPOLESTR str2;
	DWORD size;
	LPWSTR str = NULL;
	TAGID dbid = TAGID_NULL;
	PVOID tmp;
	HKEY res, res2;
	DWORD disp;
	DWORD status = 0;
	DWORD64 quad = 0;
	char buf[1024];


	printf("Registering %ws...\n", filename);

	size = GetFullPathNameW(filename, 0, NULL, NULL);
	str = malloc((size+1)*sizeof(WCHAR));
	if (!str) fatalError("Failed to allocated memory");
	size = GetFullPathNameW(filename, size, str, NULL);

	// get database id
	db = SdbOpenDatabasePtr(str, DOS_PATH);
	if (!db) fatalError("Could not open sdb file to identify database id");

	dbid = SdbFindFirstTagPtr(db, TAGID_ROOT, TAG_DATABASE);
	if (dbid == TAGID_NULL) fatalError("Could not find DB");

	dbid = SdbFindFirstTagPtr(db, dbid, TAG_DATABASE_ID);
	if (dbid == TAGID_NULL) fatalError("Could not find DB id");

	tmp = SdbGetBinaryTagDataPtr(db, dbid);
	if (!tmp) fatalError("Error retrieving database id");
	
	if (StringFromCLSID((REFCLSID)tmp, &str2) == S_OK)
	{
		printf("Found %ws\n", str2);
		sprintf_s(buf, sizeof(buf), "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB\\%ws", str2);
		
	} else fatalError("Failed to convert databaseid to guid");

	// done searching for the database id
	SdbCloseDatabasePtr(db);

	if (!SdbRegisterDatabaseExPtr(str, SDB_DATABASE_SHIM, NULL))
	{
		fprintf(stderr, "Failed to register database: %ws", filename);
		return;
	}

	// find the database install time
	printf("Trying to open: %s\n", buf);
	status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, buf, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY , &res);
	if (status != ERROR_SUCCESS) fatalError("failed to open registery key");

	size = 8;
	status = RegQueryValueExA(res, "DatabaseInstallTimeStamp", NULL, NULL, (LPBYTE)&quad, &size);
	if (status != ERROR_SUCCESS) fatalError("failed to get database install time");

	printf("Database installed date: %llu\n", quad);
	RegCloseKey(res);

	// create the application name in the Custom
	sprintf_s(buf, sizeof(buf), "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom");
	printf("trying to open: %s\n", buf);
	status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, buf, 0, KEY_ALL_ACCESS | KEY_CREATE_SUB_KEY | KEY_WOW64_64KEY , &res);
	if (status != ERROR_SUCCESS) fatalError("failed to open registery key");

	// Create or open existing application
	status = RegOpenKeyExW(res, appname, 0, KEY_ALL_ACCESS, &res2);
	if (status != ERROR_SUCCESS)
	{
		status = RegCreateKeyExW(res, appname, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &res2, &disp);
	}
	if (status != ERROR_SUCCESS) 
	{
		fatalError("Can't create RegCreateKeyExW, error: %d (0x%x)", status, status);
	}
	
	// write the database install time value
	sprintf_s(buf, sizeof(buf), "%ws.sdb", str2);
	printf("writting to: %s\n", buf);
	status = RegSetValueExA(res2, buf, 0, REG_QWORD, (LPBYTE)&quad, sizeof(DWORD64));
	if (status != ERROR_SUCCESS) fatalError("failed to set value");

	RegCloseKey(res2); // application name
	RegCloseKey(res); // custom

	CoTaskMemFree(str2);
	str2 = NULL;
	free(str);
	str = NULL;

	printf("done\n");
	return;
}

void createIDAPython(LPBYTE buf)
{
	DWORD i;
	PPATCHBITS pb;
	char *tmp;
	DWORD size;

	printf("from idaapi import *\n\n");
	printf("base = idaapi.get_imagebase();\n");
	printf("addr = 0;\n\n");

	// iterate through the patch actions
	pb = (PPATCHBITS)buf;
	while (1)
	{
		if (pb->opcode != PATCH_MATCH && pb->opcode != PATCH_REPLACE)
		{
			break;
		}

		// ignore match actions
		if (pb->opcode == PATCH_REPLACE)
		{	
			printf("addr = base + 0x%x;\n", pb->rva);

			// turn each byte into \xYY
			size = pb->patternSize * 4;
			tmp = (char*)malloc(size + 1);
			if (!tmp) break;

			// for each byte put into \xYY form.
			for (i = 0; i < pb->patternSize; i++)
			{
				sprintf_s(&tmp[i*4], 5, "\\x%02x", pb->pattern[i]);
			}
			printf("print \"Patching: 0x%%x %d bytes\" %% (addr)\n", pb->patternSize);
			printf("idaapi.patch_many_bytes(addr, \"%s\");\n\n", tmp);

			free(tmp);
			tmp = NULL;

		}
		// goto next action
		pb = (PPATCHBITS)((PBYTE)pb + pb->actionSize);
	}
}

void displayPatch(LPBYTE buf)
{
	DWORD i;
	PPATCHBITS pb;
	ud_t disasm;

	if (buf == NULL)
	{
		return;
	}

	if (createIDC == TRUE)
	{
		createIDAPython(buf);
		return;
	}

	initUdis(&disasm);

	// iterate through the patch actions
	pb = (PPATCHBITS)buf;
	while (1)
	{
		if (pb->opcode != PATCH_MATCH && pb->opcode != PATCH_REPLACE)
		{
			break;
		}
		wprintf(L"module     : %s\n", pb->moduleName);
		wprintf(L"opcode     : %d %s\n", pb->opcode, pb->opcode == PATCH_MATCH ? L"MATCH" : L"REPLACE");
		wprintf(L"actionSize : %d\n", pb->actionSize);
		wprintf(L"patternSize: %d\n", pb->patternSize);
		wprintf(L"RVA        : 0x%08x\n", pb->rva);
		wprintf(L"Bytes: ");
		for (i = 0; i < pb->patternSize; i++)
		{
			wprintf(L"%02x ", pb->pattern[i]);
		}
		wprintf(L"\n\n");

		printf("Code:\n");
		ud_set_input_buffer(&disasm, pb->pattern, pb->patternSize);
		while (ud_disassemble(&disasm))
		{
			printf("\t%08llx  %-16s %s\n", ud_insn_off(&disasm), ud_insn_hex(&disasm), ud_insn_asm(&disasm));
		}
		printf("\n");
		initUdis(&disasm);

		// goto next action
		pb = (PPATCHBITS)( (PBYTE)pb + pb->actionSize ); 
	}
}

void dumpPatchBits(PDB db, TAGID patchbits)
{
	DWORD size;
	TAG tmpTag;
	char tmp[20];
	size_t i;
	unsigned char* buf;

	tmpTag = SdbGetTagFromTagIDPtr(db, patchbits);
	if (tmpTag != TAG_PATCH_BITS)
	{
		fatalError("dumpPatchBits called with a non-patchbit tag");
		return;
	}

	size = SdbGetTagDataSizePtr(db, patchbits);
	if (size == -1)
	{
		wprintf(L"Error getting patchbin size\n");
		return;
	}
	buf = (unsigned char*)SdbGetBinaryTagDataPtr(db, patchbits);
	if (buf == NULL)
	{
		wprintf(L"Error getting patchbin data\n");
		return;
	}

	wprintf(L"\n");
	sprintf_s(tmp, sizeof(tmp), "%08X:  ", 0);
	printf(" %s", tmp);
	for (i = 0; i < size; i++)
	{

		wprintf(L"%02x ", buf[i]);
		if (((i + 1) % 4) == 0)
		{
			printf(" ");
		}
		if (((i + 1) % 16) == 0)
		{
			wprintf(L"\n");
			sprintf_s(tmp, sizeof(tmp), "%08X:  ", i + 1);
			printf(" %s", tmp);
		}
	}
	wprintf(L"\n\n");

	// iterate through the patch actions
	displayPatch(buf);
}

void dumpPatch(PDB db, TAGID patch)
{
	//TAGID patch = TAGID_NULL;
	TAGID patchbits = TAGID_NULL;
	TAG tmpTag;

	tmpTag = SdbGetTagFromTagIDPtr(db, patch);
	if (tmpTag != TAG_PATCH)
	{
		fatalError("dumpPatch called with a non-patch tag");
		return;
	}

	patchbits = SdbFindFirstTagPtr(db, patch, TAG_PATCH_BITS);
	if (patchbits == TAGID_NULL)
	{
		wprintf(L"Error getting patchbits tag\n");
		return;
	}

	dumpPatchBits(db, patchbits);
}

void dumpPatchTagId(PDB db, TAGID patchtagid)
{
	TAG tmpTag;
	DWORD patch;

	tmpTag = SdbGetTagFromTagIDPtr(db, patchtagid);
	if (tmpTag != TAG_PATCH_TAGID)
	{
		fatalError("dumpPatchTagId called with a non-patchtagid tag");
		return;
	}

	patch = SdbReadDWORDTagPtr(db, patchtagid, -1);
	if (patch == -1)
	{
		wprintf(L"Error getting patch tag\n");
	}

	dumpPatch(db, patch);
}

void dumpPatchRef(PDB db, TAGID patchref)
{
	TAGID patchbinid = TAGID_NULL;
	TAG tmpTag;

	tmpTag = SdbGetTagFromTagIDPtr(db, patchref);
	if (tmpTag != TAG_PATCH_REF)
	{
		fatalError("dumpPatchRef called with a non-patchref tag");
		return;
	}

	patchbinid = SdbFindFirstTagPtr(db, patchref, TAG_PATCH_TAGID);
	if (patchbinid == TAGID_NULL)
	{
		wprintf(L"Error getting patchbinid tag\n");
		return;
	}

	dumpPatchTagId(db, patchbinid);
}

void processPatchByChecksum(PDB db, DWORD checksum)
{
	TAGID exe = TAGID_NULL;
	TAGID patchref = TAGID_NULL;
	
	findPatchForChecksum(db, TAGID_ROOT, checksum, &exe);
	if (exe != TAGID_NULL)
	{
		//wprintf(L"found tagid: %x\n", exe);
		patchref = SdbFindFirstTagPtr(db, exe, TAG_PATCH_REF);

		while (patchref != TAGID_NULL)
		{

			if (patchref == TAGID_NULL)
			{
				wprintf(L"Error getting patchref\n");
				return;
			}
			dumpPatchRef(db, patchref);

			patchref = SdbFindNextTagPtr(db, exe, patchref);
		}
	}
}

void printPatchByTagId(PDB db, TAGID tid)
{
	TAG tmpTag = 0;
	LPCTSTR tmp;

	tmpTag = SdbGetTagFromTagIDPtr(db, tid);
	tmp = SdbTagToStringPtr(tmpTag);

	printf("Trying to process patch by tag type: %S\n", tmp);

	switch (tmpTag)
	{
	case TAG_PATCH_BITS:
		dumpPatchBits(db, tid);
		break;
	case TAG_PATCH:
		dumpPatch(db, tid);
		break;
	case TAG_PATCH_REF:
		dumpPatchRef(db, tid);
		break;
	case TAG_PATCH_TAGID:
		dumpPatchTagId(db, tid);
		break;

	default:
		fatalError("You must specify a tagid of type PATCH, PATCH_REF, PATCH_BITS, or PATCH_TAGID");
		break;
	}
}

BOOL processArgs(int argc, wchar_t** argv)
{
	if(argc<2)
	{
		return 0;
	}

	argv++;
	argc--;
	while((argc>0) &&(argv[0][0]=='-'))
	{
		switch(argv[0][1])
		{
		case 't': // print tree
			if (argc < 2)
			{
				fprintf(stderr, "-t requires a filename\n");
				return 0;
			}
			cmd = PRINT_TREE;
			filename = argv[1];
			argv+=2;
			argc-=2;
			break;

		case 'l': // print leak
			if (argc < 2)
			{
				fprintf(stderr, "-l requires a filename\n");
				return 0;
			}
			cmd = PRINT_LEAK;
			filename = argv[1];
			argv+=2;
			argc-=2;
			break;
		case 'r': // register database
			if (argc < 2)
			{
				fprintf(stderr, "-r requires a filename\n");
				return 0;
			}
			cmd = REGISTER_DATABASE;
			filename = argv[1];
			argv+=2;
			argc-=2;
			break;
		case 'd': // print dlls
			if (argc < 2)
			{
				fprintf(stderr, "-d requires a filename\n");
				return 0;
			}
			cmd = PRINT_DLLS;
			filename = argv[1];
			argv+=2;
			argc-=2;
			break;
		case 'm': // match exe
			if (argc < 2)
			{
				fprintf(stderr, "-m requires a filename\n");
				return 0;
			}
			cmd = MATCH_EXE;
			filename = argv[1];
			searchexe = argv[2];
			argv+=3;
			argc-=3;
			break;
		case 'p': // print patch info from patch tag id
			if (argc < 3)
			{
				fprintf(stderr, "-p requires a filename and patchtagid\n");
				return 0;
			}
			cmd = PROCESS_PATCH;
			filename = argv[1];
			g_patchid = (DWORD)wcstoul((const wchar_t*)argv[2], 0, 16);
			argv+=3;
			argc-=3;
			break;
		case 'i':
			createIDC = TRUE;
			argv++;
			argc--;
			break;
		case 's': // print patch info from checksum
			if (argc < 3)
			{
				fprintf(stderr, "-p requires a filename and checksum\n");
				return 0;
			}
			cmd = PROCESS_CHECKSUM;
			filename = argv[1];
			g_checksum = (DWORD)wcstoul((const wchar_t*)argv[2], 0, 0);
			argv += 3;
			argc -= 3;
			break;
		case 'h':
			usage();
			break;
		case 'C':
			if (argc < 2)
			{
				fprintf(stderr, "-C requires a filename\n");
				return 0;
			}
			cmd = CREATE_DATABASE_FROMFILE;
			configFilename = argv[1];
			argv+=2;
			argc-=2;
			break;

		case 'o':
			if (argc < 2)
			{
				fprintf(stderr, "-o requires a filename\n");
				return 0;
			}
			filename = argv[1];
			argv+=2;
			argc-=2;
			break;
		case 'a':
			if (argc < 2)
			{
				fprintf(stderr, "-a requires a application name\n");
				return 0;
			}
			appname = argv[1];
			argv+=2;
			argc-=2;
			break;
		default:
			{
				fprintf(stderr, "Invaild option %S\n", argv[0]);
				return 0;
			}
		}
	}
	return 1;
}

LPBYTE unhexify(char* str, LPDWORD out)
{
	BYTE tmp[3];
	DWORD i;
	DWORD len;
	LPBYTE buf;
	tmp [2] = 0;
	len = strlen(str);
	if (len % 2) fatalError("hex string is not divisable by 2, check your config file");

	buf = (LPBYTE)malloc(len);
	if (!buf) fatalError("Failed to allocate memory");

	for (i = 0; i < len / 2; i++)
	{
		memcpy(tmp, &str[i*2], 2);
		buf[i] = strtoul(tmp, 0, 16) & 0xff;
	}

	*out = len / 2;

	return buf;

}

DWORD split(char* str, char** out, DWORD count)
{
	DWORD returnMe = 1;
	char* tmp = NULL;
	char* context = NULL;

	if (count == 0) 
	{
		return 0;
	}

	tmp = strtok_s(str, ",", &context);
	out[0] = tmp;
	count--;
	while (count && tmp)
	{
		tmp = strtok_s(NULL, ",", &context);
		out[returnMe++] = tmp;
		count--;
	}
	return returnMe;
}

PBYTE getPatchDataBuffer(PPATCH_DATA ppd)
{
	DWORD i;
	PBYTE tmp;
	PPATCHENTRY ppe;
	PBYTE buf = (PBYTE)malloc(ppd->totalSizeOfPatchEntries + 8);
	if (!buf) fatalError("Failed to allocate memory\n");

	tmp = buf;
	ppe = ppd->patchentry;
	for (i = 0; i < ppd->count; i++)
	{
		memcpy(tmp, ppe->pb, ppe->size);
		tmp += ppe->size;
		ppe = ppe->next;
	}
	memset(tmp, 0, 8);

	return buf;
}

void createDatabaseFromAppData(PAPP_DATA appdata)
{
	GUID guid;
	wchar_t tmp[512];
	TAGID databaseref, libraryref, patchref, exeref, matchfileref, patchfileref;
	PPATCH_DATA ppb;
	INDEXID idxId = -1;
	PBYTE patchdata;
	DWORD i;


	// lets create the patch
	PDB newDb = SdbCreateDatabasePtr(filename, DOS_PATH);

	// index?
	if (!SdbDeclareIndexPtr(newDb, TAG_EXE, TAG_NAME, 1, TRUE, &idxId))
	{
		fprintf(stderr, "Failed to declare index\n");
		return;
	}

	if (!SdbStartIndexingPtr(newDb, idxId))
	{
		fprintf(stderr, "Failed to start indexing\n");
		return;
	}

	SdbStopIndexingPtr(newDb, idxId);
	SdbCommitIndexesPtr(newDb);

	// Database
	databaseref = SdbBeginWriteListTagPtr(newDb, TAG_DATABASE);
	swprintf(tmp, sizeof(tmp)/sizeof(wchar_t), L"%S", dbname);
	SdbWriteStringTagPtr(newDb, TAG_NAME, tmp);
	
	safeCoCreateGuid(&guid);
	SdbWriteBinaryTagPtr(newDb, TAG_DATABASE_ID, (PBYTE)&guid, sizeof(GUID));

	// library
	libraryref = SdbBeginWriteListTagPtr(newDb, TAG_LIBRARY);

	// PATCHES
	ppb = appdata->patches;
	for (i = 0; i < appdata->count; i++)
	{
		patchref = SdbBeginWriteListTagPtr(newDb, TAG_PATCH);
		ppb->patch_tagID = patchref;
		patchdata = getPatchDataBuffer(ppb);
		swprintf_s(tmp, 12, L"patchdata%d", i);
		SdbWriteStringTagPtr(newDb, TAG_NAME, tmp);
		SdbWriteBinaryTagPtr(newDb, TAG_PATCH_BITS, (PBYTE)patchdata, ppb->totalSizeOfPatchEntries+8);
		free(patchdata);

		SdbEndWriteListTagPtr(newDb, patchref);

		ppb = ppb->next;
	}

	// end Library
	SdbEndWriteListTagPtr(newDb, libraryref);


	SdbStartIndexingPtr(newDb, idxId);

	if (appdata->count > 999)
		fatalError("Too many patches, this can be increased if needed");

	ppb = appdata->patches;
	for (i = 0; i < appdata->count; i++)
	{

		// start EXE
		exeref = SdbBeginWriteListTagPtr(newDb, TAG_EXE);
		swprintf(tmp, sizeof(tmp)/sizeof(wchar_t), L"%S", appdata->appName);
		SdbWriteStringTagPtr(newDb, TAG_NAME, tmp);
		SdbWriteStringTagPtr(newDb, TAG_APP_NAME, tmp);

		safeCoCreateGuid(&guid);
		SdbWriteBinaryTagPtr(newDb, TAG_EXE_ID, (PBYTE)&guid, sizeof(GUID));

		// match file
		/*
		matchfileref = SdbBeginWriteListTagPtr(newDb, TAG_MATCHING_FILE);
		SdbWriteStringTagPtr(newDb, TAG_NAME, L"*");
		SdbEndWriteListTagPtr(newDb, matchfileref);
		*/

		// match file
		matchfileref = SdbBeginWriteListTagPtr(newDb, TAG_MATCHING_FILE);
		swprintf(tmp, sizeof(tmp)/sizeof(wchar_t), L"%S", ppb->moduleName);

		SdbWriteStringTagPtr(newDb, TAG_NAME, tmp);

		if (ppb->checksum != 0)
		{
			SdbWriteDWORDTagPtr(newDb, TAG_PE_CHECKSUM, ppb->checksum);
		}

		// end MATCH
		SdbEndWriteListTagPtr(newDb, matchfileref);

		// patch file ref
		patchfileref = SdbBeginWriteListTagPtr(newDb, TAG_PATCH_REF);

		swprintf_s(tmp, 12, L"patchdata%d", i);
		

		SdbWriteStringTagPtr(newDb, TAG_NAME, tmp);
		SdbWriteDWORDTagPtr(newDb, TAG_PATCH_TAGID, ppb->patch_tagID);
		SdbEndWriteListTagPtr(newDb, patchfileref);
		
		// end EXE
		SdbEndWriteListTagPtr(newDb, exeref);

		ppb = ppb->next;

	}
	// end Database
	SdbEndWriteListTagPtr(newDb, databaseref);

	// close
	SdbCloseDatabaseWritePtr(newDb);

}

void createDatabaseFromFile(void)
{
	wchar_t wmod_name[(MAX_MODULE+1)/sizeof(wchar_t)];
	PAPP_DATA appdata = NULL;
	PPATCH_DATA pd = NULL;
	GUID dbGuid;
	BOOL error = FALSE;
	BOOL status = FALSE;
	LPOLESTR str = NULL;
	LPBYTE configData = NULL;
	DWORD i, out;
	char* newline = NULL;
	HANDLE f = INVALID_HANDLE_VALUE;
	myState = INIT;

	if (!filename)
	{
		safeCoCreateGuid(&dbGuid);
		if (StringFromCLSID((REFCLSID)&dbGuid, &str) == S_OK)
		{
			wprintf(L"Creating new Database: %s.sdb\n\n", str);
			filename = str;
		}
		else
		{
			fatalError("StringFromCLSID failed");

		}
	} 
	else
	{
		wprintf(L"Creating new Database: %s\n\n", filename);
	}

	f = CreateFileW(configFilename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (f == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "Failed to load the config file\n");
		if (str) CoTaskMemFree(str);
		return;
	}

	i = GetFileSize(f, NULL);
	configData = malloc(i + 1);
	if (!configData)
	{
		fprintf(stderr, "Failed to allocate space for config\n");
		if (str) CoTaskMemFree(str);
		CloseHandle(f);
		return;
	}
	configData[i] = 0;

	status = ReadFile(f, configData, i, &out, NULL);
	if (status == FALSE || out != i)
	{
		fprintf(stderr, "Failed to read config file\n");
		if (str) CoTaskMemFree(str);
		CloseHandle(f);
		return;
	}

	newline = strchr(configData, '\n');
	if (newline)
	{
		newline[0] = 0;
	}

	// check for valid start
	if (strcmp(configData, "!sdbpatch") != 0)
	{
		// invalid start
		fprintf(stderr, "Bad read config file\n");
		if (str) CoTaskMemFree(str);
		CloseHandle(f);
		return;
	}
	configData = newline+1;

	// Process config file.
	while (error == FALSE || (configData && configData[0]))
	{
		newline = strchr(configData, '\n');
		if (newline)
		{
			newline[0] = 0;
		}

		if (configData[0] == '#')
		{
			// ignore
		}
		else
		{
			//printf("GOT: %s\n", configData);

			// skip whitespace
			while (configData[0] == ' ' || configData[0] == '\t' || configData[0] == '\r') configData++;

			if (myState == INIT)
			{
				if (_strnicmp(configData, "APP=", 4) == 0)
				{
					configData += 4;
					printf("Application: %s\n", configData);
					appdata = newApplication(configData);
					myState = APPLICATION;
				}
				else
				{
					fprintf(stderr, "Failed to find APP in conf\n");
					error = TRUE;
					break;
				}
			}
			else if (myState == APPLICATION)
			{
				if (_strnicmp(configData, "DBNAME=", 7) == 0)
				{
					configData += 7;
					printf("Database Name: %s\n", configData);
					dbname = configData;
					myState = DATABASE;
				}
				else 
				{
					fprintf(stderr, "Failed to find a PATCH in conf\n");
					error = TRUE;
					break;
				}
			}
			else if (myState == DATABASE)
			{
				if (_strnicmp(configData, "P:", 2) == 0)
				{
					char* entries[2];
					DWORD checksum = 0;
					DWORD tmps = -1;
					DWORD count;

					configData += 2;
					printf("Patch: %s\n", configData);

					count = split(configData, entries, 2);
					if (count != 1 && count != 2)
					{
						fprintf(stderr, "bad P: line\n");
						error = TRUE;
						break;
					}
					if (count == 2 && entries[1])
						checksum = strtoul(entries[1], 0, 16);

					pd = newPatch(appdata, entries[0], checksum);		
					myState = PATCH;
				}
				else 
				{
					fprintf(stderr, "Failed to find a PATCH in conf\n");
					error = TRUE;
					break;
				}
			}
			else if (myState == PATCH)
			{
				if (_strnicmp(configData, "P:", 2) == 0)
				{
					char* entries[2];
					DWORD checksum = 0;
					DWORD tmps = -1;
					DWORD count;
					configData += 2;
					printf("NEW Patch: %s\n", configData);

					count = split(configData, entries, 2);
					if (count != 1 && count != 2)
					{
						fprintf(stderr, "bad P: line\n");
						error = TRUE;
						break;
					}

					if (count == 2 && entries[1])
						checksum = strtoul(entries[1], 0, 16);

					pd = newPatch(appdata, entries[0], checksum);					
					myState = PATCH;
				}
				else if (_strnicmp((const char*)configData, "MR:", 3) == 0)
				{
					char* modulename;
					DWORD rva;
					char* myrp;
					DWORD rpsize;
					char* mymp;
					DWORD mpsize;
					DWORD count;
					char* entries[4];

					configData += 3;
					printf("Match Replace: %s\n", configData);

					count = split(configData, entries, 4);
					if (count != 4)
					{
						fprintf(stderr, "bad MR: line\n");
						error = TRUE;
						break;
					}

					modulename = entries[0];
					rva = strtoul(entries[1], 0, 16);
					mymp = unhexify(entries[2], &mpsize);
					myrp = unhexify(entries[3], &rpsize);

					swprintf(wmod_name, MAX_MODULE, L"%S", modulename);
					newMatchReplacePatchEntry(pd, (LPCTSTR)wmod_name, rva, mymp, mpsize, myrp, rpsize);

				}
				else if (_strnicmp(configData, "R:", 2) == 0)
				{
					char* modulename;
					DWORD rva;
					char* myrp;
					DWORD rpsize;
					char* entries[3];
					DWORD count;
					configData += 2;
					printf("Replace: %s\n", configData);

					count = split(configData, entries, 3);
					if (count != 3)
					{
						fprintf(stderr, "bad R: line\n");
						error = TRUE;
						break;
					}
					modulename = entries[0];
					rva = strtoul(entries[1], 0, 16);
					myrp = unhexify(entries[2], &rpsize);

					swprintf(wmod_name, MAX_MODULE, L"%S", modulename);
					newReplacePatchEntry(pd, (LPCTSTR)wmod_name, rva, myrp, rpsize);

				}
				else if (_strnicmp(configData, "!endsdbpatch", 12) == 0)
				{
					myState = COMPLETE;
					printf("ending....\n");
					break;
				}
				else 
				{
					fprintf(stderr, "config file corrupt\n");
					error = TRUE;
					break;
				}
			}
			else 
			{
				// should never get here
				fprintf(stderr, "should never get here\n");
				error = TRUE;
				break;
			}
		}

		// move to the next line.
		if (!newline)
		{
			configData = newline;
		}
		else 
		{
			configData = newline+1;
		}
	} // end while loop

	if (myState != COMPLETE || error == TRUE)
	{
		fprintf(stderr, "config file corrupt\n");
		return;
	}

	printf("Completed Processing\n");


	printMyPatchInfo(appdata);

	createDatabaseFromAppData(appdata);

	return;
}

int wmain(int argc, wchar_t** argv)
{
	PDB db = NULL;
	HANDLE leakF = NULL;

	if (!resolveSdbFunctions())
	{
		fprintf(stderr, "Failed to load SdbFunctions, exiting..\n");
		exit(-1);
	}

	if (!processArgs(argc, argv))
	{
		usage();
		return 0;
	}

	if (cmd == MATCH_EXE)
	{
		matchEXE();
		return;
	}
	else if (cmd == REGISTER_DATABASE)
	{
		registerDatabase();
		return;
	}
	else if (cmd == CREATE_DATABASE_FROMFILE)
	{
		createDatabaseFromFile();
		return;
	}

	db = SdbOpenDatabasePtr(filename, DOS_PATH);
	if (!db)
	{
		DWORD stat = GetLastError();
		fprintf(stderr, "Failed to load SDB file %d (0x%x)\n", stat, stat);
		exit(-1);
	}
	switch (cmd)
	{
	case PRINT_TREE:
		printTree(db, TAGID_ROOT, 0);
		break;
	case PROCESS_PATCH:
		printPatchByTagId(db, g_patchid);
		break;
	case PROCESS_CHECKSUM:
		processPatchByChecksum(db, g_checksum);
		break;
	case PRINT_LEAK:
		leakF = CreateFileA("leaked.bin", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		printLeaked(db, TAGID_ROOT, leakF);
		CloseHandle(leakF);
		break;
	case PRINT_DLLS:
		printDlls(db, TAGID_ROOT);
	}
	SdbCloseDatabasePtr(db);

	return 0;
}